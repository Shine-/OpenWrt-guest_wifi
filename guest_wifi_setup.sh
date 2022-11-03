#!/bin/sh

# This script will automatically set up Guest WiFi network(s), separated from your LAN network, on your OpenWrt device.
# For OpenWrt versions/configurations that support it, it will also enable OWE (Enhanced Open) using a transition network.
# Based on an original script from https://github.com/jkool702/OpenWrt-guest_wifi/
# This script features the following fixes and rewrites, compared to the original script:
#  * remove/fix several typos, invalid or missing settings and unwanted dependencies
#  * make compatible with earlier (and later) versions of OpenWrt
#  * improve detection of OWE capabilities and rewrite WiFi setup to support any number of radios and bands
#  * turn guest networks on/off with a helper script similar to OpenWrt's "wifi", instead of a system service
#  * get rid of all the reboots that the original script performs, as none of them is necessary
#  * replace some hardcoded settings with automatic/randomized ones to prevent possible collisions
# Please find the latest version of this script at https://github.com/Shine-/OpenWrt-guest_wifi/

# Prerequisites for OWE:
#  OpenWrt 21.02 or later will work out-of-the-box
#  for OpenWrt 19.07, install prerequisites as follows: opkg update && opkg remove wpad* && opkg install wpad-wolfssl

# Turning on or off the guest WiFi networks:
# After this script finishes, you can enable or disable the Guest WiFi SSIDs using the following command:
#  'guest_wifi enable'   turns on the Guest WiFi SSIDs
#  'guest_wifi disable'  turns off the Guest WiFi SSIDs
#  'guest_wifi restart'  restarts all radios that carry Guest WiFi SSIDs
#  'guest_wifi'          without parameters is the same as 'restart'
# Note: If your radios are turned off globally, the 'guest_wifi' command will not turn them on.
# It will warn you regarding which radio(s) are disabled, though.


# === User configurable settings below ===

# By setting the below variable, you can define a custom guest network SSID to use.
# If this is unset, the default setting of 'Guest_WiFi' will be used.
# Note: In case OWE transition is used, the OWE SSID will have an additional "_OWE" appended.
GuestWiFi_SSID=''

# By setting the below variable, you can forcibly enable/disable OWE and OWE transition mode.
#  empty         = autodetect based on OpenWrt version and wpad/hostapd variant with SAE (WPA3+OWE) support
#  '1'           = use OWE and generate randomized transition BSSIDs (requires OpenWrt 19.07 or later)
#  '2'           = use OWE and let OpenWrt assign transition BSSIDs (requires OpenWrt 22.03.0-rc5 or later)
#  '3'           = use OWE only, don't create any unencrypted transition SSID (requires OpenWrt 19.07 or later)
#  anything else = don't use OWE, create unencrypted guest WiFi (Open Network) only
# Note: Setting the below forced flag turns off any prerequisite check - make sure that your setup supports the selected option!
use_OWE_flag=''

# By setting the below variables, you can forcibly assign a specific subnet to use for your Guest WiFi.
# Example:
#  GuestWiFi_IP='192.0.2.1'
#  GuestWiFi_netmask='255.255.255.0'
# If this is unset (default) or invalid, the script will choose a random /24 subnet in the 10.0.0.0/8 range.
GuestWiFi_IP=''
GuestWiFi_netmask=''

# === End of user configurable settings ===


# determine whether to use user-defined SSID or default one

[ -z "$GuestWiFi_SSID" ] && GuestWiFi_SSID='Guest_WiFi'

# determine whether to use OWE transition mode, based on version, wpad/hostapd variant, or forced setting

[ -z "$use_OWE_flag" ] && {
	eval $(cat /etc/openwrt_release | grep -E '^DISTRIB_RE(LEASE|VISION)=')
	REV=${DISTRIB_REVISION/[+-]*/}; REV=${REV#r}; [ -n "$REV" ] && { echo "$REV" | grep -qe "^[0-9]*$"; } || unset REV
	case $DISTRIB_RELEASE in
		# up to 18.06: no SAE support at all
		[0-9]|1[0-8].*) use_OWE_flag='0' ;;
		# 19.07: need full wpad/hostapd variant with openssl/wolfssl for OWE support
		19.*) [ -z "$({ opkg list-installed wpad*; opkg list-installed hostapd*; } | cut -f 1 -d ' ' | grep -E '^wpad$|^hostapd$|basic')" ] && use_OWE_flag='1' || use_OWE_flag='0' ;;
		# starting from 21.02: OWE enabled in all full and all openssl/wolfssl variants of hostapd/wpad (including "basic")
		21.*) use_OWE_flag='1' ;;
		# starting from 22.03 r19446 or SNAPSHOT r19805: can auto-generate transition SSIDs/BSSIDs, choose that method if supported
		22.*) [ -n "$REV" ] && [ "$REV" -lt "19446" ] && use_OWE_flag='1' || use_OWE_flag='2' ;;
		SNAPSHOT) [ -n "$REV" ] && [ "$REV" -lt "19805" ] && use_OWE_flag='1' || use_OWE_flag='2' ;;
		*) use_OWE_flag='2' ;;
	esac
	[ -z "$({ opkg list-installed wpad*; opkg list-installed hostapd*; } | cut -f 1 -d ' ' | grep -E '^hostapd$|^wpad$|ssl$|tls$')" ] && use_OWE_flag='0'
}

# determine whether to use predefined IP address and subnet (minimum allowed size is /29) or generate random 10.x.x.1/24

RNG='/dev/urandom'
echo "${GuestWiFi_IP}" | grep -qE '^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))$' || GuestWiFi_IP=''
echo "${GuestWiFi_netmask}" | grep -qE '^(254|252|248|240|224|192|128)\.0\.0\.0|255\.(254|252|248|240|224|192|128|0)\.0\.0|255\.255\.(254|252|248|240|224|192|128|0)\.0|255\.255\.255\.(248|240|224|192|128|0)$' || GuestWiFi_netmask=''
[ -z "${GuestWiFi_IP}" -o -z "${GuestWiFi_netmask}" ] && {
	INTIP=$((0x0a`head -c2 $RNG | hexdump -ve '/1 \"%02x\"'`01))
	INTNM=$((0xffffff00))
} || {
	INTIP=$((0)); for BYTE in `echo "${GuestWiFi_IP}" | tr '.' ' '`; do INTIP=$(( ${INTIP}<<8|${BYTE} )); done
	INTNM=$((0)); for BYTE in `echo "${GuestWiFi_netmask}" | tr '.' ' '`; do INTNM=$(( ${INTNM}<<8|${BYTE} )); done
}
INTSN=$((INTIP&INTNM)); INTBC=$((~INTNM&0xffffffff|INTIP))
[ "$INTIP" -eq "$INTSN" ] && INTIP=$((INTSN+1)) || { [ "$INTIP" -eq "$INTBC" ] && INTIP=$((INTBC-1)); } # sanitize IP
GuestWiFi_IP=$((INTIP>>24&0xff)).$((INTIP>>16&0xff)).$((INTIP>>8&0xff)).$((INTIP&0xff))
GuestWiFi_netmask=$((INTNM>>24&0xff)).$((INTNM>>16&0xff)).$((INTNM>>8&0xff)).$((INTNM&0xff))

# calculate largest possible consecutive DHCP range in selected subnet

[ $((INTIP-(INTSN+1))) -gt $((INTBC-1-INTIP)) ] && { DHCPSTART=$((INTSN+1)); DHCPEND=$((INTIP-1)); } || { DHCPSTART=$((INTIP+1)); DHCPEND=$((INTBC-1)); }
DHCPCOUNT=$((DHCPEND-DHCPSTART+1)); DHCPSTART=$((DHCPSTART>>24&0xff)).$((DHCPSTART>>16&0xff)).$((DHCPSTART>>8&0xff)).$((DHCPSTART&0xff))

# setup network config

. /lib/functions.sh
config_load network

[ -z "$(config_foreach echo 'device')" ] && {
	# config style up to 19.07
	uci -q delete network.guest
	uci batch << EOI
set network.guest=interface
set network.guest.type='bridge'
EOI
} || {
	# config style from 21.02 onward
	uci -q delete network.guest_dev
	uci batch << EOI
set network.guest_dev=device
set network.guest_dev.type='bridge'
set network.guest_dev.name='br-guest'
EOI
	uci -q delete network.guest
	uci batch << EOI
set network.guest=interface
set network.guest.device='br-guest'
EOI
}

uci batch << EOI
set network.guest.proto='static'
set network.guest.ip6assign='64'
set network.guest.ipaddr="${GuestWiFi_IP}"
set network.guest.netmask="${GuestWiFi_netmask}"
EOI

uci commit network

# setup dhcp config

uci -q delete dhcp.guest
uci batch << EOI
set dhcp.guest=dhcp
set dhcp.guest.interface='guest'
set dhcp.guest.start="${DHCPSTART}"
set dhcp.guest.limit="${DHCPCOUNT}"
set dhcp.guest.leasetime='12h'
set dhcp.guest.dhcpv6='server'
set dhcp.guest.ra='server'
set dhcp.guest.force='1'
EOI

uci commit dhcp

# setup wireless config

config_load wireless
ALLRADIOS=$(config_foreach echo 'wifi-device')

for RADIO in $ALLRADIOS; do

	uci -q delete wireless.guest_${RADIO}
	uci -q delete wireless.guest_${RADIO}_owe

	# create Open Network (unencrypted) SSID
	[ "${use_OWE_flag}" = "3" ] || {
		IFNAMEA="guest$(head -c2 $RNG | hexdump -ve '/1 "%02x"' | tr a-z A-Z)"
		uci batch << EOI
set wireless.guest_${RADIO}=wifi-iface
set wireless.guest_${RADIO}.ifname="${IFNAMEA}"
set wireless.guest_${RADIO}.device="${RADIO}"
set wireless.guest_${RADIO}.mode='ap'
set wireless.guest_${RADIO}.network='guest'
set wireless.guest_${RADIO}.ssid="${GuestWiFi_SSID}"
set wireless.guest_${RADIO}.isolate='1'
set wireless.guest_${RADIO}.encryption='none'
set wireless.guest_${RADIO}.disabled='1'
EOI
	}

	# create Enhanced Open (OWE) SSID
	[ "${use_OWE_flag}" = "1" -o "${use_OWE_flag}" = "2" -o "${use_OWE_flag}" = "3" ] && {

		IFNAMEB="guest$(head -c2 $RNG | hexdump -ve '/1 "%02x"' | tr a-z A-Z)"
		uci batch << EOI
set wireless.guest_${RADIO}_owe=wifi-iface
set wireless.guest_${RADIO}_owe.ifname="${IFNAMEB}"
set wireless.guest_${RADIO}_owe.device="${RADIO}"
set wireless.guest_${RADIO}_owe.mode='ap'
set wireless.guest_${RADIO}_owe.network='guest'
set wireless.guest_${RADIO}_owe.ssid="${GuestWiFi_SSID}"
set wireless.guest_${RADIO}_owe.isolate='1'
set wireless.guest_${RADIO}_owe.encryption='owe'
set wireless.guest_${RADIO}_owe.ieee80211w='2'
set wireless.guest_${RADIO}_owe.disabled='1'
EOI
	}

	# enable OWE transition using randomly generated BSSIDs (requires OpenWrt 19.07 or later)
	[ "${use_OWE_flag}" = "1" ] && {

		# generate random BSSID prefix (first 5 bytes) in LAA range
		unset BSSID
		while [ -z "$(echo \"$BSSID\" | grep -E '[0-9a-fA-F][26aeAE]')" ]; do BSSID=$(head -c1 $RNG | hexdump -ve '/1 "%02x"'); done
		BSSID=${BSSID}:$(head -c4 $RNG | hexdump -ve '/1 "%02x:"')
		# generate random byte to complete BSSID for Open network
		BSSIDA=$(head -c1 $RNG | hexdump -ve '/1 "%02x"')
		# generate another random byte to complete BSSID for OWE network
		BSSIDB=$BSSIDA
		while [ "$BSSIDA" = "$BSSIDB" ]; do BSSIDB=$(head -c1 $RNG | hexdump -ve '/1 "%02x"'); done

		uci batch << EOI
set wireless.guest_${RADIO}_owe.ssid="${GuestWiFi_SSID}_OWE"
set wireless.guest_${RADIO}_owe.hidden='1'
set wireless.guest_${RADIO}.macaddr=${BSSID}${BSSIDA}
set wireless.guest_${RADIO}.owe_transition_ssid="${GuestWiFi_SSID}_OWE"
set wireless.guest_${RADIO}.owe_transition_bssid=${BSSID}${BSSIDB}
set wireless.guest_${RADIO}_owe.macaddr=${BSSID}${BSSIDB}
set wireless.guest_${RADIO}_owe.owe_transition_ssid="${GuestWiFi_SSID}"
set wireless.guest_${RADIO}_owe.owe_transition_bssid=${BSSID}${BSSIDA}
EOI
	}

	# enable OWE transition management (SSID/BSSID) by OpenWrt (requires OpenWrt 22.03.0-rc5 or later)
	[ "${use_OWE_flag}" = "2" ] && {

		uci batch << EOI
set wireless.guest_${RADIO}_owe.ssid="${GuestWiFi_SSID}_OWE"
set wireless.guest_${RADIO}_owe.hidden='1'
set wireless.guest_${RADIO}.owe_transition_ifname="${IFNAMEB}"
set wireless.guest_${RADIO}_owe.owe_transition_ifname="${IFNAMEA}"
EOI
	}

done

uci commit wireless

# setup firewall config

uci -q delete firewall.guest
uci batch << EOI
set firewall.guest=zone
set firewall.guest.name='guest'
set firewall.guest.network='guest'
set firewall.guest.input='REJECT'
set firewall.guest.output='ACCEPT'
set firewall.guest.forward='REJECT'
EOI

uci -q delete firewall.guest_wan
uci batch << EOI
set firewall.guest_wan=forwarding
set firewall.guest_wan.src='guest'
set firewall.guest_wan.dest='wan'
EOI

uci -q delete firewall.guest_dhcp
uci batch << EOI
set firewall.guest_dhcp=rule
set firewall.guest_dhcp.name='Allow-DHCP-guest'
set firewall.guest_dhcp.src='guest'
set firewall.guest_dhcp.family='ipv4'
set firewall.guest_dhcp.target='ACCEPT'
set firewall.guest_dhcp.src_port='67-68'
set firewall.guest_dhcp.dest_port='67-68'
set firewall.guest_dhcp.proto='udp'
EOI

uci -q delete firewall.guest_dhcpv6
uci batch << EOI
set firewall.guest_dhcpv6=rule
set firewall.guest_dhcpv6.name='Allow-DHCPv6-guest'
set firewall.guest_dhcpv6.src='guest'
set firewall.guest_dhcpv6.dest_port='547'
set firewall.guest_dhcpv6.proto='udp'
set firewall.guest_dhcpv6.family='ipv6'
set firewall.guest_dhcpv6.target='ACCEPT'
EOI

uci -q delete firewall.guest_dns
uci batch << EOI
set firewall.guest_dns=rule
set firewall.guest_dns.name='Allow-DNS-guest'
set firewall.guest_dns.src='guest'
set firewall.guest_dns.dest_port='53'
set firewall.guest_dns.proto='tcp udp'
set firewall.guest_dns.target='ACCEPT'
EOI

uci -q delete firewall.guest_ndp
uci batch << EOI
set firewall.guest_ndp=rule
set firewall.guest_ndp.name='Allow-NDP-guest'
set firewall.guest_ndp.src='guest'
set firewall.guest_ndp.family='ipv6'
set firewall.guest_ndp.proto='icmp'
set firewall.guest_ndp.target='ACCEPT'
add_list firewall.guest_ndp.icmp_type='neighbour-advertisement'
add_list firewall.guest_ndp.icmp_type='router-advertisement'
EOI

uci commit firewall

# setup init script to bring guest wifi up/down

	cat<<'EOF' > /sbin/guest_wifi
#! /bin/sh

unset DISABLED
[ -z "$1" ] && RESTART=1 || unset RESTART

case "$1" in
	"restart")
		RESTART='1'
		;;
	"disable")
		DISABLED='1'
		;;
	"enable")
		DISABLED='0'
		;;
	*)
		[ -z "$RESTART" ] && { >&2 echo "Possible parameters: enable|disable|restart"; exit 1; }
		;;
esac

GUESTNETS=$(uci show wireless | grep -E "\.ifname='guest[0-9A-F]{4}'$" | cut -f 2 -d '.')
[ -z "$GUESTNETS" ] && { >&2 echo "No guest networks found, exiting."; exit 1; }

[ -z "$DISABLED" ] || {
	for GUESTNET in $GUESTNETS; do
		[ "0$(uci -q get wireless.$GUESTNET.disabled)" -eq $DISABLED ] || {
			uci set wireless.$GUESTNET.disabled="$DISABLED"
		}
	done
	uci commit wireless
}

RADIOS=$(for GUESTNET in $GUESTNETS; do uci get wireless.${GUESTNET}.device; done | sort -u)
for RADIO in $RADIOS; do wifi up $RADIO; done
EOF

chmod 755 /sbin/guest_wifi

/etc/init.d/odhcpd restart >/dev/null 2>&1
/etc/init.d/dnsmasq restart >/dev/null 2>&1
/etc/init.d/firewall restart >/dev/null 2>&1
/sbin/guest_wifi enable
