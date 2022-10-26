#!/bin/sh

# This is a fork of the original script, with a some fixes and rewrites, many of them related to OWE transitional mode
#  * typo in original script: missing blank before "]" when forcefully enabling OWE mode
#  * original script uses .bssid property of WiFi I/F, which is only valid in STA and AdHoc mode - use .macaddr instead
#  * enable OWE transition mode by default if any TLS-capable hostapd/wpad is installed
#  * use identical OWE SSID for 2G and 5G band, works more reliably for me
#  * turn guest networks on/off with a helper script similar to OpenWrt's "wifi", instead of a system service
#  * rewrite guest Open WiFi and OWE setup to support any number of radios
#  * use randomized OWE transition BSSIDs to prevent BSSID collision with default and/or manually set up WiFi networks
#  * get rid of all dependencies on the full version of sed
#  * get rid of all the reboots that the original script performs, as none of them is necessary
# Original script without my fixes/changes is available from https://github.com/jkool702/OpenWrt-guest_wifi/

# set guest network SSID + router IP + netmask
GuestWiFi_SSID='Guest_WiFi'
GuestWiFi_IP='192.168.2.1'
GuestWiFi_netmask='255.255.255.0'

# explicity set whether or not to use OWE 
# '1' --> use OWE  /  '0' --> dont use OWE 
# <blank>/<anything else> --> auto-determine based on wpad/hostapd version
use_OWE_flag=''

# determine whether or not to use OWE 
# if not explicitly defined, it will be enabled if any WPA3-capable version of wpad or hostapd is present, otherwise disabled
if [ -z ${use_OWE_flag} ] || ! { [ "${use_OWE_flag}" == '0' ] || [ "${use_OWE_flag}" == '1' ]; }; then
	opkg list-installed | grep -E '((wpad)|(hostapd))' | grep -q -E '((mini)|(basic)|(mesh))' && use_OWE_flag='0' || use_OWE_flag='1'
	opkg list-installed | grep -E '((wpad)|(hostapd))' | grep -q -E '((ssl)|(tls))' && use_OWE_flag='1'
fi

# setup network config

uci -q delete network.guest_dev
uci batch << EOI
set network.guest_dev=device
set network.guest_dev.type='bridge'
set network.guest_dev.name='br-guest'
set network.guest_dev.bridge_empty='1'
EOI

uci -q delete network.guest
uci batch << EOI
set network.guest=interface
set network.guest.proto='static'
set network.guest.device='br-guest'
set network.guest.force_link='0'
set network.guest.ip6assign='60'
set network.guest.ipaddr="${GuestWiFi_IP}"
set network.guest.netmask="${GuestWiFi_netmask}"
set network.guest.type='bridge'
add_list network.guest.dns="${GuestWiFi_IP}"

EOI

uci commit network

# setup wireless config

RNG='/dev/urandom'; [ -c /dev/hwrng ] && RNG='/dev/hwrng'

. /lib/functions.sh; config_load wireless
ALLRADIOS=$(config_foreach echo 'wifi-device')

for RADIO in $ALLRADIOS; do

	uci -q delete wireless.guest_${RADIO}
	uci batch << EOI
set wireless.guest_${RADIO}=wifi-iface
set wireless.guest_${RADIO}.ifname=guest$(head -c2 $RNG | hexdump -ve '/1 "%02x"' | tr a-z A-Z)
set wireless.guest_${RADIO}.device="${RADIO}"
set wireless.guest_${RADIO}.mode='ap'
set wireless.guest_${RADIO}.network='guest'
set wireless.guest_${RADIO}.ssid="${GuestWiFi_SSID}"
set wireless.guest_${RADIO}.isolate='1'
set wireless.guest_${RADIO}.encryption='none'
set wireless.guest_${RADIO}.na_mcast_to_ucast='1'
set wireless.guest_${RADIO}.disabled='1'
EOI

	[ "${use_OWE_flag}" == '1' ] && {

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
set wireless.guest_${RADIO}.macaddr=${BSSID}${BSSIDA}
set wireless.guest_${RADIO}.owe_transition_ssid="${GuestWiFi_SSID}_OWE"
set wireless.guest_${RADIO}.owe_transition_bssid=${BSSID}${BSSIDB}
EOI

		uci -q delete wireless.guest_${RADIO}_owe
		uci batch << EOI
set wireless.guest_${RADIO}_owe=wifi-iface
set wireless.guest_${RADIO}_owe.ifname=guest$(head -c2 $RNG | hexdump -ve '/1 "%02x"' | tr a-z A-Z)
set wireless.guest_${RADIO}_owe.device="${RADIO}"
set wireless.guest_${RADIO}_owe.mode='ap'
set wireless.guest_${RADIO}_owe.network='guest'
set wireless.guest_${RADIO}_owe.ssid="${GuestWiFi_SSID}_OWE"
set wireless.guest_${RADIO}_owe.isolate='1'
set wireless.guest_${RADIO}_owe.encryption='owe'
set wireless.guest_${RADIO}_owe.hidden='1'
set wireless.guest_${RADIO}_owe.macaddr=${BSSID}${BSSIDB}
set wireless.guest_${RADIO}_owe.owe_transition_ssid="${GuestWiFi_SSID}"
set wireless.guest_${RADIO}_owe.owe_transition_bssid=${BSSID}${BSSIDA}
set wireless.guest_${RADIO}_owe.ieee80211w='2'
set wireless.guest_${RADIO}_owe.na_mcast_to_ucast='1'
set wireless.guest_${RADIO}_owe.disabled='1'
EOI
	}
done

uci commit wireless

# setup dhcp config

uci -q delete dhcp.guest
uci batch << EOI
set dhcp.guest=dhcp
set dhcp.guest.interface='guest'
set dhcp.guest.start='100'
set dhcp.guest.limit='150'
set dhcp.guest.leasetime='1h'
set dhcp.guest.dhcpv4='server'
set dhcp.guest.dhcpv4_forcereconf='1'
set dhcp.guest.dhcpv6='server'
set dhcp.guest.dhcpv6_na='1'
set dhcp.guest.dhcpv6_pd='1'
set dhcp.guest.ra='server'
set dhcp.guest.ra_management='1'
set dhcp.guest.ra_dns='1'
set dhcp.guest.force='1'
set dhcp.guest.netmask="${GuestWiFi_netmask}"
add_list dhcp.guest.router="${GuestWiFi_IP}"
add_list dhcp.guest.dhcp_option="3,${GuestWiFi_IP}"
add_list dhcp.guest.dhcp_option="6,${GuestWiFi_IP}"
EOI

uci commit dhcp

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
