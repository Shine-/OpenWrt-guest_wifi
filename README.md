# OpenWrt-guest_wifi
Automatic setup script for a guest wireless network for routers running OpenWrt firmware. 
NOTE: this is intended for dual band wifi devices where the 2G and 5G radios are labelled "radio0" and "radio1", respectively (which is which doesn't matter). It could likely be adapted for other devices without too much modification.

The script supports both "standard" guest networks and guest networks that use Open Wireless Encryption (OWE) with a transition SSID. The OWE guest network is setup such that all clients can connect regardless of whether or not they support OWE. Clients that support OWE will utilize it, and clients that don't will automatically fall back to using legacy mode (open network, no encryption).

# Usage
This script is almost fully automated, and using it is quite simple. To use this script, do the following:

1. Download the script `guest_wifi_setup.sh` and save it somewhere on the router.
      NOTE: If you are using OWE, the script *must* be saved on persistent storage. The OWE install requires a reboot mid-installation, and the script file needs to be available at the same location after this reboot happens.
2. Fill in the `GuestWifi_{SSID,IP,netmask}` variables at the top of the script. 
3. (optional) To force OWE support to be enabled/disabled, set `use_OWE_flag` to `1` or `0`. 
      NOTE: if this variable is blank / undefined / anything other than 0 or 1; the default behavior is to use OWE if any TLS capable version of wpad or hostapd is installed, and not to use OWE if the mesh / mini / basic version without TLS support is installed.
4. `chmod +x` the script and run it. 
5. Wait for the script to finish running. Your router will restart when it is done. 
6. (for OWE setup only) After booting back up, the script will resume running. When it has finished, the router will restart a 2nd time.
      NOTE: you dont need to do anything to resume the script - it will automatically resume itself. Just wait for the router to restart a 2nd time. 

Your guest wifi network is now setup on your router and should be active and broadcasting!!! 

The script will install a new script called `guest_wifi` which you can use to control new guest wifi network. The guest wifi SSIDs can be started / stopped / restarted by running:

```
guest_wifi enable    # enable and start guest WiFi SSIDs
guest_wifi disable   # disable and stop guest WiFi SSIDs
guest_wifi restart   # restart all WiFi radios that carry guest WiFi SSIDs
```

The command `guest_wifi` without any parameter is the same as `restart`.

Radios that don't carry a guest WiFi SSID as set up by this script will not be affected by the guest_wifi command, nor will the guest_wifi command enable radios that have been disabled globally, even if they do carry a guest WiFi SSID. The guest_wifi command will, similar to OpenWrt's "wifi" command, not require a router restart in any case.

The guest_wifi command won't correct any misconfiguration that you may have performed on the guest WiFi interfaces. If it doesn't find any of its guest SSIDs, it will exit with an error message (though this check is rather primitive and only based on part of their arbitrary ".ifname" property).

# How the script sets everything up
In setting up the guest wifi network, the following actions are performed:

NOTE: a few of these steps are only done when setting up a guest network with OWE support. These are labeled with the tag `(OWE ONLY)`

1. `network` config is setup in UCI. The script creates a bridge device called `br-guest` and guest interface called `guest`
2. `wireless` config is setup in UCI.  The script sets up the guest wifi network interfaces. Two open interfaces are setup (one on the 2.4 GHz radio, one on the 5 GHz radio). These will both use the same SSID (defined by the script variable `GuestWiFi_SSID`). Guests are isolated on all interfaces. All interfaces are (for the moment) disabled.
2a. `(OWE ONLY)` two additional interfaces (one per radio) that are hidden and use OWE encryption are setup. These enable client isolation and are also (for the moment) disabled. They have SSID's that are based on `${GuestWiFi_SSID}`. NOTE: BSSIDs are (intentionally) not defined in this step.
3. `dhcp` config is setup in UCI. This allows clients connected to the guest network to obtain DHCP leases.
4. `firewall` config is setup in UCI. a `guest` firewall zone (which forwards to WAN) is created, and firewall rules permitting DCHP, DHCPv6 and DNS traffic are setup
5. The `guest_wifi` command is installed to `/sbin/guest_wifi`. This enables one to easily bring up/down the guest network.
6. `(OWE  ONLY)` The current `/etc/rc.local` is backup up to `/etc/rc.local.orig`, and a modified `/etc/rc.local` which automatically re-calls the script after reboot. A flag to signal script contuation is also setup via  `touch /root/guest-wifi-OWE-setup-2nd-reboot-flag`
7. The guest wifi network is brought up via the (just installed) `guest_wifi` command. This culminates in the device rebooting. After which the guest wifi should be active.

*----- END OF STANDARD GUEST WIFI SETUP -----*

8.  `(OWE  ONLY)` When the script is automatically re-called after rebooting (via `/etc/rc.local`), it will notice the flag at `/root/guest-wifi-OWE-setup-2nd-reboot-flag` and move to the appropiate place in the script. The script will pause for 20 seconds to allow the guest wifi time to come upo fully.
9.  `(OWE  ONLY)` The script determines the BSSIDs of the guest network (which is currently running without explicitly defining them) and uses these to set `macaddr` and `owe_transition_bssid` in the `wireless` UCI config. By setting the BSSID's used in UCI to be the same as the ones that are used by default, we ensure that the BSSIDs used are valid and won't cause problems.
10.  `(OWE ONLY)` `/etc/rc.local` is restored to its original version, and the flag at `/root/guest-wifi-OWE-setup-2nd-reboot-flag` is removed.
11.  `(OWE ONLY)` the router is rebooted to implement the new guest network configuration (with defined BSSIDs).

*----- END OF OWE GUEST WIFI SETUP -----*
