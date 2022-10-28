# OpenWrt-guest_wifi
Automatic setup script for a guest wireless network for routers running OpenWrt firmware. 
This script should work with any OpenWrt-supported WiFi device and any recent OpenWrt version.

The script supports both "standard" guest networks and guest networks that use Open Wireless Encryption (OWE) with a transition SSID. The OWE guest network is setup such that all clients can connect regardless of whether or not they support OWE. Clients that support OWE will utilize it, and clients that don't will automatically fall back to using legacy mode (open network, no encryption).

# Usage
This script is almost fully automated, and using it is quite simple. To use this script, do the following:

1. Download the script `guest_wifi_setup.sh` and save it somewhere on the router, preferrably on non-persistent storage, like `/tmp`.
2. Fill in the `GuestWifi_{SSID,IP,netmask}` variables at the top of the script. 
3. (optional) To force OWE support to be enabled/disabled, set `use_OWE_flag` to `1` or `0`. 
      NOTE: if this variable is blank / undefined / anything other than 0 or 1; the default behavior is to use OWE if any TLS capable version of wpad or hostapd is installed, and not to use OWE if the mesh / mini / basic version without TLS support is installed.
4. `chmod +x` the script and run it. 
5. Wait for the script to finish running.
6. Your guest WiFi network(s) are now available.
     NOTE: in case your WiFi radio(s) were disabled before execution of this script, they're still disabled now. You have to manually enable them for the guest network(s) to start working. The script will warn you at the end of execution if this is the case.

Your guest wifi network is now setup on your router and should be active and broadcasting!!! 

The script will install a new script called `guest_wifi` which you can use to control the new guest wifi network(s). The guest wifi SSIDs can be started / stopped / restarted by running:

```
guest_wifi enable    # enable and start guest WiFi SSIDs
guest_wifi disable   # disable and stop guest WiFi SSIDs
guest_wifi restart   # restart all WiFi radios that carry guest WiFi SSIDs
```

The command `guest_wifi` without any parameter is the same as `restart`.

Radios that don't carry a guest WiFi SSID as set up by this script will not be affected by the `guest_wifi` command, nor will the `guest_wifi` command enable radios that have been disabled globally, even if they do carry a guest WiFi SSID. The `guest_wifi` command will, similar to OpenWrt's `wifi` command, not require a router restart in any case.

The `guest_wifi` command won't correct any misconfiguration that you may have performed on the guest WiFi interfaces. If it doesn't find any of its guest SSIDs, it will exit with an error message.

# How the script sets everything up
In setting up the guest wifi network, the following actions are performed:

NOTE: a few of these steps are only done when setting up a guest network with OWE support. These are labeled with the tag `(OWE ONLY)`

1. `network` config is setup in UCI. The script creates a bridge device called `br-guest` and guest interface called `guest`
2. `wireless` config is setup in UCI.  The script sets up the guest wifi network interfaces. As many interfaces are setup as there are physical radios. These will all use the same SSID (defined by the script variable `GuestWiFi_SSID`). Guests are isolated on all interfaces. All interfaces are (for the moment) disabled. The script generates interface names in the format "guest" + a random 4-digit hex number. It does this for the `guest_wifi` command to be able to find its own WiFi networks later.
3. `(OWE ONLY)` Additional interfaces (one per radio) that are hidden and use OWE encryption are setup. These enable client isolation and are also (for the moment) disabled. They have SSID's that are based on `${GuestWiFi_SSID}`. If a supported OpenWrt version is detected, the script lets OpenWrt handle the OWE transition management. Otherwise, the script calculates random BSSIDs in the LAA ("locally administered") ranges and configures each WiFi interface to point its transitional BSSID at the other (Open resp. OWE) BSSID of the respective radio. NOTE: This script is intentionally not employing the same or similar BSSID calculation that OpenWrt uses by default, to prevent collissions with your other, manually set up WiFi networks.
4. `dhcp` config is setup in UCI. This allows clients connected to the guest network to obtain DHCP leases.
5. `firewall` config is setup in UCI. a `guest` firewall zone (which forwards to WAN) is created, and firewall rules permitting DCHP, DHCPv6 and DNS traffic are setup
6. The `guest_wifi` command is installed to `/sbin/guest_wifi`. This enables one to easily bring up/down the guest network(s).
7. The guest wifi network is brought up via the (just installed) `guest_wifi` command, which will warn you in case one or more of your radios are disabled globally (you'll have to manually enable them in that case). After which the guest wifi should be active.

*----- END OF GUEST WIFI SETUP -----*

Original script is by GH user "jkool702" using MIT license (see LICENSE file). All of **my** changes are public domain. You may reuse my work for any purpuse, with or without crediting me. Since the original license is MIT, you will still have to credit the original author, though, in most cases.