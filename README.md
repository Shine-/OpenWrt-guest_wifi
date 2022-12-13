# OpenWrt-guest_wifi
Automatic setup script for unencrypted and/or OWE-encrypted Open Guest WiFi networks on routers running OpenWrt firmware.
This script should work with any OpenWrt-supported WiFi device and any recent OpenWrt version.

The script supports setting up legacy unencrypted SSIDs as well as OWE (encrypted) "Enhanced Open" networks. By default - if supported by your OpenWrt version/configuration, that is - both kinds of networks are set up and OWE transition will be enabled. This means that WPA3/SAE-capable clients will automatically "upgrade" their connection to the "Enhanced Open" network with encryption. Clients that don't support WPA3/SAE will automatically fall back to the legacy unencrypted Open Network.

The Guest WiFi network is completely separated from your LAN.

# Usage
This script will do its job fully automated while trying to prevent collissions with your existing configuration as good as possible.

If desired, you can control the scipt's behavior to some extent by pre-setting certain variables. Please see the top of the script for more detailed instructions.

Upload the script `guest_wifi_setup.sh` to your OpenWrt device, preferrably to non-persistent storage such as `/tmp`, since you will only need to run it once. Then, `chmod +x` it and run it.

After the script finishes running, your Guest WiFi SSID(s) are immediately available. If your radio(s) were disabled globally, they will only get (re-)enabled in case the script doesn't find any other SSID that might also get enabled unwantedly. The script will inform you which radio is still disabled, in such a case. The factory-default OpenWrt SSID that would expose your LAN as an Open WiFi will be automatically disabled, in case it's still present.

In addition, the script will install a new command `guest_wifi` that can be used to control your Guest WiFi SSIDs (turn on, off or restart).

```
guest_wifi enable    # enable and start Guest WiFi SSIDs
guest_wifi disable   # disable and stop Guest WiFi SSIDs
guest_wifi restart   # restart all WiFi radios that carry Guest WiFi SSIDs
guest_wifi           # without parameter is the same as 'restart'
```

Radios that don't carry a guest WiFi SSID as set up by this script will not be affected by the `guest_wifi` command, nor will the `guest_wifi` command enable radios that have been disabled globally, even if they do carry a guest WiFi SSID. The `guest_wifi` command will, similar to OpenWrt's `wifi` command, not require a router restart in any case.

The `guest_wifi` command won't correct any misconfiguration that you may have performed on the Guest WiFi SSIDs and network interfaces. If it doesn't find any of its guest SSIDs, it will exit with an error message.

# Technical details
See comments inside the script.

# Disclaimer
This script is based on an original script by GH user "jkool702" using MIT license (see LICENSE file). All of **my** changes are public domain. You may reuse my work for any purpuse, with or without crediting me. Since the original license is MIT, you will still have to credit the original author and include the original license, though, in most cases.
