# Overview

`wg2if` converts a WireGuard configuration in wg-quick format into an OpenBSD-compatible `hostname.if` file.

Usage example:

```
perl ./wg2if.pl fr-wg-001.conf | doas tee /etc/hostname.wg0
```

The script:

- supports both IPv4 and IPv6 addresses
- installs IPv4 and IPv6 routes
- updates the default route to prefer the VPN path

# DNS

DNS configuration is not modified. On OpenBSD the `resolvd` service manages `/etc/resolv.conf` using DHCP-provided settings. To use custom resolvers, stop and disable `resolvd` and edit `/etc/resolv.conf` manually.

# Notes

- Removing the VPN interface does not automatically revert the routing changes.

# Further hardening

For a more resilient setup, route non-VPN traffic through a separate routing domain and keep VPN traffic in the primary domain. Reference: https://dataswamp.org/~solene/2021-10-09-openbsd-wireguard-exit.html