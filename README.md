# Overview

`wg2if` converts a WireGuard configuration in wg-quick format into
OpenBSD-compatible `hostname.if` directives.

It writes text to stdout. It does not apply configuration, create
interfaces, change routes, or modify DNS.

## Usage

Generate to a temporary file, review it, and install it with restrictive
permissions. The generated file contains the WireGuard private key.

```sh
set -eu
tmp=$(mktemp /tmp/wg2if.XXXXXX)
trap 'rm -f "$tmp"' 0
perl ./wg2if.pl fr-wg-001.conf >"$tmp"
# Review "$tmp" before installing it.
doas install -o root -g wheel -m 600 "$tmp" /etc/hostname.wg0
doas sh /etc/netstart wg0
```

Back up an existing `/etc/hostname.wg0` first. `netstart` changes the
running system.

## Supported input

`[Interface]`:

- `PrivateKey` - required, 44-character base64 WireGuard key.
- `Address` - comma-separated IPv4 or IPv6 addresses or CIDRs. A missing
  prefix becomes `/32` or `/128`.
- `ListenPort` - emitted as `wgport`; 1-65535.
- `MTU` - emitted as `mtu`; 576-65535.
- `PersistentKeepalive` - default for peers that do not set their own.

`[Peer]` (repeatable):

- `PublicKey` - required, 44-character base64 WireGuard key.
- `PresharedKey` - optional, 44-character base64 WireGuard key.
- `Endpoint` - `host:port` or `[IPv6]:port`; the port is required.
- `AllowedIPs` - comma-separated IPv4 or IPv6 addresses or CIDRs. A missing
  prefix becomes `/32` or `/128`.
- `PersistentKeepalive` - overrides the interface default for this peer.

Section headers and key names are case-insensitive. Leading whitespace,
blank lines, and `#` comments are accepted. Unknown keys and unsupported
wg-quick directives are reported on stderr and ignored; unknown sections are
errors. `DNS`, `Table`, `SaveConfig`, `FwMark`, and the
`PreUp`/`PostUp`/`PreDown`/`PostDown` hooks are not applied.

Values are validated before output. Keys must be valid base64, addresses
must parse as IPv4 or IPv6 addresses or CIDRs, and numeric fields must be in
range. Unsafe values are rejected instead of being written to
`hostname.if`.

## Generated output

The script emits:

- `wgkey` and optional `wgport`/`mtu`;
- `inet`/`inet6` lines for `Address`;
- one `wgpeer` line per peer, with `wgpsk`, `wgendpoint`, `wgaip`, and
  `wgpka` options on the same line;
- `up`;
- deduplicated `!route` lines.

Endpoint routes are emitted before `AllowedIPs` routes. IPv6 endpoints use
`-inet6`. If the local default route cannot be found during conversion, the
endpoint route is omitted with a warning and the rest of the output is still
generated.

## Routing

`AllowedIPs` entries produce `!route add ... -iface $if` commands. An
endpoint produces a host route through the local default gateway. The
gateway is captured when the script runs, not when the file is applied at
boot.

The script does not replace the default route. An `AllowedIPs` entry of
`0.0.0.0/0` or `::/0` is added like any other prefix and may conflict with
an existing default route. Hostname endpoints use the IPv4 default gateway
for the pinned route.

Removing the VPN interface does not automatically revert the routing
changes. Remove routes explicitly and verify the routing table.

## DNS

DNS configuration is not modified. On OpenBSD the `resolvd` service manages
`/etc/resolv.conf` using DHCP-provided settings. To use custom resolvers,
stop and disable `resolvd` and edit `/etc/resolv.conf` manually.

## Notes

- The generated file must be owned by root, group wheel, and mode `600`
  because it contains the private key.

## Further hardening

For a more resilient setup, route non-VPN traffic through a separate routing
domain and keep VPN traffic in the primary domain. Reference:
https://dataswamp.org/~solene/2021-10-09-openbsd-wireguard-exit.html
