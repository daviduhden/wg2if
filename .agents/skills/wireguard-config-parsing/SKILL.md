---
name: wireguard-config-parsing
description: "Use when changing or validating wg2if.pl's wg-quick parser: section handling, validation helpers, Address, AllowedIPs, Endpoint, IPv4/IPv6, duplicate routes, untrusted input, and fixtures."
---

# WireGuard config parsing

## When to use this skill

Activate this skill when a task touches:

- `parse_args`, `open_config`, or `parse_config` in `wg2if.pl`.
- Which wg-quick keys are read, validated, warned about, or ignored.
- `Address`, `AllowedIPs`, `Endpoint`, `PrivateKey`, `PublicKey`,
  `PresharedKey`, `ListenPort`, `MTU`, or `PersistentKeepalive` handling.
- IPv4/IPv6 classification, comma splitting, canonicalization, duplicate
  routes, or parser fixtures.

Do not use it to apply generated configuration. Use
`openbsd-hostname-if-rendering` for output/application and
`route-and-interface-safety` for network changes.

## Current parser contract

`parse_config` parses the entire file into an in-memory structure before
`render_config` writes anything. Errors go to stderr with exit 1 and cannot
leave partial stdout.

Parsing rules:

- `[Interface]` and `[Peer]` headers are case-insensitive and may have
  surrounding whitespace. Only `[Interface]` and `[Peer]` are accepted;
  `[Peers]`, unknown sections, duplicate `[Interface]`, and `[Peer]` before
  `[Interface]` are errors.
- Key names are case-insensitive. Lines use `key = value`; leading
  whitespace, blank lines, and `#` comments are accepted.
- CRLF input is handled. Values are trimmed.
- `PrivateKey` is required in `[Interface]`. Every peer must have a
  `PublicKey`.
- Duplicate `PrivateKey`, `PublicKey`, `PresharedKey`, and `Endpoint` are
  errors. Repeated `Address`, `AllowedIPs`, and `[Peer]` sections are
  supported. Repeated `ListenPort`, `MTU`, and `PersistentKeepalive` use the
  last value.

Supported keys and output:

| Section | Key | Validation and behavior |
| --- | --- | --- |
| `[Interface]` | `PrivateKey` | 44-character base64; emits `wgkey` |
| `[Interface]` | `Address` | Comma-separated IPv4/IPv6 addresses or CIDRs; emits `inet` or `inet6` |
| `[Interface]` | `ListenPort` | 1-65535; emits `wgport` |
| `[Interface]` | `MTU` | 576-65535; emits `mtu` |
| `[Interface]` | `PersistentKeepalive` | 0-65535; default for peers without their own |
| `[Peer]` | `PublicKey` | Required; 44-character base64; starts `wgpeer` |
| `[Peer]` | `PresharedKey` | 44-character base64; emits `wgpsk` |
| `[Peer]` | `Endpoint` | `host:port` or `[IPv6]:port`; port required |
| `[Peer]` | `AllowedIPs` | Comma-separated IPv4/IPv6 addresses or CIDRs; emits `wgaip` and routes |
| `[Peer]` | `PersistentKeepalive` | 0-65535; overrides the interface default |

Validation details:

- Keys must match 43 base64 characters followed by `=`. Invalid keys are
  rejected; the value is not echoed in the error.
- Addresses are parsed with `Socket::inet_pton` and emitted in canonical
  form with `inet_ntop`. IPv4 prefixes are 0-32; IPv6 prefixes are 0-128.
  A missing prefix becomes `/32` or `/128`.
- Endpoint IPv6 literals must be bracketed and followed by a port. IPv4
  literals and hostnames use `host:port`. Hostnames are limited to letters,
  digits, dots, and hyphens, with valid label lengths and no leading or
  trailing hyphen. Port is 1-65535.
- `AllowedIPs` and `Address` entries are deduplicated in their own lists.
  Generated route commands are deduplicated globally.
- `DNS`, `Table`, `SaveConfig`, `FwMark`, and wg-quick hooks are reported as
  unsupported on stderr and ignored. Unknown keys are handled the same way.
  Unknown sections are fatal.
- Invalid values, missing required keys, and malformed lines fail before
  rendering. There is no silent fallback and no partial output on error.

Facts that are easy to get wrong:

- Family detection is based on `inet_pton`, not a naive colon check.
- `Address` and `AllowedIPs` values are split on commas only; each item is
  trimmed, so spaces after commas no longer leak into output.
- `PersistentKeepalive` is emitted on the `wgpeer` line, where OpenBSD
  `ifconfig(8)` expects it. An interface-level value is a default, not a
  standalone line.
- Multiple peers produce one `wgpeer` line per peer.
- A peer with no endpoint or allowed IPs is still emitted, with its
  keepalive if configured.
- `die_tool` and `fail` write to stderr. Unsupported-feature warnings also
  go to stderr and do not stop generation.

## Procedure

Step 1. Read `parse_config`, `parse_interface_key`, `parse_peer_key`, and
the validation helpers before editing.

Step 2. Create a fixture with fake keys. Keep section headers and keys at
column zero or use the now-supported leading whitespace deliberately.

```sh
tmp=$(mktemp -d /tmp/wg2if-parse.XXXXXX)
cat >"$tmp/minimal.conf" <<'EOF'
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/24, fd00::2/64
ListenPort = 51820
MTU = 1420
PersistentKeepalive = 25

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
PresharedKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
Endpoint = [2001:db8::1]:51820
AllowedIPs = 10.1.0.0/24, fd01::/64

[Peer]
PublicKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=
Endpoint = 192.0.2.10:51820
AllowedIPs = 10.1.0.0/24
EOF
```

Step 3. Check syntax, then capture stdout, stderr, and status separately.

```sh
perl -c wg2if.pl
perl ./wg2if.pl "$tmp/minimal.conf" >"$tmp/out" 2>"$tmp/err"
status=$?
printf 'exit=%s\n' "$status"
cat -A "$tmp/out"
cat -A "$tmp/err"
```

Step 4. Compare against the expected structure. On a host with no default
gateway, endpoint routes are omitted and warnings appear on stderr; the
rest must still be emitted.

```text
wgkey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
wgport 51820
mtu 1420
inet 10.0.0.2/24
inet6 fd00::2/64
wgpeer BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB= wgpsk CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC= wgendpoint 2001:db8::1 51820 wgaip 10.1.0.0/24 wgaip fd01::/64 wgpka 25
wgpeer DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD= wgendpoint 192.0.2.10 51820 wgaip 10.1.0.0/24 wgpka 25
up
```

Routes, when gateways are available, start with one endpoint route per
peer, then deduplicated allowed-IP routes:

```text
!route add -inet6 2001:db8::1 <IPv6 gateway>
!route add 192.0.2.10 <IPv4 gateway>
!route add 10.1.0.0/24 -iface $if
!route add -inet6 fd01::/64 -iface $if
```

Step 5. Add negative cases: invalid base64, invalid CIDR, missing or
out-of-range port, bare IPv6 endpoint without brackets, duplicate
`PublicKey`, peer without `PublicKey`, unsupported key, unknown section,
CRLF, and shell metacharacters. Invalid inputs must fail with stderr output
and no stdout.

## Validation checklist

- [ ] `perl -c wg2if.pl` reports syntax OK.
- [ ] The fixture contains only fake keys and documentation addresses.
- [ ] Valid keys, CIDRs, endpoints, ports, MTU, and keepalive values are
      accepted and emitted in canonical form.
- [ ] Invalid keys, CIDRs, ports, endpoints, unknown sections, malformed
      lines, and missing required keys are rejected.
- [ ] `PersistentKeepalive` appears on each `wgpeer` line; per-peer values
      override the interface default.
- [ ] Duplicate addresses and routes are removed as documented.
- [ ] Unsupported keys warn on stderr and do not appear in stdout.
- [ ] stdout is empty when parsing fails; errors are on stderr with exit 1.
- [ ] No generated line was executed, and no interface or route was changed.
- [ ] `git diff --check` passes and the diff contains only intended changes.

## Input validation and fixtures

The parser uses allowlists, not quote-based escaping. Keep it that way:

- Validate keys as base64, addresses with `inet_pton`, and numeric fields
  with a digit-and-range check before interpolation.
- Reject control characters, shell metacharacters, embedded whitespace in
  single tokens, malformed hostnames, and out-of-range prefixes.
- Do not wrap values in shell quotes as a substitute for validation.
  `hostname.if` is parsed by `netstart` and `ifconfig`.
- Add fixtures for injection attempts such as `Address =
  10.0.0.2/24;reboot`, `AllowedIPs = $(id)`, and an endpoint host containing
  `#`, backticks, or `$()`. They must fail or be ignored, never reach stdout.
- Test CRLF, inline comments, leading whitespace, mixed-case headers, and
  duplicate sections/keys.

## Common problems

| Symptom | Cause and action |
| --- | --- |
| `invalid PrivateKey` | The fake key is not 43 base64 characters plus `=`. Use a 44-character fake. |
| Address became `/32` or `/128` | The input omitted a prefix; this is the documented default. |
| `invalid Endpoint` | IPv6 literals require brackets and every endpoint requires a port. |
| `peer has no PublicKey` | Each `[Peer]` needs a `PublicKey` before the next peer or EOF. |
| `unsupported section header` | Only `[Interface]` and `[Peer]` are accepted; old prefix matches are gone. |
| Unsupported directive warning | `DNS`, `Table`, hooks, `SaveConfig`, and `FwMark` are not applied. |
| No stdout on failure | Parsing is now atomic; check stderr and exit status. |
| Duplicate key error | `PrivateKey`, `PublicKey`, `PresharedKey`, and `Endpoint` are single-valued. |

## Maintenance & Continuous Learning

When this skill is used to modify the repository, review it after the task.
Update it when parsing behavior, validation procedures, tools, configuration
assumptions, fixtures, or validation commands change. Add reusable findings
and correct inaccurate guidance; keep examples and procedures current. Do
not add one-off execution details. Review related agent instructions and
skills, then run `python3 scripts/validate-agent-knowledge.py --scope worktree`.

## References

- OpenBSD `hostname.if(5)`: https://man.openbsd.org/hostname.if.5
- OpenBSD `ifconfig(8)`, WireGuard options: https://man.openbsd.org/ifconfig.8
- OpenBSD `wg(4)`: https://man.openbsd.org/wg.4
- OpenBSD `netstart` implementation:
  https://raw.githubusercontent.com/openbsd/src/master/etc/netstart
- Local source: `wg2if.pl`, `parse_config` and the validation helpers.
- Related skill: `openbsd-hostname-if-rendering`.
