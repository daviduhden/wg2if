---
name: openbsd-hostname-if-rendering
description: "Use when changing wg2if.pl's emitted hostname.if tokens or order, or when debugging, reviewing, or documenting generated OpenBSD interface configuration, including MTU, DNS, and apply-versus-render boundaries."
---

# OpenBSD hostname.if rendering

## When to use this skill

Activate this skill when a task touches:

- Which `hostname.if(5)` tokens `wg2if.pl` emits, or their order and
  whitespace.
- `wgkey`, `wgport`, `mtu`, `inet`, `inet6`, `wgpeer`, `wgpka`, `wgpsk`,
  `wgendpoint`, `wgaip`, `up`, or `!route` output.
- `MTU`, `DNS`, `ListenPort`, `Table`, or interface `up` handling.
- Reviewing a generated file, writing it to `/etc/hostname.wg0`, or
  explaining why it does not work at boot.

Use `wireguard-config-parsing` for input parsing and
`route-and-interface-safety` for route changes and teardown.

## Output contract

The script validates the whole configuration before writing text to stdout.
It does not create, configure, or bring up an interface.

| Input | Emitted token | Notes |
| --- | --- | --- |
| `PrivateKey` | `wgkey <key>` | Required; contains secret key material |
| `ListenPort` | `wgport <port>` | Emitted when present |
| `MTU` | `mtu <value>` | Emitted when present |
| `Address` | `inet <cidr>` or `inet6 <cidr>` | Canonical IPv4/IPv6 CIDR |
| `PublicKey` | `wgpeer <key>` | One peer line per `[Peer]` |
| `PresharedKey` | `wgpsk <key>` | On the same peer line |
| `Endpoint` | `wgendpoint <host> <port>` | IPv6 host is unbracketed |
| `AllowedIPs` | `wgaip <cidr>` per item | On the same peer line |
| `PersistentKeepalive` | `wgpka <seconds>` | Per peer; interface value is the default |
| Always | `up` | Emitted after peers and addresses |
| Endpoint/allowed IPs | `!route ...` lines | Collected, deduplicated, printed last |

Ordering and formatting:

1. `wgkey`
2. `wgport` if present
3. `mtu` if present
4. One `inet` or `inet6` line per address
5. One `wgpeer` line per peer
6. `up`
7. One blank line and the route commands, if any routes were generated

All values are validated: keys are base64, addresses are emitted by
`inet_ntop`, ports and MTU are numeric, and endpoint hosts are either IP
literals or validated hostnames. No unvalidated config text is echoed.

Route order is deterministic: endpoint routes in peer order first, then
allowed-IP routes in peer order. Exact duplicate routes are removed.

## How OpenBSD consumes the file

`netstart(8)` reads each line of `/etc/hostname.<if>` and passes it to
`ifconfig`. Lines beginning with `!` are arbitrary shell commands; `$if` is
replaced with the interface name before execution. `netstart` builds and
evaluates the resulting command strings.

Important consequences:

- Arguments containing whitespace or single quotes must be double quoted
  according to `hostname.if(5)`. The generator emits only validated tokens,
  so it does not add quoting.
- `$if` in generated route lines is literal text until `netstart` replaces
  it. Running the script does not expand it.
- A real file must be owned by root, group wheel, and mode `600`.
  `netstart` warns and attempts to fix insecure ownership and permissions,
  but do not rely on that repair.
- The file is applied in line order. `up` runs after addresses and peers;
  route commands run after `up`.
- When `netstart` is invoked for a single interface, it processes the
  hostname file before adding `/etc/mygate` default routes, so do not assume
  a default route already exists.

## What is not rendered

- `DNS`: ignored with a warning. On OpenBSD, `resolvd(8)` manages
  `/etc/resolv.conf` from DHCP and autoconfiguration. wg-quick DNS settings
  are not applied.
- `Table`, `SaveConfig`, `FwMark`, `PreUp`, `PostUp`, `PreDown`,
  `PostDown`: ignored with warnings.
- Default-route replacement: never emitted. See
  `route-and-interface-safety`.
- Teardown or route cleanup: no code.

`MTU` and `ListenPort` are now supported and emitted as `mtu` and `wgport`.
They are not silently dropped.

## Procedure for a safe render review

1. Read `parse_config` and `render_config`, and confirm the expected tokens.
2. Create a fixture with fake keys under `/tmp`. Do not use a production
   config.

```sh
tmp=$(mktemp -d /tmp/wg2if-render.XXXXXX)
cat >"$tmp/fake.conf" <<'EOF'
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/24, fd00::2/64
ListenPort = 51820
MTU = 1420

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
PresharedKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
Endpoint = [2001:db8::1]:51820
AllowedIPs = 10.1.0.0/24, fd01::/64
EOF
```

3. Generate into a temporary file and inspect bytes without applying it.

```sh
perl -c wg2if.pl
perl ./wg2if.pl "$tmp/fake.conf" >"$tmp/hostname.wg0" 2>"$tmp/err"
status=$?
printf 'exit=%s\n' "$status"
cat -A "$tmp/hostname.wg0"
cat -A "$tmp/err"
```

4. Confirm the output order and the `up` line. A typical result is:

```text
wgkey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
wgport 51820
mtu 1420
inet 10.0.0.2/24
inet6 fd00::2/64
wgpeer BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB= wgpsk CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC= wgendpoint 2001:db8::1 51820 wgaip 10.1.0.0/24 wgaip fd01::/64
up
```

With a usable IPv6 default gateway, one endpoint route follows the blank
line; allowed-IP routes follow it:

```text
!route add -inet6 2001:db8::1 <IPv6 gateway>
!route add 10.1.0.0/24 -iface $if
!route add -inet6 fd01::/64 -iface $if
```

5. Do not pipe the output into a shell, `doas tee`, or `/etc/netstart`.
   Compare against a saved expected snapshot when changing formatting.

```sh
diff -u "$tmp/expected" "$tmp/hostname.wg0"
```

The generated file is not a shell script. `sh -n hostname.wg0` is not a
meaningful validation because `inet` and `wgpeer` are not shell commands.
A real dry run is `sh /etc/netstart -n wg0` on OpenBSD; it requires root and
reads the real `/etc/hostname.wg0`. Leave that to the operator and do not
run it as part of repository work.

## Validation checklist

- [ ] `perl -c wg2if.pl` passes.
- [ ] Output order is `wgkey`, optional `wgport`/`mtu`, addresses, peer
      lines, `up`, then optional routes.
- [ ] Each peer occupies exactly one `wgpeer` line, with `wgpka` on the
      same line.
- [ ] IPv6 endpoints are unbracketed in `wgendpoint` and use `-inet6` for
      their route.
- [ ] Duplicate allowed-IP routes appear only once.
- [ ] No `DNS`, `Table`, hook, `SaveConfig`, or `FwMark` line is claimed.
- [ ] Invalid input produced no stdout and an error on stderr.
- [ ] The fixture and any displayed output use fake keys.
- [ ] The generated file was not installed or applied.
- [ ] `git diff --check` passes.

## Common problems

| Symptom | Cause and response |
| --- | --- |
| Interface stays down after boot | `up` should be emitted; if it is missing, treat it as a rendering regression. |
| Keepalive missing | Check peer `PersistentKeepalive`, then the interface default. It must be on the `wgpeer` line. |
| MTU or ListenPort unchanged | Check the input value range and whether it is present in `[Interface]`. |
| DNS unchanged | `DNS` is intentionally unsupported; configure `resolvd` or `/etc/resolv.conf`. |
| Endpoint never reachable | Endpoint route may be missing because no default gateway was found at generation time. |
| File contains an error message | Errors belong on stderr now; check the exit status and redirect only stdout. |
| Existing config destroyed | A direct redirect or `tee` truncates the target. Render to `/tmp` and review before installing. |
| Sensitive key exposed | `wgkey` and `wgpsk` are printed. Keep output out of logs and use mode `600`, root:wheel. |

## Maintenance & Continuous Learning

When this skill is used to modify the repository, review it after the task.
Update it when rendering procedures, tools, configuration assumptions,
validation commands, or the output contract change. Add reusable findings
and correct inaccurate guidance; keep examples and validation steps current.
Do not add one-off execution details. Review related agent instructions
and skills, then run `perl scripts/check-agent-maintenance.pl`.

## References

- OpenBSD `hostname.if(5)`: https://man.openbsd.org/hostname.if.5
- OpenBSD `ifconfig(8)`: https://man.openbsd.org/ifconfig.8
- OpenBSD `wg(4)`: https://man.openbsd.org/wg.4
- OpenBSD `netstart(8)`: https://man.openbsd.org/netstart.8
- OpenBSD `resolvd(8)`: https://man.openbsd.org/resolvd.8
- `netstart` source: https://raw.githubusercontent.com/openbsd/src/master/etc/netstart
- Local files: `README.md`, `wg2if.pl`.
- Related skill: `route-and-interface-safety`.
