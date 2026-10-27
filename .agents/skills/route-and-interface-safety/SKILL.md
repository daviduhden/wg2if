---
name: route-and-interface-safety
description: "Use when reviewing or changing how wg2if.pl generates routes, endpoints, default-gateway lookups, interface lifecycle, or when any task might apply WireGuard configuration or alter an OpenBSD routing table."
---

# Route and interface safety

## When to use this skill

Activate this skill when a task involves:

- Generated `!route` lines, `AllowedIPs`, endpoints, or the default gateway.
- Applying output to `/etc/hostname.wg0`, running `netstart`, or bringing an
  interface up or down.
- Removing a WireGuard interface, cleaning up routes, or changing the
  default route.
- Deciding whether a route change is safe on a remote host.

Use `openbsd-hostname-if-rendering` for token formatting and
`wireguard-config-parsing` for input handling.

## Current route behavior

The script generates routes from two sources only:

| Source | Emitted route | Family handling |
| --- | --- | --- |
| `Endpoint` | `!route add <host> <gateway>` | IPv6 uses `!route add -inet6 <host> <gateway>` |
| IPv4 `AllowedIPs` item | `!route add <cidr> -iface $if` | IPv4 default |
| IPv6 `AllowedIPs` item | `!route add -inet6 <cidr> -iface $if` | Explicit `-inet6` |

Key facts:

- `get_default_gateway` runs `/sbin/route -n get ...` without a shell,
  selects the IPv4 or IPv6 default, validates the returned gateway, and
  caches the result per address family.
- The gateway is captured when the script runs, not when the file is
  applied at boot.
- If no default gateway is found, the script warns on stderr, omits the
  affected endpoint routes, and still exits 0 with the rest of the output.
- Endpoint routes are emitted in peer order first; allowed-IP routes follow
  in peer order. Exact duplicate route commands are removed.
- There is no overlap detection, longest-prefix handling, or conflict
  reporting. Overlapping prefixes are emitted as given.
- `AllowedIPs = 0.0.0.0/0` produces `!route add 0.0.0.0/0 -iface $if`. It
  does not run `route change default` and does not replace an existing
  default route.
- Hostname endpoints use the IPv4 default gateway for the pinned route.
  A hostname that resolves only to IPv6 may need manual adjustment.
- `Table`, routing domains, and `rdomain` are not supported. Routes target
  the default routing table.
- There is no teardown code, no `PreDown`/`PostDown`, and no route cleanup.

## Interface lifecycle warning

Removing a WireGuard interface does not necessarily revert the routes that
were added. In particular, an endpoint route via a gateway is an ordinary
host route and can survive interface removal; a default route changed by an
operator also persists. Routes installed with `-iface` may disappear with
the interface in some cases, but this is not guaranteed and must not be
assumed.

Before removing an interface or applying a different configuration:

1. Record the routes that will be added and any pre-existing routes they
   could shadow.
2. Decide explicitly which routes must be deleted and in what order.
3. Keep console or out-of-band access for remote hosts. A wrong default
   route can terminate the management session.
4. Verify the route table after cleanup. Do not describe interface removal
   as a rollback.

## Safety rules for agents

- Do not run `ifconfig`, `route add`, `route change`, `route delete`,
  `route flush`, `/etc/netstart`, or `doas` as part of a documentation or
  code task.
- Do not edit `/etc/hostname.*`, `/etc/mygate`, `/etc/resolv.conf`, or any
  other system file.
- Never apply generated output that has not been reviewed. The generator
  validates config values, but `netstart` still evaluates the resulting
  commands with the shell. Do not reintroduce raw interpolation.
- Do not use `route flush` or `ifconfig destroy` in tests. There is no
  disposable routing table in this repository.
- Keep private keys and preshared keys out of logs and chat. Generated
  output contains `wgkey` and possibly `wgpsk`.
- If the user asks for an actual deployment, require explicit approval,
  a reviewed diff, a rollback plan, and console access. Do not infer
  approval from a request to "make it work".

## Procedure for a static route review

1. Generate to a temporary file with a fake fixture. Do not touch `/etc`.

```sh
tmp=$(mktemp -d /tmp/wg2if-routes.XXXXXX)
cat >"$tmp/fake.conf" <<'EOF'
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/24, fd00::2/64

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 192.0.2.10:51820
AllowedIPs = 10.1.0.0/24, fd01::/64, 10.1.0.0/24
EOF
perl ./wg2if.pl "$tmp/fake.conf" >"$tmp/hostname.wg0" 2>"$tmp/err"
printf 'exit=%s\n' "$?"
grep -n '^!route' "$tmp/hostname.wg0" || true
cat -A "$tmp/err"
```

2. Check each allowed-IP route for the correct family and the literal
   `$if` placeholder.

```sh
grep -n '^!route add -inet6' "$tmp/hostname.wg0" || true
grep -n '^!route add ' "$tmp/hostname.wg0" | grep -v -- '-inet6' || true
```

3. Check for duplicate route commands. The generator deduplicates exact
   duplicates, so this must print nothing.

```sh
grep '^!route' "$tmp/hostname.wg0" | sort | uniq -d
```

4. Check endpoint routes separately. Confirm that the host is not mangled
   and that the route uses `-inet6` for an IPv6 endpoint. A missing endpoint
   route is expected when generation ran where no default route exists.
5. Compare the routes with the operator's intended policy. Flag any
   `0.0.0.0/0` or `::/0` route, any route that could shadow management
   traffic, and any overlapping prefixes.
6. Do not apply the file. Report the exact commands that an operator would
   need to run and the routes that would need cleanup later.

Read-only inspection commands such as `route -n show` or
`route -n get <address>` are operator verification steps, not agent tests.
They still require access to the target host and should not be run merely
to complete a documentation task.

## Validation checklist

- [ ] No interface or route command was executed.
- [ ] The route block was generated from a fake fixture in `/tmp`.
- [ ] Each IPv6 allowed-IP route has `-inet6`.
- [ ] Each IPv6 endpoint route has `-inet6`.
- [ ] Each allowed-IP route ends with the literal `$if` placeholder.
- [ ] Endpoint routes have a real gateway and were omitted with a warning
      when no default route existed.
- [ ] Exact duplicate routes are absent.
- [ ] A `0.0.0.0/0` route is described as an add, not a default-route
      replacement.
- [ ] No secret key was printed into a shared log.
- [ ] Cleanup for endpoint, allowed-IP, and any default routes is stated
      explicitly.
- [ ] Remote-change risk and rollback access are documented.

## Common problems

| Symptom | Cause and response |
| --- | --- |
| Endpoint route missing | No default gateway was found at generation time; the script warns on stderr and continues. |
| `route add` fails at boot with "File exists" | A route already exists or overlapping prefixes conflict; exact duplicates are deduplicated by the generator, so inspect the live table and the input. |
| Full tunnel does not replace the default | `0.0.0.0/0` is added with `-iface`, not changed. Plan the default explicitly. |
| IPv6 endpoint route malformed | Treat it as a regression: IPv6 endpoints are parsed with brackets and routed with `-inet6`. |
| Routes persist after removal | No teardown exists. Delete routes explicitly and verify. |
| Management session lost | A route change redirected traffic. Use console access and a rollback plan. |
| Routes land in the wrong table | `Table`/rdomain is ignored; only the default table is used. |

## Maintenance & Continuous Learning

When this skill is used to modify the repository, review it after the task.
Update it when route behavior, safety procedures, tools, configuration
assumptions, or validation commands change. Add reusable findings and
correct inaccurate guidance; keep examples and procedures current. Do not
add one-off execution details. Review related agent instructions and skills,
then run `perl scripts/check-agent-maintenance.pl`.

## References

- OpenBSD `route(8)`: https://man.openbsd.org/route.8
- OpenBSD `hostname.if(5)`: https://man.openbsd.org/hostname.if.5
- OpenBSD `netstart(8)`: https://man.openbsd.org/netstart.8
- OpenBSD `ifconfig(8)`: https://man.openbsd.org/ifconfig.8
- OpenBSD `wg(4)`: https://man.openbsd.org/wg.4
- Local operational notes: `README.md` (including the routing and DNS
  caveats).
- Related skills: `wireguard-config-parsing`,
  `openbsd-hostname-if-rendering`.
