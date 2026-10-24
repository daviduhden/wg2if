# Agent instructions for wg2if

## Purpose and scope

`wg2if.pl` is a single-file Perl 5 utility. It reads a WireGuard
configuration in wg-quick style, validates the values, and writes OpenBSD
`hostname.if(5)` directives to stdout. It never applies configuration,
creates interfaces, changes routes, or configures DNS.

Keep changes small and evidence-based. Do not describe features the parser
does not implement.

## Repository layout

- `wg2if.pl` - the entire product; executable Perl script.
- `README.md` - user-facing usage, supported input, and operational notes.
- `LICENSE` - ISC license, copyright David Uhden Collado. Preserve it.
- `.agents/skills/` - task-specific agent procedures.

There is no Makefile, build system, CI configuration, test suite, or lint
configuration in this repository.

## Architecture

Data flow in `wg2if.pl`:

1. `parse_args` accepts exactly one regular file. `-h` and `--help` print
   usage; missing, extra, or non-regular arguments fail with exit 1.
2. `open_config` opens the file with a lexical handle and three-argument
   `open`.
3. `parse_config` reads lines, strips comments and CRLF, and builds an
   in-memory configuration: one interface hash and an ordered list of peer
   hashes. It validates values through `validate_key`, `parse_uint`,
   `parse_cidr`, and `parse_endpoint`.
4. `render_config` emits the final text only after parsing succeeds, so an
   invalid input cannot leave partial output.
5. `get_default_gateway` runs `route -n get default` (and IPv6 variants)
   without a shell, validates the returned gateway, and caches it per
   address family.

The parser is intentionally strict:

- `[Interface]` and `[Peer]` headers are case-insensitive; duplicate
  `[Interface]`, `[Peer]` before `[Interface]`, unknown sections, malformed
  lines, and missing required keys are errors.
- `PrivateKey` is required in `[Interface]`; `PublicKey` is required in every
  `[Peer]`.
- Supported interface keys: `PrivateKey`, `Address`, `ListenPort`, `MTU`,
  and `PersistentKeepalive`.
- Supported peer keys: `PublicKey`, `PresharedKey`, `Endpoint`,
  `AllowedIPs`, and `PersistentKeepalive`.
- `DNS`, `Table`, `SaveConfig`, `FwMark`, and wg-quick hooks are reported as
  unsupported on stderr and ignored. Unknown keys are treated the same way.
- Values are validated with allowlists: 44-character base64 keys, IPv4/IPv6
  CIDRs, numeric ports/ranges, and endpoint hosts that are IP addresses or
  syntactically valid hostnames.
- Comments, leading whitespace, case-insensitive keys, and CRLF input are
  accepted. Missing CIDR prefixes default to `/32` or `/128`.
- Addresses and `AllowedIPs` are deduplicated per list; generated route
  commands are deduplicated globally.

The emitted vocabulary is `wgkey`, `wgport`, `mtu`, `inet`, `inet6`,
`wgpeer`, `wgpsk`, `wgendpoint`, `wgaip`, `wgpka`, `up`, and `!route`
lines. One `wgpeer` line is emitted per peer. See
`.agents/skills/openbsd-hostname-if-rendering/SKILL.md` for the exact output
contract.

## Commands that actually exist

Run these from the repository root:

```sh
perl -c wg2if.pl                  # static syntax check
perl ./wg2if.pl /tmp/fake.conf    # generate output on stdout
git diff --check                  # whitespace/error check
git status --short                # inspect the working tree
```

There is no `make`, `prove` suite, package build, installer, or repository
lint target. Do not invent one in documentation. `perl -c` is a static
syntax check, not a test run. Generating output is not the same as applying
it. Real validation on OpenBSD means running `/etc/netstart`, which is a
system change and is outside the scope of agent tasks unless the user
explicitly authorizes it.

When verifying behavior, create fixtures under `/tmp` with fake keys and
compare exact stdout, stderr, and exit status. Do not add permanent test
files unless the user asks for a test suite; if that happens, use core
`Test::More` under `t/` and document the command.

## Conventions

- `use strict;`, `use warnings;`, and core-only modules stay enabled.
- Four-space indentation, no tabs, ASCII source only.
- Keep Perl source lines at 72 characters or fewer.
- Use `snake_case` for functions and variables.
- Prefer lexical filehandles and three-argument `open`.
- Validate input before interpolation; never pass raw config values to
  output, `open`, `exec`, or the shell.
- User-facing errors go to stderr with exit 1. Unsupported-feature warnings
  go to stderr and do not stop generation.
- Preserve the existing output contract unless the requested change is
  about that contract. Formatting changes affect generated `hostname.if`
  files.

## Security and testing policy

- Never use real private keys, preshared keys, or production endpoints in
  fixtures, logs, commits, or chat. Use obvious fakes.
- Generated output contains `wgkey` and possibly `wgpsk`. Do not paste full
  output into shared logs. A real `hostname.if` must be root-owned, group
  wheel, and mode `600`.
- OpenBSD `netstart` substitutes `$if` and evaluates the resulting commands
  with the shell. The validator reduces injection risk, but generated output
  must still be reviewed before it is installed. Do not reintroduce raw
  interpolation.
- Distinguish these stages: static syntax check, generation, fixture
  comparison, and application. Never report generation as a passing test.
- Do not run `ifconfig`, `route add/change/delete/flush`, `/etc/netstart`,
  or `doas`, and do not edit `/etc`, as part of an agent task. Do not run
  destructive tests.
- Removing a WireGuard interface does not necessarily revert routes that
  were added. Plan cleanup explicitly and warn the user.
- The script does not replace the default route. An `AllowedIPs` entry of
  `0.0.0.0/0` or `::/0` is an add and may conflict with an existing default.
- DNS, `Table`, `SaveConfig`, `FwMark`, and hooks are not applied; DNS
  remains under `resolvd`/`/etc/resolv.conf` control.

## Pre-existing changes

Inspect `git status --short` before editing. Preserve unrelated modified or
untracked files; never revert them to make the tree clean. Do not commit,
amend, rebase, tag, or push unless the user explicitly requests it. Report
unrelated changes instead of hiding them.

## Workflow

1. Read the relevant skill below before changing behavior.
2. Reproduce the current behavior with a fake fixture in `/tmp`.
3. Make the smallest change consistent with the existing style.
4. Run `perl -c wg2if.pl`, regenerate the fixture, and diff the result.
5. Run `git diff --check` and review `git diff`.
6. Report what was verified, what was not, and any system-level step left
   to the operator.

## Skills

- `wireguard-config-parsing` - parser scope, validation helpers, field
  handling, IPv4/IPv6, endpoints, duplicates, and fixtures.
- `openbsd-hostname-if-rendering` - output contract, directive ordering,
  rendering versus applying, MTU/DNS reality, and safe inspection.
- `route-and-interface-safety` - route semantics, endpoint gateway lookup,
  interface teardown, and operational safeguards.

The requested `perl-input-validation-and-fixtures` material is merged into
`wireguard-config-parsing` because this repository is small and a separate
skill would duplicate the same parser procedure.
