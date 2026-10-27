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
- `scripts/validate-agent-knowledge.py` - structural maintenance-policy
  validator, using Python 3.11+ and Git.
- `.github/workflows/agent-maintenance.yml` - pull-request enforcement.

There is no Makefile, build system, test suite, or lint configuration.
GitHub Actions runs the agent-maintenance validator for pull requests.

## Continuous Agent & Skills Maintenance

**EVERY CHANGE TO THE REPOSITORY MUST TRIGGER AN AGENT AND SKILLS
MAINTENANCE REVIEW.** This applies to source, configuration, dependencies,
features, bug fixes, refactors, tests, workflows, documentation, and
repository structure. Agent instructions and skills are living repository
artifacts.

> Agent instructions and skills are living repository artifacts.
>
> Every repository modification MUST include an agent/skills
> synchronization step.
>
> Before completing any task, inspect the applicable AGENTS.md and SKILL.md
> files, update the affected instructions, and validate their consistency
> with the implementation.
>
> A code change without the corresponding agent knowledge maintenance is
> considered incomplete.
>
> Never claim completion when the synchronization step has been skipped or
> has failed.

For every task that changes the repository:

1. Inspect all applicable `AGENTS.md`, `.github/agents/*.agent.md`,
   `.agents/skills/**/SKILL.md`, `.github/skills/**/SKILL.md`,
   `.claude/skills/**/SKILL.md`, `.github/instructions/*.instructions.md`,
   and any tool-specific agent instructions present in the repository
   (including Claude, Cursor, Copilot, Gemini, and Windsurf instructions).
2. Map changed components and procedures to agent responsibilities and
   skills by their scope and `When to use` guidance. Review the root
   instructions and every mapped instruction file after implementation.
3. Update at least one relevant instruction or skill in the same change.
   Update an existing skill when its procedure, assumptions, validation,
   commands, paths, or reusable knowledge changed. Create a skill only
   when no existing skill can own recurring, sufficiently distinct work;
   avoid duplicate scopes.
4. Keep specialized agent instructions aligned with their skills and the
   implementation. There are currently no specialized agent files in this
   repository. A future agent that changes the project must add the
   `Post-Change Knowledge Synchronization` section to any specialized agent
   instructions it creates or updates.
5. Remove obsolete or conflicting guidance, add reusable knowledge learned
   during the task, and verify local links and references.
6. Run `python3 scripts/validate-agent-knowledge.py --scope worktree` after the relevant
   instruction updates. The check validates changed-file coverage,
   instruction structure, and resolvable local Markdown links. Also run
   project-specific validation required by the affected skill.

The validator enforces structural conditions and substantive additions to
an instruction file; it cannot determine whether an update is semantically
relevant. Review the diff for that. If synchronization cannot be completed,
document why and report the task as incomplete. A missing instruction
update, invalid references, or failed maintenance check blocks completion.
When changing this policy, the validator, or their workflow, review the
whole maintenance system once at the end and rerun validation only to check
corrections; this avoids an endless update loop.

### Shared Agent Knowledge Validation Contract

Use `python3 scripts/validate-agent-knowledge.py --scope worktree` for local
changes and `python3 -m unittest discover -s tests/agent_knowledge_validator -v`
for its contract tests. The validator requires Python 3.11+ and Git, uses only
the Python standard library, and publishes contract version `1.0.0`. All
adopting repositories share the same CLI, AK001-AK006 identifiers, output
schema, and exit codes (`0` pass, `1` policy failure, `2` execution/configuration
error). For a pull request, pass both revisions with
`--scope range --base BASE_REF --head HEAD_REF`; compare from their merge base.

Read [Agent Knowledge Validation Contract](docs/agent-knowledge-validation.md)
for the complete rules, JSON schema, optional repository configuration,
warning semantics, and extension process. AK004 and AK006 can require human
review; their warnings do not prove or disprove semantic correctness. Keep the
canonical script and black-box unittest suite byte-identical across adopting
repositories. Repository-specific requirements belong in the documented TOML
configuration or a stable `AKX...` extension, never in a private fork of the
shared rules. The GitHub PR workflow runs the same tests and range command;
it does not edit files or require secrets.

### Mandatory Definition of Done

- [ ] Repository changes implemented.
- [ ] Relevant agent instructions reviewed.
- [ ] Relevant skills reviewed.
- [ ] Affected `AGENTS.md` / `SKILL.md` files updated.
- [ ] Obsolete knowledge removed.
- [ ] New reusable knowledge incorporated.
- [ ] Agent and skill references validated.
- [ ] Automated maintenance checks passed.
- [ ] Final synchronization status reported.

If any check fails, correct it or explicitly report the limitation and mark
the task incomplete. Every final report must include **Agent & Skills
Synchronization** with agents and skills reviewed, instruction files
updated, knowledge incorporated or corrected, validations run, and status
`PASS` or `FAIL`. Never report a validation as passing unless it ran.

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

1. Read the relevant skills below before changing behavior.
2. Reproduce current behavior with a fake fixture in `/tmp` when behavior
   changes.
3. Make the smallest change consistent with existing style.
4. Run project-specific validation, including `perl -c wg2if.pl` for Perl
   changes and fixture comparison when behavior changes.
5. Complete the Continuous Agent & Skills Maintenance procedure and run
   `python3 scripts/validate-agent-knowledge.py --scope worktree`.
6. Run `git diff --check`, review the full diff, and report verification,
   synchronization status, and any system-level step left to the operator.

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
