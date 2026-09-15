# Add `airlock start --network <policy>` to override the config policy per run

## Motivation

A common workflow is to keep `[network] policy = "deny-by-default"` in
`airlock.toml` for the agent session, but bootstrap the sandbox's tooling
(`mise install`, `npm ci`, ...) first. That bootstrap step pulls from a long
tail of registries and CDNs that nobody wants to enumerate as allow rules.
Until now the options were to temporarily edit the config, keep a second
config file around, or flip the policy in the monitor by hand — none of
which work for an automated one-shot `airlock start -- ./init.sh`.

## Change

`airlock start` gains `--network <POLICY>`. The value is the same
kebab-case set as the config field (`allow-always`, `deny-always`,
`allow-by-default`, `deny-by-default`), enforced by deriving
`clap::ValueEnum` on `config::Policy` so the CLI and the config parser can
never drift apart. The override is applied to the loaded `Config` right
after `config::load`, before the project lock, so everything downstream
(rule compilation, the monitor's policy dropdown, verbose output) sees the
overridden value as if it had come from the file. Only the policy is
replaced; rules, middleware, ports, and sockets remain as configured.

The override is applied by mutating the loaded config in place and is
recorded in `airlock.log` at info level. Nothing downstream needs to know
the policy came from the CLI rather than the file, so no extra parameters
are threaded through the start path; the `--verbose` rules summary shows
the effective policy as usual.

`Policy::label()` was added as the single source of the kebab-case name.
The verbose rules summary previously formatted the policy via `Debug` and
`to_lowercase()`, producing `denybydefault`; it now prints
`deny-by-default`.

## Tests and docs

CLI bats tests cover the help text (value list is visible), rejection of an
unknown value such as `allow-all` (exit 2), and that `--verbose` reports
the overridden policy on a config that says `deny-by-default`. The manual gains a "Network policy
override" section in the starting-sandbox chapter and a tips entry,
"Bootstrapping tooling with an open network", that walks through the
`init.sh` + mise task pattern.
