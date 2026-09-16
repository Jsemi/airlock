# Reject malformed ports in network patterns instead of widening to every port

## Symptom

A network pattern is `host[:port]`. A port that did not parse as a number
was silently treated as "any port", so a typo widened the rule instead of
narrowing it. Under `policy = "deny-by-default"`:

- `allow = ["*:8O80"]` (letter O) or `["*:https"]` allowed every host on
  every port, not none.
- `allow = ["api.example.com:443 "]` (trailing space) allowed every port on
  that host.
- `inject` targets are built from the same `allow` list, so a typo'd port
  injected the real secret into every port on that host.

No warning was printed. This is the same shape as the named-`USER` bug
(`2026-09-14-fix-named-user-resolves-to-root.md`): a parse failure that
falls back to the most permissive value.

One correction to the audit's example: `allow = [":8O80"]` (empty host)
did **not** allow every host. `host_matches(host, "")` is an exact match
against the empty string and never succeeds, so that pattern matched
nothing. The widening shapes were `*:<bad>` and `<host>:<bad>`.

## Root cause

Every site that builds a matcher from a pattern parsed the port the same
way:

```rust
port: port.and_then(|p| p.parse::<u16>().ok()),
```

That is `rules::resolve`, `resolve_middleware` and `resolve_inject` in
`app/airlock-cli/src/network/rules.rs`, and the three `labeled_*` helpers
in `network.rs` that feed the passthrough conflict check. `ok()` turns
any unparseable port into `None`, and the matchers in `target.rs` treat
`None` as the wildcard:

```rust
self.port.is_none_or(|p| p == port)
```

`parse_target` also swallowed an empty port after a bracketed IPv6
literal (`[::1]:` → no port), which took the same path.

## Fix

`rules::parse_pattern(target) -> anyhow::Result<(&str, Option<u16>)>`
wraps the existing lexical split (`parse_target`, which still handles the
IPv6 forms). `None` is produced only by an absent port or a literal `*`;
every other port string is an error naming the pattern and the offending
port. `*` stays legal because the config docs promise "Both host and port
support `*` wildcards". Port `0` still parses; it matches no real
connection, so it cannot widen anything. `[::1]:` now yields an empty
port string, which is rejected like the unbracketed `host:` form.

All six construction sites use `parse_pattern`. `resolve`,
`resolve_middleware`, `resolve_inject` and the `labeled_*` helpers now
return `Result`, so a malformed pattern that somehow reached the proxy
fails startup rather than resolving to a wildcard.

The user-facing check runs earlier, at config load. `validate_inject` in
`load_config.rs` became `validate_network` and additionally walks every
enabled rule's `allow`/`deny` and every enabled middleware's `target`,
collecting all problems into the existing `invalid configuration` block:

```
invalid configuration
* `network.rules.api.allow` `*:8O80`: port `8O80` must be a number in 0-65535 or `*`
```

Disabled rules are skipped, consistent with the inject checks and with
`resolve`; a user who disables an inherited preset rule should not be
blocked by a typo in it.

## Tests

`parse_pattern_rejects_malformed_ports` pins nine shapes that used to
resolve to "any port": letter O, service name, trailing space, empty,
out of range, negative, `**`, and bracketed IPv6 with junk or empty port.
`parse_pattern_accepts_numeric_and_star_ports` covers numeric ports,
`*`, absent, and the IPv6 forms.

`resolve_rejects_malformed_port_instead_of_widening` and
`resolve_inject_rejects_malformed_port` check that the runtime backstop
names the rule path; `resolve_treats_star_port_as_any_port` pins `host:*`.

`config/tests/test_network_targets.rs` covers load-time rejection for
`allow`, `deny` and middleware `target`, that all problems are reported
at once, that a disabled rule is skipped, and that every documented
wildcard form still loads. `all_bundled_presets_are_valid` runs the
shipped presets through the new check; they all use numeric ports or
none.

## Docs

`docs/manual/src/configuration/network.md` and
`docs/manual/src/technical/networking.md` now say the port must be a
number or `*`, list `host:*`, and state that a malformed port is a
load-time error.
