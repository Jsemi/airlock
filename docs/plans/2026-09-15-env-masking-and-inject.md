# Environment variable masking + `inject` on network rules

## Context

Today the `claude-code`, `openai-codex` and `copilot-cli` presets keep the real
API token on the host by giving the guest a fixed placeholder string in `[env]`
and having a Lua middleware overwrite the `Authorization` header on the host.
That works but is ad hoc: every preset re-implements the same header rewrite,
the placeholder is a hard-coded constant, and a user who wants the same for
their own secret has to write Lua.

This feature makes it declarative:

- `[env]` values may be written as `{ value = "...", mask = true }`. The guest
  then sees a **surrogate**: a random alphanumeric string of the same length
  as the real value. The real value never enters the VM.
- `[network.rules.<name>]` gains `inject = ["VAR", ...]`. For HTTP traffic to
  that rule's `allow` targets, the host proxy replaces every occurrence of the
  surrogate in **request header values** with the real value (before Lua
  middleware runs), and every occurrence of the real value in **response header
  values** with the surrogate (after Lua middleware has run).
- Every name in `inject` must be defined in `[env]` with `mask = true`;
  otherwise config loading fails, so `airlock start` exits with
  `Config error: …` and `airlock show` with `Sandbox details loading failed: …`.

The `claude-code` preset is rewritten on top of this and drops its Lua
middleware. `openai-codex` and `copilot-cli` are left as they are (copilot
needs path-scoped logic; codex can be converted in a follow-up).

## Decisions / assumptions

- **Surrogate alphabet**: ASCII `[A-Za-z0-9]`, generated with
  `rand::distr::{Alphanumeric, SampleString}`:
  `Alphanumeric.sample_string(&mut rand::rng(), n)` (`rand::rng()` is a
  CSPRNG; `SysRng` only implements `TryRng` and does not fit `SampleString`).
  `n` = number of **characters** of the real value (byte length may differ
  for non-ASCII values; harmless). Empty value → empty surrogate, and empty
  needles are skipped during header rewriting.
- **Secrets never printed**: `MaskedSecret` gets a manual `Debug` that
  redacts both `real` and `surrogate`; rewrite errors sent to the guest as a
  502 body must not embed header bytes.
- **Minimum injected length**: a value referenced by `inject` must be at
  least 8 characters, else startup errors. A 2–3 char random surrogate would
  collide with ordinary header text and rewrite unrelated bytes. Masked
  variables that are *not* injected have no minimum.
- **Scope of rewriting**: header values only (request and response), every
  header including `cookie`/`host`, all occurrences, byte-level replace. Not
  header names, URI, or bodies.
- **Daemons and `airlock exec`** inherit the guest env, so they see the
  surrogate for masked variables unless they redefine them. Middleware `env`
  templates still resolve real values on the host.
- **Ordering**: request unmask runs before `middleware::run`; response
  re-mask runs on the response returned by `middleware::run`. Lua scripts
  therefore observe real values on the request and can set real values on the
  response; both are masked again at the guest boundary. Monitor events keep
  showing surrogates (request event is emitted before unmask, response event
  after re-mask).
- **Passthrough conflict**: a rule with `passthrough = true` and a non-empty
  `inject` is an error, and an inject target overlapping a passthrough target
  of another rule is reported through the existing overlap checker, exactly
  like middleware.
- **When env is resolved**: `${VAR}` substitution for `[env]` moves from
  `vm::start` to right after `project::lock` in `cmd_start::run`, so the
  masked/real pairs exist before `network::setup`. Side effect (an
  improvement): a missing host variable / vault secret now fails before the
  image pull instead of after it. `airlock show`/`exec`/`info` are unaffected
  (they use `project::load`, which never resolves env).

## High-level design

New pieces:

| Piece | Where | Role |
|---|---|---|
| `config::EnvVar { value, mask }` | `app/airlock-cli/src/config.rs` | string-or-table config value for `[env]`, mirrors `ImageRef` |
| `NetworkRule.inject: Vec<String>` | `config.rs` | new optional field |
| cross-section validation | `config/load_config.rs::parse_config` | inject names ⊆ masked `[env]` names |
| `sandbox_env` module (`SandboxEnv`, `MaskedSecret`) | new `app/airlock-cli/src/sandbox_env.rs` | resolves `[env]` once: real value, optional surrogate; provides guest `KEY=VALUE` list and lookup by name |
| `InjectTarget` | `network/target.rs` | `host`, `port`, `secrets: Rc<[MaskedSecret]>`, parallel to `MiddlewareTarget` |
| `rules::resolve_inject` | `network/rules.rs` | builds `Vec<InjectTarget>` from enabled rules × their `allow` patterns |
| `network::labeled_inject` + conflict check | `network.rs` | passthrough overlap, min length |
| `ResolvedTarget.secrets: Vec<MaskedSecret>` | `network/target.rs` | per-connection list (deduped by name) |
| `http::inject` module | new `network/http/inject.rs` | pure `rewrite_headers(&mut HeaderMap, from→to pairs)`; `unmask_request` / `mask_response` wrappers |
| call sites | `network/http.rs::relay` | before/after `middleware::run` |

Data flow at `airlock start`:

```
config::load ─► parse_config (validates inject ⊆ masked env)
cmd_start::run ─► project::lock ─► SandboxEnv::resolve(&config.env, &vault)
   ├─► oci::effective_container_home(…, &env)   (guest-visible HOME)
   ├─► network::setup(&project, &env, home)    (inject targets from masked secrets)
   └─► vm::start(…, &env)                       (guest gets KEY=surrogate)
```

Per HTTP request on an allowed, intercepted connection:

```
guest req ─► emit_request_event ─► unmask_request(headers)  ─► Lua middleware ─► upstream
guest ◄── emit_response_event ◄── mask_response(headers)   ◄── Lua middleware ◄── upstream
```

## Detailed plan

### Phase 1 — config schema

`app/airlock-cli/src/config.rs` (inside `pub mod config`):

1. Add
   ```rust
   /// One `[env]` entry: a plain string, or `{ value = "...", mask = true }`.
   #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
   pub struct EnvVar { pub value: String, pub mask: bool }
   ```
   with a manual `serde::Deserialize` modelled on `ImageRef`
   (`config.rs:190-236`) but **typo-safe**: the untagged helper is
   `Simple(String) | Full(FullEnvVar)` where `FullEnvVar` is a separate
   `#[derive(Deserialize)] #[serde(deny_unknown_fields)] struct { value: String, #[serde(default)] mask: bool }`.
   (`ImageRef`'s inline-variant form ignores unknown keys, so
   `masked = true` would silently leak the real value.) Then
   `impl WellKnown for EnvVar` with `Serde<{STRING.or(OBJECT).raw()}>`
   (smart-config's `BTreeMap<K, V>: WellKnown` only needs `V: WellKnown + 'static`).
   Add `EnvVar::plain(s)` helper for tests/callers.
2. Change `Config.env` to `BTreeMap<String, EnvVar>` and update its doc
   comment.
3. Add to `NetworkRule`:
   ```rust
   /// Names of masked `[env]` variables whose real value is substituted
   /// into HTTP request headers (and masked back in response headers)
   /// for this rule's allow targets. Each name must be defined in `[env]`
   /// with `mask = true`.
   #[config(default)]
   pub inject: Vec<String>,
   ```
   Update every `NetworkRule { .. }` literal: `network/rules.rs` tests (two
   sites, ~L159 and ~L215), `network.rs::labeled_target_tests` (~L396),
   `network/tests/helpers.rs` (~L154).
4. `config/load_config.rs::parse_config`: after `parser.parse()` succeeds
   (next to the kvm check), validate every enabled rule's `inject` entries:
   name must exist in `config.env` and have `mask == true`. `anyhow::bail!`
   in the existing error shape:
   ```
   invalid configuration
   * `network.rules.<rule>.inject` `VAR` must be defined in [env] with mask = true
   ```
   one bullet per offence. Keeping it in `parse_config` means `airlock show`
   reports it too (via `project::load`).
5. Fix the two existing readers of `config.env`:
   - `oci.rs::effective_container_home` — becomes a lookup in `SandboxEnv`
     (Phase 2), no longer substitutes itself.
   - `vm.rs::resolve_env` — replaced by `SandboxEnv::guest_entries` (Phase 2).
   Also refresh stale doc comments that describe the old flow: `oci.rs:26`,
   `oci.rs:59`, `vm.rs:100`, `cli_server.rs:4-7, 28-29, 143-144`.
6. Tests — new `app/airlock-cli/src/config/tests/test_env.rs` (register in
   `tests/mod.rs`), same `parse()` helper style as `test_daemons.rs`:
   - plain string → `mask == false`
   - table with `mask = true`
   - table without `mask` → false
   - table missing `value` → error
   - `inject` parses on a rule
   - inject of undefined var → error mentions rule and var name
   - inject of unmasked var → error
   - inject on a disabled rule is not validated (skipped)

### Phase 2 — `SandboxEnv` (resolution + surrogates)

New `app/airlock-cli/src/sandbox_env.rs` (add `mod sandbox_env;` in `main.rs`):

```rust
#[derive(Clone)]
pub struct MaskedSecret { pub name: String, pub real: String, pub surrogate: String }
// manual Debug: prints only `name` and the length, never the values

pub struct SandboxEnv {
    /// Every `[env]` entry, config order, with the value the guest sees.
    guest: Vec<(String, String)>,
    /// Only the masked ones, keyed by name.
    masked: BTreeMap<String, MaskedSecret>,
}

impl SandboxEnv {
    /// Substitute every template through `vault.subst` (error prefix `env.<KEY>: …`,
    /// same as today) and generate a surrogate for masked entries.
    pub fn resolve(env: &BTreeMap<String, EnvVar>, vault: &Vault) -> anyhow::Result<Self>;
    /// Value the guest sees for `name` (surrogate if masked).
    pub fn guest_value(&self, name: &str) -> Option<&str>;
    /// `KEY=VALUE` entries, guest-visible values.
    pub fn guest_entries(&self) -> impl Iterator<Item = (&str, &str)>;
    pub fn masked(&self, name: &str) -> Option<&MaskedSecret>;
    pub fn masked_count(&self) -> usize;
}

fn surrogate_for(value: &str) -> String
    // Alphanumeric.sample_string(&mut rand::rng(), value.chars().count())
```

- `vm.rs`: `start(args, project, image, container_home, env: &SandboxEnv)`;
  `resolve_env(image, env)` layers `env.guest_entries()` over `image.env` with
  the existing retain/push logic. Update the `VmInstance.env` doc comment.
- `oci.rs::effective_container_home(project, image, env)`: use
  `env.guest_value("HOME")` else image home.
- `cmd_start.rs::run`: construct
  `SandboxEnv::resolve(&project.config.env, &project.vault)` immediately after
  `project::lock`; on error use the same `cli::error!("{e:#}"); return Ok(2)`
  pattern as `effective_container_home` today. Pass `&env` to the three
  consumers. `print_mounts_and_rules(&project, &env)`: add a verbose line
  `env: N vars (M masked)` when N > 0 and, per rule, append `inject K` when
  K > 0.
- Unit tests in `sandbox_env.rs`: surrogate char count equals the real
  value's, alphanumeric only, differs from the real value (len ≥ 8), empty →
  empty, unmasked entries pass through unchanged, `${VAR}` substitution is
  applied before masking. Build the vault with
  `Vault::new_with(Box::new(DisabledStorage), HashMap::from([...]), VaultStorageType::Disabled)`
  as the `vault.rs` tests do (`vault.rs:619-627`); do **not** touch the
  process env (`std::env::set_var` is `unsafe` in edition 2024). Check that
  `DisabledStorage` is reachable from outside `vault/` and re-export it if
  needed.

### Phase 3 — network: targets, validation, header rewriting

1. `network/target.rs`:
   ```rust
   #[derive(Clone)]
   pub struct InjectTarget { pub host: String, pub port: Option<u16>, pub secrets: Rc<[MaskedSecret]> }
   impl InjectTarget { pub fn matches(&self, host, port) -> bool }  // same as MiddlewareTarget
   ```
   Add `pub secrets: Rc<[MaskedSecret]>` to `ResolvedTarget` (empty slice in
   `denied()`); an `Rc` so the per-request `service_fn` clone is cheap.
2. `network/rules.rs::resolve_inject(network: &config::Network, env: &SandboxEnv) -> anyhow::Result<Vec<InjectTarget>>`:
   for each enabled rule with non-empty `inject`: look up each name via
   `env.masked(name)` (config validation already guarantees presence; still
   return an error rather than panic), enforce min length 8
   (`network.rules.<rule>.inject: \`VAR\` value is shorter than 8 characters`),
   build one `InjectTarget` per `allow` pattern sharing one `Rc<[MaskedSecret]>`.
   Rule with `passthrough = true` and non-empty inject →
   `network.rules.<rule>: inject cannot be combined with passthrough`.
3. `network.rs`:
   - `setup(project, env: &SandboxEnv, container_home)`; call
     `rules::resolve_inject`; add `labeled_inject(net)` (label
     ``rule `{name}` inject target=`{allow}` ``) and pass
     `labeled_middleware ++ labeled_inject` to `check_passthrough_conflicts`.
     Generalize that checker's message from "overlap middleware target(s)"
     to "overlap intercepting target(s)" (or similar) so inject labels read
     correctly; update its existing test expectations if they match on the
     wording.
   - `Network.inject_targets: Vec<InjectTarget>` (also add the field to the
     `Network { .. }` literal in `network/tests/helpers.rs`); in
     `resolve_target`, when allowed and not passthrough,
     `collect_secrets(host, port)` → dedupe by name → `Rc<[MaskedSecret]>`
     into `ResolvedTarget.secrets`. Fast path: a single matching target
     returns its `Rc` clone without re-allocating.
   - Extend the debug line with the inject target count.
4. New `network/http/inject.rs`:
   ```rust
   /// Replace every occurrence of `from` with `to` in every header value.
   /// Skips empty `from`. Errors if a rewritten value is not a valid HeaderValue.
   pub fn rewrite_headers(headers: &mut HeaderMap, pairs: &[(&[u8], &[u8])]) -> anyhow::Result<()>
   pub fn unmask_request(headers: &mut HeaderMap, secrets: &[MaskedSecret]) -> anyhow::Result<()>  // surrogate→real
   pub fn mask_response(headers: &mut HeaderMap, secrets: &[MaskedSecret]) -> anyhow::Result<()>   // real→surrogate
   ```
   Implementation: iterate `headers.values_mut()` (yields every value,
   including repeated names), for each value do a byte search/replace (a
   small `replace_bytes(haystack, needle, repl) -> Option<Vec<u8>>` helper;
   only rebuild via `HeaderValue::from_bytes` when something matched). The
   error for an invalid rebuilt value names the header, never its bytes.
   Unit tests: multi-occurrence, multi-header, repeated header name,
   multi-secret, no-op when absent, empty needle skipped, invalid result
   errors without leaking the value.
5. `network/http.rs::relay` (allowed branch): move `target.secrets` into the
   service closure (`move |mut req: Request<Incoming>|`). The async block
   returns `Result<_, hyper::Error>`, so `?` on an `anyhow::Result` will not
   compile; structure it so both rewrite errors land in the existing
   `Err(e)` → 502 arm:
   ```rust
   let result = match inject::unmask_request(req.headers_mut(), &secrets) {
       Err(e) => Err(e),
       Ok(()) => middleware::run(req, &middleware, deny_reporter, connect_host, send)
           .await
           .and_then(|mut resp| {
               inject::mask_response(resp.headers_mut(), &secrets).map(|()| resp)
           }),
   };
   ```
   `emit_request_event` stays before the unmask and `emit_response_event`
   after the re-mask. Both helpers return early when `secrets` is empty.
6. Integration tests — new `network/tests/test_inject.rs` (register in
   `tests/mod.rs`); extend `TestNetworkConfig` in `tests/helpers.rs` with
   `inject: Vec<MaskedSecret>` (add to its manual `Default` impl at
   ~L78; all other literals use `..Default::default()`), and have
   `build_network` set `inject` names on the `test-allow` rule and call
   `rules::resolve_inject(&config, &env)` next to `resolve_middleware`,
   with `env` from a `#[cfg(test)] SandboxEnv::from_secrets(Vec<MaskedSecret>)`
   constructor. Use `run_network_with_log` for the Lua-observation case:
   - request header `authorization: Bearer <surrogate>` reaches the axum
     upstream as `Bearer <real>`.
   - upstream response header containing `<real>` reaches the guest as
     `<surrogate>`.
   - with a Lua middleware that logs `req:header("authorization")`, the log
     shows the real value (unmask precedes middleware); a middleware that
     sets a response header to the real value is masked for the guest.
   - a host not covered by the inject rule leaves the surrogate untouched.
   - TLS path: one case in `test_tls.rs` style, or reuse `run_with_config`
     with an HTTPS upstream, to prove MITM + inject compose.
   - unit tests in `rules.rs` for `resolve_inject` errors (short value,
     passthrough+inject) and in `network.rs` for `labeled_inject`.

### Phase 4 — preset, docs, bats, log

1. `app/airlock-cli/src/config/presets/claude-code.toml`: replace the
   placeholder env + `[network.middleware.claude-auth-token]` with
   ```toml
   [env]
   CLAUDE_CODE_OAUTH_TOKEN = { value = "${CLAUDE_CODE_OAUTH_TOKEN}", mask = true }
   …
   [network.rules.claude-code]
   inject = ["CLAUDE_CODE_OAUTH_TOKEN"]
   allow = [...]
   ```
   Keep `IS_SANDBOX`, `NODE_EXTRA_CA_CERTS`, mounts.
2. Docs:
   - `docs/manual/src/configuration/env.md`: new "Masking" section (table
     form, surrogate semantics, what the guest sees, `airlock exec -e` still
     overrides).
   - `docs/manual/src/configuration/network.md`: new "Injecting masked
     secrets" subsection under Network rules (`inject`, validation rules,
     ordering relative to middleware, passthrough incompatibility, header
     values only, min length).
   - `docs/manual/src/advanced/network-scripting.md`: one paragraph on
     ordering (scripts see real values).
   - `docs/manual/src/presets/claude-code.md` and `README.md` §4: reword
     "middleware injects the header" → masked env + inject.
   - `docs/manual/src/technical/networking.md`: short "Secret injection"
     subsection after "Lua middleware".
3. Bats:
   - `tests/cli/config_loading.bats`: inject of unmasked var → `airlock show`
     fails and output contains `must be defined in [env] with mask = true`
     and the var name (note: `show` prints `Sandbox details loading failed:`,
     not `Config error`, which only `start` prints); inject of masked var →
     output does not contain that message. Same for the `{ value, mask }`
     table form parsing without error.
   - `tests/vm/env.bats`: `MASKED_VAR = { value = "${HOST_TEST_VALUE}", mask = true }`;
     assert output length is 21 (`substituted-from-host`) and output does not
     contain the real value.
4. `docs/log/2026-09-15-env-masking-and-inject.md` (Motivation / Change /
   Tests and docs, matching `2026-09-15-start-network-policy-override.md`),
   and copy this plan to `docs/plans/2026-09-15-env-masking-and-inject.md`.
5. Run `mise format`, `mise run lint`, `mise run test`, `mise run bats:cli`.
   Commit via the `/git-commit` skill.

## Verification

- `mise run test` — config, sandbox_env, inject, rules, and network
  integration tests pass.
- `mise run lint` — clippy pedantic clean.
- `mise run bats:cli` — the inject validation error surfaces through
  `airlock show`.
- `mise run bats:vm` (if KVM/docker available) — masked var length check.
- Manual: with `presets = ["claude-code"]` and a vault token,
  `airlock start --monitor -- sh -c 'echo $CLAUDE_CODE_OAUTH_TOKEN'` prints a
  random string of the token's length; running `claude` authenticates, and
  the monitor's request view shows the surrogate in `authorization`.

## Implementation notes

- Per review during implementation, `SandboxEnv::resolve` lives inside
  `project::lock` and is exposed as `project.env`; `network::setup`,
  `vm::start`, and `oci::effective_container_home` keep their original
  signatures and read it from the project. `project::load` (read-only
  subcommands) leaves it empty and never resolves secrets.
- `InjectTarget` and `ResolvedTarget` hold `Vec<InjectedSecret>`, a network-
  internal `Rc<MaskedSecret>` handle that derefs to the secret, so the
  per-connection and per-request copies are pointer bumps.
- The module lives at `app/airlock-cli/src/project/sandbox_env.rs` as a
  submodule of `project` (not a top-level `sandbox_env` module); `project`
  re-exports `SandboxEnv` and `MaskedSecret`.
