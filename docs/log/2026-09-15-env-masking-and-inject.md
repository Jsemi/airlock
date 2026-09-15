# Mask `[env]` secrets and inject them into HTTP headers per network rule

## Motivation

Presets that hand an AI agent an API token (`claude-code`, `openai-codex`,
`copilot-cli`) all used the same trick: give the guest a fixed placeholder
string in `[env]` and overwrite the `Authorization` header from a Lua
middleware on the host. It works, but every preset re-implements the same
header rewrite, the placeholder is a hard-coded constant, and a user who
wants the same protection for their own secret has to write Lua.

## Change

An `[env]` entry may now be written as `{ value = "...", mask = true }`. The
value is `${VAR}`-substituted as before, but the guest receives a random
`[A-Za-z0-9]` **surrogate** with the same character count; the real value
never enters the VM. A new `SandboxEnv` resolves the whole `[env]` section
once inside `project::lock` and is exposed as `project.env` (so a missing
variable now fails before the image pull); it feeds the guest env, the `~`
expansion of `HOME`, and the network layer.

`[network.rules.<name>]` gains `inject = ["VAR", ...]`. For HTTP traffic to
the rule's allow targets the proxy rewrites header values byte-for-byte:
surrogate → real on the request before the Lua middleware chain, real →
surrogate on the response after it. Header names, URI and bodies are
untouched; the monitor keeps showing surrogates in both directions. When
one masked value contains another, the longer one is rewritten first so the
result does not depend on `inject` order, and the body of a middleware error
(which may quote an already-unmasked header) is masked before it reaches the
guest. Every injected name must be a masked `[env]` entry and an injecting
rule cannot be `passthrough` — both validated at config load so `airlock
show` reports them too; the value must be at least 8 characters and a valid
header value, checked in `project::lock` before the image pull. Inject
targets also join middleware targets in the passthrough-overlap check.

Because config layers merge field-wise for objects but let a plain string
replace an object, string `[env]` entries are normalised to `{ value }` per
layer before merging: a later `TOKEN = "${X}"` only replaces the value and
cannot silently un-mask a base layer. Env resolution errors carry their own
type so `airlock start` still exits 2 for them, and a malformed table entry
reports the offending key rather than serde's generic untagged-enum message.

All three token presets (`claude-code`, `openai-codex`, `copilot-cli`) are
rewritten on top of this and drop their Lua middleware. Injection applies to
every host a rule allows, so the token can now be swapped into requests to
hosts the old middleware did not target (e.g. `claude.ai`, or Copilot's
telemetry hosts); that is accepted because the real value only ever replaces
a surrogate the sandboxed program itself put into a header.

## Tests and docs

Unit tests cover the string-or-table `EnvVar` parsing (including
`deny_unknown_fields`, so `masked = true` is an error rather than a silent
leak), inject validation, surrogate generation, header rewriting, and inject
target resolution. Proxy integration tests prove the request and response
rewrites over plain HTTP and MITM TLS, and the ordering around middleware.
CLI bats tests check the config error through `airlock show`; the VM env
bats test checks that a masked variable has the real value's length but not
its content. The manual gains a "Masking" section in the environment
chapter, an "Injecting masked secrets" section in the network chapter, an
ordering note in network scripting, a technical note in networking, and the
Claude Code preset page and README are reworded.
