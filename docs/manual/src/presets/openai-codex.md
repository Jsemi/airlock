# OpenAI Codex

The `openai-codex` preset bundles the sandbox setup for the
[OpenAI Codex CLI](https://github.com/openai/codex). It keeps your
OpenAI API key on the host and lets the sandbox run against a
same-length random surrogate — Codex talks to OpenAI normally, but
it never sees the real credential.

## What the preset does

Codex reads its API key from `OPENAI_API_KEY` and sends it as a
bearer token on every request. The preset
[masks](../configuration/env.md#masking) that variable and the
`codex` rule [injects](../configuration/network.md#injecting-masked-secrets)
the real key into request headers to the OpenAI hosts.

- **Your API key stays on the host.** Inside the VM,
  `OPENAI_API_KEY` is a random string of the same length.
- **Only OpenAI endpoints are reachable** (`api.openai.com` and
  `auth.openai.com`). Everything else stays blocked by your
  deny-by-default policy.
- **Your Codex settings survive.** `~/.codex` is mapped to
  `~/.airlock/codex/` on the host, so preferences and history carry
  over between sandbox runs.

## Example `airlock.toml`

```toml
presets = ["openai-codex"]

[network]
policy = "deny-by-default"

[vm]
image = "docker/sandbox-templates:codex-docker"
```

The `docker/sandbox-templates:codex-docker` image ships with `codex`
already installed. For a real project, you might prefer your own
[project-specific image](../tips/mise.md#building-a-local-image-with-docker).

## Providing the API key

Store your OpenAI API key in the airlock
[secret vault](../secrets.md) under the name `OPENAI_API_KEY`:

```bash
airlock secrets add OPENAI_API_KEY
```

The preset resolves `${OPENAI_API_KEY}` from the host env first and
the vault as a fallback. A missing value aborts `airlock start` with
a clear error rather than silently shipping requests without auth.

## Running it

```bash
airlock start --monitor -- codex --yolo
```
