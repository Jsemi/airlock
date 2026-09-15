# GitHub Copilot CLI

The `copilot-cli` preset bundles the sandbox setup for the
[GitHub Copilot CLI](https://docs.github.com/en/copilot/concepts/agents/about-copilot-cli).
It keeps the Copilot OAuth token on the host and scopes network
access to the GitHub endpoints Copilot actually uses.

## What the preset does

The sandbox sees a same-length random surrogate in
`COPILOT_GITHUB_TOKEN`, and airlock swaps in the real token at the
host boundary.

- **Your token stays on the host.** The variable is
  [masked](../configuration/env.md#masking) and the `copilot-cli`
  rule [injects](../configuration/network.md#injecting-masked-secrets)
  the real value into request headers to the hosts it allows.
- **Only Copilot endpoints are reachable** (`github.com`,
  `api.github.com`, and `*.githubcopilot.com`). Everything else stays
  blocked by your deny-by-default policy.
- **Your Copilot session survives.** `~/.copilot` is mapped to
  `~/.airlock/copilot-cli/` on the host, so Copilot CLI session state
  persists across sandboxes — configuration, interaction history, and
  the session database all carry over.

## Example `airlock.toml`

```toml
presets = ["copilot-cli"]

[network]
policy = "deny-by-default"

[vm]
image = "docker/sandbox-templates:copilot-docker"
```

The `docker/sandbox-templates:copilot-docker` image ships with `copilot`
already installed. For a real project, you might prefer your own
[project-specific image](../tips/mise.md#building-a-local-image-with-docker).

## Providing the GitHub token

Create a [fine-grained personal access token][new-pat] with the
**Account > Copilot Requests** permission. Store it in the airlock
[secret vault](../secrets.md) under the name `COPILOT_GITHUB_TOKEN`:

[new-pat]: https://github.com/settings/personal-access-tokens/new

```bash
airlock secrets add COPILOT_GITHUB_TOKEN
```

Inside the sandbox, Copilot CLI sees a surrogate value in
`COPILOT_GITHUB_TOKEN` — no `/login` step is needed. Airlock
intercepts outgoing API requests at the host boundary and swaps in
the real token there. The actual credential never enters the sandbox.

For more details on supported token types, see the
[Copilot CLI authentication docs][copilot-auth].

[copilot-auth]: https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli#authenticating-with-environment-variables

## Running it

```bash
airlock start --monitor -- copilot
```
