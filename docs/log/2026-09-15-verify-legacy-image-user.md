# Verify cached images baked before named-`USER` resolution

## Motivation

The named-`USER` fix (`2026-09-14-fix-named-user-resolves-to-root.md`,
https://github.com/milankinen/airlock/pull/12) only changes how uid/gid
are computed when an image's metadata is baked. That metadata lives at
`~/.cache/airlock/oci/images/<digest>` and is never recomputed once
present: the per-sandbox fast path is offline, and even
`pull-policy = "if-changed"` hits the digest-keyed cache before the pull
path runs. A sandbox created from `USER node` before the fix therefore
keeps running as root until its image changes or it is removed.

Nothing in the cached file distinguishes "root because the image says so"
from "root because name parsing failed" — it records only the resolved
uid/gid, and the config blob is not kept on disk. Some marker for
"written by the old resolution" is unavoidable.

## Why not a schema bump

Bumping the `schema` tag to `v3` was the first idea. It invalidates every
cached image file, which is more than needed (only named-`USER` images
were affected) and turns a registry-sourced sandbox started offline into a
hard failure, because the "carry on with the cached image?" fallback needs
a readable file. Bumping `LAYER_FORMAT` alongside it would be worse still:
layers are byte-identical before and after the fix, so it would only
re-download everything and leave the old `2.*` directories around until
some `airlock rm` triggers a sweep.

## Change

`OciImage` gains `user: Option<String>` (`#[serde(default)]`), the raw
`USER` string from the image config (`""` when none). New files always
carry `Some`; a file without it is a legacy entry.

In `prepare`, a legacy entry never takes the name-keyed fast path. After
the tag has been resolved, if the digest is unchanged, the stored uid/gid
are re-derived with `resolve_user` from the fresh `USER` string and the
layers the file already references:

- **Match** — the file is rewritten with `user` set. No further cost.
- **Same uid, different gid** — `USER 1000` used to get gid 0 instead of
  the primary group. Existing files still belong to the same owner, so the
  gid is corrected in place and a line is logged.
- **Different uid** — the sandbox has been running as the wrong user and
  its disk holds state owned by it. `prepare` fails with an error that
  explains this, links the PR, and says to run `airlock rm` and start
  again. Nothing is deleted automatically.

`ensure_image` no longer treats a legacy entry as a digest-keyed cache hit,
so after `airlock rm` the next start rebuilds the metadata through the
normal pull path (all layers are already cached; Docker sources re-run
`docker image save`, skipping cached layers) and `ensure_image_hardlink`
re-links the sandbox to the new file.

The `USER` string comes from the resolved config for registry images. The
Docker resolver leaves the config empty until export, so
`docker::image_user` asks the daemon via `docker image inspect`.

## Not covered

- Registry unreachable: the legacy file still parses, so the existing
  "continue with cached image?" prompt applies and the sandbox runs as
  before (possibly as root) until the registry is reachable again.
- Tag moved *and* legacy entry: the ordinary "image has changed" prompt
  runs first. "Re-create" rebuilds the new image correctly; "Continue
  using old environment" keeps the legacy file unverified, and the same
  prompt returns on the next start.
