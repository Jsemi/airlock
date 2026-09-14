# Resolve image `USER` names through `/etc/passwd` instead of falling back to root

## Symptom

An image whose config says `USER node` (or `USER node:node`, `USER 1000:node`,
…) ran inside the sandbox as **uid 0, gid 0**. No warning was printed. The
image author had asked for an unprivileged user, the manual said airlock
derives the user from the image's `/etc/passwd`, and the container still came
up as root — with the full capability set, which is enough to unmount the
`[mask]` bind mounts and the hidden `.airlock/` directory from inside.

Most official language images that bother to set a user set it by name, so
this affected precisely the images people pick because they are "already
non-root".

## Root cause

`parse_user` in `app/airlock-cli/src/oci.rs` only understood the numeric
`uid[:gid]` form:

```rust
let uid = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
let gid = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
```

A name fails `parse::<u32>()`, and `unwrap_or(0)` turned that failure into
root. The passwd walk that the manual describes existed, but only for the
home-directory lookup (`lookup_home_dir`), which runs *after* the uid has
already been decided.

## Fix

`parse_user` is replaced by `resolve_user(layer_keys, user)`, which handles
all six forms the OCI image spec allows and follows Docker's semantics:

- a user **name** is looked up in the image's `/etc/passwd` (topmost layer
  first), yielding both uid and primary gid;
- a bare **numeric uid** keeps its number and takes the primary gid from the
  matching `passwd` record when one exists (previously the gid was always 0
  in this case);
- a **group name** is looked up in `/etc/group`; a numeric gid is used as-is;
- an empty `USER` means root, as before;
- a user or group name that no layer declares is an **error**. Falling back
  to root here would recreate the bug for a different typo.

The per-layer file walk is factored into `lookup_layer_record`, which
`lookup_home_dir` now uses as well, so passwd and group are read with the
same whiteout handling everywhere.

## Compatibility note

`USER 1000` on an image whose `passwd` has `1000` with primary group `1000`
now yields gid 1000 instead of 0. This matches Docker and is what the image
author expressed; images that want gid 0 can say `USER 1000:0`.

## Tests

`named_user_in_image_config_does_not_become_root` builds an image config
against a layer carrying `passwd` and `group` entries for `node` (1000:1000)
and asserts uid, gid and home for `node`, `1000`, `node:node`, `1000:node`,
`node:1000` and `1000:1000`. It failed with `(0, 0)` before the fix.

`unknown_user_or_group_name_is_an_error_not_root` pins the fail-closed
choice: `ghost`, `ghost:node`, `node:ghost` and `1000:ghost` are rejected
with an error naming the missing entry, never resolved to root.

An image with no `/etc/passwd` at all could not start before this change
either — `lookup_home_dir` requires a passwd record even for root — and
that is unchanged here.

## Docs

`docs/manual/src/technical/container-execution.md` now states the
resolution rules.
