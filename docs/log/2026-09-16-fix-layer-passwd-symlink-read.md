# Refuse layer `/etc/passwd` symlinks that resolve outside the layer

## Symptom

An image could make the host read a file of the image author's choosing
while a sandbox was being prepared. Tar extraction deliberately preserves
a layer's symlinks because they are meant to resolve inside the guest.
Read on the host, the same symlinks point wherever the image author chose.
An image could ship:

- `etc/passwd -> /etc/passwd` plus a numeric `USER`: whatever host
  account has that uid is found and its home directory becomes the
  guest's `HOME`. On a Linux host that includes the user running airlock;
  on macOS regular users are not in `/etc/passwd`, so only system
  accounts (`root` → `/var/root`, `_www`, …) are exposed.
- `etc/passwd -> /dev/zero`: the read allocates until the host is out of
  memory. `-> /dev/tty` or a FIFO blocks `prepare` forever.
- `etc -> /` as a directory symlink, with the same effects one level up.

The read runs whenever an image is prepared for a sandbox (first start,
or after the image changes), whether or not the image sets `USER`.

## Root cause

`build_oci_image` resolves `USER` and `$HOME` from the image's own
`/etc/passwd` and `/etc/group`, read straight out of the extracted layer
trees under `~/.cache/airlock/oci/layers/`. That read used
`std::fs::read_to_string`, which follows symlinks and has no size limit,
and nothing checked that the path it ended up at was still inside the
layer.

## Fix

`lookup_layer_record` reads through a new `read_layer_file`, which
canonicalizes the layer directory and then walks the requested path one
component at a time, refusing the read as soon as any symlink on the way
resolves outside the layer's own tree. Checking only the final path would
let `etc -> /` slip through as "no such file" whenever the host lacks the
target file, since `lstat` follows every component but the last. Symlinks
that resolve _within the same layer_ — merged-usr style
`etc/passwd -> ../usr/lib/passwd` — still work, because the rule is about
where the path ends up, not whether a symlink was involved. A symlink whose
target lives in a _different_ layer did not resolve before this change
either (the target is missing from this layer's tree, so the read failed
and the walk moved on) and still does not; that is a pre-existing limit of
reading per-layer trees rather than a merged rootfs, not a regression.

The read is also bounded by `MAX_LAYER_RECORD_FILE` (1 MiB): a real
`passwd` or `group` is a few kilobytes, and anything larger is treated as
having no records rather than read whole. Non-regular files are refused
the same way. The `tar` crate creates neither FIFOs nor device nodes on
unpack, so a non-regular file can only reach the lookup through an
escaping symlink (already refused) or as a directory at that path.

A refused file counts as "no records in this layer" and the walk falls
through to the next layer, exactly as it already did for a whiteout. So a
malicious upper layer cannot hide a lower layer's real `passwd`, and if no
layer has a real one the existing "no user … found" error fires instead of
a host file being consulted.

Refusals are reported, not just logged. On its own, refusing the read
would leave the user with the generic "no home directory found for uid N
in any layer /etc/passwd", the same message a broken image produces, with
the real reason only in the project's `.airlock/airlock.log`. So the
lookup carries every refusal (which layer, which file, and why: symlink
outside the layer, unresolvable symlink, not a regular file, over the size
limit) alongside the match. Falling through is unchanged, a refused upper
layer still yields to a real lower one, but when *nothing* resolves the
error appends them, e.g. `no user node found in any layer /etc/passwd
(ignored: etc/passwd in layer 2.<digest>: symlink resolves outside the
layer (/etc/passwd))`. For the fall-through case, where the image starts
and no error fires, the suspicious reasons still leave a `warn` line in
the log; an unresolvable in-layer symlink is only logged at `debug`, since
a target living in a lower layer is a limitation, not a warning.

## Tests

- `passwd_symlink_outside_layer_is_not_followed` — `etc/passwd`, and
  separately the whole `etc` directory, symlinked to a file outside the
  layer: skipped in favour of a lower layer's real file, and an error when
  no layer has one. The outside file carries a distinctive home directory
  so a leak would be visible.
- `refused_passwd_is_named_in_the_error` — when nothing resolves, the
  error keeps the original not-found text and names the refused file, its
  layer and the reason, for both the home lookup and named-`USER`
  resolution; an oversized file is named with its own reason.
- `escaping_directory_symlink_is_reported_even_without_target_file` —
  `etc -> <outside>` where `<outside>` lacks `passwd` is still reported as
  an escaping symlink, not as a missing file.
- `directory_and_dangling_symlink_refusals_are_named` — a directory at
  `etc/passwd`, and a symlink whose target is absent from the layer.
- `passwd_symlink_inside_layer_is_followed` — merged-usr style
  `etc/passwd -> ../usr/lib/passwd` keeps resolving.
- `oversized_passwd_is_not_read` — a record placed past the 1 MiB cap is
  not found.

## Docs

`docs/manual/src/technical/container-execution.md` now states that
`passwd`/`group` are read from the extracted layers, which symlinks are
ignored, and that a refusal is named in the error.

## Related surfaces

- The same class of read exists nowhere else on the host side; `layer.rs`
  already resolves whiteout paths component-wise and refuses symlink
  traversal, and `file_sync` opens with `O_NOFOLLOW`. This change brings
  the passwd/group lookup in line with them.
- A layer that is _itself_ placed on a symlinked cache directory is the
  user's own filesystem layout and is canonicalized as the root, so it is
  unaffected.
