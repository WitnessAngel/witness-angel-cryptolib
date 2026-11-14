## Context

See proposal.md - Why. Public keystore methods uppercase `key_algo` before calling the storage hooks (`_get_filepath`, `_public_key_exists`, `_get_public_key`, `_add_free_keypair`, `_attach_free_keypair_to_uuid`...). `ReadonlyFilesystemKeystore` builds `<keychain_uid>_<key_algo>_{public,private}_key.pem` from that name, and free keys live in `free_keys/<key_algo>/<random>_{public,private}_key.pem`. `_list_unordered_keypair_identifiers()` returns the algo as written in the file name. `TrusteeApi._ensure_keypair_exists()` generates a keypair whenever `_private_key_exists()` is false, which is how an unfound key gets shadowed. `ReadonlyFilesystemKeystore` serves imported authenticators, which must never be modified.

## Goals / Non-Goals

**Goals:**
- Decouple the on-disk spelling (lowercase) from the API spelling (uppercase), in a single place.
- Existing uppercase-named keys and free keys keep working on every filesystem, with no file mutation on lookup.

**Non-Goals:**
- Bulk renaming or migration of existing uppercase files (can be a later opt-in command).
- Other spellings than all-lowercase and all-uppercase.
- Any change to in-memory keystores.

## Decisions

**1. Two spellings in the path layer: lowercase canonical, uppercase fallback.**
`_get_filepath()` keeps building the *canonical* (lowercase) path, used for all writes. A new resolver (`_find_existing_filepath()`) returns the canonical path if it exists, else the uppercase path if it exists, else the canonical path. `_public_key_exists`, `_private_key_exists`, `_get_public_key`, `_get_private_key` and the listing's private key presence go through it. Public and private halves are resolved independently, so a keypair renamed by hand in only one half still loads. Alternatives: renaming existing files when the keystore is opened (needs write access, so impossible for read-only authenticators, racy since the keystore documents it isn't multiprocess-safe, and conflicts need destructive resolution), or a case-insensitive directory scan (a `listdir` per access, and it would match unrelated mixed-case names).

**2. No shadowing on write.**
Because existence checks see uppercase files, `set_public_key`/`set_private_key` raise `KeyAlreadyExists` for an existing uppercase keypair instead of creating a lowercase twin, and the autogenerating paths find the key and don't generate.

**3. Conflict policy: lowercase wins, with a warning.**
Lowercase is the canonical name and the newest writer. The warning names the ignored uppercase file so users can clean up. The warning is only logged when `exists()` is true for both spellings *and* they are not the same file (`Path.samefile`), so case-insensitive filesystems don't warn spuriously. Alternative: raise, rejected since it would lock out keystores that can only be repaired by hand.

**4. Free keys: same two-spelling logic on the subdirectory.**
`_get_free_keypairs_count()` sums both subdirectories (once if they are the same directory). `_attach_free_keypair_to_uuid()` takes from the lowercase subdirectory first, then the uppercase one, and moves the pair to the canonical (lowercase) target path. `_add_free_keypair()` writes into the lowercase subdirectory.

**5. Listing uppercases and dedupes.**
`_list_unordered_keypair_identifiers()` uppercases the parsed algo, merges entries found under both spellings by `(keychain_uid, algo)`, and computes `private_key_present` with the resolver. Every listed identifier is thus fetchable, which fixes `check_authenticator()` and `export_to_keystore_tree()`, and exported trees pass `validate_keystore_tree()` (uppercase supported algos).

**6. Documentation.**
The CHANGELOG entry for #61/#64 is reworded (see proposal.md), including the downgrade caveat.

## Risks / Trade-offs

- [Newly written lowercase files are invisible to older library versions on case-sensitive filesystems] → Documented in the CHANGELOG as unsupported for new keys. Existing uppercase files are untouched, so existing keys remain usable by old versions.
- [Extra `exists()` call on the lookup miss path] → Negligible; the lowercase hit path is the common one for new keys, and the miss path only costs one more stat.
- [Case-insensitive filesystems: both spellings are the same file] → The canonical path hits first, `samefile` suppresses the conflict warning, and listing dedupes by `(uid, algo)`.
- [A keystore ends up with both spellings over time] → Accepted: behaviour is identical, and an opt-in migration can unify them later.

## Migration Plan

No data migration. Releasing the code makes existing keystores keep working, and new keys use lowercase file names. Rollback is reverting the code: files written meanwhile under lowercase names would then need renaming to uppercase by hand.
