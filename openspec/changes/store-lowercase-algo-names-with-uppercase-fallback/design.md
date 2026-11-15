## Context

See proposal.md - Why. Public keystore methods uppercase `key_algo` before calling the storage hooks (`_public_key_exists`, `_get_public_key`, `_add_free_keypair`, `_attach_free_keypair_to_uuid`...). `ReadonlyFilesystemKeystore` builds `<keychain_uid>_<key_algo>_{public,private}_key.pem` from that name, and free keys live in `free_keys/<key_algo>/<random>_{public,private}_key.pem`. `_list_unordered_keypair_identifiers()` returns the algo as written in the file name. `TrusteeApi._ensure_keypair_exists()` generates a keypair whenever `_private_key_exists()` is false, which is how an unfound key gets shadowed. `ReadonlyFilesystemKeystore` serves imported authenticators, which must never be modified.

## Goals / Non-Goals

**Goals:**
- Decouple the on-disk spelling (lowercase) from the API spelling (uppercase), in a single place (`_get_disk_algo_names()`).
- Existing keys and free keys with legacy uppercase algo names keep working on every filesystem, with no file mutation on lookup.

**Non-Goals:**
- Bulk renaming or migration of existing uppercase files (can be a later opt-in command).
- Other spellings than all-lowercase and all-uppercase.
- Any change to in-memory keystores.

## Decisions

**1. Two spellings in the path layer, resolved per keypair: lowercase canonical, legacy uppercase.**
`_get_disk_algo_names()` is the only place deciding the (canonical lowercase, legacy uppercase) spellings. `_get_key_filepath()` builds a key file path for an algo name already spelled as on disk, and `_get_canonical_key_filepath()` the lowercase one. The resolver `_resolve_keypair_files()` stats the public and private files under both spellings, and returns both paths and existence flags with a *single* spelling: the legacy one if it holds the keypair's files, else the canonical one. `_public_key_exists`, `_private_key_exists`, `_get_public_key`, `_get_private_key`, the listing's private key presence, `_set_public_key`, `_set_private_key` and the target of `_attach_free_keypair_to_uuid` all go through it, so a keypair is never split between spellings (e.g. a private key set for a legacy public key gets the legacy name too). Alternatives: renaming existing files when the keystore is opened (needs write access, so impossible for read-only authenticators, racy since the keystore documents it isn't multiprocess-safe, and conflicts need destructive resolution), or a case-insensitive directory scan (a `listdir` per access, and it would match unrelated mixed-case names).

**2. No shadowing on write.**
Because existence checks see uppercase files, `set_public_key`/`set_private_key` raise `KeyAlreadyExists` for an existing uppercase keypair instead of creating a lowercase twin, and the autogenerating paths find the key and don't generate.

**3. Conflict policy: fail outright.**
If distinct files of a keypair exist under both spellings (both versions of a key, or its halves under different spellings), the keystore can't tell which ones are authoritative: a "lowercase wins" rule could pair a public key with an unrelated private key, or silently hide the key actually used by older versions. So every operation resolving this keypair raises `KeyFilenameConflict`, naming the keys directory and the files, which the user must fix by hand. It is a plain `FunctionalError`, NOT a `KeyDoesNotExist`, so that autogenerating paths (`TrusteeApi._ensure_keypair_exists()`) propagate it instead of generating a keypair; being a `FunctionalError` subclass, it gets a JSON-RPC error slug automatically. Files are "distinct" unless their stats designate the same file (`os.path.samestat`), so case-insensitive filesystems, where both names alias a single file, never conflict. Alternative: lowercase wins with a warning, rejected for the reasons above.

**4. Free keys: same two-spelling logic on the subdirectory.**
`_get_free_keypairs_count()` sums both subdirectories (once if they are the same directory). `_attach_free_keypair_to_uuid()` takes from the lowercase subdirectory first, then the uppercase one, and moves the pair to the paths given by the resolver (lowercase for a new keypair). `_add_free_keypair()` writes into the lowercase subdirectory.

**5. Listing uppercases and dedupes.**
`_list_unordered_keypair_identifiers()` uppercases the parsed algo, merges entries found under both spellings by `(keychain_uid, algo)`, and computes `private_key_present` with the resolver, called with the keychain uid as spelled in the file name so that non-canonical spellings (e.g. a UUID without dashes) find their sibling private key. Files with a mixed-case algo name are skipped with a warning, since the getters (which only try the two spellings) couldn't fetch them; a conflicting keypair makes the listing raise, like the getters. Every listed identifier is thus fetchable, which fixes `check_authenticator()` and `export_to_keystore_tree()`, and exported trees pass `validate_keystore_tree()` (uppercase supported algos).

**6. Documentation.**
The CHANGELOG entry for #61/#64 is reworded (see proposal.md), including the downgrade caveat.

## Risks / Trade-offs

- [Newly written lowercase files are invisible to older library versions on case-sensitive filesystems] → Documented in the CHANGELOG as unsupported for new keys. Existing uppercase files are untouched, so existing keys remain usable by old versions.
- [Each resolution stats 4 paths (public and private, both spellings), and the listing resolves each keypair] → Negligible next to key file reads and cryptographic operations; this is the price of detecting conflicts and keeping keypairs on a single spelling.
- [Case-insensitive filesystems: both spellings are the same file] → `os.path.samestat` recognizes the alias, so there is no conflict, and listing dedupes by `(uid, algo)`.
- [A keystore ends up with different keypairs under different spellings over time] → Accepted: behaviour is identical, and an opt-in migration can unify them later.
- [A keystore ends up with a same keypair under both spellings (manual copy, older version writing next to a newer one)] → Operations on this keypair fail with `KeyFilenameConflict` until fixed by hand, rather than guessing.

## Migration Plan

No data migration. Releasing the code makes existing keystores keep working, and new keys use lowercase file names. Rollback is reverting the code: files written meanwhile under lowercase names would then need renaming to uppercase by hand.
