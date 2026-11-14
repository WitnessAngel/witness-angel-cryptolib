## Why

PRs #61 and #64 normalize algo names to uppercase in the `TrusteeApi` and keystore public methods, and pass that uppercase name straight to the filesystem layer. The on-disk file naming therefore depends on the case used by the API, and the two have drifted apart (issue #70): keys stored under another case than the one the code now asks for are not found on case-sensitive filesystems (Linux, Android...), the autogenerating paths (`fetch_public_key()` without `must_exist`, `get_message_signature()`) then **silently create new keypairs** that shadow the existing ones, and `list_keypair_identifiers()` reports algo names that the getters can't fetch, so `check_authenticator()` and `export_to_keystore_tree()` raise `KeyDoesNotExist`. macOS/Windows keystores keep working, so behaviour differs per platform.

Decision: the **API keeps uppercase algo names**, while filesystem keystores **write lowercase file names from now on** (decoupling the on-disk naming from the API's normalization), and keep **loading existing uppercase-named files** through a fallback.

## What Changes

- The filesystem keystore converts the algo name in one place, the path layer: new key files and free-key subdirectories are named with the **lowercase** algo (e.g. `<uid>_rsa_oaep_public_key.pem`, `free_keys/rsa_oaep/`).
- Lookups (existence checks, public/private key reads, free-keypair counting and attachment) try the lowercase name first, then the **uppercase** name used by existing keystores. The autogenerating paths therefore find existing keys instead of creating new ones. Files are never renamed or deleted by lookups, so read-only authenticator keystores stay untouched.
- If both spellings exist for the same keypair, the lowercase file wins and a warning names the ignored uppercase file.
- `list_keypair_identifiers()` returns **uppercase** `key_algo` values whatever the file spelling, lists a keypair present under both spellings once, and computes the private key presence with the same lookup. `check_authenticator()` and `export_to_keystore_tree()` then work on every keystore, and exported trees pass tree validation.
- Rewrite the CHANGELOG entry of #61/#64: existing keystores keep working, new keys are written with lowercase file names, API algo names are uppercase.
- Regression tests with keystore directories in both layouts (uppercase, as written by earlier releases, and lowercase), covering `fetch_public_key`, `get_message_signature`, decryption, free keypairs, listing, and tree export.

## Capabilities

### New Capabilities
- `keystore-algo-name-storage`: lowercase on-disk naming of keys in filesystem keystores, loading of uppercase-named files, and uppercase algo names in the API and in listings.

### Modified Capabilities

(none: no existing spec covers keystore storage)

## Impact

- Code: `src/wacryptolib/keystore.py` (`ReadonlyFilesystemKeystore` / `FilesystemKeystore`: path building and resolution, free keys, listing), tests in `tests/test_wacryptolib_keystore.py` and `tests/test_wacryptolib_trustee.py`, `CHANGELOG`.
- **Compatibility:** keystores written by this version on a case-sensitive filesystem hold lowercase-named files, which earlier releases (expecting uppercase) won't find. Opening a keystore with an older library after using it with this one is therefore not supported for newly created keys. No API signature or dependency change; in-memory keystores are unaffected.
- Non-goals: bulk renaming of existing uppercase files, and mixed-case spellings other than all-lowercase and all-uppercase.
