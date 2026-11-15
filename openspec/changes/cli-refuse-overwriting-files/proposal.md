## Why

The `flightbox` CLI overwrites existing files silently. `encrypt` replaces a same-named cryptainer (and its offloaded `.payload`) in the cryptainer storage. `cryptainer decrypt` and `cryptoconf generate-simple -o` truncate their output file. The riskiest case is `decrypt` without `-o`: it writes the cryptainer name minus `.crypt` into the current directory, so running it next to the original media file replaces that file with no prompt. A tool that handles sensitive media should not destroy data by default.

Decision: the CLI **never overwrites a file by default**. It raises an error naming the blocking file, and a per-command `--force` flag (long form only) allows silent overwriting. Target **directories** can never be overwritten, and no flag exists for them: the user must remove the directory manually first.

## What Changes

- **BREAKING**: `encrypt` fails if `<basename>.crypt` or its offloaded `<basename>.crypt.payload` already exists in the cryptainer storage. `encrypt --force` overwrites them.
- **BREAKING**: `cryptainer decrypt` fails if its output file (from `-o`, or the default name derived from the cryptainer name) already exists. `cryptainer decrypt --force` overwrites it. Writing to STDOUT (`-o -`) is unaffected.
- **BREAKING**: `cryptoconf generate-simple -o FILE` fails if `FILE` already exists. `cryptoconf generate-simple --force -o FILE` overwrites it. The default STDOUT output is unaffected.
- **BREAKING**: the `-f` short option is removed from the whole CLI, because it is ambiguous (`--format` or `--force`?). `--format` (on `authenticator view`, `foreign-keystore list/view` and `cryptainer list`) is only available in its long form, and `--force` gets no short alias. No other short option may reuse `-f`.
- The existence check runs early, before passphrase prompts, encryption, decryption or remote trustee calls, so the user doesn't lose that work. The error message names the blocking path and points to `--force`.
- `authenticator create DIR` gets no `--force`. It keeps refusing an existing directory and now also refuses an existing *file* at that path with the same clean usage error, before the passphrase prompt (today that case reaches `mkdir` and crashes with a `FileExistsError` traceback).
- Output paths that point to an existing directory are rejected even with `--force` (for example `decrypt -o some_dir/`).
- The Sphinx CLI tutorial runs these commands live at build time. The docs build now removes the files they generate beforehand, so rebuilds keep working.
- CHANGELOG entry (BREAKING) and CLI tests for both the default and the `--force` behaviour.

## Capabilities

### New Capabilities
- `cli-overwrite-protection`: how `flightbox` commands handle output files and directories that already exist: refusal by default, the long-only `--force` opt-in for files, the absence of any `-f` short option, and no override for directories.

### Modified Capabilities

(none: no existing spec covers the CLI)

## Impact

- Code: `src/wacryptolib/cli.py` (`encrypt`, `cryptainer decrypt`, `cryptoconf generate-simple`, `authenticator create`), possibly `src/wacryptolib/operations.py` (`_check_target_authenticator_parameters_validity`), `tests/test_wacryptolib_cli.py`, `docs/conf.py`, `CHANGELOG`.
- **Compatibility:** scripts that re-run `encrypt` with the same basename, or `decrypt` to an existing file, now fail with a usage error until they add `--force`. Scripts using `-f json` must switch to `--format json`. The Python library API (`CryptainerStorage`, `dump_cryptainer_to_filesystem`...) is unchanged and keeps overwriting.
- Non-goals: `foreign-keystore import` (it merges into the internal keystore pool and reports "updated" keystores by design), the internal app directories auto-created under `~/.witnessangel`, `cryptainer purge`/`delete` (explicit deletions), and the background `enqueue_file_for_encryption()` library path.
