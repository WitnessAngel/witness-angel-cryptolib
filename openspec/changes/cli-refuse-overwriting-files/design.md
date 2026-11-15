## Context

All the commands involved live in `src/wacryptolib/cli.py` (the `flightbox` entry point). Today they write files as follows:

- `encrypt` builds `<basename>.crypt` in the cryptainer storage and calls `CryptainerStorage.encrypt_file()`. That path either streams the payload (offloaded `<basename>.crypt.payload` opened with `"wb"`, by `CryptainerEncryptionPipeline`) or dumps the whole cryptainer at once (`dump_cryptainer_to_filesystem()`, "overwriting it if existing"). The CLI never sees the file handles.
- `cryptainer decrypt` takes `-o` as `click.File("wb")`, which click opens lazily. Without `-o`, it builds a `LazyFile(<name minus .crypt>, "wb")` in the current directory. The file is only opened at `with output_file:`, after decryption.
- `cryptoconf generate-simple` is a chained group whose `-o` (`click.File("w")`, default `-`) is consumed by the `result_callback`, after all subcommands have run.
- `authenticator create` calls `_check_target_authenticator_parameters_validity()` (`operations.py`) before the passphrase prompt. That check only tests `is_dir()`, so an existing regular file slips through until `mkdir()` raises `FileExistsError`.

Click 8.3's `LazyFile` passes the mode through to `open()` and turns any `OSError` into `click.FileError` when it opens, so lazy exclusive creation (`"xb"`) is available for free.

## Goals / Non-Goals

**Goals:**
- One shared helper and one error style for every refusal, so messages are consistent and tests can assert on them.
- Detect conflicts before passphrase prompts, payload reads, decryption or trustee calls (see specs: "The existence check happens before any costly or interactive step").
- Close the check-then-write race wherever the CLI owns the file handle.

**Non-Goals:**
- Changing the Python library's overwrite semantics (`CryptainerStorage`, `dump_cryptainer_to_filesystem`, the encryption pipeline). Library callers such as the Flightbox recorder rely on them.
- Atomic "write to temp then rename" outputs, interactive confirmation prompts, and backup files.

## Decisions

### D1. A shared CLI helper raising `click.UsageError`
Add `_ensure_paths_not_existing(paths, force)` to `cli.py`, which:
- rejects any path that is an existing directory, even with `force` ("... is a directory");
- otherwise, if `force` is false and the path exists (`os.path.lexists`, so dangling symlinks count too), raises `click.UsageError("Target file '<path>' already exists, use --force to overwrite it")`;
- ignores `-`.

It checks every path of the command before raising, and reports the first conflict found.

`UsageError` (exit code 2) matches what `authenticator create` already does for an existing directory. *Alternatives:* `click.FileError` (exit 1, "Could not open file") reads as an I/O failure rather than a refused operation. A custom exception type adds no value for CLI users.

### D2. A per-command, long-only `--force` flag, not a global one
Define a reusable `FORCE_OPTION = click.option("--force", is_flag=True, help="Overwrite existing target files")`, next to `FORMAT_OPTION`. Apply it to `encrypt`, `cryptainer decrypt` and the `cryptoconf generate-simple` group. There is deliberately no short alias (see D8). *Alternative:* a global `flightbox --force` would also cover read-only commands and directory targets, which the request explicitly excludes. The strict option positioning documented in the tutorial would also make it awkward to use.

### D3. `cryptainer decrypt`: early check, then exclusive creation
- Change `-o` to `click.Path(dir_okay=False, allow_dash=True, path_type=Path)`. Click then rejects an existing directory by itself, and no file is opened at parse time.
- Compute the output path (explicit, or the existing default derivation), call the helper, and only then build the keystore pool and load the cryptainer.
- After a successful decryption, write through `LazyFile(path, "wb" if force else "xb")`, or to the binary STDOUT for `-`. If another process creates the file between the check and the write, `"xb"` makes the command fail with click's `FileError` instead of overwriting it. The message is less friendly, but nothing is destroyed.

### D4. `encrypt`: early check on both cryptainer files, no library change
- Once `output_basename` is resolved and the storage directory is known, check `<dir>/<basename>.crypt` and `<dir>/<basename>.crypt.payload`. Build the names from `CRYPTAINER_SUFFIX` and `OFFLOADED_PAYLOAD_FILENAME_SUFFIX`, without reaching into private storage helpers. Both are checked even with `--bundle`: a stale payload file belongs to the same cryptainer name, and `cryptainer delete` would remove it together with the new bundled file.
- The check runs before the input file or STDIN is opened.
- With `--force`, nothing changes compared with today: the library overwrites. A stale `.payload` left next to a forced `--bundle` cryptainer is pre-existing behaviour and stays out of scope.
- *Alternative considered:* an `overwrite=False` parameter threaded through `CryptainerStorage.encrypt_file()`, the pipeline and `dump_cryptainer_to_filesystem()`, to get exclusive creation. That touches public library APIs and the streaming pipeline (which creates the `.crypt` file and the payload at different moments), only to close a race in a single-user CLI. It is rejected for now (see Risks).

### D5. `cryptoconf generate-simple`: check in the group callback
Change `-o` to `click.Path(dir_okay=False, allow_dash=True)` with default `-`. Add `force` to the group callback and to the `result_callback` signature. The group callback runs the helper before any chained subcommand. The `result_callback` writes with `click.open_file(path, "w" if force else "x")`, which handles `-` as STDOUT.

### D6. `authenticator create`: reject any existing path, still no override
In `_check_target_authenticator_parameters_validity()`, replace `is_dir()` with an existence test (`os.path.lexists`):
- an existing directory keeps today's message, "Target directory %s must not exist yet";
- an existing non-directory gets "Target path %s already exists and is not a directory, remove it first".

`operations.create_authenticator()` shares the check, so library callers also get a `ValidationError` instead of a raw `FileExistsError` in the file case, which is an improvement. No `--force` is added. `mkdir(parents=False)` already fails if the path appears in between.

### D7. Keep the docs build re-runnable
`sphinxcontrib.programoutput` runs `flightbox encrypt readme.rst` and `flightbox cryptainer decrypt readme.rst.crypt -o readme.rst.decrypted` at every build. They would now fail from the second build on. `docs/conf.py` already deletes `docs/mysphinxdocauthenticator` up front, and will also delete exactly the artifacts these commands produce: `docs/readme.rst.decrypted`, and `readme.rst.crypt` / `readme.rst.crypt.payload` in the default cryptainer storage. *Alternative:* add `--force` to the tutorial commands. That would show `--force` on the very first example, which is misleading for newcomers.

### D8. Drop the `-f` short option CLI-wide
`-f` reads as both `--format` and `--force`, so it is removed instead of being given two meanings. `FORMAT_OPTION` becomes `click.option("--format", ...)`, used by `authenticator view`, `foreign-keystore list/view` and `cryptainer list`. `FORCE_OPTION` has no short form. A test walks the whole click command tree and asserts that no parameter declares `-f`, so the letter can't come back unnoticed. Other short options (`-o`, `-c`, `-k`, `-g`) are unambiguous and stay. *Alternative:* keep `-f` for `--format` only. That was rejected because `-f` for "force" is a strong convention (`rm -f`, `cp -f`), and users of the writing commands would reach for it.

## Risks / Trade-offs

- [Check-then-write race in `encrypt`: another process could create the cryptainer between the check and the write, and it would be overwritten] → Accepted. The CLI is single-user, and storage names are chosen by the user. `decrypt` and `generate-simple` are protected by exclusive creation (D3, D5). If needed, D4's library alternative can be adopted later without changing the specs.
- [Breaking scripts that relied on silent overwriting] → BREAKING CHANGELOG entry. The error message tells the user to add `--force`.
- [Removing `-f` from `--format` breaks scripts and habits using `-f json`] → BREAKING CHANGELOG entry. Click's "No such option: -f" error is explicit, and the fix (`--format`) is obvious.
- [The docs build deletes files in the developer's default `~/.witnessangel/cryptainers`] → Only the exact names that the tutorial itself writes are removed.

## Migration Plan

No data migration. Users and scripts add `--force` where overwriting is intended, and replace `-f` with `--format`. Rolling back means reverting the CLI change; no on-disk format is affected.
