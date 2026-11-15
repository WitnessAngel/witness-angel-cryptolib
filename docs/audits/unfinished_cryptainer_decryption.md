# Decrypting unfinished cryptainers, and warning about their limitations

Date: 2026-11-15. Status: audit, no code changed.
Scope: how to decrypt "unfinished" cryptainers (state `STARTED`, left behind
when a recording stops before `finalize()`: crash, power loss, destroyed
device), and how to tell users what such a decryption can and cannot
guarantee. Tracks GitHub issue
[#45](https://github.com/WitnessAngel/witness-angel-cryptolib/issues/45)
("Handle unfinished cryptainers during decryption").

## Summary

- **Today, decrypting an unfinished cryptainer fails** with a
  `SchemaValidationError`. The strict validation done by `decrypt_payload()`
  rejects `payload_macs: None`, so the `FIXME` at
  `src/wacryptolib/cryptainer/_decryptor.py:498` is never reached.
- **The rest of the workflow already supports them.** Loading by name works,
  and `gather_decryptable_symkeys()` already accepts `STARTED` cryptainers
  (Revelation Station flow). Only the final local payload decryption is
  missing.
- **Recovery is technically easy.** The keys are complete and usable, and the
  available ciphertext is a valid prefix. Stream/AEAD layers (AES_EAX,
  CHACHA20_POLY1305) decrypt any prefix. AES_CBC layers must be cut to a
  16-byte boundary and decrypted **without** PKCS#7 unpadding.
- **What is lost matters more than how to recover.** An unfinished
  cryptainer has no MAC tags, no digests, no signatures and no timestamps,
  and its end is cut off by an unknown amount. Its recovered plaintext is
  **unauthenticated**, which is critical for evidence recordings.
- **Recommendation:** an explicit opt-in (`allow_unfinished=True` in the API,
  `--allow-unfinished` in the CLI), kept separate from
  `verify_integrity_tags`, with structured `OperationReport` warnings.

## 1. What an unfinished cryptainer is on disk

`CryptainerEncryptionPipeline`
(`src/wacryptolib/cryptainer/_encryption_pipeline.py`) dumps a "savegame"
when it starts. The real cryptainer is only written by `finalize()`:

```
   __init__ (dump_initial_cryptainer)      encrypt_chunk() x N             finalize()
  +-------------------------------+    +---------------------------+   +------------------------------+
  | foo.crypt~   (JSON)           |    | foo.crypt.payload         |   | foo.crypt (JSON, FINISHED)   |
  |  cryptainer_state = STARTED   |    |  ciphertext appended,     |   |  payload_macs = {tag: ...}   |
  |  payload_macs     = None      |    |  BUFFERED, never fsynced  |   |  digests + signatures        |
  |  signatures: confs only,      |    |                           |   | then unlink foo.crypt~       |
  |   no digest/signature values  |    |                           |   |                              |
  |  key_ciphertext: OK, usable   |    |                           |   |                              |
  +-------------------------------+    +---------------------------+   +------------------------------+
```

- `payload_macs` is set to `None` in `_generate_cryptainer_base_and_secrets()`
  (`_flightbox.py`). It is only filled, along with the plaintext and
  ciphertext digests and signatures, by `add_authentication_data_to_cryptainer()`
  (`_encryptor.py`), which also switches the state to `FINISHED`.
- The offloaded payload path drops the `~` suffix (`_get_offloaded_file_path()`
  in `_filesystem.py`), so `foo.crypt~` and `foo.crypt` share
  `foo.crypt.payload`.

## 2. Current behavior

```
 load_cryptainer_from_storage("foo.crypt~")     --> works (by name; an int index only sees FINISHED)
 gather_decryptable_symkeys(...)                --> works, STARTED already tolerated (_analysis.py)
 decrypt_payload(...)
   ensure_validated_cryptainer(strict)          --> SchemaValidationError ("payload_macs": None is not a dict)
   (the FIXME at _decryptor.py:498 is never reached)
```

- `ReadonlyCryptainerStorage.list_cryptainer_names()` excludes `*.crypt~`
  files by default (`finished=True`). An integer index passed to
  `load_cryptainer_from_storage()` therefore never reaches an unfinished
  cryptainer, but a name does. The docstring says "Only FINISHED cryptainers
  are expected to be loaded".
- `check_cryptainer_sanity(require_inline_payload=False)` accepts `STARTED`
  cryptainers (it replaces `payload_macs: None` by `{}` before validating), but
  the same flag also means "payload ciphertext may be absent or offloaded".
  Decryption needs "inline payload required" **and** "STARTED tolerated",
  which no current combination provides.
- The purge applies age, quota and count rules to unfinished cryptainers as
  well (`finished=None`).

## 3. What the truncated payload contains

A throwaway script built unfinished cryptainers with
`CryptainerEncryptionPipeline`. It encrypted 1037 bytes of plaintext
(`b"A"*1000 + b"B"*37`), flushed the payload file without finalizing, and
then decrypted truncated ciphertexts with `verify_integrity_tags=False`:

| Layer algo | Payload on disk | Decrypting a truncated prefix | Note |
|---|---|---|---|
| AES_CBC | 1024 bytes (13 bytes stuck in the CBC remainder buffer) | `Padding is incorrect`, or `Data must be padded to 16 byte boundary` | Finalize never padded, so unpadding is wrong here. There's also a ~1/256 chance that unpad "succeeds" and silently drops trailing bytes. |
| AES_EAX | 1037 bytes | OK, plaintext prefix is correct | `check_cipherdict_sanity()` requires a `tag` key, so it needs a bypass |
| CHACHA20_POLY1305 | 1037 bytes | OK, plaintext prefix is correct | Same as AES_EAX |
| AES_CBC then CHACHA20_POLY1305 | 1024 bytes | The outer layer gives the inner CBC layer an arbitrary length | Every CBC layer must round down to 16 bytes and skip unpadding |

All four unfinished cryptainers were rejected by `decrypt_payload()` with
the `SchemaValidationError` described in section 2.

### Best-effort decryption algorithm

Peel the layers from outermost to innermost:

- **Stream/AEAD layers (AES_EAX, CHACHA20_POLY1305):** decrypt the available
  ciphertext without verifying any tag.
- **AES_CBC layers:** cut the input to `len // 16 * 16` bytes, decrypt in raw
  mode, and don't unpad.

### Where bytes get lost

From earliest to latest:

```
 plaintext stream  ====================================================X  (crash)
                                                                    |
 lost: CBC remainder (<16 B per CBC layer) -------------------------+
 lost: Python BufferedWriter (up to ~8 KB, encrypt_chunk never flushes)
 lost: OS page cache (no fsync) -> on power cut, possibly MUCH more
 risk: FAT/exFAT SD cards can keep the file length but zero-filled blocks
       -> garbage tail that NOTHING can detect (no MAC)
```

## 4. Limitations to warn users about

From most to least serious:

1. **No authenticity at all.** Without their tag, AES_EAX and
   CHACHA20_POLY1305 are malleable: flipping a bit in the ciphertext flips the
   same plaintext bit, and nothing detects it. Anyone with write access to
   the payload file can alter the recovered content. For a product whose
   purpose is evidence, this is the main warning.
2. **No signatures and no timestamps**, so there is no proof of when or by
   whom the content was recorded. Both are written only by
   `add_authentication_data_to_cryptainer()`.
3. **The end is cut off** by an unknown amount. The original length can't be
   known.
4. **The tail may be corrupted** (zero-filled blocks after a power cut)
   without any way to detect it.
5. **Media may not play.** For example, an MP4 whose `moov` atom was never
   written won't open without repair. That's outside the cryptolib, but
   worth saying in the user documentation.

## 5. API design options

```
 (A) automatic                     (B) explicit opt-in               (C) separate entrypoint
 decrypt_payload(c)                decrypt_payload(c,                recover_unfinished_payload(c)
  STARTED? -> best effort             allow_unfinished=True)          -> PartialPayload(data,
  + WARNING entries                default: clear error               authenticated=False,
                                    "cryptainer is unfinished,         truncated=True, ...)
                                     pass allow_unfinished=True"
 risk: callers that only check     the caller has to say it          cleanest semantics, but
 "payload is not None" silently    knows; the report says what       duplicates the layer loop
 get unauthenticated data          was skipped
```

Recommendation: **(B)**, with these details.

- **Keep it separate from `verify_integrity_tags=False`.** That flag means
  "ignore tags that don't match" (a forensic tool). Here the tags don't exist
  at all. Merging the two would blur both meanings.
- **Report entries.** Add one top-level entry for the cryptainer
  ("UNFINISHED cryptainer: no integrity tags, no signatures, payload possibly
  truncated"), plus one per layer ("integrity check skipped: no MAC",
  "AES_CBC: N trailing bytes discarded, no unpadding").
- **Severity.** `DecryptionErrorCriticity.WARNING` already exists. The open
  question is whether to add an `entry_type` (for example `INTEGRITY_WARNING`)
  to `OPERATION_REPORT_ENTRY_SCHEMA`, since report consumers (Revelation
  Station GUI) would see it.
- **Validation.** Split the `require_inline_payload` flag of
  `check_cryptainer_sanity()` and `ensure_validated_cryptainer()` into two
  independent flags: "payload must be inline" and "STARTED is tolerated".
- **Storage.** `decrypt_cryptainer_from_storage()` passes the opt-in through.
  Update the `load_cryptainer_from_storage()` docstring, and decide whether
  integer indexes should be able to reach unfinished cryptainers.
- **CLI.** `cryptainer decrypt` refuses `STARTED` cryptainers unless
  `--allow-unfinished` is given, prints a visible banner, and maybe writes
  `foo.partial.ext`. This overlaps with the pending
  `cli-refuse-overwriting-files` change, because `foo.crypt~` currently gets
  the output name `foo.crypt~.decrypted`.

## 6. Related problems found during the audit

- **Crash between the final dump and the unlinking of `foo.crypt~`.** In that
  window both `foo.crypt` and `foo.crypt~` exist and share **the same**
  `foo.crypt.payload` file (`_get_offloaded_file_path()` strips the `~`).
  Deleting or purging the stale `foo.crypt~` (via
  `delete_cryptainer_from_filesystem()`) also deletes the payload of the
  finished cryptainer. This looks like a real data-loss bug.
- **Crash after the payload was finalized but before the final JSON dump.**
  The payload is then complete and padded, but the only JSON says `STARTED`.
  Raw CBC decryption would leave 1 to 16 padding bytes at the end. That's
  minor, but the report should say that trailing bytes may include padding.
- **Writer resilience.** Flushing the payload file after each chunk and
  calling `fsync` from time to time would recover much more data after a
  power cut. That is an encryption-side change, probably its own change.
- **Verifiable partial recordings (long term).** Authenticating partial
  recordings needs a format change: segmented AEAD (an age/STREAM-style
  construction with one tag per chunk) or periodic signed checkpoints of
  the ciphertext digest. That is out of scope for #45. The C flightbox design
  (`openspec/changes/add-c-flightbox-encryptor/design.md`) lists the `STARTED`
  savegame (specification section 7.2) as optional, so the same decryption
  path would apply to C devices that emit it later.

## 7. Open questions

- **Callers:** who decrypts unfinished cryptainers: the Revelation Station,
  the CLI, or both? That decides how much the warnings rely on the
  `OperationReport` versus on the return value.
- **Opt-in:** explicit opt-in (B), or automatic recovery (A), given that a
  crashed recording is exactly the evidence someone wants back?
- **Bundling:** should the shared-payload deletion bug and the writer
  flush/fsync be part of the change for #45, or separate changes?
