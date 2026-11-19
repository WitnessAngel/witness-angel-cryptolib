# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from contextlib import suppress
from pathlib import Path

from typing import Optional

from wacryptolib.cryptainer import CRYPTAINER_TEMP_SUFFIX, CryptainerEncryptor, OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER, \
    dump_cryptainer_to_filesystem, logger, _get_offloaded_file_path, KEY_CIPHERTEXT_FORMAT_JSON, KEY_CIPHERTEXT_FORMATS
from wacryptolib.cryptainer._filesystem import _get_written_cryptainer_file_format
from wacryptolib.exceptions import EncryptionError
from wacryptolib.keystore import KeystorePoolBase
from wacryptolib.utilities import dump_to_document_bytes


class CryptainerEncryptionPipeline:  # Fixme normalize to CryptainerEncryptionStream and expose File write/close API?
    """
    Helper which prebuilds a cryptainer without signatures nor payload,
    fills its OFFLOADED ciphertext file chunk by chunk, and then
    dumps the final cryptainer (with signatures) to disk.

    No file is created nor modified if the inputs are rejected, or if the cryptainer can't be built.

    A failure of `encrypt_chunk()` or `finalize()` puts the pipeline in a failed state, where every further call
    raises an EncryptionError, so that no finished cryptainer gets written over a partial payload. The payload file
    is then closed, and deleted; unless an initial cryptainer was dumped, in which case both are kept as they would
    be after a crash of the process, for a potential recovery of the data already recorded.

    :param key_ciphertext_format: document format ("json" or "cbor") of the structures serialized then encrypted
        into the key ciphertexts, independent of the format of the cryptainer file
    """

    _output_data_stream = None  # So that __del__() works even when __init__() failed early
    _has_initial_cryptainer = False
    _is_finalized = False
    _is_failed = False

    def __init__(
        self,
        cryptainer_filepath: Path,
        *,
        cryptoconf: dict,
        cryptainer_metadata: Optional[dict],
        signature_policy: Optional[str],
        keystore_pool: Optional[KeystorePoolBase] = None,
        dump_initial_cryptainer=True,
        key_ciphertext_format: str = KEY_CIPHERTEXT_FORMAT_JSON,
    ):
        if key_ciphertext_format not in KEY_CIPHERTEXT_FORMATS:  # Before the payload file gets created
            raise ValueError("Unknown key ciphertext format %r" % (key_ciphertext_format,))
        if cryptainer_filepath.name.endswith(CRYPTAINER_TEMP_SUFFIX):
            # Else its payload file would be the one of the cryptainer named without this suffix
            raise ValueError(
                "Cryptainer filename %r must not end with the temporary suffix %r"
                % (cryptainer_filepath.name, CRYPTAINER_TEMP_SUFFIX)
            )
        self._cryptainer_filepath = cryptainer_filepath
        self._cryptainer_filepath_temp = cryptainer_filepath.with_name(  # Final filename + "~", in any format
            cryptainer_filepath.name + CRYPTAINER_TEMP_SUFFIX
        )
        self._offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)

        # Everything which may reject the inputs happens BEFORE any file is created or truncated, since the
        # target files might be those of an existing cryptainer

        self._cryptainer_encryptor = CryptainerEncryptor(
            signature_policy=signature_policy,
            keystore_pool=keystore_pool,
            key_ciphertext_format=key_ciphertext_format,
        )

        (
            self._wip_cryptainer,
            self._encryption_pipeline,
        ) = self._cryptainer_encryptor.build_cryptainer_and_encryption_pipeline(
            output_stream=None,  # Provided below
            cryptoconf=cryptoconf,
            cryptainer_metadata=cryptainer_metadata,
        )
        self._wip_cryptainer["payload_ciphertext_struct"] = OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER  # Important

        # Dry run, else a cryptainer unfit for its file format would only fail after the whole payload was streamed
        dump_to_document_bytes(self._wip_cryptainer, format=_get_written_cryptainer_file_format(cryptainer_filepath))

        self._output_data_stream = open(self._offloaded_file_path, mode="wb")  # Leaves existing file as is on failure

        try:
            self._encryption_pipeline.set_output_stream(self._output_data_stream)
            if dump_initial_cryptainer:  # Savegame in case the stream is broken before finalization
                self._dump_current_cryptainer_to_filesystem(is_temporary=True)  # Leaves no partial file on failure
                self._has_initial_cryptainer = True
        except BaseException:
            self._abort()  # Else leak of open file, and orphan payload (since storage only lists cryptainer files)
            raise

    def _dump_current_cryptainer_to_filesystem(self, is_temporary):
        filepath = self._cryptainer_filepath_temp if is_temporary else self._cryptainer_filepath
        dump_cryptainer_to_filesystem(
            filepath, cryptainer=self._wip_cryptainer, offload_payload_ciphertext=False
        )  # Payload is ALREADY offloaded separately
        if not is_temporary:  # Cleanup temporary cryptainer
            try:
                self._cryptainer_filepath_temp.unlink()  # TODO use missing_ok=True later with python3.8
            except FileNotFoundError:
                pass

    def _abort(self):
        """Switch to the failed state, close the payload file, and delete it unless an initial cryptainer
        was dumped (both being then kept for recovery)."""
        self._is_failed = True
        with suppress(OSError):  # A cleanup failure must not replace the original error
            self._output_data_stream.close()
        if not self._has_initial_cryptainer:
            with suppress(OSError):
                self._offloaded_file_path.unlink(missing_ok=True)

    def _ensure_still_open(self):
        if self._is_failed:
            raise EncryptionError(
                "Cryptainer encryption pipeline for %s has failed, it can't be used anymore"
                % self._cryptainer_filepath.name
            )
        if self._is_finalized:
            raise EncryptionError(
                "Cryptainer encryption pipeline for %s is already finalized" % self._cryptainer_filepath.name
            )

    def encrypt_chunk(self, chunk: bytes):
        self._ensure_still_open()
        try:
            self._encryption_pipeline.encrypt_chunk(chunk)
        except BaseException:
            self._abort()
            raise

    def finalize(self):
        self._ensure_still_open()
        try:
            self._encryption_pipeline.finalize()
            self._output_data_stream.close()  # Important

            payload_integrity_tags = self._encryption_pipeline.get_payload_integrity_tags()

            self._cryptainer_encryptor.add_authentication_data_to_cryptainer(
                self._wip_cryptainer, payload_integrity_tags
            )
            self._dump_current_cryptainer_to_filesystem(is_temporary=False)  # Leaves no partial file on failure
        except BaseException:
            self._abort()
            raise
        self._is_finalized = True

    def abort(self):
        """Give up an encryption which can't be completed (e.g. its payload source is broken), as if a chunk
        had failed. No-op if the pipeline is already finalized or failed."""
        if not (self._is_finalized or self._is_failed):
            self._abort()

    def __del__(self):
        # Emergency closing of open file on deletion
        if self._output_data_stream is not None and not self._output_data_stream.closed:
            logger.error(
                "Encountered abnormal open file in __del__ of CryptainerEncryptionPipeline: %s"
                % self._output_data_stream
            )
            self._output_data_stream.close()

