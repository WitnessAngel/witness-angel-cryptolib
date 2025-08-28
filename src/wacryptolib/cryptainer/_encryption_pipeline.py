# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from pathlib import Path

from typing import Optional

from wacryptolib.cryptainer import CRYPTAINER_TEMP_SUFFIX, CryptainerEncryptor, OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER, \
    dump_cryptainer_to_filesystem, logger
from wacryptolib.cryptainer import _get_offloaded_file_path
from wacryptolib.keystore import KeystorePoolBase


class CryptainerEncryptionPipeline:  # Fixme normalize to CryptainerEncryptionStream and expose File write/close API?
    """
    Helper which prebuilds a cryptainer without signatures nor payload,
    fills its OFFLOADED ciphertext file chunk by chunk, and then
    dumps the final cryptainer (with signatures) to disk.
    """

    def __init__(
        self,
        cryptainer_filepath: Path,
        *,
        cryptoconf: dict,
        cryptainer_metadata: Optional[dict],
        signature_policy: Optional[str],
        keystore_pool: Optional[KeystorePoolBase] = None,
        dump_initial_cryptainer=True,
    ):
        self._cryptainer_filepath = cryptainer_filepath
        self._cryptainer_filepath_temp = cryptainer_filepath.with_suffix(
            cryptainer_filepath.suffix + CRYPTAINER_TEMP_SUFFIX
        )

        offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
        self._output_data_stream = open(offloaded_file_path, mode="wb")

        try:
            self._cryptainer_encryptor = CryptainerEncryptor(
                signature_policy=signature_policy, keystore_pool=keystore_pool
            )

            (
                self._wip_cryptainer,
                self._encryption_pipeline,
            ) = self._cryptainer_encryptor.build_cryptainer_and_encryption_pipeline(
                output_stream=self._output_data_stream,
                cryptoconf=cryptoconf,
                cryptainer_metadata=cryptainer_metadata,
            )
            self._wip_cryptainer["payload_ciphertext_struct"] = OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER  # Important

            if dump_initial_cryptainer:  # Savegame in case the stream is broken before finalization
                self._dump_current_cryptainer_to_filesystem(is_temporary=True)
        except Exception:  # FIXME TEST THIS CASE OF SELF-CLEANUP
            self._output_data_stream.close()  # Avoid leak of open file
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

    def encrypt_chunk(self, chunk: bytes):
        self._encryption_pipeline.encrypt_chunk(chunk)

    def finalize(self):
        self._encryption_pipeline.finalize()  # Would raise if statemachine incoherence
        self._output_data_stream.close()  # Important

        payload_integrity_tags = self._encryption_pipeline.get_payload_integrity_tags()

        self._cryptainer_encryptor.add_authentication_data_to_cryptainer(self._wip_cryptainer, payload_integrity_tags)
        self._dump_current_cryptainer_to_filesystem(is_temporary=False)

    def __del__(self):
        # Emergency closing of open file on deletion
        if not self._output_data_stream.closed:
            logger.error(
                "Encountered abnormal open file in __del__ of CryptainerEncryptionPipeline: %s"
                % self._output_data_stream
            )
            self._output_data_stream.close()

