# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Optional, BinaryIO, Union
from urllib.parse import urlparse
import uuid

from wacryptolib.cryptainer import SHARED_SECRET_ALGO_MARKER, DEFAULT_DATA_CHUNK_SIZE, CryptainerEncryptionPipeline, \
    CryptainerEncryptor, CryptainerDecryptor, CRYPTAINER_TRUSTEE_TYPES
from wacryptolib.keygen import SUPPORTED_SYMMETRIC_KEY_ALGOS, SUPPORTED_ASYMMETRIC_KEY_ALGOS
from wacryptolib.keystore import KeystorePoolBase
from wacryptolib.utilities import consume_bytes_as_chunks


def encrypt_payload_and_stream_cryptainer_to_filesystem(
    payload: Union[bytes, BinaryIO],
    *,
    cryptainer_filepath,
    cryptoconf: dict,
    cryptainer_metadata: Optional[dict],
    keystore_pool: Optional[KeystorePoolBase] = None,
    signature_policy=None,
) -> None:
    """
    Optimized version which directly streams encrypted payload to **offloaded** file,
    instead of creating a whole cryptainer and then dumping it to disk.

    The cryptoconf used must be streamable with an EncryptionPipeline!
    """
    # No need to dump initial (signature-less) cryptainer here, this is all a quick operation...
    encryptor = CryptainerEncryptionPipeline(
        cryptainer_filepath,
        cryptoconf=cryptoconf,
        cryptainer_metadata=cryptainer_metadata,
        signature_policy=signature_policy,
        keystore_pool=keystore_pool,
        dump_initial_cryptainer=False,
    )

    for chunk in consume_bytes_as_chunks(payload, chunk_size=DEFAULT_DATA_CHUNK_SIZE):
        encryptor.encrypt_chunk(chunk)

    encryptor.finalize()  # Handles the dumping to disk


def encrypt_payload_into_cryptainer(
    payload: Union[bytes, BinaryIO],
    *,
    cryptoconf: dict,
    cryptainer_metadata: Optional[dict],
    signature_policy: Optional[str] = None,
    keystore_pool: Optional[KeystorePoolBase] = None,
) -> dict:
    """Turn a raw payload into a secure cryptainer, which can only be decrypted with
    the agreement of the owner and third-party trustees.

    :param payload: bytestring of media (image, video, sound...) or readable file object (file immediately deleted then)
    :param cryptoconf: tree of specific encryption settings
    :param cryptainer_metadata: dict of metadata describing the payload (remains unencrypted in cryptainer)
    :param keystore_pool: optional key storage pool, might be required by cryptoconf
    :return: dict of cryptainer
    """
    cryptainer_encryptor = CryptainerEncryptor(signature_policy=signature_policy, keystore_pool=keystore_pool)
    cryptainer = cryptainer_encryptor.encrypt_data(
        payload, cryptoconf=cryptoconf, cryptainer_metadata=cryptainer_metadata
    )
    return cryptainer


def decrypt_payload_from_cryptainer(
    cryptainer: dict,
    *,
    keystore_pool: Optional[KeystorePoolBase] = None,
    passphrase_mapper: Optional[dict] = None,
    verify_integrity_tags: bool = True,
    gateway_urls: Optional[list] = None,
    revelation_requestor_uid: Optional[uuid.UUID] = None,
) -> tuple:
    """Decrypt a cryptainer with the help of third-parties.

    :param cryptainer: the cryptainer tree, which holds all information about involved keys
    :param keystore_pool: optional key storage pool
    :param passphrase_mapper: optional dict mapping trustee IDs to their lists of passphrases
    :param verify_integrity_tags: whether to check MAC tags of the ciphertext

    :return: tuple (data)
    """
    cryptainer_decryptor = CryptainerDecryptor(keystore_pool=keystore_pool, passphrase_mapper=passphrase_mapper)
    data, operation_report = cryptainer_decryptor.decrypt_payload(
        cryptainer=cryptainer,
        verify_integrity_tags=verify_integrity_tags,
        gateway_urls=gateway_urls,
        revelation_requestor_uid=revelation_requestor_uid,
    )
    return data, operation_report


def extract_metadata_from_cryptainer(cryptainer: dict) -> Optional[dict]:
    """Read the metadata tree (possibly None) from a cryptainer.

    CURRENTLY CRYPTAINER METADATA ARE NEITHER ENCRYPTED NOR AUTHENTIFIED.

    :param cryptainer: the cryptainer tree, which also holds cryptainer_metadata about encrypted content

    :return: dict
    """
    reader = CryptainerDecryptor()
    cryptainer_metadata = reader.extract_cryptainer_metadata(cryptainer)
    return cryptainer_metadata


def get_cryptoconf_summary(cryptoconf_or_cryptainer):
    """
    Returns a string summary of the layers of encryption/signature of a cryptainer or a configuration tree.
    """
    indent = "  "

    text_lines = []

    def _get_signature_description(_payload_signature):
        payload_signature_trustee = payload_signature["payload_signature_trustee"]
        trustee_id = _get_trustee_displayable_identifier(payload_signature_trustee)
        return "%s/%s via trustee '%s'" % (
            payload_signature["payload_digest_algo"],
            payload_signature["payload_signature_algo"],
            trustee_id,
        )

    def _get_trustee_displayable_identifier(_trustee_conf):
        trustee_type = _trustee_conf.get("trustee_type", None)
        if trustee_type == CRYPTAINER_TRUSTEE_TYPES.LOCAL_KEYFACTORY_TRUSTEE:
            trustee_display = "local device"
        elif trustee_type == CRYPTAINER_TRUSTEE_TYPES.AUTHENTICATOR_TRUSTEE:
            trustee_display = "authenticator %s" % _trustee_conf["keystore_uid"]
        elif trustee_type == CRYPTAINER_TRUSTEE_TYPES.JSONRPC_API_TRUSTEE:
            trustee_display = "server %s" % urlparse(_trustee_conf["jsonrpc_url"]).netloc
        else:
            raise ValueError("Unrecognized key trustee %s for display" % str(_trustee_conf))
        return trustee_display

    def _get_key_encryption_layer_description(key_cipher_layer, current_level):
        key_cipher_algo = key_cipher_layer["key_cipher_algo"]

        if key_cipher_algo == SHARED_SECRET_ALGO_MARKER:
            text_lines.append(
                current_level * indent
                + "Shared secret with threshold %d:" % key_cipher_layer["key_shared_secret_threshold"]
            )
            shard_confs = key_cipher_layer["key_shared_secret_shards"]
            for shard_idx, shard_conf in enumerate(shard_confs, start=1):
                text_lines.append((current_level + 1) * indent + "Shard %d encryption layers:" % shard_idx)
                for key_cipher_layer2 in shard_conf["key_cipher_layers"]:
                    _get_key_encryption_layer_description(key_cipher_layer2, current_level + 2)  # Recursive call
        elif key_cipher_algo in SUPPORTED_SYMMETRIC_KEY_ALGOS:
            text_lines.append(
                current_level * indent + "%s with subkey encryption layers:" % (key_cipher_layer["key_cipher_algo"])
            )
            for key_cipher_layer2 in key_cipher_layer["key_cipher_layers"]:
                _get_key_encryption_layer_description(key_cipher_layer2, current_level + 1)  # Recursive call
        else:
            assert key_cipher_algo in SUPPORTED_ASYMMETRIC_KEY_ALGOS
            key_cipher_trustee = key_cipher_layer["key_cipher_trustee"]
            trustee_id = _get_trustee_displayable_identifier(key_cipher_trustee)
            text_lines.append(
                current_level * indent + "%s via trustee '%s'" % (key_cipher_layer["key_cipher_algo"], trustee_id)
            )

    payload_plaintext_signatures = cryptoconf_or_cryptainer.get("payload_plaintext_signatures", [])
    text_lines.append("Plaintext signatures:" + ("" if payload_plaintext_signatures else " None"))
    for payload_signature in payload_plaintext_signatures:
        text_lines.append(indent + _get_signature_description(payload_signature))

    for idx, payload_cipher_layer in enumerate(cryptoconf_or_cryptainer["payload_cipher_layers"], start=1):
        text_lines.append("Data encryption layer %d: %s" % (idx, payload_cipher_layer["payload_cipher_algo"]))
        text_lines.append(indent + "Key encryption layers:")
        for key_cipher_layer in payload_cipher_layer["key_cipher_layers"]:
            _get_key_encryption_layer_description(key_cipher_layer, current_level=2)
        text_lines.append(
            indent
            + "Ciphertext signatures:"
            + ("" if payload_cipher_layer["payload_ciphertext_signatures"] else " None")
        )
        for payload_signature in payload_cipher_layer["payload_ciphertext_signatures"]:
            text_lines.append(2 * indent + _get_signature_description(payload_signature))

    result = "\n".join(text_lines) + "\n"
    return result
