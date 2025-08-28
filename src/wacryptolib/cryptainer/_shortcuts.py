# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Sequence, Optional, BinaryIO, Union
from urllib.parse import urlparse
import uuid

from wacryptolib.cipher import STREAMABLE_CIPHER_ALGOS, _update_hashers_dict, _create_hashers_dict, \
    _get_hashers_dict_digests
from wacryptolib.cryptainer import get_trustee_id, SHARED_SECRET_ALGO_MARKER, get_trustee_proxy, \
    DEFAULT_DATA_CHUNK_SIZE, CryptainerEncryptionPipeline, CryptainerEncryptor, CryptainerDecryptor, \
    CRYPTAINER_TRUSTEE_TYPES
from wacryptolib.keygen import SUPPORTED_SYMMETRIC_KEY_ALGOS, SUPPORTED_ASYMMETRIC_KEY_ALGOS
from wacryptolib.keystore import KeystorePoolBase
from wacryptolib.utilities import load_from_json_bytes, consume_bytes_as_chunks


def gather_trustee_dependencies(cryptainers: Sequence) -> dict:
    """Analyse a cryptainer and return the trustees (and their keypairs) used by it.

    :return: dict with lists of keypair identifiers in fields "encryption" and "signature".
    """

    signature_dependencies = {}
    cipher_dependencies = {}

    def _add_keypair_identifiers_for_trustee(mapper, trustee_conf, keychain_uid, key_algo):
        trustee_id = get_trustee_id(trustee_conf=trustee_conf)
        keypair_identifiers = dict(keychain_uid=keychain_uid, key_algo=key_algo)
        mapper.setdefault(trustee_id, (trustee_conf, []))
        keypair_identifiers_list = mapper[trustee_id][1]
        if keypair_identifiers not in keypair_identifiers_list:
            keypair_identifiers_list.append(keypair_identifiers)

    def _grab_key_cipher_layers_dependencies(key_cipher_layers):
        for key_cipher_layer in key_cipher_layers:
            key_cipher_algo = key_cipher_layer["key_cipher_algo"]

            if key_cipher_algo == SHARED_SECRET_ALGO_MARKER:
                shard_confs = key_cipher_layer["key_shared_secret_shards"]
                for shard_conf in shard_confs:
                    _grab_key_cipher_layers_dependencies(shard_conf["key_cipher_layers"])  # Recursive call
            elif key_cipher_algo in SUPPORTED_SYMMETRIC_KEY_ALGOS:
                _grab_key_cipher_layers_dependencies(key_cipher_layer["key_cipher_layers"])  # Recursive call
            else:
                assert key_cipher_algo in SUPPORTED_ASYMMETRIC_KEY_ALGOS, key_cipher_algo
                keychain_uid_for_encryption = key_cipher_layer.get("keychain_uid") or keychain_uid
                trustee_conf = key_cipher_layer["key_cipher_trustee"]
                _add_keypair_identifiers_for_trustee(
                    mapper=cipher_dependencies,
                    trustee_conf=trustee_conf,
                    keychain_uid=keychain_uid_for_encryption,
                    key_algo=key_cipher_algo,
                )

    for cryptainer in cryptainers:
        keychain_uid = cryptainer["keychain_uid"]
        for payload_cipher_layer in cryptainer["payload_cipher_layers"]:
            for signature_conf in payload_cipher_layer["payload_ciphertext_signatures"]:
                key_algo_signature = signature_conf["payload_signature_algo"]
                keychain_uid_for_signature = signature_conf.get("keychain_uid") or keychain_uid
                trustee_conf = signature_conf["payload_signature_trustee"]

                _add_keypair_identifiers_for_trustee(
                    mapper=signature_dependencies,
                    trustee_conf=trustee_conf,
                    keychain_uid=keychain_uid_for_signature,
                    key_algo=key_algo_signature,
                )

            _grab_key_cipher_layers_dependencies(payload_cipher_layer["key_cipher_layers"])

    trustee_dependencies = {"signature": signature_dependencies, "encryption": cipher_dependencies}
    return trustee_dependencies


def gather_decryptable_symkeys(cryptainers_with_names: Sequence) -> dict:  # TODO Update this name
    """Analyse a cryptainer and returns the symkeys/shards (and their corresponding trustee) needed for decryption.

    :return: dict with a tuple of the cipher key and the symkey/shard by trustee id.
    """
    decryptable_symkeys_per_trustee = {}

    def _add_decryptable_symkeys_for_trustee(
        cryptainer_name,
        cryptainer_uid,
        cryptainer_metadata,
        key_cipher_trustee,
        key_ciphertext,
        keychain_uid_for_encryption,
        key_algo_for_encryption,
    ):
        assert isinstance(key_ciphertext, bytes), key_ciphertext

        trustee_id = get_trustee_id(trustee_conf=key_cipher_trustee)
        symkey_decryption_request = {
            "cryptainer_name": str(cryptainer_name),  # No Pathlib object
            "cryptainer_uid": cryptainer_uid,
            "cryptainer_metadata": cryptainer_metadata,
            "symkey_decryption_request_data": key_ciphertext,
            "keychain_uid": keychain_uid_for_encryption,
            "key_algo": key_algo_for_encryption,
        }
        _trustee_data, _decryptable_symkeys = decryptable_symkeys_per_trustee.setdefault(
            trustee_id, (key_cipher_trustee, [])
        )
        _decryptable_symkeys.append(symkey_decryption_request)

    def _gather_decryptable_symkeys(
        cryptainer_name, cryptainer_uid, cryptainer_metadata, key_cipher_layers: list, key_ciphertext
    ):
        assert isinstance(key_ciphertext, bytes), key_ciphertext

        # Only the LAST layer of symkey ciphering allows for a remote symkey decryption request
        last_key_cipher_layer = key_cipher_layers[-1]
        last_key_cipher_algo = last_key_cipher_layer["key_cipher_algo"]

        if last_key_cipher_algo == SHARED_SECRET_ALGO_MARKER:
            key_shared_secret_shards = last_key_cipher_layer["key_shared_secret_shards"]
            key_cipherdict = load_from_json_bytes(key_ciphertext)
            shard_ciphertexts = key_cipherdict["shard_ciphertexts"]

            for shard_ciphertext, shard_conf in zip(shard_ciphertexts, key_shared_secret_shards):
                _gather_decryptable_symkeys(
                    cryptainer_name,
                    cryptainer_uid,
                    cryptainer_metadata,
                    shard_conf["key_cipher_layers"],
                    shard_ciphertext,
                )

        elif last_key_cipher_algo in SUPPORTED_SYMMETRIC_KEY_ALGOS:
            subkey_ciphertext = last_key_cipher_layer["key_ciphertext"]
            _gather_decryptable_symkeys(
                cryptainer_name,
                cryptainer_uid,
                cryptainer_metadata,
                last_key_cipher_layer["key_cipher_layers"],
                subkey_ciphertext,
            )

        else:
            assert last_key_cipher_algo in SUPPORTED_ASYMMETRIC_KEY_ALGOS, last_key_cipher_algo

            keychain_uid_for_encryption = last_key_cipher_layer.get("keychain_uid") or default_keychain_uid
            key_algo_for_encryption = last_key_cipher_layer["key_cipher_algo"]
            key_cipher_trustee = last_key_cipher_layer["key_cipher_trustee"]

            _add_decryptable_symkeys_for_trustee(
                cryptainer_name=cryptainer_name,
                cryptainer_uid=cryptainer_uid,
                cryptainer_metadata=cryptainer_metadata,
                key_cipher_trustee=key_cipher_trustee,
                key_ciphertext=key_ciphertext,
                keychain_uid_for_encryption=keychain_uid_for_encryption,
                key_algo_for_encryption=key_algo_for_encryption,
            )

    for cryptainer_name, cryptainer in cryptainers_with_names:
        default_keychain_uid = cryptainer["keychain_uid"]
        cryptainer_uid = cryptainer["cryptainer_uid"]
        cryptainer_metadata = cryptainer["cryptainer_metadata"]

        for payload_cipher_layer in cryptainer["payload_cipher_layers"]:
            key_ciphertext = payload_cipher_layer.get("key_ciphertext")

            _gather_decryptable_symkeys(
                cryptainer_name=cryptainer_name,
                cryptainer_uid=cryptainer_uid,
                cryptainer_metadata=cryptainer_metadata,
                key_cipher_layers=payload_cipher_layer["key_cipher_layers"],
                key_ciphertext=key_ciphertext,
            )

    return decryptable_symkeys_per_trustee



def request_decryption_authorizations(
    trustee_dependencies: dict, keystore_pool, request_message: str, passphrases: Optional[list] = None
) -> dict:
    """Loop on encryption trustees and request decryption authorization for all the keypairs that they own.

    :return: dict mapping trustee ids to authorization result dicts.
    """
    request_authorization_result = {}
    cipher_trustee_dependencies = trustee_dependencies.get("encryption")

    for trustee_id, trustee_data in cipher_trustee_dependencies.items():
        key_cipher_trustee, keypair_identifiers = trustee_data
        proxy = get_trustee_proxy(trustee=key_cipher_trustee, keystore_pool=keystore_pool)
        result = proxy.request_decryption_authorization(
            keypair_identifiers=keypair_identifiers, request_message=request_message, passphrases=passphrases
        )
        request_authorization_result[trustee_id] = result

    return request_authorization_result



def is_cryptainer_cryptoconf_streamable(cryptoconf):  # FIXME rename and add to docs?
    for payload_cipher_layer in cryptoconf["payload_cipher_layers"]:
        if payload_cipher_layer["payload_cipher_algo"] not in STREAMABLE_CIPHER_ALGOS:
            return False
    return True


def __wip_sign_payload_into_sigainer(payload, *, sigconf):  # FIXME IMPLEMENT LATER
    """
    Compute digests and retrieve signatures for a plaintext payload
    """

    payload_hash_algos = [signature["payload_digest_algo"] for signature in sigconf["payload_plaintext_signatures"]]

    hashers_dict = _create_hashers_dict(payload_hash_algos)

    if hasattr(payload, "read"):  # File-like object
        for chunk in payload.read(DEFAULT_DATA_CHUNK_SIZE):
            _update_hashers_dict(hashers_dict, chunk=chunk)
    else:
        assert isinstance(payload, bytes), payload
        _update_hashers_dict(hashers_dict, chunk=payload)  # All at once

    payload_digests = _get_hashers_dict_digests(hashers_dict)

    assert len(payload_digests) == len(sigconf["payload_plaintext_signatures"])  # Coherence
    for signature in sigconf["payload_plaintext_signatures"]:
        signature["payload_digest_value"] = payload_digests[signature["payload_digest_algo"]]

    # TODO extract code of _generate_message_signature() method!!


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
