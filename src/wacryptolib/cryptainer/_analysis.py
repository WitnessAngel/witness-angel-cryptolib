# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Sequence

from wacryptolib.cipher import STREAMABLE_CIPHER_ALGOS
from wacryptolib.cryptainer import get_trustee_id, SHARED_SECRET_ALGO_MARKER
from wacryptolib.keygen import SUPPORTED_SYMMETRIC_KEY_ALGOS, SUPPORTED_ASYMMETRIC_KEY_ALGOS
from wacryptolib.utilities import load_from_json_bytes


def is_cryptainer_cryptoconf_streamable(cryptoconf):  # FIXME rename and add to docs?
    for payload_cipher_layer in cryptoconf["payload_cipher_layers"]:
        if payload_cipher_layer["payload_cipher_algo"] not in STREAMABLE_CIPHER_ALGOS:
            return False
    return True


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
