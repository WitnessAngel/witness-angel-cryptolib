# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
This is the core of the Flightbox algorithms, meant to be portable to any
Python environment, including MicroPython.

As such, it must only use dependency injection, and not import anything
specific by itself.
"""
from __future__ import annotations

import typing
if typing.TYPE_CHECKING:
    import uuid
    import logging

import copy


SHARED_SECRET_ALGO_MARKER = "[SHARED_SECRET]"  # Special "key_cipher_algo" value

CRYPTAINER_FORMAT = "cryptainer_1.0"

class CRYPTAINER_STATES:
    STARTED = "STARTED"
    FINISHED = "FINISHED"


class FlightboxUtilitiesBase:
    """
    THIS CLASS IS PRIVATE API

    Contains a set of platform-specific functions to deal with time,
    cryptography, and other primitives required for Flightbox to operate.
    """

    logger: logging.Logger

    SUPPORTED_SYMMETRIC_CIPHER_ALGOS: typing.Sequence[str]
    SUPPORTED_ASYMMETRIC_CIPHER_ALGOS: typing.Sequence[str]

    def raise_validation_error(self, msg: str) -> None:
        raise NotImplementedError

    def dump_to_json_bytes(self, data):
        raise NotImplementedError

    def generate_uuid0(self) -> uuid.UUID:
        raise NotImplementedError

    def split_secret_into_shards(self, secret: bytes, *, shard_count: int, threshold_count: int) -> list:
        raise NotImplementedError

    def generate_symkey(self, cipher_algo: str):
        raise NotImplementedError

    def get_public_key(self, trustee: dict, key_algo: str, keychain_uid: uuid.UUID) -> dict:
        raise NotImplementedError

    def encrypt_bytestring(self, plaintext: bytes, *, cipher_algo: str, key_dict: dict) -> dict:
        # For both symmetric and asymmetric algos!
        raise NotImplementedError


class FlightBox:
    """
    THIS CLASS IS PRIVATE API

    Contains the algorithm to generate a cryptainer skeleton, and the corresponding secrets
    to use in an encryption pipeline.
    """

    def __init__(self, flightbox_utilities: FlightboxUtilitiesBase):
        self._fbu = flightbox_utilities
        self._logger = self._fbu.logger  # Shortcut

    def generate_cryptainer_base_and_secrets(self, cryptoconf: dict, cryptainer_metadata=None) -> tuple:
        """
        Build a payload-less and signature-less cryptainer, preconfigured with a set of symmetric keys
        under their final form (encrypted by trustees). A separate extract, with symmetric keys as well
        as algo names, is returned so that actual payload encryption and signature can be performed separately.

        :param cryptoconf: configuration tree
        :param cryptainer_metadata: additional payload to store unencrypted in cryptainer, and also inside encrypted keys/shards

        :return: a (cryptainer: dict, secrets: list) tuple, where each secret has 'payload_plaintext_hash_algos' and
        'payload_cipher_layer_extracts' keys, and each of 'payload_cipher_layer_extracts' items has
        keys 'cipher_algo', 'symmetric_key' and 'payload_hash_algos'.
        """

        assert cryptainer_metadata is None or isinstance(cryptainer_metadata, dict), cryptainer_metadata
        cryptainer_format = CRYPTAINER_FORMAT
        cryptainer_uid = self._fbu.generate_uuid0()  # ALWAYS UNIQUE!

        default_keychain_uid = (
            cryptoconf.get("keychain_uid") or self._fbu.generate_uuid0()
        )  # Might be shared by lots of cryptainers

        assert isinstance(cryptoconf, dict), cryptoconf
        cryptainer = copy.deepcopy(cryptoconf)  # So that we can manipulate it as new cryptainer
        del cryptoconf
        if not cryptainer["payload_cipher_layers"]:
            raise self._fbu.raise_validation_error("Empty payload_cipher_layers list is forbidden in cryptoconf")

        payload_plaintext_hash_algos = [
            signature["payload_digest_algo"] for signature in cryptainer.get("payload_plaintext_signatures", ())
        ]

        payload_cipher_layer_extracts = []  # Sensitive info with secret keys!

        for payload_cipher_layer in cryptainer["payload_cipher_layers"]:
            payload_cipher_algo = payload_cipher_layer["payload_cipher_algo"]

            # Legacy naming in old cryptoconfs, new naming has precedence (like in get_payload_ciphertext_signatures())
            if "payload_signatures" in payload_cipher_layer:
                legacy_payload_signatures = payload_cipher_layer.pop("payload_signatures")
                payload_cipher_layer.setdefault("payload_ciphertext_signatures", legacy_payload_signatures)

            payload_cipher_layer["payload_macs"] = None  # Will be filled later with MAC tags etc.

            self._logger.debug("Generating symmetric key of type %r for payload encryption", payload_cipher_algo)
            symkey = self._fbu.generate_symkey(cipher_algo=payload_cipher_algo)
            key_bytes = self._fbu.dump_to_json_bytes(symkey)
            key_cipher_layers = payload_cipher_layer["key_cipher_layers"]

            key_ciphertext = self._encrypt_key_through_multiple_layers(
                default_keychain_uid=default_keychain_uid,
                key_bytes=key_bytes,
                key_cipher_layers=key_cipher_layers,
                cryptainer_metadata=cryptainer_metadata,
            )
            assert isinstance(key_ciphertext, bytes), type(key_ciphertext)
            payload_cipher_layer["key_ciphertext"] = key_ciphertext

            payload_cipher_layer_extract = dict(
                cipher_algo=payload_cipher_algo,
                symkey=symkey,
                hash_algos=[
                    signature["payload_digest_algo"]
                    for signature in payload_cipher_layer["payload_ciphertext_signatures"]
                ],
            )
            payload_cipher_layer_extracts.append(payload_cipher_layer_extract)

        cryptainer.update(
            cryptainer_state=CRYPTAINER_STATES.STARTED,
            cryptainer_format=cryptainer_format,
            cryptainer_uid=cryptainer_uid,
            keychain_uid=default_keychain_uid,
            payload_ciphertext_struct=None,  # Must be filled asap, by OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER if needed!
            cryptainer_metadata=cryptainer_metadata,
        )

        secrets = dict(
            payload_plaintext_hash_algos=payload_plaintext_hash_algos,
            payload_cipher_layer_extracts=payload_cipher_layer_extracts,
        )

        return cryptainer, secrets

    def _encrypt_key_through_multiple_layers(
        self,
        default_keychain_uid: uuid.UUID,
        key_bytes: bytes,
        key_cipher_layers: list,
        cryptainer_metadata: typing.Optional[dict],
    ) -> bytes:
        # HERE KEY IS A REAL KEY OR A SHARD !!!
        key_bytes_initial = key_bytes

        if not key_cipher_layers:
            raise self._fbu.raise_validation_error("Empty key_cipher_layers list is forbidden in cryptoconf")

        for key_cipher_layer in key_cipher_layers:
            key_cipherdict = self._encrypt_key_through_single_layer(
                default_keychain_uid=default_keychain_uid,
                key_bytes=key_bytes,
                key_cipher_layer=key_cipher_layer,
                cryptainer_metadata=cryptainer_metadata,
            )
            key_bytes = self._fbu.dump_to_json_bytes(key_cipherdict)  # Thus its remains as bytes all along

        assert key_bytes != key_bytes_initial  # safety
        key_ciphertext = key_bytes
        return key_ciphertext

    def _encrypt_key_through_single_layer(
        self,
        default_keychain_uid: uuid.UUID,
        key_bytes: bytes,
        key_cipher_layer: dict,
        cryptainer_metadata: typing.Optional[dict],
    ) -> dict:
        """
        Encrypt a symmetric key using an asymmetric encryption scheme.

        The symmetric key payload might already be the result of previous encryption passes.
        Encryption can use a simple public key algorithm, or rely on a a set of public keys,
        by using a shared secret scheme.

        :param default_keychain_uid: default uuid for the set of encryption keys used
        :param key_bytes: symmetric key to encrypt (potentially already encrypted)
        :param key_cipher_layer: part of the cryptoconf related to this key encryption layer

        :return: if the scheme used is 'SHARED_SECRET', a list of encrypted shards is returned.
                 If an asymmetric algorithm has been used, a dictionary with all the information
                 needed to decipher the symmetric key is returned.
        """
        assert isinstance(key_bytes, bytes), type(key_bytes)
        key_cipher_algo = key_cipher_layer["key_cipher_algo"]

        if key_cipher_algo == SHARED_SECRET_ALGO_MARKER:
            key_shared_secret_shards = key_cipher_layer["key_shared_secret_shards"]
            shard_count = len(key_shared_secret_shards)

            threshold_count = key_cipher_layer["key_shared_secret_threshold"]
            if not (0 < threshold_count <= shard_count):
                raise self._fbu.raise_validation_error(
                    "Shared secret threshold must be strictly positive and not greater than shard count, in cryptoconf"
                )

            shards = self._fbu.split_secret_into_shards(
                secret=key_bytes, shard_count=shard_count, threshold_count=threshold_count
            )

            assert len(shards) == shard_count

            shard_ciphertexts = []

            for shard, key_shared_secret_shard_conf in zip(shards, key_shared_secret_shards):
                shard_bytes = self._fbu.dump_to_json_bytes(
                    shard
                )  # The tuple (idx, payload) of each shard thus becomes encryptable
                shard_ciphertext = self._encrypt_key_through_multiple_layers(
                    default_keychain_uid=default_keychain_uid,
                    key_bytes=shard_bytes,
                    key_cipher_layers=key_shared_secret_shard_conf["key_cipher_layers"],
                    cryptainer_metadata=cryptainer_metadata,
                )  # Recursive structure
                assert isinstance(shard_ciphertext, bytes), shard_ciphertext
                shard_ciphertexts.append(shard_ciphertext)

            key_cipherdict = {"shard_ciphertexts": shard_ciphertexts}  # A dict is more future-proof than list

        elif key_cipher_algo in self._fbu.SUPPORTED_SYMMETRIC_CIPHER_ALGOS:

            self._logger.debug("Generating symmetric subkey of type %r for key encryption", key_cipher_algo)
            sub_symkey = self._fbu.generate_symkey(cipher_algo=key_cipher_algo)
            sub_symkey_bytes = self._fbu.dump_to_json_bytes(sub_symkey)

            sub_symkey_ciphertext = self._encrypt_key_through_multiple_layers(
                default_keychain_uid=default_keychain_uid,
                key_bytes=sub_symkey_bytes,
                key_cipher_layers=key_cipher_layer["key_cipher_layers"],
                cryptainer_metadata=cryptainer_metadata,
            )  # Recursive structure
            assert isinstance(sub_symkey_ciphertext, bytes), sub_symkey_ciphertext

            key_cipher_layer["key_ciphertext"] = sub_symkey_ciphertext

            key_cipherdict = self._fbu.encrypt_bytestring(key_bytes, cipher_algo=key_cipher_algo, key_dict=sub_symkey)
            # We do not need to separate ciphertext from integrity/authentication data here, since key encryption is atomic

        else:  # Using asymmetric algorithm
            assert key_cipher_algo in self._fbu.SUPPORTED_ASYMMETRIC_CIPHER_ALGOS, repr(key_cipher_algo)

            keychain_uid = key_cipher_layer.get("keychain_uid") or default_keychain_uid
            key_cipherdict = self._encrypt_key_with_asymmetric_cipher(
                cipher_algo=key_cipher_algo,
                keychain_uid=keychain_uid,
                key_bytes=key_bytes,
                trustee=key_cipher_layer["key_cipher_trustee"],
                cryptainer_metadata=cryptainer_metadata,
            )

        assert isinstance(key_cipherdict, dict), key_cipherdict
        return key_cipherdict

    def _encrypt_key_with_asymmetric_cipher(
        self,
        cipher_algo: str,
        keychain_uid: uuid.UUID,
        key_bytes: bytes,
        trustee: dict,
        cryptainer_metadata: typing.Optional[dict],
    ) -> dict:
        """
        Encrypt given payload (representing a symmetric key) with an asymmetric algorithm.

        :param cipher_algo: string with name of algorithm to use
        :param keychain_uid: final uuid for the set of encryption keys used
        :param key_bytes: symmetric key as bytes to encrypt
        :param trustee: trustee used for encryption (findable in configuration tree)

        :return: dictionary which contains every payload needed to decrypt the ciphered key
        """
        public_key = self._fbu.get_public_key(trustee=trustee, key_algo=cipher_algo, keychain_uid=keychain_uid)

        # FIXME provide utilities to wrap/unwrap this struct?
        key_struct = dict(key_bytes=key_bytes, cryptainer_metadata=cryptainer_metadata)  # SPECIAL FORMAT FOR CHECKUPS
        key_struct_bytes = self._fbu.dump_to_json_bytes(key_struct)
        key_cipherdict = self._fbu.encrypt_bytestring(
            key_struct_bytes, cipher_algo=cipher_algo, key_dict=dict(key=public_key)
        )
        return key_cipherdict
