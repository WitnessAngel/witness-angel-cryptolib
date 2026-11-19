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


SHARED_SECRET_ALGO_MARKER = "[SHARED_SECRET]"  # Special "key_cipher_algo" value

CRYPTAINER_FORMAT = "cryptainer_1.0"

# Document formats of the structures serialized then encrypted into a "key_ciphertext" (an absent
# "key_ciphertext_format" field means Extended JSON, the only format written by older encryptors)
KEY_CIPHERTEXT_FORMAT_JSON = "json"
KEY_CIPHERTEXT_FORMAT_CBOR = "cbor"
KEY_CIPHERTEXT_FORMATS = (KEY_CIPHERTEXT_FORMAT_JSON, KEY_CIPHERTEXT_FORMAT_CBOR)

class CRYPTAINER_STATES:
    STARTED = "STARTED"
    FINISHED = "FINISHED"


def _copy_data_tree(data_tree):
    """Deep-copy the dicts and lists of a data tree WITHOUT preserving aliasing (unlike copy.deepcopy()), so that a
    sub-tree reused at several places of a cryptoconf gets its own copy in the cryptainer, where encryption results
    (e.g. the "key_ciphertext" of symmetric key cipher layers) are stored. Tuples are copied as lists, else the dicts
    they hold would be shared with the cryptoconf, on platforms whose validation lets them through."""
    if isinstance(data_tree, dict):
        return {key: _copy_data_tree(value) for key, value in data_tree.items()}
    if isinstance(data_tree, (list, tuple)):
        return [_copy_data_tree(item) for item in data_tree]
    return data_tree  # Leaves (str, bytes, int, UUID...) are immutable


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

    def dump_to_cbor_bytes(self, data):  # Only needed for the "cbor" key ciphertext format
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

    def generate_cryptainer_base_and_secrets(
        self, cryptoconf: dict, cryptainer_metadata=None, key_ciphertext_format=KEY_CIPHERTEXT_FORMAT_JSON
    ) -> tuple:
        """
        Build a payload-less and signature-less cryptainer, preconfigured with a set of symmetric keys
        under their final form (encrypted by trustees). A separate extract, with symmetric keys as well
        as algo names, is returned so that actual payload encryption and signature can be performed separately.

        :param cryptoconf: configuration tree
        :param cryptainer_metadata: additional payload to store unencrypted in cryptainer, and also inside encrypted keys/shards
        :param key_ciphertext_format: document format ("json" or "cbor") of all the structures serialized then
            encrypted into key ciphertexts (symkeys, key cipherdicts, shards, key structs); with "cbor", it is
            stored as "key_ciphertext_format" next to each "key_ciphertext", with "json" nothing is stored

        :return: a (cryptainer: dict, secrets: list) tuple, where each secret has 'payload_plaintext_hash_algos' and
        'payload_cipher_layer_extracts' keys, and each of 'payload_cipher_layer_extracts' items has
        keys 'cipher_algo', 'symmetric_key' and 'payload_hash_algos'.
        """

        # These checks come before any key generation, and are no assertions since these can be stripped (python -O)
        if key_ciphertext_format not in KEY_CIPHERTEXT_FORMATS:
            raise ValueError("Unknown key ciphertext format %r" % (key_ciphertext_format,))
        if not (cryptainer_metadata is None or isinstance(cryptainer_metadata, dict)):
            raise self._fbu.raise_validation_error(
                "Cryptainer metadata must be a dict or None, not %s" % type(cryptainer_metadata).__name__
            )
        if not isinstance(cryptoconf, dict):
            raise self._fbu.raise_validation_error("Cryptoconf must be a dict, not %s" % type(cryptoconf).__name__)
        cryptainer_format = CRYPTAINER_FORMAT
        cryptainer_uid = self._fbu.generate_uuid0()  # ALWAYS UNIQUE!

        default_keychain_uid = (
            cryptoconf.get("keychain_uid") or self._fbu.generate_uuid0()
        )  # Might be shared by lots of cryptainers

        cryptainer = _copy_data_tree(cryptoconf)  # So that we can manipulate it as new cryptainer
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
            self._encrypt_payload_symkey(
                payload_cipher_layer=payload_cipher_layer,
                symkey=symkey,
                default_keychain_uid=default_keychain_uid,
                cryptainer_metadata=cryptainer_metadata,
                key_ciphertext_format=key_ciphertext_format,
            )

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

    def _encrypt_payload_symkey(
        self,
        payload_cipher_layer: dict,
        symkey: dict,
        default_keychain_uid: uuid.UUID,
        cryptainer_metadata: typing.Optional[dict],
        key_ciphertext_format: str,
    ):
        """Serialize the symkey of a payload cipher layer, encrypt it through the key cipher layers, and store the
        resulting key ciphertext in the payload cipher layer, along with its format."""
        key_bytes = self._serialize_key_structure(symkey, key_ciphertext_format=key_ciphertext_format)

        key_ciphertext = self._encrypt_key_through_multiple_layers(
            default_keychain_uid=default_keychain_uid,
            key_bytes=key_bytes,
            key_cipher_layers=payload_cipher_layer["key_cipher_layers"],
            cryptainer_metadata=cryptainer_metadata,
            key_ciphertext_format=key_ciphertext_format,
        )
        assert isinstance(key_ciphertext, bytes), type(key_ciphertext)
        payload_cipher_layer["key_ciphertext"] = key_ciphertext
        self._set_key_ciphertext_format(payload_cipher_layer, key_ciphertext_format=key_ciphertext_format)

    def _serialize_key_structure(self, data, key_ciphertext_format: str) -> bytes:
        """Serialize a structure meant to be encrypted into a key ciphertext, in the given document format."""
        if key_ciphertext_format == KEY_CIPHERTEXT_FORMAT_CBOR:
            return self._fbu.dump_to_cbor_bytes(data)  # Deterministic WA-CBOR encoding
        assert key_ciphertext_format == KEY_CIPHERTEXT_FORMAT_JSON, key_ciphertext_format
        return self._fbu.dump_to_json_bytes(data)

    @staticmethod
    def _set_key_ciphertext_format(cipher_layer: dict, key_ciphertext_format: str):
        """Declare the format of the "key_ciphertext" of a cipher layer, next to it. Nothing is written for
        Extended JSON, so that such cryptainers keep the exact form produced by older encryptors."""
        if key_ciphertext_format != KEY_CIPHERTEXT_FORMAT_JSON:
            cipher_layer["key_ciphertext_format"] = key_ciphertext_format

    def _encrypt_key_through_multiple_layers(
        self,
        default_keychain_uid: uuid.UUID,
        key_bytes: bytes,
        key_cipher_layers: list,
        cryptainer_metadata: typing.Optional[dict],
        key_ciphertext_format: str,
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
                key_ciphertext_format=key_ciphertext_format,
            )
            key_bytes = self._serialize_key_structure(  # Thus its remains as bytes all along
                key_cipherdict, key_ciphertext_format=key_ciphertext_format
            )

        assert key_bytes != key_bytes_initial  # safety
        key_ciphertext = key_bytes
        return key_ciphertext

    def _encrypt_key_through_single_layer(
        self,
        default_keychain_uid: uuid.UUID,
        key_bytes: bytes,
        key_cipher_layer: dict,
        cryptainer_metadata: typing.Optional[dict],
        key_ciphertext_format: str,
    ) -> dict:
        """
        Encrypt a symmetric key using an asymmetric encryption scheme.

        The symmetric key payload might already be the result of previous encryption passes.
        Encryption can use a simple public key algorithm, or rely on a a set of public keys,
        by using a shared secret scheme.

        :param default_keychain_uid: default uuid for the set of encryption keys used
        :param key_bytes: symmetric key to encrypt (potentially already encrypted)
        :param key_cipher_layer: part of the cryptoconf related to this key encryption layer
        :param key_ciphertext_format: document format of the structures serialized in this chain

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
                shard_bytes = self._serialize_key_structure(
                    shard, key_ciphertext_format=key_ciphertext_format
                )  # The tuple (idx, payload) of each shard thus becomes encryptable
                shard_ciphertext = self._encrypt_key_through_multiple_layers(
                    default_keychain_uid=default_keychain_uid,
                    key_bytes=shard_bytes,
                    key_cipher_layers=key_shared_secret_shard_conf["key_cipher_layers"],
                    cryptainer_metadata=cryptainer_metadata,
                    key_ciphertext_format=key_ciphertext_format,  # Shard ciphertexts have no format field of their own
                )  # Recursive structure
                assert isinstance(shard_ciphertext, bytes), type(shard_ciphertext)
                shard_ciphertexts.append(shard_ciphertext)

            key_cipherdict = {"shard_ciphertexts": shard_ciphertexts}  # A dict is more future-proof than list

        elif key_cipher_algo in self._fbu.SUPPORTED_SYMMETRIC_CIPHER_ALGOS:

            self._logger.debug("Generating symmetric subkey of type %r for key encryption", key_cipher_algo)
            sub_symkey = self._fbu.generate_symkey(cipher_algo=key_cipher_algo)
            # This sub-chain gets its own format field, holding the same format since one is used per cryptainer
            sub_symkey_bytes = self._serialize_key_structure(sub_symkey, key_ciphertext_format=key_ciphertext_format)

            sub_symkey_ciphertext = self._encrypt_key_through_multiple_layers(
                default_keychain_uid=default_keychain_uid,
                key_bytes=sub_symkey_bytes,
                key_cipher_layers=key_cipher_layer["key_cipher_layers"],
                cryptainer_metadata=cryptainer_metadata,
                key_ciphertext_format=key_ciphertext_format,
            )  # Recursive structure
            assert isinstance(sub_symkey_ciphertext, bytes), type(sub_symkey_ciphertext)

            key_cipher_layer["key_ciphertext"] = sub_symkey_ciphertext
            self._set_key_ciphertext_format(key_cipher_layer, key_ciphertext_format=key_ciphertext_format)

            key_cipherdict = self._fbu.encrypt_bytestring(key_bytes, cipher_algo=key_cipher_algo, key_dict=sub_symkey)
            # We do not need to separate ciphertext from integrity/authentication data here, since key encryption is atomic

        else:  # Using asymmetric algorithm
            if key_cipher_algo not in self._fbu.SUPPORTED_ASYMMETRIC_CIPHER_ALGOS:  # No assertion, see above
                raise self._fbu.raise_validation_error(
                    "Unsupported key cipher algo %r in cryptoconf" % (key_cipher_algo,)
                )

            keychain_uid = key_cipher_layer.get("keychain_uid") or default_keychain_uid
            key_cipherdict = self._encrypt_key_with_asymmetric_cipher(
                cipher_algo=key_cipher_algo,
                keychain_uid=keychain_uid,
                key_bytes=key_bytes,
                trustee=key_cipher_layer["key_cipher_trustee"],
                cryptainer_metadata=cryptainer_metadata,
                key_ciphertext_format=key_ciphertext_format,
            )

        assert isinstance(key_cipherdict, dict), type(key_cipherdict)
        return key_cipherdict

    def _encrypt_key_with_asymmetric_cipher(
        self,
        cipher_algo: str,
        keychain_uid: uuid.UUID,
        key_bytes: bytes,
        trustee: dict,
        cryptainer_metadata: typing.Optional[dict],
        key_ciphertext_format: str,
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
        key_struct_bytes = self._serialize_key_structure(key_struct, key_ciphertext_format=key_ciphertext_format)
        key_cipherdict = self._fbu.encrypt_bytestring(
            key_struct_bytes, cipher_algo=cipher_algo, key_dict=dict(key=public_key)
        )
        return key_cipherdict
