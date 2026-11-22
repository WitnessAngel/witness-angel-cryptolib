# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import copy
import logging
from typing import Union, BinaryIO
import uuid

from wacryptolib.cryptainer import CryptainerBase, SIGNATURE_POLICIES, PAYLOAD_CIPHERTEXT_LOCATIONS, logger, \
    CRYPTAINER_STATES, get_trustee_proxy, \
    _inject_payload_digests_and_signatures, FlightboxUtilitiesBase, FlightBox, ensure_validated_cryptoconf, ValidatedCryptainer, \
    KEY_CIPHERTEXT_FORMAT_JSON, KEY_CIPHERTEXT_FORMATS

from wacryptolib.cipher import (
    encrypt_bytestring,
    PayloadEncryptionPipeline,
    SUPPORTED_CIPHER_ALGOS,
)
from wacryptolib.exceptions import (
    SchemaValidationError,
)
from wacryptolib.keygen import (
    generate_symkey,
    load_asymmetric_key_from_pem_bytestring,
    SUPPORTED_SYMMETRIC_KEY_ALGOS,
    SUPPORTED_ASYMMETRIC_KEY_ALGOS,
)
from wacryptolib.keystore import KeystorePoolBase
from wacryptolib.shared_secret import split_secret_into_shards
from wacryptolib.utilities import (
    MAX_SHARED_SECRET_SHARD_COUNT,
    dump_to_cbor_bytes,
    dump_to_json_bytes,
    generate_uuid0,
)
from wacryptolib.utilities.wacbor import EXTJSON_KEYWORDS


def _check_metadata_has_no_extjson_keyword_map(cryptainer_metadata) -> None:
    """Reject metadata holding, at any depth, a single-key map whose key is an Extended JSON keyword (like
    {"$uuid": "..."}), whatever the document format: Extended JSON readers would load it back as a typed value,
    or fail to load the cryptainer, and WA-CBOR refuses it. Checked before any random draw or output."""
    pending_items = [(cryptainer_metadata, "cryptainer_metadata")]
    while pending_items:  # Iterative, so that deep metadata doesn't hit the recursion limit here
        item, location = pending_items.pop()
        if isinstance(item, dict):
            if len(item) == 1:
                (key,) = item
                if key in EXTJSON_KEYWORDS:
                    raise SchemaValidationError(
                        "Cryptainer metadata can't hold an Extended JSON keyword map (%r) at %s" % (key, location)
                    )
            pending_items.extend((value, "%s.%s" % (location, key)) for key, value in item.items())
        elif isinstance(item, (list, tuple)):
            pending_items.extend((value, "%s[%d]" % (location, index)) for index, value in enumerate(item))
from wacryptolib.hash import hash_message


class FlightboxUtilitiesImpl(FlightboxUtilitiesBase):
    """
    THIS CLASS IS PRIVATE API

    Contains a set of platform-specific functions to deal with time,
    cryptography, and other primitives required for Flightbox to operate.
    """

    SUPPORTED_SYMMETRIC_CIPHER_ALGOS = sorted(set(SUPPORTED_SYMMETRIC_KEY_ALGOS) & set(SUPPORTED_CIPHER_ALGOS))
    SUPPORTED_ASYMMETRIC_CIPHER_ALGOS = sorted(set(SUPPORTED_ASYMMETRIC_KEY_ALGOS) & set(SUPPORTED_CIPHER_ALGOS))

    MAX_SHARED_SECRET_SHARD_COUNT = MAX_SHARED_SECRET_SHARD_COUNT

    def __init__(self, logger: logging.Logger, keystore_pool: KeystorePoolBase) -> None:
        self.logger = logger
        self._keystore_pool = keystore_pool

    def raise_validation_error(self, msg: str) -> None:
        raise SchemaValidationError(msg)

    def dump_to_json_bytes(self, data):
        return dump_to_json_bytes(data)

    def dump_to_cbor_bytes(self, data):
        return dump_to_cbor_bytes(data)

    def generate_uuid0(self) -> uuid.UUID:
        return generate_uuid0()

    def split_secret_into_shards(self, secret: bytes, *, shard_count: int, threshold_count: int) -> list:
        return split_secret_into_shards(secret, shard_count=shard_count, threshold_count=threshold_count)

    def generate_symkey(self, cipher_algo: str):
        return generate_symkey(cipher_algo)

    def _fetch_asymmetric_key_pem_from_trustee(self, trustee, key_algo, keychain_uid):
        """Method meant to be easily replaced by a mockup in tests"""
        trustee_proxy = get_trustee_proxy(trustee=trustee, keystore_pool=self._keystore_pool)
        self.logger.debug("Fetching asymmetric key %s %r", key_algo, keychain_uid)
        public_key_pem = trustee_proxy.fetch_public_key(keychain_uid=keychain_uid, key_algo=key_algo)
        return public_key_pem

    def get_public_key(self, trustee: dict, key_algo: str, keychain_uid: uuid.UUID) -> dict:
        public_key_pem = self._fetch_asymmetric_key_pem_from_trustee(trustee, key_algo=key_algo, keychain_uid=keychain_uid)
        self.logger.debug("Fetching asymmetric keypair %s/%s to encrypt symmetric key struct", key_algo, keychain_uid)
        public_key = load_asymmetric_key_from_pem_bytestring(key_pem=public_key_pem, key_algo=key_algo)
        return public_key

    def encrypt_bytestring(self, plaintext: bytes, *, cipher_algo: str, key_dict: dict) -> dict:
        return encrypt_bytestring(plaintext=plaintext, cipher_algo=cipher_algo, key_dict=key_dict)


class CryptainerEncryptor(CryptainerBase):
    """
    THIS CLASS IS PRIVATE API

    Contains every method used to write and encrypt a cryptainer, IN MEMORY.

    :param key_ciphertext_format: document format ("json" or "cbor") of the structures serialized then encrypted
        into the key ciphertexts of produced cryptainers
    """

    def __init__(self, signature_policy, key_ciphertext_format: str = KEY_CIPHERTEXT_FORMAT_JSON, **kwargs):
        super().__init__(**kwargs)
        if signature_policy is None:
            signature_policy = SIGNATURE_POLICIES.ATTEMPT_SIGNING  # Sensible default
        assert getattr(SIGNATURE_POLICIES, signature_policy), signature_policy
        self._signature_policy = signature_policy
        if key_ciphertext_format not in KEY_CIPHERTEXT_FORMATS:  # Not an assert (python -O)
            raise ValueError("Unknown key ciphertext format %r" % (key_ciphertext_format,))
        self._key_ciphertext_format = key_ciphertext_format

        _flightbox_utilities = FlightboxUtilitiesImpl(logger=logger, keystore_pool=self._keystore_pool)
        self._flightbox = FlightBox(_flightbox_utilities)

    def build_cryptainer_and_encryption_pipeline(
        self,
        *,
        cryptoconf: dict,
        output_stream: BinaryIO,
        cryptainer_metadata=None,
    ) -> tuple:
        """
        Build a base cryptainer to store encrypted keys, as well as a stream encryptor
        meant to process heavy payload chunk by chunk.

        Signatures, and final ciphertext (if not offloaded), will have to be added
        later to the cryptainer.

        :param cryptoconf: configuration tree
        :param output_stream: open file where the stream encryptor should write to
        :param cryptainer_metadata: additional informations to store unencrypted in cryptainer

        :return: cryptainer with all the information needed to attempt payload decryption
        """

        cryptainer, secrets = self._generate_cryptainer_base_and_secrets(
            cryptoconf=cryptoconf, cryptainer_metadata=cryptainer_metadata
        )

        encryption_pipeline = PayloadEncryptionPipeline(output_stream=output_stream, secrets=secrets)

        return cryptainer, encryption_pipeline

    def encrypt_data(self, payload: Union[bytes, BinaryIO], *, cryptoconf: dict, cryptainer_metadata=None) -> dict:
        """
        Shortcut when data is already available.

        This method browses through configuration tree to apply the right succession of encryption+signature algorithms to data.

        :param payload: initial plaintext, or file pointer (file immediately deleted then)
        :param cryptoconf: configuration tree
        :param cryptainer_metadata: additional data to store unencrypted in cryptainer

        :return: cryptainer with all the information needed to attempt data decryption
        """

        payload_plaintext = self._load_all_payload_bytes(payload)  # Ensure we get the whole payload buffer

        cryptainer, secrets = self._generate_cryptainer_base_and_secrets(
            cryptoconf=cryptoconf, cryptainer_metadata=cryptainer_metadata
        )

        payload_plaintext_hash_algos = secrets["payload_plaintext_hash_algos"]
        plaintext_digests = {
            payload_hash_algo: hash_message(payload_plaintext, hash_algo=payload_hash_algo)
            for payload_hash_algo in payload_plaintext_hash_algos
        }

        payload_cipher_layer_extracts = secrets["payload_cipher_layer_extracts"]
        payload_ciphertext, ciphertext_integrity_tags = self._encrypt_and_hash_payload(
            payload_plaintext, payload_cipher_layer_extracts
        )

        cryptainer["payload_ciphertext_struct"] = dict(
            ciphertext_location=PAYLOAD_CIPHERTEXT_LOCATIONS.INLINE, ciphertext_value=payload_ciphertext
        )

        payload_integrity_tags = dict(
            plaintext_digests=plaintext_digests,
            ciphertext_integrity_tags=ciphertext_integrity_tags,
        )
        self.add_authentication_data_to_cryptainer(cryptainer, payload_integrity_tags)

        # A valid cryptoconf (and dict metadata) yields a valid cryptainer, so no need to validate it again
        return ValidatedCryptainer(cryptainer, inline_payload_checked=True)._seal()

    @staticmethod
    def _load_all_payload_bytes(payload: Union[bytes, BinaryIO]):
        if hasattr(payload, "read"):  # File-like object
            logger.debug("Reading all data from open file handle %r", payload)
            payload_stream = payload
            payload = payload_stream.read()
            # DO NOT delete the file, e.g. it might come from CLI!
        assert isinstance(payload, bytes), type(payload)
        ## FIXME LATER ADD THIS - assert payload, payload  # No encryption must be launched if we have no payload to process!
        return payload

    def _encrypt_and_hash_payload(self, payload, payload_cipher_layer_extracts):
        assert payload_cipher_layer_extracts, payload_cipher_layer_extracts  # Else security flaw!

        payload_current = payload
        ciphertext_integrity_tags = []

        for payload_cipher_layer_extract in payload_cipher_layer_extracts:
            payload_cipher_algo = payload_cipher_layer_extract["cipher_algo"]
            symkey = payload_cipher_layer_extract["symkey"]
            payload_hash_algos = payload_cipher_layer_extract["hash_algos"]

            logger.debug("Encrypting payload with symmetric key of type %r", payload_cipher_algo)
            payload_cipherdict = encrypt_bytestring(
                plaintext=payload_current, cipher_algo=payload_cipher_algo, key_dict=symkey
            )
            assert isinstance(
                payload_cipherdict, dict
            ), type(payload_cipherdict)  # Might contain integrity/authentication data too

            payload_ciphertext = payload_cipherdict.pop("ciphertext")  # Mandatory field
            assert isinstance(
                payload_ciphertext, bytes
            ), type(payload_ciphertext)  # Same raw content as would be in offloaded payload file

            payload_digests = {
                payload_hash_algo: hash_message(payload_ciphertext, hash_algo=payload_hash_algo)
                for payload_hash_algo in payload_hash_algos
            }

            ciphertext_integrity_tags.append(
                dict(payload_macs=payload_cipherdict, payload_digests=payload_digests)  # Only remains tags, macs etc.
            )

            payload_current = payload_ciphertext

        return payload_current, ciphertext_integrity_tags

    def _generate_cryptainer_base_and_secrets(self, cryptoconf: dict, cryptainer_metadata=None) -> tuple:
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
        cryptoconf = ensure_validated_cryptoconf(cryptoconf)  # Mandatory upfront validation of user input
        if cryptainer_metadata is not None and not isinstance(cryptainer_metadata, dict):  # Not an assert (python -O)
            raise SchemaValidationError("Cryptainer metadata must be a dict or None, not %s" % type(cryptainer_metadata).__name__)
        _check_metadata_has_no_extjson_keyword_map(cryptainer_metadata)
        cryptainer_metadata = copy.deepcopy(cryptainer_metadata)  # The validated cryptainer must not alias caller data

        cryptainer, secrets = self._flightbox.generate_cryptainer_base_and_secrets(
            cryptoconf=cryptoconf,
            cryptainer_metadata=cryptainer_metadata,
            key_ciphertext_format=self._key_ciphertext_format,
        )
        return cryptainer, secrets

    def add_authentication_data_to_cryptainer(self, cryptainer: dict, payload_integrity_tags: dict):
        default_keychain_uid = cryptainer["keychain_uid"]  # No hierarchical override of uids here

        plaintext_digests = payload_integrity_tags["plaintext_digests"]
        if plaintext_digests:
            _inject_payload_digests_and_signatures(
                signature_confs=cryptainer["payload_plaintext_signatures"],  # Entry MUST exist here
                payload_digests=plaintext_digests,
                default_keychain_uid=default_keychain_uid,
                signature_policy=self._signature_policy,
                keystore_pool=self._keystore_pool,
            )

        ciphertext_integrity_tags = payload_integrity_tags["ciphertext_integrity_tags"]
        del payload_integrity_tags

        payload_cipher_layers = cryptainer["payload_cipher_layers"]
        assert len(payload_cipher_layers) == len(ciphertext_integrity_tags)  # Sanity check

        for payload_cipher_layer, ciphertext_integrity_tags_dict in zip(
            cryptainer["payload_cipher_layers"], ciphertext_integrity_tags
        ):
            assert payload_cipher_layer["payload_macs"] is None  # Set at cryptainer build time
            payload_cipher_layer["payload_macs"] = ciphertext_integrity_tags_dict["payload_macs"]

            payload_digests = ciphertext_integrity_tags_dict["payload_digests"]

            _inject_payload_digests_and_signatures(
                signature_confs=payload_cipher_layer["payload_ciphertext_signatures"],
                payload_digests=payload_digests,
                default_keychain_uid=default_keychain_uid,
                signature_policy=self._signature_policy,
                keystore_pool=self._keystore_pool,
            )

        cryptainer["cryptainer_state"] = CRYPTAINER_STATES.FINISHED
