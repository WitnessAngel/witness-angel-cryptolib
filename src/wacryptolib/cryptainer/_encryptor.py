# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import copy
import logging
from typing import Union, BinaryIO, Optional
import uuid

from wacryptolib.cryptainer import CryptainerBase, SIGNATURE_POLICIES, PAYLOAD_CIPHERTEXT_LOCATIONS, logger, \
    CRYPTAINER_STATES, CRYPTAINER_TRUSTEE_TYPES, SHARED_SECRET_ALGO_MARKER, get_trustee_proxy, get_trustee_id, \
    _inject_payload_digests_and_signatures, FlightboxUtilitiesBase, FlightBox, ensure_validated_cryptoconf, ValidatedCryptainer, \
    KEY_CIPHERTEXT_FORMAT_JSON, KEY_CIPHERTEXT_FORMATS, check_cryptainer_metadata_sanity, \
    check_cryptoconf_fits_cryptainer_file_format

from wacryptolib.cipher import (
    check_asymmetric_encryption_key_sanity,
    encrypt_bytestring,
    PayloadEncryptionPipeline,
    SUPPORTED_CIPHER_ALGOS,
)
from wacryptolib.exceptions import (
    KeyDoesNotExist,
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
    dump_to_cbor_bytes,
    dump_to_json_bytes,
    generate_uuid0,
    DOCUMENT_FORMATS,
)
from wacryptolib.hash import hash_message


def _iter_asymmetric_key_cipher_layers(cryptoconf: dict):
    """Yield the asymmetric key cipher layers of a validated cryptoconf, whatever their nesting."""
    pending_key_cipher_layers = [
        payload_cipher_layer["key_cipher_layers"] for payload_cipher_layer in cryptoconf["payload_cipher_layers"]
    ]
    while pending_key_cipher_layers:
        for key_cipher_layer in pending_key_cipher_layers.pop():
            if key_cipher_layer["key_cipher_algo"] == SHARED_SECRET_ALGO_MARKER:
                pending_key_cipher_layers.extend(
                    shard["key_cipher_layers"] for shard in key_cipher_layer["key_shared_secret_shards"]
                )
            elif "key_cipher_layers" in key_cipher_layer:  # Symmetric layer, its sub-key has its own layers
                pending_key_cipher_layers.append(key_cipher_layer["key_cipher_layers"])
            else:
                yield key_cipher_layer


class FlightboxUtilitiesImpl(FlightboxUtilitiesBase):
    """
    THIS CLASS IS PRIVATE API

    Contains a set of platform-specific functions to deal with time,
    cryptography, and other primitives required for Flightbox to operate.
    """

    SUPPORTED_SYMMETRIC_CIPHER_ALGOS = sorted(set(SUPPORTED_SYMMETRIC_KEY_ALGOS) & set(SUPPORTED_CIPHER_ALGOS))
    SUPPORTED_ASYMMETRIC_CIPHER_ALGOS = sorted(set(SUPPORTED_ASYMMETRIC_KEY_ALGOS) & set(SUPPORTED_CIPHER_ALGOS))

    def __init__(self, logger: logging.Logger, keystore_pool: KeystorePoolBase) -> None:
        self.logger = logger
        self._keystore_pool = keystore_pool
        self._prefetched_public_keys = {}  # Only filled during a cryptainer creation

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

    def _fetch_asymmetric_key_pem_from_trustee(self, trustee, key_algo, keychain_uid, must_exist=False):
        """Method meant to be easily replaced by a mockup in tests"""
        trustee_proxy = get_trustee_proxy(trustee=trustee, keystore_pool=self._keystore_pool)
        self.logger.debug("Fetching asymmetric key %s %r", key_algo, keychain_uid)
        public_key_pem = trustee_proxy.fetch_public_key(
            keychain_uid=keychain_uid, key_algo=key_algo, must_exist=must_exist
        )
        return public_key_pem

    def _fetch_and_check_public_key(self, trustee: dict, key_algo: str, keychain_uid: uuid.UUID, must_exist=False):
        public_key_pem = self._fetch_asymmetric_key_pem_from_trustee(
            trustee, key_algo=key_algo, keychain_uid=keychain_uid, must_exist=must_exist
        )
        self.logger.debug("Fetching asymmetric keypair %s/%s to encrypt symmetric key struct", key_algo, keychain_uid)
        public_key = load_asymmetric_key_from_pem_bytestring(key_pem=public_key_pem, key_algo=key_algo)
        check_asymmetric_encryption_key_sanity(public_key, cipher_algo=key_algo)  # Before any use
        return public_key

    def get_public_key(self, trustee: dict, key_algo: str, keychain_uid: uuid.UUID) -> dict:
        public_key = self._prefetched_public_keys.get((get_trustee_id(trustee), key_algo, keychain_uid))
        if public_key is None:
            public_key = self._fetch_and_check_public_key(trustee, key_algo=key_algo, keychain_uid=keychain_uid)
        return public_key

    def prefetch_local_public_keys(self, cryptoconf: dict) -> None:
        """Resolve and check, before any random draw, the public keys of a validated cryptoconf which are
        available locally and without side effect: those of authenticator trustees, whose imported keystores are
        read-only (a missing keystore or key is then an error), and those already present in the local keyfactory.
        They are kept until clear_prefetched_public_keys() is called, so that encryption uses the checked keys.

        Other keys are still resolved and checked when their layer gets encrypted: those of jsonrpc_api trustees,
        those that the local keyfactory will generate on demand, and those of layers falling back to a root
        keychain uid which is absent from the cryptoconf (it is then drawn during encryption)."""
        root_keychain_uid = cryptoconf.get("keychain_uid")
        seen_cache_keys = set()
        for key_cipher_layer in _iter_asymmetric_key_cipher_layers(cryptoconf):
            trustee = key_cipher_layer["key_cipher_trustee"]
            trustee_type = trustee["trustee_type"]
            key_algo = key_cipher_layer["key_cipher_algo"]
            keychain_uid = key_cipher_layer.get("keychain_uid") or root_keychain_uid  # Like the flightbox core
            if not keychain_uid or trustee_type == CRYPTAINER_TRUSTEE_TYPES.JSONRPC_API_TRUSTEE:
                continue
            cache_key = (get_trustee_id(trustee), key_algo, keychain_uid)
            if cache_key in seen_cache_keys:
                continue
            seen_cache_keys.add(cache_key)
            try:
                public_key = self._fetch_and_check_public_key(
                    trustee, key_algo=key_algo, keychain_uid=keychain_uid, must_exist=True
                )
            except KeyDoesNotExist:
                if trustee_type != CRYPTAINER_TRUSTEE_TYPES.LOCAL_KEYFACTORY_TRUSTEE:
                    raise
                continue  # Will be generated on demand
            self._prefetched_public_keys[cache_key] = public_key

    def clear_prefetched_public_keys(self) -> None:
        self._prefetched_public_keys.clear()

    def encrypt_bytestring(self, plaintext: bytes, *, cipher_algo: str, key_dict: dict) -> dict:
        return encrypt_bytestring(plaintext=plaintext, cipher_algo=cipher_algo, key_dict=key_dict)


class CryptainerEncryptor(CryptainerBase):
    """
    THIS CLASS IS PRIVATE API

    Contains every method used to write and encrypt a cryptainer, IN MEMORY.

    :param key_ciphertext_format: document format ("json" or "cbor") of the structures serialized then encrypted
        into the key ciphertexts of produced cryptainers
    :param cryptainer_file_format: document format ("json" or "cbor") of the files which will store the produced
        cryptainers, if known: cryptoconfs nested too deeply for that format are then refused upfront
    """

    def __init__(
        self,
        signature_policy,
        key_ciphertext_format: str = KEY_CIPHERTEXT_FORMAT_JSON,
        cryptainer_file_format: Optional[str] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        if signature_policy is None:
            signature_policy = SIGNATURE_POLICIES.ATTEMPT_SIGNING  # Sensible default
        assert getattr(SIGNATURE_POLICIES, signature_policy), signature_policy
        self._signature_policy = signature_policy
        if key_ciphertext_format not in KEY_CIPHERTEXT_FORMATS:  # Not an assert (python -O)
            raise ValueError("Unknown key ciphertext format %r" % (key_ciphertext_format,))
        self._key_ciphertext_format = key_ciphertext_format
        if cryptainer_file_format is not None and cryptainer_file_format not in DOCUMENT_FORMATS:
            raise ValueError("Unknown cryptainer file format %r" % (cryptainer_file_format,))
        self._cryptainer_file_format = cryptainer_file_format

        self._flightbox_utilities = FlightboxUtilitiesImpl(logger=logger, keystore_pool=self._keystore_pool)
        self._flightbox = FlightBox(self._flightbox_utilities)

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
        if self._cryptainer_file_format is not None:  # Else a too deep cryptoconf only fails when dumping the result
            check_cryptoconf_fits_cryptainer_file_format(cryptoconf, self._cryptainer_file_format)
        check_cryptainer_metadata_sanity(cryptainer_metadata)  # Before any random draw, key generation or output
        cryptainer_metadata = copy.deepcopy(cryptainer_metadata)  # The validated cryptainer must not alias caller data

        try:
            self._flightbox_utilities.prefetch_local_public_keys(cryptoconf)  # Still before any random draw
            cryptainer, secrets = self._flightbox.generate_cryptainer_base_and_secrets(
                cryptoconf=cryptoconf,
                cryptainer_metadata=cryptainer_metadata,
                key_ciphertext_format=self._key_ciphertext_format,
            )
        finally:
            self._flightbox_utilities.clear_prefetched_public_keys()  # Keys may change before the next cryptainer
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
