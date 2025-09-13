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
import copy
import logging
import uuid
import typing


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

    def split_secret_into_shards(secret: bytes, *, shard_count: int, threshold_count: int) -> list:
        raise NotImplementedError

    def generate_symkey(self, cipher_algo: str):
        raise NotImplementedError

    def get_public_key(self, trustee: dict, key_algo: str, keychain_uid: uuid.UUID) -> dict:
        raise NotImplementedError

    def encrypt_bytestring(plaintext: bytes, *, cipher_algo: str, key_dict: dict) -> dict:
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


    def ________init__(self, signature_policy, **kwargs):
        if signature_policy is None:
            signature_policy = SIGNATURE_POLICIES.ATTEMPT_SIGNING  # Sensible default
        assert getattr(SIGNATURE_POLICIES, signature_policy), signature_policy
        self._signature_policy = signature_policy
        super().__init__(**kwargs)

    def ________build_cryptainer_and_encryption_pipeline(
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

    def _____encrypt_data(self, payload: Union[bytes, BinaryIO], *, cryptoconf: dict, cryptainer_metadata=None) -> dict:
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

        return cryptainer

    @staticmethod
    def ______load_all_payload_bytes(payload: Union[bytes, BinaryIO]):
        if hasattr(payload, "read"):  # File-like object
            logger.debug("Reading all data from open file handle %r", payload)
            payload_stream = payload
            payload = payload_stream.read()
            # DO NOT delete the file, e.g. it might come from CLI!
        assert isinstance(payload, bytes), payload
        ## FIXME LATER ADD THIS - assert payload, payload  # No encryption must be launched if we have no payload to process!
        return payload

    def ______encrypt_and_hash_payload(self, payload, payload_cipher_layer_extracts):
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
            ), payload_cipherdict  # Might contain integrity/authentication data too

            payload_ciphertext = payload_cipherdict.pop("ciphertext")  # Mandatory field
            assert isinstance(
                payload_ciphertext, bytes
            ), payload_ciphertext  # Same raw content as would be in offloaded payload file

            payload_digests = {
                payload_hash_algo: hash_message(payload_ciphertext, hash_algo=payload_hash_algo)
                for payload_hash_algo in payload_hash_algos
            }

            ciphertext_integrity_tags.append(
                dict(payload_macs=payload_cipherdict, payload_digests=payload_digests)  # Only remains tags, macs etc.
            )

            payload_current = payload_ciphertext

        return payload_current, ciphertext_integrity_tags

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
            assert isinstance(key_ciphertext, bytes), key_ciphertext
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
        assert isinstance(key_bytes, bytes), key_bytes
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

    def _____fetch_asymmetric_key_pem_from_trustee(self, trustee, key_algo, keychain_uid):
        """Method meant to be easily replaced by a mockup in tests"""
        trustee_proxy = get_trustee_proxy(trustee=trustee, keystore_pool=self._keystore_pool)
        logger.debug("Fetching asymmetric key %s %r", key_algo, keychain_uid)
        public_key_pem = trustee_proxy.fetch_public_key(keychain_uid=keychain_uid, key_algo=key_algo)
        return public_key_pem

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
        ''' TO MOVE TO MAIN WACRYPTOLIB
        public_key_pem = self._fetch_asymmetric_key_pem_from_trustee(
            trustee=trustee, key_algo=cipher_algo, keychain_uid=keychain_uid
        )

        logger.debug("Encrypting symmetric key struct with asymmetric keypair %s/%s", cipher_algo, keychain_uid)
        public_key = load_asymmetric_key_from_pem_bytestring(key_pem=public_key_pem, key_algo=cipher_algo)
        '''

        # FIXME provide utilities to wrap/unwrap this struct?
        key_struct = dict(key_bytes=key_bytes, cryptainer_metadata=cryptainer_metadata)  # SPECIAL FORMAT FOR CHECKUPS
        key_struct_bytes = self._fbu.dump_to_json_bytes(key_struct)
        key_cipherdict = self._fbu.encrypt_bytestring(
            plaintext=key_struct_bytes, cipher_algo=cipher_algo, key_dict=dict(key=public_key)
        )
        return key_cipherdict

    def ________add_authentication_data_to_cryptainer(self, cryptainer: dict, payload_integrity_tags: dict):
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

