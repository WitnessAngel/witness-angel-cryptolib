import copy
import logging
import math
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Union, Sequence, BinaryIO
from urllib.parse import urlparse

import jsonschema
import schema as pythonschema
from jsonschema import validate as jsonschema_validate
from schema import And, Or, Schema, Optional as OptionalKey

from wacryptolib.cipher import (
    encrypt_bytestring,
    decrypt_bytestring,
    PayloadEncryptionPipeline,
    STREAMABLE_CIPHER_ALGOS,
    SUPPORTED_CIPHER_ALGOS,
)
from wacryptolib.exceptions import DecryptionError, SchemaValidationError
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.keygen import generate_symkey, load_asymmetric_key_from_pem_bytestring, ASYMMETRIC_KEY_ALGOS_REGISTRY
from wacryptolib.keystore import InMemoryKeystorePool, KeystorePoolBase
from wacryptolib.shared_secret import split_secret_into_shards, recombine_secret_from_shards
from wacryptolib.signature import verify_message_signature, SUPPORTED_SIGNATURE_ALGOS
from wacryptolib.trustee import TrusteeApi, ReadonlyTrusteeApi
from wacryptolib.utilities import (
    dump_to_json_bytes,
    load_from_json_bytes,
    dump_to_json_file,
    load_from_json_file,
    generate_uuid0,
    hash_message,
    synchronized,
    catch_and_log_exception,
    get_utc_now_date,
    consume_bytes_as_chunks,
    delete_filesystem_node_for_stream,
    SUPPORTED_HASH_ALGOS,
    get_validation_micro_schemas,
)

logger = logging.getLogger(__name__)

CRYPTAINER_FORMAT = "cryptainer_1.0"
CRYPTAINER_SUFFIX = ".crypt"
CRYPTAINER_DATETIME_FORMAT = "%Y%m%d_%H%M%S"  # For use in cryptainer names and their records
CRYPTAINER_DATETIME_LENGTH = (
    15
)  # Important to lookup prefix of filename before matching it with CRYPTAINER_DATETIME_FORMAT
CRYPTAINER_TEMP_SUFFIX = "~"  # To name temporary, unfinalized, cryptainers


class PAYLOAD_CIPHERTEXT_LOCATIONS:
    INLINE = "inline"  # Ciphertext is included in the json cryptainer
    OFFLOADED = "offloaded"  # Ciphertext is in a nearby binary file


# Shortcut helper, should NOT be modified
OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER = dict(ciphertext_location=PAYLOAD_CIPHERTEXT_LOCATIONS.OFFLOADED)

OFFLOADED_PAYLOAD_FILENAME_SUFFIX = ".payload"  # Added to CRYPTAINER_SUFFIX

DATA_CHUNK_SIZE = 1024 ** 2  # E.g. when streaming a big payload through encryptors

DECRYPTED_FILE_SUFFIX = ".medium"  # To construct decrypted filename when no output filename is provided

SHARED_SECRET_ALGO_MARKER = "[SHARED_SECRET]"  # Special "key_cipher_algo" value

DUMMY_KEYSTORE_POOL = InMemoryKeystorePool()  # Common fallback storage with in-memory keys


class CRYPTAINER_TRUSTEE_TYPES:
    LOCAL_KEYFACTORY_TRUSTEE = "local_keyfactory"
    AUTHENTICATOR_TRUSTEE = "authenticator"
    JSONRPC_API_TRUSTEE = "jsonrpc_api"


# Shortcut helper, should NOT be modified
LOCAL_KEYFACTORY_TRUSTEE_MARKER = dict(trustee_type=CRYPTAINER_TRUSTEE_TYPES.LOCAL_KEYFACTORY_TRUSTEE)


class CRYPTAINER_STATES:
    STARTED = "STARTED"
    FINISHED = "FINISHED"


def _get_trustee_id(trustee_conf: dict) -> str:
    """Build opaque unique identifier for a specific trustee.

    Remains the same as long as trustee dict is completely unmodified.
    """
    return str(sorted(trustee_conf.items()))


def gather_trustee_dependencies(cryptainers: Sequence) -> dict:
    """Analyse a cryptainer and return the trustees (and their keypairs) used by it.

    :return: dict with lists of keypair identifiers in fields "encryption" and "signature".
    """

    signature_dependencies = {}
    cipher_dependencies = {}

    def _add_keypair_identifiers_for_trustee(mapper, trustee_conf, keychain_uid, key_algo):
        trustee_id = _get_trustee_id(trustee_conf=trustee_conf)
        keypair_identifiers = dict(keychain_uid=keychain_uid, key_algo=key_algo)
        mapper.setdefault(trustee_id, (trustee_conf, []))
        keypair_identifiers_list = mapper[trustee_id][1]
        if keypair_identifiers not in keypair_identifiers_list:
            keypair_identifiers_list.append(keypair_identifiers)

    def _grab_key_cipher_layers_dependencies(key_cipher_layers):
        for key_cipher_layer in key_cipher_layers:
            key_algo_encryption = key_cipher_layer["key_cipher_algo"]

            if key_algo_encryption == SHARED_SECRET_ALGO_MARKER:
                trustees = key_cipher_layer["key_shared_secret_shards"]
                for trustee in trustees:
                    _grab_key_cipher_layers_dependencies(trustee["key_cipher_layers"])  # Recursive call
            else:
                keychain_uid_encryption = key_cipher_layer.get("keychain_uid") or keychain_uid
                trustee_conf = key_cipher_layer["key_cipher_trustee"]
                _add_keypair_identifiers_for_trustee(
                    mapper=cipher_dependencies,
                    trustee_conf=trustee_conf,
                    keychain_uid=keychain_uid_encryption,
                    key_algo=key_algo_encryption,
                )

    for cryptainer in cryptainers:
        keychain_uid = cryptainer["keychain_uid"]
        for payload_cipher_layer in cryptainer["payload_cipher_layers"]:
            for signature_conf in payload_cipher_layer["payload_signatures"]:
                key_algo_signature = signature_conf["payload_signature_algo"]
                keychain_uid_signature = signature_conf.get("keychain_uid") or keychain_uid
                trustee_conf = signature_conf["payload_signature_trustee"]

                _add_keypair_identifiers_for_trustee(
                    mapper=signature_dependencies,
                    trustee_conf=trustee_conf,
                    keychain_uid=keychain_uid_signature,
                    key_algo=key_algo_signature,
                )

            _grab_key_cipher_layers_dependencies(payload_cipher_layer["key_cipher_layers"])

    trustee_dependencies = {"signature": signature_dependencies, "encryption": cipher_dependencies}
    return trustee_dependencies


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


def get_trustee_proxy(trustee: dict, keystore_pool: KeystorePoolBase):
    """
    Return an TrusteeApi subclass instance (or proxy) depending on the content of `trustee` dict.
    """
    assert isinstance(trustee, dict), trustee

    trustee_type = trustee.get("trustee_type")  # Might be None

    if trustee_type == CRYPTAINER_TRUSTEE_TYPES.LOCAL_KEYFACTORY_TRUSTEE:
        return TrusteeApi(keystore_pool.get_local_keyfactory())
    elif trustee_type == CRYPTAINER_TRUSTEE_TYPES.AUTHENTICATOR_TRUSTEE:
        keystore_uid = trustee["keystore_uid"]  # ID of authenticator is identical to that of its keystore
        keystore = keystore_pool.get_foreign_keystore(keystore_uid)
        return ReadonlyTrusteeApi(keystore)
    elif trustee_type == CRYPTAINER_TRUSTEE_TYPES.JSONRPC_API_TRUSTEE:
        return JsonRpcProxy(url=trustee["url"], response_error_handler=status_slugs_response_error_handler)
    raise ValueError("Unrecognized trustee identifiers: %s" % str(trustee))


class CryptainerBase:
    """
    THIS CLASS IS PRIVATE API

    `keystore_pool` will be used to fetch local/imported trustees necessary to encryption/decryption operations.

    `passphrase_mapper` maps trustees IDs to potential passphrases; a None key can be used to provide additional
    passphrases for all trustees.
    """

    def __init__(self, keystore_pool: KeystorePoolBase = None, passphrase_mapper: Optional[dict] = None):
        if not keystore_pool:
            logger.warning(
                "No key storage pool provided for %s instance, falling back to common InMemoryKeystorePool()",
                self.__class__.__name__,
            )
            keystore_pool = DUMMY_KEYSTORE_POOL
        assert isinstance(keystore_pool, KeystorePoolBase), keystore_pool
        self._keystore_pool = keystore_pool
        self._passphrase_mapper = passphrase_mapper or {}


class CryptainerEncryptor(CryptainerBase):
    """
    THIS CLASS IS PRIVATE API

    Contains every method used to write and encrypt a cryptainer, IN MEMORY.
    """

    def build_cryptainer_and_encryption_pipeline(
        self, *, cryptoconf: dict, output_stream: BinaryIO, keychain_uid=None, cryptainer_metadata=None
    ) -> tuple:
        """
        Build a base cryptainer to store encrypted keys, as well as a stream encryptor
        meant to process heavy payload chunk by chunk.

        Signatures, and final ciphertext (if not offloaded), will have to be added
        later to the cryptainer.

        :param cryptoconf: configuration tree
        :param output_stream: open file where the stream encryptor should write to
        :param keychain_uid: uuid for the set of encryption keys used
        :param cryptainer_metadata: additional informations to store unencrypted in cryptainer

        :return: cryptainer with all the information needed to attempt payload decryption
        """

        cryptainer, payload_cipher_layer_extracts = self._generate_cryptainer_base_and_secrets(
            cryptoconf=cryptoconf, keychain_uid=keychain_uid, cryptainer_metadata=cryptainer_metadata
        )

        encryption_pipeline = PayloadEncryptionPipeline(
            output_stream=output_stream, payload_cipher_layer_extracts=payload_cipher_layer_extracts
        )

        return cryptainer, encryption_pipeline

    def encrypt_data(
        self, payload: Union[bytes, BinaryIO], *, cryptoconf: dict, keychain_uid=None, cryptainer_metadata=None
    ) -> dict:
        """
        Shortcut when data is already available.

        This method browses through configuration tree to apply the right succession of encryption+signature algorithms to data.

        :param payload: initial plaintext, or file pointer (file immediately deleted then)
        :param cryptoconf: configuration tree
        :param keychain_uid: uuid for the set of encryption keys used
        :param cryptainer_metadata: additional data to store unencrypted in cryptainer

        :return: cryptainer with all the information needed to attempt data decryption
        """

        payload = self._load_payload_bytes_and_cleanup(payload)  # Ensure we get the whole payload buffer

        cryptainer, payload_cipher_layer_extracts = self._generate_cryptainer_base_and_secrets(
            cryptoconf=cryptoconf, keychain_uid=keychain_uid, cryptainer_metadata=cryptainer_metadata
        )

        payload_ciphertext, payload_integrity_tags = self._encrypt_and_hash_payload(
            payload, payload_cipher_layer_extracts
        )

        cryptainer["payload_ciphertext_struct"] = dict(
            ciphertext_location=PAYLOAD_CIPHERTEXT_LOCATIONS.INLINE, ciphertext_value=payload_ciphertext
        )

        self.add_authentication_data_to_cryptainer(cryptainer, payload_integrity_tags)

        return cryptainer

    @staticmethod
    def _load_payload_bytes_and_cleanup(payload: Union[bytes, BinaryIO]):
        """Automatically deletes filesystem entry if it exists!"""
        if hasattr(payload, "read"):  # File-like object
            logger.debug("Reading and deleting open file handle %s", payload)
            payload_stream = payload
            payload = payload_stream.read()
            payload_stream.close()
            delete_filesystem_node_for_stream(payload_stream)
        assert isinstance(payload, bytes), payload
        ## FIXME LATER ADD THIS - assert payload, payload  # No encryption must be launched if we have no payload to process!
        return payload

    def _encrypt_and_hash_payload(self, payload, payload_cipher_layer_extracts):

        payload_current = payload

        payload_integrity_tags = []

        for payload_cipher_layer_extract in payload_cipher_layer_extracts:
            payload_cipher_algo = payload_cipher_layer_extract["cipher_algo"]
            symkey = payload_cipher_layer_extract["symkey"]
            payload_digest_algos = payload_cipher_layer_extract["payload_digest_algos"]

            logger.debug("Encrypting payload with symmetric key of type %r", payload_cipher_algo)
            payload_cipherdict = encrypt_bytestring(
                plaintext=payload_current, cipher_algo=payload_cipher_algo, key_dict=symkey
            )
            assert isinstance(
                payload_cipherdict, dict
            ), payload_cipherdict  # Might contain integrity/authentication payload

            payload_ciphertext = payload_cipherdict.pop("ciphertext")  # Mandatory field
            assert isinstance(
                payload_ciphertext, bytes
            ), payload_ciphertext  # Same raw content as would be in offloaded payload file

            payload_digests = {
                payload_digest_algo: hash_message(payload_ciphertext, hash_algo=payload_digest_algo)
                for payload_digest_algo in payload_digest_algos
            }

            payload_integrity_tags.append(
                dict(payload_macs=payload_cipherdict, payload_digests=payload_digests)  # Only remains tags, macs etc.
            )

            payload_current = payload_ciphertext

        return payload_current, payload_integrity_tags

    def _generate_cryptainer_base_and_secrets(
        self, cryptoconf: dict, keychain_uid=None, cryptainer_metadata=None
    ) -> tuple:
        """
        Build a payload-less and signature-less cryptainer, preconfigured with a set of symmetric keys
        under their final form (encrypted by trustees). A separate extract, with symmetric keys as well as algo names, is returned so that actual payload encryption and signature can be performed separately.

        :param cryptoconf: configuration tree
        :param keychain_uid: uuid for the set of encryption keys used
        :param cryptainer_metadata: additional payload to store unencrypted in cryptainer, and also inside encrypted keys/shards

        :return: a (cryptainer: dict, secrets: list) tuple, where each secret has keys cipher_algo, symmetric_key and payload_digest_algos.
        """

        assert cryptainer_metadata is None or isinstance(cryptainer_metadata, dict), cryptainer_metadata
        cryptainer_format = CRYPTAINER_FORMAT
        cryptainer_uid = generate_uuid0()  # ALWAYS UNIQUE!
        keychain_uid = keychain_uid or generate_uuid0()  # Might be shared by lots of cryptainers

        assert isinstance(cryptoconf, dict), cryptoconf
        cryptainer = copy.deepcopy(cryptoconf)  # So that we can manipulate it as new cryptainer
        del cryptoconf
        if not cryptainer["payload_cipher_layers"]:
            raise SchemaValidationError("Empty payload_cipher_layers list is forbidden in cryptoconf")

        payload_cipher_layer_extracts = []  # Sensitive info with secret keys!

        for payload_cipher_layer in cryptainer["payload_cipher_layers"]:
            payload_cipher_algo = payload_cipher_layer["payload_cipher_algo"]

            payload_cipher_layer["payload_macs"] = None  # Will be filled later with MAC tags etc.

            logger.debug("Generating symmetric key of type %r", payload_cipher_algo)
            symkey = generate_symkey(cipher_algo=payload_cipher_algo)
            key_bytes = dump_to_json_bytes(symkey)
            key_cipher_layers = payload_cipher_layer["key_cipher_layers"]

            key_ciphertext = self._encrypt_key_through_multiple_layers(
                keychain_uid=keychain_uid,
                key_bytes=key_bytes,
                key_cipher_layers=key_cipher_layers,
                cryptainer_metadata=cryptainer_metadata,
            )
            payload_cipher_layer["key_ciphertext"] = key_ciphertext

            payload_cipher_layer_extract = dict(
                cipher_algo=payload_cipher_algo,
                symkey=symkey,
                payload_digest_algos=[
                    signature["payload_digest_algo"] for signature in payload_cipher_layer["payload_signatures"]
                ],
            )
            payload_cipher_layer_extracts.append(payload_cipher_layer_extract)

        cryptainer.update(
            cryptainer_state=CRYPTAINER_STATES.STARTED,
            cryptainer_format=cryptainer_format,
            cryptainer_uid=cryptainer_uid,
            keychain_uid=keychain_uid,
            payload_ciphertext_struct=None,  # Must be filled asap, by OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER if needed!
            cryptainer_metadata=cryptainer_metadata,
        )
        return cryptainer, payload_cipher_layer_extracts

    def _encrypt_key_through_multiple_layers(
        self, keychain_uid: uuid.UUID, key_bytes: bytes, key_cipher_layers: list, cryptainer_metadata: Optional[dict]
    ) -> bytes:
        # HERE KEY IS REAL KEY OR SHARE !!!

        if not key_cipher_layers:
            raise SchemaValidationError("Empty key_cipher_layers list is forbidden in cryptoconf")

        key_ciphertext = key_bytes
        for key_cipher_layer in key_cipher_layers:
            key_ciphertext_dict = self._encrypt_key_through_single_layer(
                keychain_uid=keychain_uid,
                key_bytes=key_ciphertext,
                key_cipher_layer=key_cipher_layer,
                cryptainer_metadata=cryptainer_metadata,
            )
            key_ciphertext = dump_to_json_bytes(key_ciphertext_dict)  # Thus its remains as bytes all along

        return key_ciphertext

    def _encrypt_key_through_single_layer(
        self, keychain_uid: uuid.UUID, key_bytes: bytes, key_cipher_layer: dict, cryptainer_metadata: Optional[dict]
    ) -> dict:
        """
        Encrypt a symmetric key using an asymmetric encryption scheme.

        The symmetric key payload might already be the result of previous encryption passes.
        Encryption can use a simple public key algorithm, or rely on a a set of public keys,
        by using a shared secret scheme.

        :param keychain_uid: uuid for the set of encryption keys used
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
            assert threshold_count <= shard_count

            logger.debug("Generating shared secret shards (%d needed amongst %d)", threshold_count, shard_count)

            shards = split_secret_into_shards(
                secret=key_bytes, shard_count=shard_count, threshold_count=threshold_count
            )

            logger.debug("Secret has been shared into %d shards", shard_count)
            assert len(shards) == shard_count

            shard_ciphertexts = []

            for shard, trustee_conf in zip(shards, key_shared_secret_shards):
                shard_bytes = dump_to_json_bytes(
                    shard
                )  # The tuple (idx, payload) of each shard thus becomes encryptable
                shard_ciphertext = self._encrypt_key_through_multiple_layers(
                    keychain_uid=keychain_uid,
                    key_bytes=shard_bytes,
                    key_cipher_layers=trustee_conf["key_cipher_layers"],
                    cryptainer_metadata=cryptainer_metadata,
                )  # Recursive structure
                shard_ciphertexts.append(shard_ciphertext)

            key_cipherdict = {"shard_ciphertexts": shard_ciphertexts}  # A dict is more future-proof

        else:  # Using asymmetric algorithm

            keychain_uid_encryption = key_cipher_layer.get("keychain_uid") or keychain_uid
            key_cipherdict = self._encrypt_with_asymmetric_cipher(
                cipher_algo=key_cipher_algo,
                keychain_uid=keychain_uid_encryption,
                key_bytes=key_bytes,
                trustee=key_cipher_layer["key_cipher_trustee"],
                cryptainer_metadata=cryptainer_metadata,
            )

        return key_cipherdict

    def _encrypt_with_asymmetric_cipher(
        self,
        cipher_algo: str,
        keychain_uid: uuid.UUID,
        key_bytes: bytes,
        trustee: dict,
        cryptainer_metadata: Optional[dict],
    ) -> dict:
        """
        Encrypt given payload (representing a symmetric key) with an asymmetric algorithm.

        :param cipher_algo: string with name of algorithm to use
        :param keychain_uid: uuid for the set of encryption keys used
        :param key_bytes: symmetric key as bytes to encrypt
        :param trustee: trustee used for encryption (findable in configuration tree)

        :return: dictionary which contains every payload needed to decrypt the ciphered payload
        """
        trustee_proxy = get_trustee_proxy(trustee=trustee, keystore_pool=self._keystore_pool)

        logger.debug("Generating asymmetric key of type %r", cipher_algo)
        public_key_pem = trustee_proxy.fetch_public_key(keychain_uid=keychain_uid, key_algo=cipher_algo)

        logger.debug("Encrypting symmetric key struct with asymmetric key of type %r", cipher_algo)
        public_key = load_asymmetric_key_from_pem_bytestring(key_pem=public_key_pem, key_algo=cipher_algo)

        key_struct = dict(key_bytes=key_bytes, cryptainer_metadata=cryptainer_metadata)  # SPECIAL FORMAT FOR CHECKUPS
        key_struct_bytes = dump_to_json_bytes(key_struct)
        cipherdict = encrypt_bytestring(
            plaintext=key_struct_bytes, cipher_algo=cipher_algo, key_dict=dict(key=public_key)
        )
        return cipherdict

    def add_authentication_data_to_cryptainer(self, cryptainer: dict, payload_integrity_tags: list):
        keychain_uid = cryptainer["keychain_uid"]

        payload_cipher_layers = cryptainer["payload_cipher_layers"]
        assert len(payload_cipher_layers) == len(payload_integrity_tags)  # Sanity check

        for payload_cipher_layer, payload_integrity_tags_dict in zip(
            cryptainer["payload_cipher_layers"], payload_integrity_tags
        ):

            assert payload_cipher_layer["payload_macs"] is None  # Set at cryptainer build time
            payload_cipher_layer["payload_macs"] = payload_integrity_tags_dict["payload_macs"]

            payload_digests = payload_integrity_tags_dict["payload_digests"]

            _encountered_payload_digest_algos = set()
            for signature_conf in payload_cipher_layer["payload_signatures"]:
                payload_digest_algo = signature_conf["payload_digest_algo"]

                signature_conf["payload_digest_value"] = payload_digests[
                    payload_digest_algo
                ]  # MUST exist, else incoherence

                payload_signature_struct = self._generate_message_signature(
                    keychain_uid=keychain_uid, cryptoconf=signature_conf
                )
                signature_conf["payload_signature_struct"] = payload_signature_struct

                _encountered_payload_digest_algos.add(payload_digest_algo)
            assert _encountered_payload_digest_algos == set(payload_digests)  # No abnormal extra digest

        cryptainer["cryptainer_state"] = CRYPTAINER_STATES.FINISHED

    def _generate_message_signature(self, keychain_uid: uuid.UUID, cryptoconf: dict) -> dict:
        """
        Generate a signature for a specific ciphered payload.

        :param keychain_uid: uuid for the set of encryption keys used
        :param cryptoconf: configuration tree inside payload_signatures, which MUST already contain the message digest
        :return: dictionary with information needed to verify_integrity_tags signature
        """
        payload_signature_algo = cryptoconf["payload_signature_algo"]
        payload_digest = cryptoconf[
            "payload_digest_value"
        ]  # Must have been set before, using payload_digest_algo field
        assert payload_digest, payload_digest

        trustee_proxy = get_trustee_proxy(
            trustee=cryptoconf["payload_signature_trustee"], keystore_pool=self._keystore_pool
        )

        keychain_uid_signature = cryptoconf.get("keychain_uid") or keychain_uid

        logger.debug("Signing hash of encrypted payload with algo %r", payload_signature_algo)
        payload_signature_struct = trustee_proxy.get_message_signature(
            keychain_uid=keychain_uid_signature, message=payload_digest, signature_algo=payload_signature_algo
        )
        return payload_signature_struct


def _get_cryptainer_inline_ciphertext_value(cryptainer):
    assert "payload_ciphertext_struct" in cryptainer, list(cryptainer.keys())
    payload_ciphertext_struct = cryptainer["payload_ciphertext_struct"]
    assert (
        payload_ciphertext_struct["ciphertext_location"] == PAYLOAD_CIPHERTEXT_LOCATIONS.INLINE
    ), payload_ciphertext_struct["ciphertext_location"]
    ciphertext_value = payload_ciphertext_struct["ciphertext_value"]
    assert isinstance(ciphertext_value, bytes), repr(ciphertext_value)  # Always (no more "special markers")
    return ciphertext_value


class CryptainerDecryptor(CryptainerBase):
    """
    THIS CLASS IS PRIVATE API

    Contains every method used to read and decrypt a cryptainer, IN MEMORY.
    """

    def extract_cryptainer_metadata(self, cryptainer: dict) -> Optional[dict]:
        assert isinstance(cryptainer, dict), cryptainer
        return cryptainer["cryptainer_metadata"]

    def decrypt_payload(self, cryptainer: dict, verify_integrity_tags: bool = True) -> bytes:
        """
        Loop through cryptainer layers, to decipher payload with the right algorithms.

        :param cryptainer: dictionary previously built with CryptainerEncryptor method
        :param verify_integrity_tags: whether to check MAC tags of the ciphertext

        :return: deciphered plaintext
        """
        assert isinstance(cryptainer, dict), cryptainer

        cryptainer_format = cryptainer["cryptainer_format"]
        if cryptainer_format != CRYPTAINER_FORMAT:
            raise ValueError("Unknown cryptainer format %s" % cryptainer_format)

        cryptainer_uid = cryptainer["cryptainer_uid"]
        del cryptainer_uid  # Might be used for logging etc, later...

        keychain_uid = cryptainer["keychain_uid"]

        cryptainer_metadata = cryptainer["cryptainer_metadata"]

        payload_current = _get_cryptainer_inline_ciphertext_value(cryptainer)

        for payload_cipher_layer in reversed(
            cryptainer["payload_cipher_layers"]
        ):  # Non-emptiness of this will be checked by validator

            payload_cipher_algo = payload_cipher_layer["payload_cipher_algo"]

            for signature_conf in payload_cipher_layer["payload_signatures"]:
                self._verify_payload_signature(
                    keychain_uid=keychain_uid, payload=payload_current, cryptoconf=signature_conf
                )

            key_ciphertext = payload_cipher_layer["key_ciphertext"]  # We start fully encrypted, and unravel it

            key_bytes = self._decrypt_key_through_multiple_layers(
                keychain_uid=keychain_uid,
                key_ciphertext=key_ciphertext,
                cipher_layers=payload_cipher_layer["key_cipher_layers"],
                cryptainer_metadata=cryptainer_metadata,
            )
            assert isinstance(key_bytes, bytes), key_bytes
            symkey = load_from_json_bytes(key_bytes)

            payload_macs = payload_cipher_layer[
                "payload_macs"
            ]  # FIXME handle if it's not there, missing integrity tags due to unfinished container!!
            payload_cipherdict = dict(ciphertext=payload_current, **payload_macs)
            payload_current = decrypt_bytestring(
                cipherdict=payload_cipherdict,
                key_dict=symkey,
                cipher_algo=payload_cipher_algo,
                verify_integrity_tags=verify_integrity_tags,
            )

        data = payload_current  # Now decrypted
        return data

    def _decrypt_key_through_multiple_layers(
        self, keychain_uid: uuid.UUID, key_ciphertext: bytes, cipher_layers: list, cryptainer_metadata: Optional[dict]
    ) -> bytes:
        key_bytes = key_ciphertext

        for key_cipher_layer in reversed(cipher_layers):  # Non-emptiness of this will be checked by validator
            key_cipherdict = load_from_json_bytes(key_bytes)  # We remain as bytes all along
            key_bytes = self._decrypt_key_through_single_layer(
                keychain_uid=keychain_uid,
                key_cipherdict=key_cipherdict,
                cipher_layer=key_cipher_layer,
                cryptainer_metadata=cryptainer_metadata,
            )

        return key_bytes

    def _decrypt_key_through_single_layer(
        self, keychain_uid: uuid.UUID, key_cipherdict: dict, cipher_layer: dict, cryptainer_metadata: Optional[dict]
    ) -> bytes:
        """
        Function called when decryption of a symmetric key is needed. Encryption may be made by shared secret or
        by a asymmetric algorithm.

        :param keychain_uid: uuid for the set of encryption keys used
        :param key_cipherdict: dictionary with input data needed to decrypt symmetric key
        :param cipher_layer: part of the cryptainer related to this key encryption layer

        :return: deciphered symmetric key
        """
        assert isinstance(key_cipherdict, dict), key_cipherdict
        key_cipher_algo = cipher_layer["key_cipher_algo"]

        if key_cipher_algo == SHARED_SECRET_ALGO_MARKER:

            decrypted_shards = []
            decryption_errors = []
            key_shared_secret_shards = cipher_layer["key_shared_secret_shards"]
            key_shared_secret_threshold = cipher_layer["key_shared_secret_threshold"]

            shard_ciphertexts = key_cipherdict["shard_ciphertexts"]

            logger.debug("Deciphering each shard")

            # If some shards are missing, we won't detect it here because zip() stops at shortest list
            for shard_ciphertext, trustee_conf in zip(shard_ciphertexts, key_shared_secret_shards):

                try:
                    shard_bytes = self._decrypt_key_through_multiple_layers(
                        keychain_uid=keychain_uid,
                        key_ciphertext=shard_ciphertext,
                        cipher_layers=trustee_conf["key_cipher_layers"],
                        cryptainer_metadata=cryptainer_metadata,
                    )  # Recursive structure
                    shard = load_from_json_bytes(
                        shard_bytes
                    )  # The tuple (idx, payload) of each shard thus becomes encryptable
                    decrypted_shards.append(shard)

                # FIXME use custom exceptions here, when all are properly translated (including ValueError...)
                except Exception as exc:  # If actual trustee doesn't work, we can go to next one
                    decryption_errors.append(exc)
                    logger.error("Error when decrypting shard of %s: %r" % (trustee_conf, exc), exc_info=True)

                if len(decrypted_shards) == key_shared_secret_threshold:
                    logger.debug("A sufficient number of shards has been decrypted")
                    break

            if len(decrypted_shards) < key_shared_secret_threshold:
                raise DecryptionError(
                    "%s valid shard(s) missing for reconstitution of symmetric key (errors: %r)"
                    % (key_shared_secret_threshold - len(decrypted_shards), decryption_errors)
                )

            logger.debug("Recombining shared-secret shards")
            key_bytes = recombine_secret_from_shards(shards=decrypted_shards)
            return key_bytes

        else:  # Using asymmetric algorithm

            keychain_uid_encryption = cipher_layer.get("keychain_uid") or keychain_uid

            key_bytes = self._decrypt_with_asymmetric_cipher(
                cipher_algo=key_cipher_algo,
                keychain_uid=keychain_uid_encryption,
                cipherdict=key_cipherdict,
                trustee=cipher_layer["key_cipher_trustee"],
                cryptainer_metadata=cryptainer_metadata,
            )
            return key_bytes

    def _decrypt_with_asymmetric_cipher(
        self,
        cipher_algo: str,
        keychain_uid: uuid.UUID,
        cipherdict: dict,
        trustee: dict,
        cryptainer_metadata: Optional[dict],
    ) -> bytes:
        """
        Decrypt given cipherdict with an asymmetric algorithm.

        :param cipher_algo: string with name of algorithm to use
        :param keychain_uid: uuid for the set of encryption keys used
        :param cipherdict: dictionary with payload components needed to decrypt the ciphered payload
        :param trustee: trustee used for encryption (findable in configuration tree)

        :return: decypted payload as bytes
        """
        trustee_proxy = get_trustee_proxy(trustee=trustee, keystore_pool=self._keystore_pool)

        trustee_id = _get_trustee_id(trustee)
        passphrases = self._passphrase_mapper.get(trustee_id) or []
        assert isinstance(passphrases, list), repr(passphrases)  # No SINGLE passphrase here

        passphrases += self._passphrase_mapper.get(None) or []  # Add COMMON passphrases

        # We expect decryption authorization requests to have already been done properly
        key_struct_bytes = trustee_proxy.decrypt_with_private_key(
            keychain_uid=keychain_uid,
            cipher_algo=cipher_algo,
            cipherdict=cipherdict,
            passphrases=passphrases,
            cryptainer_metadata=cryptainer_metadata,
        )
        key_struct = load_from_json_bytes(key_struct_bytes)

        actual_cryptainer_metadata = key_struct["cryptainer_metadata"]  # Metadata stored along the encrypted key!
        del actual_cryptainer_metadata  # No use for now

        key_bytes = key_struct["key_bytes"]
        assert isinstance(key_bytes, bytes), key_bytes
        return key_bytes

    def _verify_payload_signature(self, keychain_uid: uuid.UUID, payload: bytes, cryptoconf: dict):
        """
        Verify a signature for a specific message. An error is raised if signature isn't correct.

        :param keychain_uid: uuid for the set of encryption keys used
        :param payload: payload on which to verify signature (after digest)
        :param cryptoconf: configuration tree inside payload_signatures
        """
        payload_digest_algo = cryptoconf["payload_digest_algo"]
        payload_signature_algo = cryptoconf["payload_signature_algo"]
        keychain_uid_signature = cryptoconf.get("keychain_uid") or keychain_uid
        trustee_proxy = get_trustee_proxy(
            trustee=cryptoconf["payload_signature_trustee"], keystore_pool=self._keystore_pool
        )
        public_key_pem = trustee_proxy.fetch_public_key(
            keychain_uid=keychain_uid_signature, key_algo=payload_signature_algo, must_exist=True
        )
        public_key = load_asymmetric_key_from_pem_bytestring(key_pem=public_key_pem, key_algo=payload_signature_algo)

        payload_digest = hash_message(payload, hash_algo=payload_digest_algo)

        expected_payload_digest = cryptoconf.get("payload_digest_value")  # Might be missing
        if expected_payload_digest and expected_payload_digest != payload_digest:
            raise RuntimeError(
                "Mismatch between actual and expected payload digests during signature verification"
            )  # FIXME improve that

        payload_signature_struct = cryptoconf.get("payload_signature_struct")
        if not payload_signature_struct:
            raise RuntimeError("Missing signature structure")  # FIXME improve that

        verify_message_signature(
            message=payload_digest,
            signature_algo=payload_signature_algo,
            signature=payload_signature_struct,
            key=public_key,
        )  # Raises if troubles


class CryptainerEncryptionPipeline:
    """
    Helper which prebuilds a cryptainer without signatures nor payload,
    fills its offloaded ciphertext file chunk by chunk, and then
    dumps the final cryptainer (now containing signatures).
    """

    def __init__(
        self,
        cryptainer_filepath: Path,
        *,
        cryptoconf: dict,
        cryptainer_metadata: Optional[dict],
        keychain_uid: Optional[uuid.UUID] = None,
        keystore_pool: Optional[KeystorePoolBase] = None,
        dump_initial_cryptainer=True
    ):

        self._cryptainer_filepath = cryptainer_filepath
        self._cryptainer_filepath_temp = cryptainer_filepath.with_suffix(
            cryptainer_filepath.suffix + CRYPTAINER_TEMP_SUFFIX
        )

        offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
        self._output_data_stream = open(offloaded_file_path, mode="wb")

        self._cryptainer_decryptor = CryptainerEncryptor(keystore_pool=keystore_pool)
        self._wip_cryptainer, self._encryption_pipeline = self._cryptainer_decryptor.build_cryptainer_and_encryption_pipeline(
            output_stream=self._output_data_stream,
            cryptoconf=cryptoconf,
            keychain_uid=keychain_uid,
            cryptainer_metadata=cryptainer_metadata,
        )
        self._wip_cryptainer["payload_ciphertext_struct"] = OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER  # Important

        if dump_initial_cryptainer:  # Savegame in case the stream is broken before finalization
            self._dump_current_cryptainer_to_filesystem(is_temporary=True)

    def _dump_current_cryptainer_to_filesystem(self, is_temporary):
        filepath = self._cryptainer_filepath_temp if is_temporary else self._cryptainer_filepath
        dump_cryptainer_to_filesystem(
            filepath, cryptainer=self._wip_cryptainer, offload_payload_ciphertext=False
        )  # ALREADY offloaded
        if not is_temporary:  # Cleanup temporary cryptainer
            try:
                self._cryptainer_filepath_temp.unlink()  # TODO use missing_ok=True later
            except FileNotFoundError:
                pass

    def encrypt_chunk(self, chunk: bytes):
        self._encryption_pipeline.encrypt_chunk(chunk)

    def finalize(self):
        self._encryption_pipeline.finalize()  # Would raise if statemachine incoherence
        self._output_data_stream.close()  # Important

        payload_integrity_tags = self._encryption_pipeline.get_payload_integrity_tags()

        self._cryptainer_decryptor.add_authentication_data_to_cryptainer(self._wip_cryptainer, payload_integrity_tags)
        self._dump_current_cryptainer_to_filesystem(is_temporary=False)

    def __del__(self):
        # Emergency closing of open file on deletion
        if not self._output_data_stream.closed:
            logger.error(
                "Encountered abnormal open file in __del__ of CryptainerEncryptionPipeline: %s"
                % self._output_data_stream
            )
            self._output_data_stream.close()


def is_cryptainer_cryptoconf_streamable(cryptoconf):  # FIXME rename and add to docs and add separate tests
    for payload_cipher_layer in cryptoconf["payload_cipher_layers"]:
        if payload_cipher_layer["payload_cipher_algo"] not in STREAMABLE_CIPHER_ALGOS:
            return False
    return True


def encrypt_payload_and_stream_cryptainer_to_filesystem(
    payload: Union[bytes, BinaryIO],
    *,
    cryptainer_filepath,
    cryptoconf: dict,
    cryptainer_metadata: Optional[dict],
    keychain_uid: Optional[uuid.UUID] = None,
    keystore_pool: Optional[KeystorePoolBase] = None
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
        keychain_uid=keychain_uid,
        cryptainer_metadata=cryptainer_metadata,
        keystore_pool=keystore_pool,
        dump_initial_cryptainer=False,
    )

    for chunk in consume_bytes_as_chunks(payload, chunk_size=DATA_CHUNK_SIZE):
        encryptor.encrypt_chunk(chunk)

    encryptor.finalize()  # Handles the dumping to disk


def encrypt_payload_into_cryptainer(
    payload: Union[bytes, BinaryIO],
    *,
    cryptoconf: dict,
    cryptainer_metadata: Optional[dict],
    keychain_uid: Optional[uuid.UUID] = None,
    keystore_pool: Optional[KeystorePoolBase] = None
) -> dict:
    """Turn a raw payload into a secure cryptainer, which can only be decrypted with
    the agreement of the owner and third-party trustees.

    :param payload: bytestring of media (image, video, sound...) or readable file object (file immediately deleted then)
    :param cryptoconf: tree of specific encryption settings
    :param cryptainer_metadata: dict of metadata describing the payload (remains unencrypted in cryptainer)
    :param keychain_uid: optional ID of a keychain to reuse
    :param keystore_pool: optional key storage pool, might be required by cryptoconf
    :return: dict of cryptainer
    """
    cryptainer_encryptor = CryptainerEncryptor(keystore_pool=keystore_pool)
    cryptainer = cryptainer_encryptor.encrypt_data(
        payload, cryptoconf=cryptoconf, keychain_uid=keychain_uid, cryptainer_metadata=cryptainer_metadata
    )
    return cryptainer


def decrypt_payload_from_cryptainer(
    cryptainer: dict,
    *,
    keystore_pool: Optional[KeystorePoolBase] = None,
    passphrase_mapper: Optional[dict] = None,
    verify_integrity_tags: bool = True
) -> bytes:
    """Decrypt a cryptainer with the help of third-parties.

    :param cryptainer: the cryptainer tree, which holds all information about involved keys
    :param keystore_pool: optional key storage pool
    :param passphrase_mapper: optional dict mapping trustee IDs to their lists of passphrases
    :param verify_integrity_tags: whether to check MAC tags of the ciphertext

    :return: raw bytestring
    """
    cryptainer_decryptor = CryptainerDecryptor(keystore_pool=keystore_pool, passphrase_mapper=passphrase_mapper)
    data = cryptainer_decryptor.decrypt_payload(cryptainer=cryptainer, verify_integrity_tags=verify_integrity_tags)
    return data


def extract_metadata_from_cryptainer(cryptainer: dict) -> Optional[dict]:
    """Read the metadata tree (possibly None) from a cryptainer.

    CURRENTLY CRYPTAINER METADATA ARE NEITHER ENCRYPTED NOR AUTHENTIFIED.

    :param cryptainer: the cryptainer tree, which also holds cryptainer_metadata about encrypted content

    :return: dict
    """
    reader = CryptainerDecryptor()
    cryptainer_metadata = reader.extract_cryptainer_metadata(cryptainer)
    return cryptainer_metadata


def get_cryptoconf_summary(conf_or_cryptainer):
    """
    Returns a string summary of the layers of encryption/signature of a cryptainer or a configuration tree.
    """

    def _get_trustee_displayable_identifier(_trustee):
        if _trustee == LOCAL_KEYFACTORY_TRUSTEE_MARKER:
            _trustee = "local device"
        elif "url" in _trustee:
            _trustee = urlparse(_trustee["url"]).netloc
        else:
            raise ValueError("Unrecognized key trustee %s" % _trustee)
        return _trustee

    lines = []
    for idx, payload_cipher_layer in enumerate(conf_or_cryptainer["payload_cipher_layers"], start=1):
        lines.append("Data encryption layer %d: %s" % (idx, payload_cipher_layer["payload_cipher_algo"]))
        lines.append("  Key encryption layers:")
        for idx2, key_cipher_layer in enumerate(payload_cipher_layer["key_cipher_layers"], start=1):
            key_cipher_trustee = key_cipher_layer["key_cipher_trustee"]
            trustee_id = _get_trustee_displayable_identifier(key_cipher_trustee)
            lines.append("    %s (by %s)" % (key_cipher_layer["key_cipher_algo"], trustee_id))
        lines.append("  Signatures:")
        for idx3, payload_signature in enumerate(payload_cipher_layer["payload_signatures"], start=1):
            payload_signature_trustee = payload_signature["payload_signature_trustee"]
            trustee_id = _get_trustee_displayable_identifier(payload_signature_trustee)
            lines.append(
                "    %s/%s (by %s)"
                % (payload_signature["payload_digest_algo"], payload_signature["payload_signature_algo"], trustee_id)
            )
    result = "\n".join(lines) + "\n"
    return result


def _get_offloaded_file_path(cryptainer_filepath: Path):
    """We also support, discreetly, TEMPORARY cryptainers"""
    return cryptainer_filepath.parent.joinpath(
        cryptainer_filepath.name.rstrip(CRYPTAINER_TEMP_SUFFIX) + OFFLOADED_PAYLOAD_FILENAME_SUFFIX
    )


def dump_cryptainer_to_filesystem(cryptainer_filepath: Path, cryptainer: dict, offload_payload_ciphertext=True) -> None:
    """Dump a cryptainer to a file path, overwritting it if existing.

    If `offload_payload_ciphertext`, actual encrypted payload is dumped to a separate bytes file nearby the json-formatted cryptainer.
    """
    if offload_payload_ciphertext:
        offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
        payload_ciphertext = _get_cryptainer_inline_ciphertext_value(cryptainer)
        offloaded_file_path.write_bytes(payload_ciphertext)
        cryptainer = cryptainer.copy()  # Shallow copy, since we DO NOT touch original dict here!
        cryptainer["payload_ciphertext_struct"] = OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER
    dump_to_json_file(cryptainer_filepath, cryptainer)


def load_cryptainer_from_filesystem(cryptainer_filepath: Path, include_payload_ciphertext=True) -> dict:
    """Load a json-formatted cryptainer from a file path, potentially loading its offloaded ciphertext from a separate nearby bytes file.

    Field `payload_ciphertext` is only present in result dict if `include_payload_ciphertext` is True.
    """

    cryptainer = load_from_json_file(cryptainer_filepath)

    if include_payload_ciphertext:
        if cryptainer["payload_ciphertext_struct"] == OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER:
            offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
            ciphertext_value = offloaded_file_path.read_bytes()
            cryptainer["payload_ciphertext_struct"] = dict(
                ciphertext_location=PAYLOAD_CIPHERTEXT_LOCATIONS.INLINE, ciphertext_value=ciphertext_value
            )
    else:
        del cryptainer["payload_ciphertext_struct"]  # Ensure that a nasty error pops if we try to access it

    return cryptainer


def delete_cryptainer_from_filesystem(cryptainer_filepath):
    """Delete a cryptainer file and its potential offloaded payload file."""
    os.remove(cryptainer_filepath)  # TODO - additional retries if file access errors?
    offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
    if offloaded_file_path.exists():
        # We don't care about OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER here, we go the quick way
        os.remove(offloaded_file_path)


def get_cryptainer_size_on_filesystem(cryptainer_filepath):
    """Return the total size in bytes occupied by a cryptainer and its potential offloaded payload file."""
    size = cryptainer_filepath.stat().st_size  # FIXME - Might fail if file got deleted concurrently
    offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
    if offloaded_file_path.exists():
        # We don't care about OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER here, we go the quick way
        size += offloaded_file_path.stat().st_size
    return size


# FIXME add ReadonlyCryptainerStorage here!!


class ReadonlyCryptainerStorage:
    """
    This class provides read access to a directory filled with cryptainers..

    :param cryptainers_dir: the folder where cryptainer files are stored
    :param keystore_pool: optional KeystorePool, which might be required by current cryptoconf
    """

    def __init__(self, cryptainer_dir: Path, keystore_pool: Optional[KeystorePoolBase] = None):
        cryptainer_dir = Path(cryptainer_dir).absolute()
        assert cryptainer_dir.is_dir(), cryptainer_dir
        self._cryptainer_dir = cryptainer_dir
        self._keystore_pool = keystore_pool  # Might be None, in this case fallback to in-memory pool

    def get_cryptainer_count(self):
        return len(self.list_cryptainer_names(as_absolute_paths=True))  # Fastest version

    def list_cryptainer_names(
        self, as_sorted_list: bool = False, as_absolute_paths: bool = False
    ):  # FIXME add function annotations everywhere in this class
        """Returns the list of encrypted cryptainers present in storage,
        sorted by name or not, absolute or not, as Path objects."""
        assert self._cryptainer_dir.is_absolute(), self._cryptainer_dir
        paths = list(self._cryptainer_dir.glob("*" + CRYPTAINER_SUFFIX))  # As list, for multiple looping on it
        assert all(p.is_absolute() for p in paths), paths
        if as_sorted_list:
            paths = sorted(paths)
        if not as_absolute_paths:
            paths = [Path(p.name) for p in paths]  # beware, only works since we don't have subfolders for now!
        assert isinstance(paths, list), paths
        return paths

    def _get_cryptainer_datetime_utc(self, cryptainer_name):
        """Returns an UTC datetime corresponding to the creation time stored in filename, or else the file-stat mtime"""
        try:
            dt = datetime.strptime(cryptainer_name.name[:CRYPTAINER_DATETIME_LENGTH], CRYPTAINER_DATETIME_FORMAT)
            dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            logger.warning(
                "Couldn't recognize timestamp in filename %s, falling back to file time", cryptainer_name.name
            )
            mtime = (
                self._make_absolute(cryptainer_name).stat().st_mtime
            )  # FIXME - Might fail if file got deleted concurrently
            dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
        return dt

    def _get_cryptainer_size(self, cryptainer_name):
        """Returns a size in bytes"""
        return get_cryptainer_size_on_filesystem(self._make_absolute(cryptainer_name))

    def list_cryptainer_properties(self, with_age=False, with_size=False):
        """Returns an unsorted list of dicts having the fields "name", [age] and [size], depending on requested properties."""
        cryptainer_names = self.list_cryptainer_names(as_sorted_list=False, as_absolute_paths=False)

        now = get_utc_now_date()

        result = []
        for cryptainer_name in cryptainer_names:
            entry = dict(name=cryptainer_name)
            if with_age:
                cryptainer_datetime = self._get_cryptainer_datetime_utc(cryptainer_name)
                entry["age"] = now - cryptainer_datetime  # We keep as timedelta
            if with_size:
                entry["size"] = self._get_cryptainer_size(cryptainer_name)
            result.append(entry)
        return result

    def _make_absolute(self, cryptainer_name):
        assert not Path(cryptainer_name).is_absolute()
        return self._cryptainer_dir.joinpath(cryptainer_name)

    def load_cryptainer_from_storage(self, cryptainer_name_or_idx, include_payload_ciphertext=True) -> dict:
        """
        Return the encrypted cryptainer dict for `cryptainer_name_or_idx` (which must be in `list_cryptainer_names()`,
        or an index suitable for this sorted list).
        """
        if isinstance(cryptainer_name_or_idx, int):
            cryptainer_names = self.list_cryptainer_names(as_sorted_list=True, as_absolute_paths=False)
            cryptainer_name = cryptainer_names[cryptainer_name_or_idx]  # Will break if idx is out of bounds
        else:
            assert isinstance(cryptainer_name_or_idx, (Path, str)), repr(cryptainer_name_or_idx)
            cryptainer_name = Path(cryptainer_name_or_idx)
        assert not cryptainer_name.is_absolute(), cryptainer_name

        logger.info("Loading cryptainer %s from storage", cryptainer_name)
        cryptainer_filepath = self._make_absolute(cryptainer_name)
        cryptainer = load_cryptainer_from_filesystem(
            cryptainer_filepath, include_payload_ciphertext=include_payload_ciphertext
        )
        return cryptainer

    def decrypt_cryptainer_from_storage(
        self, cryptainer_name_or_idx, passphrase_mapper: Optional[dict] = None, verify_integrity_tags: bool = True
    ) -> bytes:
        """
        Return the decrypted content of the cryptainer `cryptainer_name_or_idx` (which must be in `list_cryptainer_names()`,
        or an index suitable for this sorted list).
        """
        logger.info("Decrypting cryptainer %r from storage", cryptainer_name_or_idx)

        cryptainer = self.load_cryptainer_from_storage(cryptainer_name_or_idx, include_payload_ciphertext=True)

        result = self._decrypt_payload_from_cryptainer(
            cryptainer, passphrase_mapper=passphrase_mapper, verify_integrity_tags=verify_integrity_tags
        )
        logger.info("Cryptainer %s successfully decrypted", cryptainer_name_or_idx)
        return result

    def _decrypt_payload_from_cryptainer(
        self, cryptainer: dict, passphrase_mapper: Optional[dict], verify_integrity_tags: bool
    ) -> bytes:
        return decrypt_payload_from_cryptainer(
            cryptainer,
            keystore_pool=self._keystore_pool,
            passphrase_mapper=passphrase_mapper,
            verify_integrity_tags=verify_integrity_tags,
        )  # Will fail if authorizations are not OK

    def check_cryptainer_sanity(self, cryptainer_name_or_idx):
        """Allows the validation of a cryptainer with a python"""
        cryptainer = self.load_cryptainer_from_storage(cryptainer_name_or_idx, include_payload_ciphertext=True)

        check_cryptainer_sanity(cryptainer=cryptainer, jsonschema_mode=False)


class CryptainerStorage(ReadonlyCryptainerStorage):
    """
    This class encrypts file streams and stores them into filesystem, in a thread-safe way.

    Exceeding cryptainers are automatically purged when enqueuing new files or waiting for idle state.
    A thread pool is used to encrypt files in the background.

    :param cryptainers_dir: the folder where cryptainer files are stored
    :param keystore_pool: optional KeystorePool, which might be required by current cryptoconf
    :param default_cryptoconf: cryptoconf to use when none is provided when enqueuing payload
    :param max_cryptainer_quota: if set, cryptainers are deleted if they exceed this size in bytes
    :param max_cryptainer_count: if set, oldest exceeding cryptainers (time taken from their name, else their file-stats) are automatically erased
    :param max_cryptainer_age: if set, cryptainers exceeding this age (taken from their name, else their file-stats) in days are automatically erased
    :param max_workers: count of worker threads to use in parallel
    :param offload_payload_ciphertext: whether actual encrypted payload must be kept separated from structured cryptainer file
    """

    def __init__(
        self,
        cryptainer_dir: Path,
        keystore_pool: Optional[KeystorePoolBase] = None,
        default_cryptoconf: Optional[dict] = None,
        max_cryptainer_quota: Optional[int] = None,
        max_cryptainer_count: Optional[int] = None,
        max_cryptainer_age: Optional[timedelta] = None,
        max_workers: int = 1,
        offload_payload_ciphertext=True,
    ):
        super().__init__(cryptainer_dir=cryptainer_dir, keystore_pool=keystore_pool)
        assert max_cryptainer_quota is None or max_cryptainer_quota >= 0, max_cryptainer_quota
        assert max_cryptainer_count is None or max_cryptainer_count >= 0, max_cryptainer_count
        assert max_cryptainer_age is None or max_cryptainer_age >= timedelta(seconds=0), max_cryptainer_age
        self._default_cryptoconf = default_cryptoconf
        self._max_cryptainer_quota = max_cryptainer_quota
        self._max_cryptainer_count = max_cryptainer_count
        self._max_cryptainer_age = max_cryptainer_age
        self._thread_pool_executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="cryptainer_worker")
        self._pending_executor_futures = []
        self._lock = threading.Lock()
        self._offload_payload_ciphertext = offload_payload_ciphertext

    def __del__(self):
        self._thread_pool_executor.shutdown(wait=False)

    def _delete_cryptainer(self, cryptainer_name):
        cryptainer_filepath = self._make_absolute(cryptainer_name)
        delete_cryptainer_from_filesystem(cryptainer_filepath)

    def delete_cryptainer(self, cryptainer_name):
        logger.info("Deleting cryptainer %s" % cryptainer_name)
        self._delete_cryptainer(cryptainer_name=cryptainer_name)

    def _purge_exceeding_cryptainers(self):  # TODO LOG WHEN PURGING
        """Purge cryptainers first by date, then total quota, then count, depending on instance settings"""

        if self._max_cryptainer_age is not None:  # FIRST these, since their deletion is unconditional
            cryptainer_dicts = self.list_cryptainer_properties(with_age=True)
            for cryptainer_dict in cryptainer_dicts:
                if cryptainer_dict["age"] > self._max_cryptainer_age:
                    self._delete_cryptainer(cryptainer_dict["name"])

        if self._max_cryptainer_quota is not None:
            max_cryptainer_quota = self._max_cryptainer_quota

            cryptainer_dicts = self.list_cryptainer_properties(with_size=True, with_age=True)
            cryptainer_dicts.sort(key=lambda x: (-x["age"], x["name"]), reverse=True)  # Oldest last

            total_space_consumed = sum(x["size"] for x in cryptainer_dicts)

            while total_space_consumed > max_cryptainer_quota:
                deleted_cryptainer_dict = cryptainer_dicts.pop()
                self._delete_cryptainer(deleted_cryptainer_dict["name"])
                total_space_consumed -= deleted_cryptainer_dict["size"]

        if self._max_cryptainer_count is not None:
            cryptainer_dicts = self.list_cryptainer_properties(with_age=True)
            cryptainers_count = len(cryptainer_dicts)

            if cryptainers_count > self._max_cryptainer_count:
                assert cryptainers_count > 0, cryptainers_count
                excess_count = cryptainers_count - self._max_cryptainer_count
                cryptainer_dicts.sort(key=lambda x: (-x["age"], x["name"]))  # Oldest first
                deleted_cryptainer_dicts = cryptainer_dicts[:excess_count]
                for deleted_cryptainer_dict in deleted_cryptainer_dicts:
                    self._delete_cryptainer(deleted_cryptainer_dict["name"])

    def _encrypt_payload_and_stream_cryptainer_to_filesystem(
        self, payload, cryptainer_filepath, cryptainer_metadata, keychain_uid, cryptoconf
    ):
        assert cryptoconf, cryptoconf
        encrypt_payload_and_stream_cryptainer_to_filesystem(
            cryptainer_filepath=cryptainer_filepath,
            payload=payload,
            cryptoconf=cryptoconf,
            cryptainer_metadata=cryptainer_metadata,
            keychain_uid=keychain_uid,
            keystore_pool=self._keystore_pool,
        )

    def _encrypt_payload_into_cryptainer(self, payload, cryptainer_metadata, keychain_uid, cryptoconf):
        assert cryptoconf, cryptoconf
        return encrypt_payload_into_cryptainer(
            payload=payload,
            cryptoconf=cryptoconf,
            cryptainer_metadata=cryptainer_metadata,
            keychain_uid=keychain_uid,
            keystore_pool=self._keystore_pool,
        )

    @catch_and_log_exception
    def _offloaded_encrypt_payload_and_dump_cryptainer(
        self, filename_base, payload, cryptainer_metadata, keychain_uid, cryptoconf
    ):
        """Task to be called by background thread, which encrypts a payload into a disk cryptainer.

        Returns the cryptainer basename."""

        """ TODO later ass a SKIP here!
        if not payload:
            logger.warning("Skipping encryption of empty payload payload for file %s", filename_base)
            return
        """

        cryptainer_filepath = self._make_absolute(filename_base + CRYPTAINER_SUFFIX)

        if self._use_streaming_encryption_for_cryptoconf(cryptoconf):
            # We can use newer, low-memory, streamed API
            logger.debug(
                "Encrypting payload file %s into offloaded cryptainer directly streamed to storage file %s",
                filename_base,
                cryptainer_filepath,
            )
            self._encrypt_payload_and_stream_cryptainer_to_filesystem(
                payload,
                cryptainer_filepath=cryptainer_filepath,
                cryptainer_metadata=cryptainer_metadata,
                keychain_uid=keychain_uid,
                cryptoconf=cryptoconf,
            )

        else:
            # We use legacy API which encrypts all and then dumps all

            logger.debug("Encrypting payload file to self-sufficient cryptainer %s", filename_base)
            # Memory warning : duplicates payload to json-compatible cryptainer
            cryptainer = self._encrypt_payload_into_cryptainer(
                payload, cryptainer_metadata=cryptainer_metadata, keychain_uid=keychain_uid, cryptoconf=cryptoconf
            )
            logger.debug("Writing self-sufficient cryptainer payload to storage file %s", cryptainer_filepath)
            dump_cryptainer_to_filesystem(
                cryptainer_filepath, cryptainer=cryptainer, offload_payload_ciphertext=self._offload_payload_ciphertext
            )

        logger.info("Data file %r successfully encrypted into storage cryptainer", filename_base)
        return cryptainer_filepath.name

    def _use_streaming_encryption_for_cryptoconf(self, cryptoconf):
        return self._offload_payload_ciphertext and is_cryptainer_cryptoconf_streamable(cryptoconf)

    def _prepare_for_new_record_encryption(self, cryptoconf):
        """
        Validate arguments for new encryption, and purge obsolete things in storage.
        """
        cryptoconf = cryptoconf or self._default_cryptoconf
        if not cryptoconf:
            raise RuntimeError("Either default or file-specific cryptoconf must be provided to CryptainerStorage")

        self._purge_exceeding_cryptainers()
        self._purge_executor_results()
        return cryptoconf

    @synchronized
    def create_cryptainer_encryption_stream(
        self, filename_base, cryptainer_metadata, keychain_uid=None, cryptoconf=None, dump_initial_cryptainer=True
    ):
        logger.info("Enqueuing file %r for encryption and storage", filename_base)
        cryptainer_filepath = self._make_absolute(filename_base + CRYPTAINER_SUFFIX)
        cryptoconf = self._prepare_for_new_record_encryption(cryptoconf)
        cryptainer_encryption_stream = CryptainerEncryptionPipeline(
            cryptainer_filepath,
            cryptoconf=cryptoconf,
            cryptainer_metadata=cryptainer_metadata,
            keychain_uid=keychain_uid,
            keystore_pool=self._keystore_pool,
            dump_initial_cryptainer=dump_initial_cryptainer,
        )
        return cryptainer_encryption_stream

    @synchronized
    def enqueue_file_for_encryption(
        self, filename_base, payload, cryptainer_metadata, keychain_uid=None, cryptoconf=None
    ):
        """Enqueue a payload for asynchronous encryption and storage.

        The filename of final cryptainer might be different from provided one.
        And beware, target cryptainer with the same constructed name might be overwritten.

        :param payload: Bytes string, or a file-like object open for reading, which will be automatically closed.
        :param cryptainer_metadata: Dict of metadata added (unencrypted) to cryptainer.
        :param keychain_uid: If provided, replaces autogenerated keychain_uid for this cryptainer.
        :param cryptoconf: If provided, replaces default cryptoconf for this cryptainer.
        """
        logger.info("Enqueuing file %r for encryption and storage", filename_base)

        cryptoconf = self._prepare_for_new_record_encryption(cryptoconf)

        future = self._thread_pool_executor.submit(
            self._offloaded_encrypt_payload_and_dump_cryptainer,
            filename_base=filename_base,
            payload=payload,
            cryptainer_metadata=cryptainer_metadata,
            keychain_uid=keychain_uid,
            cryptoconf=cryptoconf,
        )
        self._pending_executor_futures.append(future)

    def _purge_executor_results(self):
        """Remove futures which are actually over. We don't care about their result/exception here"""
        still_pending_results = [future for future in self._pending_executor_futures if not future.done()]
        self._pending_executor_futures = still_pending_results

    @synchronized
    def wait_for_idle_state(self):
        """Wait for each pending future to be completed."""
        self._purge_executor_results()
        for future in self._pending_executor_futures:
            future.result()  # Should NEVER raise, thanks to the @catch_and_log_exception above, and absence of cancellations
        self._purge_exceeding_cryptainers()  # Good to have now


def _create_cryptainer_and_cryptoconf_schema(for_cryptainer: bool, extended_json_format: bool):
    """Create validation schema for confs and cryptainers.
    :param for_cryptainer: true if instance is a cryptainer
    :param extended_json_format: true if the scheme is extended to json format

    :return: a schema.
    """

    micro_schemas = get_validation_micro_schemas(extended_json_format=extended_json_format)

    extra_cryptainer = {}
    extra_payload_cipher_layer = {}
    extra_payload_signature = {}

    trustee_schemas = Or(
        LOCAL_KEYFACTORY_TRUSTEE_MARKER,
        {"trustee_type": CRYPTAINER_TRUSTEE_TYPES.AUTHENTICATOR_TRUSTEE, "keystore_uid": micro_schemas.schema_uid},
        {"trustee_type": CRYPTAINER_TRUSTEE_TYPES.JSONRPC_API_TRUSTEE, "jsonrpc_url": str},
    )

    payload_signature = {
        "payload_digest_algo": Or(*SUPPORTED_HASH_ALGOS),
        "payload_signature_algo": Or(*SUPPORTED_SIGNATURE_ALGOS),
        "payload_signature_trustee": trustee_schemas,  # FIXME test various trustee cases in unit-tests!!
        OptionalKey("keychain_uid"): micro_schemas.schema_uid,
    }

    if for_cryptainer:
        extra_cryptainer = {
            "cryptainer_state": Or(CRYPTAINER_STATES.STARTED, CRYPTAINER_STATES.FINISHED),
            "cryptainer_format": "cryptainer_1.0",
            "cryptainer_uid": micro_schemas.schema_uid,
            "payload_ciphertext_struct": Or(
                {
                    "ciphertext_location": PAYLOAD_CIPHERTEXT_LOCATIONS.INLINE,
                    "ciphertext_value": micro_schemas.schema_binary,
                },
                OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER,
            ),
            "cryptainer_metadata": Or(dict, None),
        }

        extra_payload_cipher_layer = {
            "key_ciphertext": micro_schemas.schema_binary,
            "payload_macs": {OptionalKey("tag"): micro_schemas.schema_binary},  # For now only "tag" is used
        }

        extra_payload_signature = {
            OptionalKey("payload_digest_value"): micro_schemas.schema_binary,
            OptionalKey("payload_signature_struct"): {
                "signature_value": micro_schemas.schema_binary,
                "signature_timestamp_utc": micro_schemas.schema_int,
            },
        }

    CIPHER_ALGO_BLOCK = {
        "key_cipher_algo": Or(*ASYMMETRIC_KEY_ALGOS_REGISTRY.keys()),
        "key_cipher_trustee": trustee_schemas,
        OptionalKey("keychain_uid"): micro_schemas.schema_uid,
    }

    RECURSIVE_SHARED_SECRET = []

    SHARED_SECRET_CRYPTAINER_PIECE = Schema(
        {
            "key_cipher_algo": SHARED_SECRET_ALGO_MARKER,
            "key_shared_secret_shards": [{"key_cipher_layers": [CIPHER_ALGO_BLOCK]}],
            "key_shared_secret_threshold": Or(And(int, lambda n: 0 < n < math.inf), micro_schemas.schema_int),
        },
        name="recursive_shared_secret",
        as_reference=True,
    )

    RECURSIVE_SHARED_SECRET.append(SHARED_SECRET_CRYPTAINER_PIECE)

    payload_signature.update(extra_payload_signature)

    SCHEMA_CRYPTAINERS = Schema(
        {
            **extra_cryptainer,
            "payload_cipher_layers": [
                {
                    "payload_cipher_algo": Or(*SUPPORTED_CIPHER_ALGOS),
                    "payload_signatures": [payload_signature],
                    **extra_payload_cipher_layer,
                    "key_cipher_layers": [CIPHER_ALGO_BLOCK, SHARED_SECRET_CRYPTAINER_PIECE],
                }
            ],
            OptionalKey("keychain_uid"): micro_schemas.schema_uid,
        }
    )

    return SCHEMA_CRYPTAINERS


CONF_SCHEMA_PYTHON = _create_cryptainer_and_cryptoconf_schema(for_cryptainer=False, extended_json_format=False)
CONF_SCHEMA_JSON = _create_cryptainer_and_cryptoconf_schema(
    for_cryptainer=False, extended_json_format=True
).json_schema("conf_schema.json")
CRYPTAINER_SCHEMA_PYTHON = _create_cryptainer_and_cryptoconf_schema(for_cryptainer=True, extended_json_format=False)
CRYPTAINER_SCHEMA_JSON = _create_cryptainer_and_cryptoconf_schema(
    for_cryptainer=True, extended_json_format=True
).json_schema("cryptainer_schema.json")


def _validate_data_tree(data_tree: dict, valid_schema: Union[dict, Schema]):
    """Allows the validation of a data_tree with a pythonschema or jsonschema

    :param data_tree: cryptainer or cryptoconf to validate
    :param valid_schema: validation scheme
    """
    if isinstance(valid_schema, Schema):
        # we use the python schema module
        try:
            valid_schema.validate(data_tree)
        except pythonschema.SchemaError as exc:
            raise SchemaValidationError("Error validating data tree with python-schema: {}".format(exc)) from exc

    else:
        # we use the json schema module
        assert isinstance(valid_schema, dict)
        try:
            jsonschema_validate(instance=data_tree, schema=valid_schema)
        except jsonschema.exceptions.ValidationError as exc:
            raise SchemaValidationError("Error validating data tree with json-schema: {}".format(exc)) from exc


def check_cryptainer_sanity(cryptainer: dict, jsonschema_mode: False):
    """Validate the format of a cryptainer.

    :param jsonschema_mode: If True, the cryptainer must have been loaded as raw json
           (with $binary, $numberInt and such) and will be checked using a jsonschema validator.
    """

    schema = CRYPTAINER_SCHEMA_JSON if jsonschema_mode else CRYPTAINER_SCHEMA_PYTHON

    _validate_data_tree(data_tree=cryptainer, valid_schema=schema)


def check_conf_sanity(cryptoconf: dict, jsonschema_mode: False):
    """Validate the format of a conf.

    :param jsonschema_mode: If True, the cryptainer must have been loaded as raw json
           (with $binary, $numberInt and such) and will be checked using a jsonschema validator.
    """

    schema = CONF_SCHEMA_JSON if jsonschema_mode else CONF_SCHEMA_PYTHON

    _validate_data_tree(data_tree=cryptoconf, valid_schema=schema)
