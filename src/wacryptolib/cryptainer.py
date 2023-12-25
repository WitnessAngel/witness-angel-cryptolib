import contextlib
import copy
import logging
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from pprint import pformat
from typing import Optional, Union, Sequence, BinaryIO
from urllib.parse import urlparse

import jsonschema
import schema as pythonschema
from bson import json_util
from jsonrpc_requests import JSONRPCError
from jsonschema import validate as jsonschema_validate
from schema import And, Or, Schema, Optional as OptionalKey

from wacryptolib.cipher import (
    encrypt_bytestring,
    decrypt_bytestring,
    PayloadEncryptionPipeline,
    STREAMABLE_CIPHER_ALGOS,
    SUPPORTED_CIPHER_ALGOS,
)
from wacryptolib.exceptions import (
    DecryptionError,
    SchemaValidationError,
    KeyDoesNotExist,
    KeyLoadingError,
    SignatureVerificationError,
    KeystoreDoesNotExist,
    DecryptionIntegrityError,
)
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.keygen import (
    generate_symkey,
    load_asymmetric_key_from_pem_bytestring,
    SUPPORTED_SYMMETRIC_KEY_ALGOS,
    SUPPORTED_ASYMMETRIC_KEY_ALGOS,
)
from wacryptolib.keystore import InMemoryKeystorePool, KeystorePoolBase, FilesystemKeystore
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
    SUPPORTED_HASH_ALGOS,
    get_validation_micro_schemas,
    is_file_basename,
)

logger = logging.getLogger(__name__)

CRYPTAINER_FORMAT = "cryptainer_1.0"
CRYPTAINER_SUFFIX = ".crypt"
CRYPTAINER_DATETIME_FORMAT = "%Y%m%d_%H%M%S"  # For use in cryptainer names and their records
CRYPTAINER_DATETIME_LENGTH = (
    15  # Important to lookup prefix of filename before matching it with CRYPTAINER_DATETIME_FORMAT
)
CRYPTAINER_TEMP_SUFFIX = "~"  # To name temporary, unfinalized, cryptainers
assert len(CRYPTAINER_TEMP_SUFFIX) == 1  # Because we use strip() with it here and there


class PAYLOAD_CIPHERTEXT_LOCATIONS:
    INLINE = "inline"  # Ciphertext is included in the json cryptainer
    OFFLOADED = "offloaded"  # Ciphertext is in a nearby binary file


# Shortcut helper, should NOT be modified
OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER = dict(ciphertext_location=PAYLOAD_CIPHERTEXT_LOCATIONS.OFFLOADED)

OFFLOADED_PAYLOAD_FILENAME_SUFFIX = ".payload"  # Added to CRYPTAINER_SUFFIX

DEFAULT_DATA_CHUNK_SIZE = 1024**2  # E.g. when streaming a big payload through encryptors

DECRYPTED_FILE_SUFFIX = ".decrypted"  # To construct decrypted filename when no output filename is provided

SHARED_SECRET_ALGO_MARKER = "[SHARED_SECRET]"  # Special "key_cipher_algo" value

DUMMY_KEYSTORE_POOL = InMemoryKeystorePool()  # Common fallback storage with in-memory keys


class CRYPTAINER_TRUSTEE_TYPES:  # FIXME rename to CRYPTAINER_TRUSTEE_TYPE (singular)
    LOCAL_KEYFACTORY_TRUSTEE = "local_keyfactory"
    AUTHENTICATOR_TRUSTEE = "authenticator"
    JSONRPC_API_TRUSTEE = "jsonrpc_api"


# Shortcut helper, should NOT be modified
LOCAL_KEYFACTORY_TRUSTEE_MARKER = dict(trustee_type=CRYPTAINER_TRUSTEE_TYPES.LOCAL_KEYFACTORY_TRUSTEE)


class CRYPTAINER_STATES:
    STARTED = "STARTED"
    FINISHED = "FINISHED"


def get_trustee_id(trustee_conf: dict) -> str:
    """Build opaque identifier unique for a given trustee."""
    trustee_type = trustee_conf.get("trustee_type", None)

    if trustee_type == CRYPTAINER_TRUSTEE_TYPES.LOCAL_KEYFACTORY_TRUSTEE:
        trustee_specifier = None  # Nothing to add for local keyfactory
    elif trustee_type == CRYPTAINER_TRUSTEE_TYPES.AUTHENTICATOR_TRUSTEE:
        trustee_specifier = str(trustee_conf["keystore_uid"])  # Ignore optional keystore_owner
    elif trustee_type == CRYPTAINER_TRUSTEE_TYPES.JSONRPC_API_TRUSTEE:
        trustee_specifier = trustee_conf["jsonrpc_url"]
    else:
        raise ValueError("Unrecognized key trustee %s" % str(trustee_conf))

    trustee_id = (trustee_type + "@" + trustee_specifier) if trustee_specifier else trustee_type
    return trustee_id


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
            for signature_conf in payload_cipher_layer["payload_signatures"]:
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
        readonly_keystore = keystore_pool.get_foreign_keystore(keystore_uid)
        assert not isinstance(readonly_keystore, FilesystemKeystore), readonly_keystore  # NOT writable for safety
        return ReadonlyTrusteeApi(readonly_keystore)
    elif trustee_type == CRYPTAINER_TRUSTEE_TYPES.JSONRPC_API_TRUSTEE:
        return JsonRpcProxy(url=trustee["jsonrpc_url"], response_error_handler=status_slugs_response_error_handler)
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
        self, *, cryptoconf: dict, output_stream: BinaryIO, cryptainer_metadata=None
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

        cryptainer, payload_cipher_layer_extracts = self._generate_cryptainer_base_and_secrets(
            cryptoconf=cryptoconf, cryptainer_metadata=cryptainer_metadata
        )

        encryption_pipeline = PayloadEncryptionPipeline(
            output_stream=output_stream, payload_cipher_layer_extracts=payload_cipher_layer_extracts
        )

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

        payload = self._load_all_payload_bytes(payload)  # Ensure we get the whole payload buffer

        cryptainer, payload_cipher_layer_extracts = self._generate_cryptainer_base_and_secrets(
            cryptoconf=cryptoconf, cryptainer_metadata=cryptainer_metadata
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
    def _load_all_payload_bytes(payload: Union[bytes, BinaryIO]):
        if hasattr(payload, "read"):  # File-like object
            logger.debug("Reading all data from open file handle %r", payload)
            payload_stream = payload
            payload = payload_stream.read()
            # DO NOT delete the file, e.g. it might come from CLI!
        assert isinstance(payload, bytes), payload
        ## FIXME LATER ADD THIS - assert payload, payload  # No encryption must be launched if we have no payload to process!
        return payload

    def _encrypt_and_hash_payload(self, payload, payload_cipher_layer_extracts):
        assert payload_cipher_layer_extracts, payload_cipher_layer_extracts  # Else security flaw!

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
            ), payload_cipherdict  # Might contain integrity/authentication data too

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

    def _generate_cryptainer_base_and_secrets(self, cryptoconf: dict, cryptainer_metadata=None) -> tuple:
        """
        Build a payload-less and signature-less cryptainer, preconfigured with a set of symmetric keys
        under their final form (encrypted by trustees). A separate extract, with symmetric keys as well as algo names, is returned so that actual payload encryption and signature can be performed separately.

        :param cryptoconf: configuration tree
        :param cryptainer_metadata: additional payload to store unencrypted in cryptainer, and also inside encrypted keys/shards

        :return: a (cryptainer: dict, secrets: list) tuple, where each secret has keys cipher_algo, symmetric_key and payload_digest_algos.
        """

        assert cryptainer_metadata is None or isinstance(cryptainer_metadata, dict), cryptainer_metadata
        cryptainer_format = CRYPTAINER_FORMAT
        cryptainer_uid = generate_uuid0()  # ALWAYS UNIQUE!

        default_keychain_uid = (
            cryptoconf.get("keychain_uid") or generate_uuid0()
        )  # Might be shared by lots of cryptainers

        assert isinstance(cryptoconf, dict), cryptoconf
        cryptainer = copy.deepcopy(cryptoconf)  # So that we can manipulate it as new cryptainer
        del cryptoconf
        if not cryptainer["payload_cipher_layers"]:
            raise SchemaValidationError("Empty payload_cipher_layers list is forbidden in cryptoconf")

        payload_cipher_layer_extracts = []  # Sensitive info with secret keys!

        for payload_cipher_layer in cryptainer["payload_cipher_layers"]:
            payload_cipher_algo = payload_cipher_layer["payload_cipher_algo"]

            payload_cipher_layer["payload_macs"] = None  # Will be filled later with MAC tags etc.

            logger.debug("Generating symmetric key of type %r for payload encryption", payload_cipher_algo)
            symkey = generate_symkey(cipher_algo=payload_cipher_algo)
            key_bytes = dump_to_json_bytes(symkey)
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
                payload_digest_algos=[
                    signature["payload_digest_algo"] for signature in payload_cipher_layer["payload_signatures"]
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
        return cryptainer, payload_cipher_layer_extracts

    def _encrypt_key_through_multiple_layers(
        self,
        default_keychain_uid: uuid.UUID,
        key_bytes: bytes,
        key_cipher_layers: list,
        cryptainer_metadata: Optional[dict],
    ) -> bytes:
        # HERE KEY IS A REAL KEY OR A SHARD !!!
        key_bytes_initial = key_bytes

        if not key_cipher_layers:
            raise SchemaValidationError("Empty key_cipher_layers list is forbidden in cryptoconf")

        for key_cipher_layer in key_cipher_layers:
            key_cipherdict = self._encrypt_key_through_single_layer(
                default_keychain_uid=default_keychain_uid,
                key_bytes=key_bytes,
                key_cipher_layer=key_cipher_layer,
                cryptainer_metadata=cryptainer_metadata,
            )
            key_bytes = dump_to_json_bytes(key_cipherdict)  # Thus its remains as bytes all along

        assert key_bytes != key_bytes_initial  # safety
        key_ciphertext = key_bytes
        return key_ciphertext

    def _encrypt_key_through_single_layer(
        self,
        default_keychain_uid: uuid.UUID,
        key_bytes: bytes,
        key_cipher_layer: dict,
        cryptainer_metadata: Optional[dict],
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
                raise SchemaValidationError(
                    "Shared secret threshold must be strictly positive and not greater than shard count, in cryptoconf"
                )

            shards = split_secret_into_shards(
                secret=key_bytes, shard_count=shard_count, threshold_count=threshold_count
            )

            assert len(shards) == shard_count

            shard_ciphertexts = []

            for shard, key_shared_secret_shard_conf in zip(shards, key_shared_secret_shards):
                shard_bytes = dump_to_json_bytes(
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

        elif key_cipher_algo in SUPPORTED_SYMMETRIC_KEY_ALGOS:
            assert key_cipher_algo in SUPPORTED_CIPHER_ALGOS, key_cipher_algo  # Not a SIGNATURE algo

            logger.debug("Generating symmetric subkey of type %r for key encryption", key_cipher_algo)
            sub_symkey = generate_symkey(cipher_algo=key_cipher_algo)
            sub_symkey_bytes = dump_to_json_bytes(sub_symkey)

            sub_symkey_ciphertext = self._encrypt_key_through_multiple_layers(
                default_keychain_uid=default_keychain_uid,
                key_bytes=sub_symkey_bytes,
                key_cipher_layers=key_cipher_layer["key_cipher_layers"],
                cryptainer_metadata=cryptainer_metadata,
            )  # Recursive structure
            assert isinstance(sub_symkey_ciphertext, bytes), sub_symkey_ciphertext

            key_cipher_layer["key_ciphertext"] = sub_symkey_ciphertext

            key_cipherdict = encrypt_bytestring(key_bytes, cipher_algo=key_cipher_algo, key_dict=sub_symkey)
            # We do not need to separate ciphertext from integrity/authentication data here, since key encryption is atomic

        else:  # Using asymmetric algorithm
            assert key_cipher_algo in SUPPORTED_ASYMMETRIC_KEY_ALGOS
            assert key_cipher_algo in SUPPORTED_CIPHER_ALGOS, key_cipher_algo  # Not a SIGNATURE algo

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

    def _fetch_asymmetric_key_pem_from_trustee(self, trustee, key_algo, keychain_uid):
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
        cryptainer_metadata: Optional[dict],
    ) -> dict:
        """
        Encrypt given payload (representing a symmetric key) with an asymmetric algorithm.

        :param cipher_algo: string with name of algorithm to use
        :param keychain_uid: final uuid for the set of encryption keys used
        :param key_bytes: symmetric key as bytes to encrypt
        :param trustee: trustee used for encryption (findable in configuration tree)

        :return: dictionary which contains every payload needed to decrypt the ciphered key
        """
        public_key_pem = self._fetch_asymmetric_key_pem_from_trustee(
            trustee=trustee, key_algo=cipher_algo, keychain_uid=keychain_uid
        )

        logger.debug("Encrypting symmetric key struct with asymmetric keypair %s/%s", cipher_algo, keychain_uid)
        public_key = load_asymmetric_key_from_pem_bytestring(key_pem=public_key_pem, key_algo=cipher_algo)

        # FIXME provide utilities to wrap/unwrap this struct?
        key_struct = dict(key_bytes=key_bytes, cryptainer_metadata=cryptainer_metadata)  # SPECIAL FORMAT FOR CHECKUPS
        key_struct_bytes = dump_to_json_bytes(key_struct)
        key_cipherdict = encrypt_bytestring(
            plaintext=key_struct_bytes, cipher_algo=cipher_algo, key_dict=dict(key=public_key)
        )
        return key_cipherdict

    def add_authentication_data_to_cryptainer(self, cryptainer: dict, payload_integrity_tags: list):
        default_keychain_uid = cryptainer["keychain_uid"]

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
                    default_keychain_uid=default_keychain_uid, cryptoconf=signature_conf
                )
                signature_conf["payload_signature_struct"] = payload_signature_struct

                _encountered_payload_digest_algos.add(payload_digest_algo)
            assert _encountered_payload_digest_algos == set(payload_digests)  # No abnormal extra digest

        cryptainer["cryptainer_state"] = CRYPTAINER_STATES.FINISHED

    def _generate_message_signature(self, default_keychain_uid: uuid.UUID, cryptoconf: dict) -> dict:
        """
        Generate a signature for a specific ciphered payload.

        :param default_keychain_uid: default uuid for the set of encryption keys used
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

        keychain_uid_for_signature = cryptoconf.get("keychain_uid") or default_keychain_uid

        logger.debug("Signing hash of encrypted payload with algo %r", payload_signature_algo)
        payload_signature_struct = trustee_proxy.get_message_signature(
            keychain_uid=keychain_uid_for_signature, message=payload_digest, signature_algo=payload_signature_algo
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


class DecryptionErrorType:  # FIXME RENAME THIS
    INFORMATION = "INFORMATION"
    SIGNATURE_ERROR = "SIGNATURE_ERROR"
    SYMMETRIC_DECRYPTION_ERROR = "SYMMETRIC_DECRYPTION_ERROR"
    ASYMMETRIC_DECRYPTION_ERROR = "ASYMMETRIC_DECRYPTION_ERROR"


class DecryptionErrorCriticity:  # FIXME rename that
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"  # Potentially non-fatal error
    CRITICAL = "CRITICAL"  # Fatal error


OPERATION_REPORT_ENTRY_SCHEMA = Schema(
    {
        "entry_type": Or(
            DecryptionErrorType.INFORMATION,
            DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
            DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            DecryptionErrorType.SIGNATURE_ERROR,
        ),
        "entry_criticity": Or(
            DecryptionErrorCriticity.INFO,
            DecryptionErrorCriticity.ERROR,
            DecryptionErrorCriticity.WARNING,
            DecryptionErrorCriticity.CRITICAL,
        ),
        "entry_message": And(str, len),
        "entry_exception": Or(Exception, None),
        "entry_nesting": And(int, lambda x: x >= 0),
    }
)


class OperationReport:
    """
    Wrapper around a list of operation info/error entries with different levels of imbrication.
    """

    def __init__(self):
        self._current_nesting = 0
        self._entries = []

    def __len__(self):
        return len(self._entries)

    @contextlib.contextmanager
    def operation_section(self, section_message):
        """Add an INFO message and add an extra level to entries in the with... keyword"""
        self.add_information(section_message)
        self._current_nesting += 1  # NOw only we raise the
        try:
            yield
        finally:
            self._current_nesting -= 1

    def add_entry(
        self,
        entry_type: str,
        entry_message: str,
        entry_criticity=DecryptionErrorCriticity.WARNING,
        entry_exception=None,
    ):
        # We immediately forward entry to standard logging too, but always in DEBUG level!
        if entry_exception:
            logger.debug("%s report entry: %s (%r)", entry_type, entry_message, entry_exception)
        else:
            logger.debug("%s report entry: %s", entry_type, entry_message)

        error_entry = {
            "entry_type": entry_type,
            "entry_criticity": entry_criticity,
            "entry_message": entry_message,
            "entry_exception": entry_exception,
            "entry_nesting": self._current_nesting,
        }

        if __debug__:  # Sanity check
            _validate_data_tree(data_tree=error_entry, valid_schema=OPERATION_REPORT_ENTRY_SCHEMA)

        self._entries.append(error_entry)

    def add_information(self, entry_message):
        self.add_entry(
            entry_type=DecryptionErrorType.INFORMATION,
            entry_message=entry_message,
            entry_criticity=DecryptionErrorCriticity.INFO,
        )

    def get_all_entries(self):
        return self._entries[:]  # COPY

    def get_error_entries(self):
        return [x for x in self._entries if x["entry_criticity"] != DecryptionErrorCriticity.INFO]

    def get_error_count(self):
        return len(self.get_error_entries())

    def has_errors(self):
        """Returns True iff report contains warnings/erros"""
        return bool(self.get_error_count)

    def format_entries(self):  # FIXME improve that
        return pformat(self._entries)


class CryptainerDecryptor(CryptainerBase):
    """
    THIS CLASS IS PRIVATE API

    Contains every method used to read and decrypt a cryptainer, IN MEMORY.
    """

    def extract_cryptainer_metadata(self, cryptainer: dict) -> Optional[dict]:
        assert isinstance(cryptainer, dict), cryptainer
        return cryptainer["cryptainer_metadata"]

    def _decrypt_with_local_private_key(
        self, cipherdict: dict, keychain_uid: uuid.UUID, cipher_algo: str, operation_report: OperationReport
    ):
        # TODO USE TrusteeApi() with local keystore then decrypt_with_private_key() function, instead ???
        keystore = self._keystore_pool.get_local_keyfactory()
        key_struct_bytes = None  # Returns "None" when unable to decrypt with the answer key

        try:
            private_key_pem = keystore.get_private_key(keychain_uid=keychain_uid, key_algo=cipher_algo)
        except KeyDoesNotExist as exc:
            operation_report.add_entry(
                entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                entry_message="Private key of revelation response not found (%s/%s)" % (cipher_algo, keychain_uid),
                entry_criticity=DecryptionErrorCriticity.ERROR,
                entry_exception=exc,
            )
            return key_struct_bytes

        try:
            private_key = load_asymmetric_key_from_pem_bytestring(key_pem=private_key_pem, key_algo=cipher_algo)

        except KeyLoadingError as exc:
            operation_report.add_entry(
                entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                entry_message="Failed loading revelation response key of from pem bytestring (%s)" % cipher_algo,
                entry_criticity=DecryptionErrorCriticity.ERROR,
                entry_exception=exc,
            )

            return key_struct_bytes

        try:
            key_struct_bytes = decrypt_bytestring(
                cipherdict=cipherdict, cipher_algo=cipher_algo, key_dict=dict(key=private_key)
            )
        except DecryptionError as exc:
            operation_report.add_entry(
                entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                entry_message="Failed decryption of remote symkey/shard %s (%s) " % (cipher_algo, exc),
                entry_criticity=DecryptionErrorCriticity.ERROR,
                entry_exception=exc,
            )

        return key_struct_bytes

    def _unwrap_predecrypted_symkeys(self, successful_symkey_decryptions, operation_report: OperationReport):
        predecrypted_symkey_mapper = {}

        for symkey_decryption in successful_symkey_decryptions:
            keychain_uid = symkey_decryption["revelation_request"]["revelation_response_keychain_uid"]
            cipher_algo = symkey_decryption["revelation_request"]["revelation_response_key_algo"]

            request_data = symkey_decryption["symkey_decryption_request_data"]

            cipherdict = load_from_json_bytes(symkey_decryption["symkey_decryption_response_data"])

            # FIXME handle errors?
            # FIXME immediately deserialize "key_struct_bytes" here and handle operation_report ? Or somewhere else ?
            key_struct_bytes = self._decrypt_with_local_private_key(
                cipherdict=cipherdict,
                keychain_uid=keychain_uid,
                cipher_algo=cipher_algo,
                operation_report=operation_report,
            )

            if key_struct_bytes:
                predecrypted_symkey_mapper.setdefault(request_data, key_struct_bytes)

        return predecrypted_symkey_mapper

    def _get_single_gateway_revelation_request_list(
        self, gateway_url: str, revelation_requestor_uid: uuid.UUID, operation_report: OperationReport
    ):
        assert gateway_url and revelation_requestor_uid  # By construction

        gateway_revelation_request_list = []

        gateway_proxy = JsonRpcProxy(url=gateway_url, response_error_handler=status_slugs_response_error_handler)
        try:
            gateway_revelation_request_list = gateway_proxy.list_requestor_revelation_requests(
                revelation_requestor_uid=revelation_requestor_uid
            )
        except (JSONRPCError, OSError) as exc:
            operation_report.add_entry(
                entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                entry_message="Unable to reach remote server %s" % gateway_url,
                entry_exception=exc,
            )
        return gateway_revelation_request_list

    def _get_multiple_gateway_revelation_request_list(
        self, gateway_urls: list, revelation_requestor_uid: uuid.UUID, operation_report: OperationReport
    ):
        assert gateway_urls and revelation_requestor_uid  # By construction

        multiple_gateway_revelation_request_list = []
        for gateway_url in gateway_urls:
            gateway_revelation_request_list = self._get_single_gateway_revelation_request_list(
                gateway_url, revelation_requestor_uid, operation_report=operation_report
            )
            multiple_gateway_revelation_request_list.extend(gateway_revelation_request_list)

        return multiple_gateway_revelation_request_list

    def _get_successful_symkey_decryptions(
        self,
        cryptainer: dict,
        gateway_urls: list,
        revelation_requestor_uid: uuid.UUID,
        operation_report: OperationReport,
    ) -> list:
        ACCEPTED = "ACCEPTED"
        REJECTED = "REJECTED"  # USE LATER

        multiple_gateway_revelation_request_list = self._get_multiple_gateway_revelation_request_list(
            gateway_urls, revelation_requestor_uid, operation_report=operation_report
        )

        successful_symkey_decryptions = []

        if multiple_gateway_revelation_request_list:
            for revelation_request in multiple_gateway_revelation_request_list:
                revelation_request_per_symkey = {
                    key: value for key, value in revelation_request.items() if key != "symkey_decryption_requests"
                }

                # Allow not to verify all decryption requests
                if revelation_request["revelation_request_status"] == ACCEPTED:
                    for symkey_decryption in revelation_request["symkey_decryption_requests"]:
                        if (
                            symkey_decryption["cryptainer_uid"] == cryptainer["cryptainer_uid"]
                            and symkey_decryption["symkey_decryption_status"] == "DECRYPTED"
                        ):
                            symkey_decryption_accepted_for_cryptainer = dict(
                                symkey_decryption.items()
                            )  # FIXME use .copy()
                            symkey_decryption_accepted_for_cryptainer[
                                "revelation_request"
                            ] = revelation_request_per_symkey
                            successful_symkey_decryptions.append(symkey_decryption_accepted_for_cryptainer)

        # FIXME add info/warning for rejected requests???

        return successful_symkey_decryptions

    def decrypt_payload(  # FIXME test the cases with gateway_urls or revelation_requestor_uid empty
        self,
        cryptainer: dict,
        verify_integrity_tags: bool = True,
        gateway_urls: Optional[list] = None,
        revelation_requestor_uid: Optional[uuid.UUID] = None,
    ) -> tuple:
        """
        Loop through cryptainer layers, to decipher payload with the right algorithms.

        Decryption was successful if and only if plaintext returned is not None

        :param cryptainer: dictionary previously built with CryptainerEncryptor method
        :param verify_integrity_tags: whether to check MAC tags of the ciphertext

        :return: deciphered plaintext and operation report
        """
        predecrypted_symkey_mapper = None
        operation_report = OperationReport()

        if revelation_requestor_uid and gateway_urls:
            successful_symkey_decryptions = self._get_successful_symkey_decryptions(
                cryptainer=cryptainer,
                gateway_urls=gateway_urls,
                revelation_requestor_uid=revelation_requestor_uid,
                operation_report=operation_report,
            )

            predecrypted_symkey_mapper = self._unwrap_predecrypted_symkeys(
                successful_symkey_decryptions=successful_symkey_decryptions, operation_report=operation_report
            )
            operation_report.add_information(
                "Performed retrieval of remotely predecrypted symkeys: %d found" % len(predecrypted_symkey_mapper)
            )
        else:
            operation_report.add_information(
                "Skipping retrieval of remotely predecrypted symkeys (requires requestor-uid and gateway urls)"
            )

        assert isinstance(cryptainer, dict), cryptainer

        cryptainer_format = cryptainer["cryptainer_format"]
        if cryptainer_format != CRYPTAINER_FORMAT:
            raise ValueError("Unknown cryptainer format %s" % cryptainer_format)

        cryptainer_uid = cryptainer["cryptainer_uid"]
        del cryptainer_uid  # Might be used for logging etc, later...

        default_keychain_uid = cryptainer["keychain_uid"]

        cryptainer_metadata = cryptainer["cryptainer_metadata"]

        payload_current = _get_cryptainer_inline_ciphertext_value(cryptainer)

        # Non-emptiness of this will be checked by validator
        payload_cipher_layer_count = len(cryptainer["payload_cipher_layers"])

        for payload_cipher_layer_idx, payload_cipher_layer in enumerate(
            reversed(cryptainer["payload_cipher_layers"]), start=1
        ):
            with operation_report.operation_section(
                "Starting decryption of payload cipher layer %d/%d (algo: %s)"
                % (payload_cipher_layer_idx, payload_cipher_layer_count, payload_cipher_layer["payload_cipher_algo"])
            ):
                payload_current = self._decrypt_single_payload_cipher_layer(
                    payload_ciphertext=payload_current,
                    payload_cipher_layer=payload_cipher_layer,
                    verify_integrity_tags=verify_integrity_tags,
                    default_keychain_uid=default_keychain_uid,
                    cryptainer_metadata=cryptainer_metadata,
                    operation_report=operation_report,
                    predecrypted_symkey_mapper=predecrypted_symkey_mapper,
                )
                if payload_current is None:
                    """TODO PUT BACK LATER
                    operation_report.add_entry(
                        entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
                        entry_criticity=DecryptionErrorCriticity.CRITICAL,
                        entry_message="Payload cipher layer decryption failed, aborting decryption of cryptainer",
                    )
                    """
                    break

        return payload_current, operation_report

    def _decrypt_single_payload_cipher_layer(
        self,
        payload_ciphertext: bytes,
        payload_cipher_layer: dict,
        verify_integrity_tags: bool,
        default_keychain_uid: uuid.UUID,
        cryptainer_metadata: Optional[dict],
        operation_report: OperationReport,
        predecrypted_symkey_mapper: Optional[dict],
    ) -> Optional[bytes]:
        assert isinstance(payload_ciphertext, bytes), repr(payload_ciphertext)
        payload_cipher_algo = payload_cipher_layer["payload_cipher_algo"]

        for signature_conf in payload_cipher_layer["payload_signatures"]:
            self._verify_payload_signature(  # Should NOT raise for now, just report errors!
                default_keychain_uid=default_keychain_uid,
                payload=payload_ciphertext,
                cryptoconf=signature_conf,
                operation_report=operation_report,
            )

        key_cipher_layers = payload_cipher_layer["key_cipher_layers"]
        operation_report.add_information(
            "Decrypting %s symmetric key through %d cipher layer(s)" % (payload_cipher_algo, len(key_cipher_layers))
        )

        key_ciphertext = payload_cipher_layer["key_ciphertext"]  # We start fully encrypted, and unravel it
        key_bytes = self._decrypt_key_through_multiple_layers(
            default_keychain_uid=default_keychain_uid,
            key_ciphertext=key_ciphertext,
            key_cipher_layers=key_cipher_layers,
            cryptainer_metadata=cryptainer_metadata,
            predecrypted_symkey_mapper=predecrypted_symkey_mapper,
            operation_report=operation_report,
        )

        if key_bytes is not None:
            assert isinstance(key_bytes, bytes), key_bytes
            symkey = load_from_json_bytes(key_bytes)

            payload_macs = payload_cipher_layer[
                "payload_macs"
            ]  # FIXME handle and test if it's None: missing integrity tags due to unfinished container!!
            payload_cipherdict = dict(ciphertext=payload_ciphertext, **payload_macs)
            try:
                payload_cleartext = decrypt_bytestring(
                    cipherdict=payload_cipherdict,
                    key_dict=symkey,
                    cipher_algo=payload_cipher_algo,
                    verify_integrity_tags=verify_integrity_tags,
                )
                assert isinstance(payload_cleartext, bytes), payload_cleartext  # Now decrypted

            except DecryptionIntegrityError as exc:
                operation_report.add_entry(
                    entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
                    entry_criticity=DecryptionErrorCriticity.ERROR,
                    entry_message="Failed decryption authentication %s (MAC check failed)" % payload_cipher_algo,
                    entry_exception=exc,
                )
                payload_cleartext = None

            except DecryptionError as exc:
                operation_report.add_entry(
                    entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
                    entry_criticity=DecryptionErrorCriticity.ERROR,
                    entry_message="Failed symmetric decryption (%s)" % payload_cipher_algo,
                    entry_exception=exc,
                )
                payload_cleartext = None
        else:
            payload_cleartext = None
            operation_report.add_entry(
                entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
                entry_criticity=DecryptionErrorCriticity.ERROR,
                entry_message="Failed symmetric decryption (%s)"
                % payload_cipher_algo,  # FIXME change this message to "aborted"? Or just skip this step?
                entry_exception=None,
            )

        return payload_cleartext  # Might be None

    def _decrypt_key_through_multiple_layers(
        self,
        default_keychain_uid: uuid.UUID,
        key_ciphertext: bytes,
        key_cipher_layers: list,
        cryptainer_metadata: Optional[dict],
        operation_report: OperationReport,
        predecrypted_symkey_mapper: Optional[dict] = None,
    ) -> Optional[bytes]:
        assert len(key_cipher_layers), key_cipher_layers  # Extra safety

        key_bytes = None

        for key_cipher_layer in reversed(key_cipher_layers):
            key_ciphertext = self._decrypt_key_through_single_layer(
                default_keychain_uid=default_keychain_uid,
                key_ciphertext=key_ciphertext,
                key_cipher_layer=key_cipher_layer,
                cryptainer_metadata=cryptainer_metadata,
                predecrypted_symkey_mapper=predecrypted_symkey_mapper,
                operation_report=operation_report,
            )
            if not key_ciphertext:
                break  # It would too complicated to analyse other cipher_layers without valid key_ciphertext
        else:
            key_bytes = key_ciphertext  # Fully decrypted version

        return key_bytes

    def _decrypt_key_through_single_layer(
        self,
        default_keychain_uid: uuid.UUID,
        key_ciphertext: bytes,
        key_cipher_layer: dict,
        cryptainer_metadata: Optional[dict],
        operation_report: OperationReport,
        predecrypted_symkey_mapper: Optional[dict] = None,
    ) -> Optional[bytes]:
        """
        Function called when decryption of a symmetric key is needed. Encryption may be made by shared secret or
        by a asymmetric algorithm.

        :param default_keychain_uid: default uuid for the set of encryption keys used
        :param key_ciphertext: encrypted symmetric key
        :param key_cipher_layer: part of the cryptainer related to this key encryption layer

        :return: deciphered symmetric key
        """
        key_bytes = None

        assert isinstance(key_ciphertext, bytes), key_ciphertext

        key_cipherdict = load_from_json_bytes(key_ciphertext)
        assert isinstance(key_cipherdict, dict), key_cipherdict

        key_cipher_algo = key_cipher_layer["key_cipher_algo"]

        if key_cipher_algo == SHARED_SECRET_ALGO_MARKER:
            decrypted_shards = []
            key_shared_secret_shards = key_cipher_layer["key_shared_secret_shards"]
            key_shared_secret_threshold = key_cipher_layer["key_shared_secret_threshold"]

            shard_ciphertexts = key_cipherdict["shard_ciphertexts"]

            with operation_report.operation_section(
                "Deciphering %d shards of shared secret (threshold: %d)"
                % (len(shard_ciphertexts), key_shared_secret_threshold)
            ):
                # If some shards are missing, we won't detect it here because zip() stops at shortest list
                for shard_idx, (shard_ciphertext, key_shared_secret_shard_conf) in enumerate(
                    zip(shard_ciphertexts, key_shared_secret_shards), start=1
                ):
                    operation_report.add_information(
                        "Decrypting shard #%d through %d cipher layer(s)"
                        % (shard_idx, len(key_shared_secret_shard_conf["key_cipher_layers"]))
                    )

                    shard_bytes = self._decrypt_key_through_multiple_layers(
                        default_keychain_uid=default_keychain_uid,
                        key_ciphertext=shard_ciphertext,
                        key_cipher_layers=key_shared_secret_shard_conf["key_cipher_layers"],
                        cryptainer_metadata=cryptainer_metadata,
                        predecrypted_symkey_mapper=predecrypted_symkey_mapper,
                        operation_report=operation_report,
                    )  # Recursive structure
                    if shard_bytes is not None:
                        shard = load_from_json_bytes(
                            shard_bytes
                        )  # The tuple (idx, payload) of each shard thus becomes encryptable
                        decrypted_shards.append(shard)
                    else:
                        operation_report.add_entry(
                            entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                            entry_message="A previous error prevented decrypting this shard",
                            entry_exception=None,
                        )

                    if len(decrypted_shards) == key_shared_secret_threshold:
                        break

                if len(decrypted_shards) < key_shared_secret_threshold:
                    operation_report.add_entry(
                        entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                        entry_message="Shared secret failure! %s valid shard(s) missing for reconstitution "
                        "of symmetric key" % (key_shared_secret_threshold - len(decrypted_shards)),
                        entry_exception=None,
                    )

                else:
                    operation_report.add_information(
                        "A sufficient number of shared-secret shards (%d) have been decrypted" % len(decrypted_shards)
                    )
                    key_bytes = recombine_secret_from_shards(shards=decrypted_shards)

        elif key_cipher_algo in SUPPORTED_SYMMETRIC_KEY_ALGOS:
            assert key_cipher_algo in SUPPORTED_CIPHER_ALGOS, key_cipher_algo  # Not a SIGNATURE algo

            sub_symkey_ciphertext = key_cipher_layer["key_ciphertext"]

            operation_report.add_information(
                "Decrypting %s symmetric key through %d cipher layer(s)"
                % (key_cipher_algo, len(key_cipher_layer["key_cipher_layers"]))
            )

            sub_symkey_bytes = self._decrypt_key_through_multiple_layers(
                default_keychain_uid=default_keychain_uid,
                key_ciphertext=sub_symkey_ciphertext,
                key_cipher_layers=key_cipher_layer["key_cipher_layers"],
                cryptainer_metadata=cryptainer_metadata,
                predecrypted_symkey_mapper=predecrypted_symkey_mapper,
                operation_report=operation_report,
            )  # Recursive structure

            if sub_symkey_bytes:
                sub_symkey_dict = load_from_json_bytes(sub_symkey_bytes)
                try:
                    key_bytes = decrypt_bytestring(
                        key_cipherdict, cipher_algo=key_cipher_algo, key_dict=sub_symkey_dict
                    )
                except DecryptionError as exc:
                    operation_report.add_entry(
                        entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
                        entry_message="Error decrypting key with symmetric algorithm %s" % key_cipher_algo,
                        entry_criticity=DecryptionErrorCriticity.ERROR,
                        entry_exception=exc,
                    )

        else:  # Using asymmetric algorithm
            assert key_cipher_algo in SUPPORTED_ASYMMETRIC_KEY_ALGOS
            assert key_cipher_algo in SUPPORTED_CIPHER_ALGOS, key_cipher_algo  # Not a SIGNATURE algo

            keychain_uid = key_cipher_layer.get("keychain_uid") or default_keychain_uid
            trustee = key_cipher_layer["key_cipher_trustee"]

            trustee_label = trustee["trustee_type"]
            if "keystore_owner" in trustee:
                trustee_label += " " + trustee["keystore_owner"]

            with operation_report.operation_section(
                "Attempting to decrypt key with asymmetric algorithm %s (trustee: %s)"
                % (key_cipher_algo, trustee_label)
            ):
                predecrypted_symmetric_key = self._get_predecrypted_symkey_or_none(
                    key_ciphertext, predecrypted_symkey_mapper=predecrypted_symkey_mapper
                )
                if predecrypted_symmetric_key:
                    operation_report.add_information(
                        "Predecrypted symmetric key found (e.g. coming from remote trustee)"
                    )
                    key_bytes = predecrypted_symmetric_key
                else:
                    operation_report.add_information(
                        "No predecrypted symmetric found (e.g. coming from remote trustee)"
                    )
                    key_bytes = self._decrypt_with_asymmetric_cipher(
                        cipher_algo=key_cipher_algo,
                        keychain_uid=keychain_uid,
                        cipherdict=key_cipherdict,
                        trustee=trustee,
                        cryptainer_metadata=cryptainer_metadata,
                        operation_report=operation_report,
                    )

        return key_bytes

    @staticmethod
    def _get_predecrypted_symkey_or_none(key_ciphertext, predecrypted_symkey_mapper: Optional[dict]) -> Optional[bytes]:
        predecrypted_symkey = None

        if predecrypted_symkey_mapper and (key_ciphertext in predecrypted_symkey_mapper):
            predecrypted_symkey_struct = load_from_json_bytes(predecrypted_symkey_mapper[key_ciphertext])
            predecrypted_symkey = predecrypted_symkey_struct["key_bytes"]

        return predecrypted_symkey

    @staticmethod
    def _build_operation_report_entry_______(  # FIXME REMOVE THIS
        entry_type: str, entry_message: str, entry_criticity=DecryptionErrorCriticity.WARNING, entry_exception=None
    ) -> dict:
        # We forward entry to standard logging too
        log_level = getattr(logging, entry_criticity)  # Same identifiers in the 2 worlds
        if entry_exception:
            logger.log(log_level, "%s report entry: %s (%r)", entry_type, entry_message, entry_exception)
        else:
            logger.log(log_level, "%s report entry: %s", entry_type, entry_message)

        error_entry = {
            "entry_type": entry_type,
            "entry_criticity": entry_criticity,
            "entry_message": entry_message,
            "entry_exception": entry_exception,
        }

        SCHEMA_ERROR = Schema(  # FIXME move that OUT of here
            {
                "entry_type": Or(
                    DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
                    DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                    DecryptionErrorType.SIGNATURE_ERROR,
                ),
                "entry_criticity": Or(DecryptionErrorCriticity.ERROR, DecryptionErrorCriticity.WARNING),
                "entry_message": And(str, len),
                "entry_exception": Or(Exception, None),
            }
        )

        _validate_data_tree(data_tree=error_entry, valid_schema=SCHEMA_ERROR)

        return error_entry

    def _decrypt_with_asymmetric_cipher(
        self,
        cipher_algo: str,
        keychain_uid: uuid.UUID,
        cipherdict: dict,
        trustee: dict,
        cryptainer_metadata: Optional[dict],
        operation_report: OperationReport,
    ) -> Optional[bytes]:
        """
        Decrypt given cipherdict with an asymmetric algorithm.

        :param cipher_algo: string with name of algorithm to use
        :param keychain_uid: final uuid for the set of encryption keys used
        :param cipherdict: dictionary with payload components needed to decrypt the ciphered payload
        :param trustee: trustee used for encryption (findable in configuration tree)

        :return: decypted payload as bytes
        """
        key_bytes = None

        trustee_id = get_trustee_id(trustee)
        passphrases = self._passphrase_mapper.get(trustee_id) or []
        assert isinstance(passphrases, list), repr(passphrases)  # No SINGLE passphrase here

        passphrases += self._passphrase_mapper.get(None) or []  # Add COMMON passphrases

        operation_report.add_information(
            "Attempting actual decryption of key using asymmetric algorithm %s (via trustee)" % cipher_algo
        )

        try:
            trustee_proxy = get_trustee_proxy(trustee=trustee, keystore_pool=self._keystore_pool)
        except KeystoreDoesNotExist as exc:
            operation_report.add_entry(
                entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                entry_message="Trustee key storage not found (%s)" % trustee["keystore_uid"],
                entry_exception=exc,
            )

        else:
            try:
                # We expect decryption authorization requests to have already been done properly
                key_struct_bytes = trustee_proxy.decrypt_with_private_key(
                    keychain_uid=keychain_uid,
                    cipher_algo=cipher_algo,
                    cipherdict=cipherdict,
                    passphrases=passphrases,
                    cryptainer_metadata=cryptainer_metadata,
                )
                key_struct = load_from_json_bytes(key_struct_bytes)
                key_bytes = key_struct["key_bytes"]
                assert isinstance(key_bytes, bytes), key_bytes

                actual_cryptainer_metadata = key_struct[
                    "cryptainer_metadata"
                ]  # Metadata stored along the encrypted key!
                del actual_cryptainer_metadata  # No use for now

            except KeyDoesNotExist as exc:
                operation_report.add_entry(
                    entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                    entry_message="Private key not found (%s/%s)" % (cipher_algo, keychain_uid),
                    entry_exception=exc,
                )

            except KeyLoadingError as exc:
                operation_report.add_entry(
                    entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                    entry_message="Could not load private key %s/%s (missing passphrase?)"
                    % (cipher_algo, keychain_uid),
                    entry_exception=exc,
                )

            except DecryptionError as exc:
                operation_report.add_entry(
                    entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                    entry_message="Failed decrypting key with asymmetric algorithm %s" % cipher_algo,
                    entry_criticity=DecryptionErrorCriticity.ERROR,
                    entry_exception=exc,
                )

        return key_bytes

    def _verify_payload_signature(
        self, default_keychain_uid: uuid.UUID, payload: bytes, cryptoconf: dict, operation_report: OperationReport
    ):
        """
        Verify a signature for a specific message.

        DOES NOT raise for now, just reports troubels in operation_report.

        :param default_keychain_uid: default uuid for the set of encryption keys used
        :param payload: payload on which to verify signature (after digest)
        :param cryptoconf: configuration tree inside payload_signatures
        """

        payload_digest_algo = cryptoconf["payload_digest_algo"]
        payload_signature_algo = cryptoconf["payload_signature_algo"]
        keychain_uid = cryptoconf.get("keychain_uid") or default_keychain_uid
        trustee_proxy = get_trustee_proxy(
            trustee=cryptoconf["payload_signature_trustee"], keystore_pool=self._keystore_pool
        )
        try:
            public_key_pem = trustee_proxy.fetch_public_key(
                keychain_uid=keychain_uid, key_algo=payload_signature_algo, must_exist=True
            )
        except KeyDoesNotExist as exc:
            message = "Public signature key %s/%s not found" % (payload_signature_algo, keychain_uid)
            operation_report.add_entry(
                entry_type=DecryptionErrorType.SIGNATURE_ERROR,
                entry_message=message,
                entry_exception=exc,
            )
            return

        try:
            public_key = load_asymmetric_key_from_pem_bytestring(
                key_pem=public_key_pem, key_algo=payload_signature_algo
            )
        except KeyLoadingError as exc:
            message = "Failed loading signature key from pem bytestring (%s)" % payload_signature_algo
            operation_report.add_entry(
                entry_type=DecryptionErrorType.SIGNATURE_ERROR,
                entry_message=message,
                entry_exception=exc,
            )
            return

        payload_digest = hash_message(payload, hash_algo=payload_digest_algo)

        expected_payload_digest = cryptoconf.get("payload_digest_value")  # Might be missing
        if expected_payload_digest and expected_payload_digest != payload_digest:
            message = "Mismatch between actual and expected payload digests during signature verification"
            operation_report.add_entry(
                entry_type=DecryptionErrorType.SIGNATURE_ERROR,
                entry_message=message,
                entry_exception=None,
            )
            return

        payload_signature_struct = cryptoconf.get("payload_signature_struct")
        if not payload_signature_struct:
            message = "Missing signature structure"
            operation_report.add_entry(
                entry_type=DecryptionErrorType.SIGNATURE_ERROR,
                entry_message=message,
                entry_exception=None,
            )
            return

        else:
            try:
                verify_message_signature(
                    message=payload_digest,
                    signature_algo=payload_signature_algo,
                    signature=payload_signature_struct,
                    public_key=public_key,
                )  # Raises if troubles

            except SignatureVerificationError as exc:
                operation_report.add_entry(
                    entry_type=DecryptionErrorType.SIGNATURE_ERROR,
                    entry_message="Failed signature verification %s (%s)" % (payload_signature_algo, exc),
                    entry_exception=exc,
                )
                return


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
            self._cryptainer_encryptor = CryptainerEncryptor(keystore_pool=keystore_pool)

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


def is_cryptainer_cryptoconf_streamable(cryptoconf):  # FIXME rename and add to docs?
    for payload_cipher_layer in cryptoconf["payload_cipher_layers"]:
        if payload_cipher_layer["payload_cipher_algo"] not in STREAMABLE_CIPHER_ALGOS:
            return False
    return True


def encrypt_payload_and_stream_cryptainer_to_filesystem(  # Fixme rename to encrypt_payload_and_stream_cryptainer_to_filesystem?
    payload: Union[bytes, BinaryIO],
    *,
    cryptainer_filepath,
    cryptoconf: dict,
    cryptainer_metadata: Optional[dict],
    keystore_pool: Optional[KeystorePoolBase] = None,
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
    cryptainer_encryptor = CryptainerEncryptor(keystore_pool=keystore_pool)
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

    for idx, payload_cipher_layer in enumerate(cryptoconf_or_cryptainer["payload_cipher_layers"], start=1):
        text_lines.append("Data encryption layer %d: %s" % (idx, payload_cipher_layer["payload_cipher_algo"]))
        text_lines.append(indent + "Key encryption layers:")
        for key_cipher_layer in payload_cipher_layer["key_cipher_layers"]:
            _get_key_encryption_layer_description(key_cipher_layer, current_level=2)
        text_lines.append(indent + "Signatures:" + ("" if payload_cipher_layer["payload_signatures"] else " None"))
        for payload_signature in payload_cipher_layer["payload_signatures"]:
            payload_signature_trustee = payload_signature["payload_signature_trustee"]
            trustee_id = _get_trustee_displayable_identifier(payload_signature_trustee)
            text_lines.append(
                2 * indent
                + "%s/%s via trustee '%s'"
                % (payload_signature["payload_digest_algo"], payload_signature["payload_signature_algo"], trustee_id)
            )
    result = "\n".join(text_lines) + "\n"
    return result


def _get_offloaded_file_path(cryptainer_filepath: Path):
    """We also support, discreetly, TEMPORARY cryptainers"""
    return cryptainer_filepath.parent.joinpath(
        cryptainer_filepath.name.rstrip(CRYPTAINER_TEMP_SUFFIX) + OFFLOADED_PAYLOAD_FILENAME_SUFFIX
    )


# FIXME handle "overwrite" argument to prevent
def dump_cryptainer_to_filesystem(cryptainer_filepath: Path, cryptainer: dict, offload_payload_ciphertext=True) -> None:
    """Dump a cryptainer to a file path, overwriting it if existing.

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
        if (
            "payload_ciphertext_struct" not in cryptainer
        ):  # Early error before we have a chance to validate the whole cryptainer...
            raise SchemaValidationError("Cryptainer has no root field 'payload_ciphertext_struct'")

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
    os.remove(cryptainer_filepath)  # TODO - additional retries if file access error?
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


class ReadonlyCryptainerStorage:
    """
    This class provides read access to a directory filled with cryptainers..

    :param cryptainer_dir: the folder where cryptainer files are stored
    :param keystore_pool: optional KeystorePool, which might be required by current cryptoconf
    """

    def __init__(self, cryptainer_dir: Path, keystore_pool: Optional[KeystorePoolBase] = None):
        cryptainer_dir = Path(cryptainer_dir).absolute()
        assert cryptainer_dir.is_dir(), cryptainer_dir
        self._cryptainer_dir = cryptainer_dir
        self._keystore_pool = keystore_pool  # Might be None, in this case fallback to in-memory pool

    def get_cryptainer_count(self, finished=True):
        return len(self.list_cryptainer_names(as_absolute_paths=True, finished=finished))  # Fastest version

    def list_cryptainer_names(
        self, as_sorted_list: bool = False, as_absolute_paths: bool = False, finished=True
    ):  # FIXME add function annotations everywhere in this class
        """Returns the list of encrypted cryptainers present in storage,
        sorted by name or not, absolute or not, as Path objects.

        If `finished` ìs None, both finished and pending cryptainers are listed.
        """
        assert self._cryptainer_dir.is_absolute(), self._cryptainer_dir
        paths = []  # Result as list, for multiple looping on it
        if finished is None or finished:
            paths += list(self._cryptainer_dir.glob("*" + CRYPTAINER_SUFFIX))
        if not finished:  # None or False
            paths += list(self._cryptainer_dir.glob("*" + CRYPTAINER_SUFFIX + CRYPTAINER_TEMP_SUFFIX))
        assert all(p.is_absolute() for p in paths), paths
        if as_sorted_list:
            paths = sorted(paths)
        if not as_absolute_paths:
            paths = [Path(p.name) for p in paths]  # Beware, it only works since we don't have subfolders for now!
        assert isinstance(paths, list), paths
        return paths

    def _get_cryptainer_datetime_utc(self, cryptainer_name):
        """Returns an UTC datetime corresponding to the creation time stored in filename, or else the file-stat mtime"""
        try:
            dt = datetime.strptime(cryptainer_name.name[:CRYPTAINER_DATETIME_LENGTH], CRYPTAINER_DATETIME_FORMAT)
            dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            logger.debug("Couldn't recognize timestamp in filename %s, falling back to file time", cryptainer_name.name)
            mtime = (
                self._make_absolute(cryptainer_name).stat().st_mtime
            )  # FIXME - Might fail if file got deleted concurrently
            dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
        return dt

    def _get_cryptainer_size(self, cryptainer_name):
        """Returns a size in bytes"""
        return get_cryptainer_size_on_filesystem(self._make_absolute(cryptainer_name))

    def list_cryptainer_properties(
        self,
        as_sorted_list=False,
        with_creation_datetime=False,
        with_age=False,
        with_size=False,
        with_offloaded=False,
        finished=True,
    ):
        """Returns an list of dicts (unsorted by default) having the fields "name", [age] and [size], depending on requested properties."""
        cryptainer_names = self.list_cryptainer_names(
            as_sorted_list=as_sorted_list, as_absolute_paths=False, finished=finished
        )

        now = get_utc_now_date()

        result = []
        for cryptainer_name in cryptainer_names:
            entry = dict(name=cryptainer_name)
            if with_age or with_creation_datetime:
                creation_datetime = self._get_cryptainer_datetime_utc(cryptainer_name)
                if with_creation_datetime:
                    entry["creation_datetime"] = creation_datetime
                if with_age:
                    entry["age"] = now - creation_datetime  # We keep it as timedelta
            if with_size:
                entry["size"] = self._get_cryptainer_size(cryptainer_name)
            if with_offloaded:
                entry["offloaded"] = _get_offloaded_file_path(self._make_absolute(cryptainer_name)).is_file()
            result.append(entry)
        return result

    def is_valid_cryptainer_name(self, cryptainer_name):
        cryptainer_path = self._make_absolute(cryptainer_name)
        return cryptainer_path.is_file()

    def _make_absolute(self, cryptainer_name):
        assert is_file_basename(cryptainer_name), cryptainer_name
        return self._cryptainer_dir.joinpath(cryptainer_name)

    def load_cryptainer_from_storage(self, cryptainer_name_or_idx, include_payload_ciphertext=True) -> dict:
        """
        Return the encrypted cryptainer dict for `cryptainer_name_or_idx` (which must be in `list_cryptainer_names()`,
        or an index suitable for this sorted list).

        Only FINISHED cryptainers are expected to be loaded.
        """
        if isinstance(cryptainer_name_or_idx, int):
            cryptainer_names = self.list_cryptainer_names(as_sorted_list=True, as_absolute_paths=False, finished=True)
            cryptainer_name = cryptainer_names[cryptainer_name_or_idx]  # Will break if idx is out of bounds
        else:
            assert isinstance(cryptainer_name_or_idx, (Path, str)), repr(cryptainer_name_or_idx)
            cryptainer_name = Path(cryptainer_name_or_idx)
        assert not cryptainer_name.is_absolute(), cryptainer_name

        logger.info(
            "Loading cryptainer %s from storage (include_payload_ciphertext=%s)",
            cryptainer_name,
            include_payload_ciphertext,
        )
        cryptainer_filepath = self._make_absolute(cryptainer_name)
        cryptainer = load_cryptainer_from_filesystem(
            cryptainer_filepath, include_payload_ciphertext=include_payload_ciphertext
        )
        return cryptainer

    def decrypt_cryptainer_from_storage(
        self,
        cryptainer_name_or_idx,
        passphrase_mapper: Optional[dict] = None,
        verify_integrity_tags: bool = True,
        gateway_urls: Optional[list] = None,
        revelation_requestor_uid: Optional[uuid.UUID] = None,
    ) -> tuple:
        """
        Return the decrypted content of the cryptainer `cryptainer_name_or_idx` (which must be in `list_cryptainer_names()`,
        or an index suitable for this sorted list).
        """
        logger.info("Decrypting cryptainer %r from storage", cryptainer_name_or_idx)

        cryptainer = self.load_cryptainer_from_storage(cryptainer_name_or_idx, include_payload_ciphertext=True)

        medium_content, operation_report = self._decrypt_payload_from_cryptainer(
            cryptainer,
            passphrase_mapper=passphrase_mapper,
            verify_integrity_tags=verify_integrity_tags,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        if medium_content is None:
            logger.error("Storage cryptainer %s decryption failed", cryptainer_name_or_idx)
        else:
            logger.info("Storage cryptainer %s successfully decrypted", cryptainer_name_or_idx)
        return medium_content, operation_report

    def _decrypt_payload_from_cryptainer(
        self,
        cryptainer: dict,
        passphrase_mapper: Optional[dict],
        verify_integrity_tags: bool,
        gateway_urls: Optional[list] = None,
        revelation_requestor_uid: Optional[uuid.UUID] = None,
    ) -> tuple:
        return decrypt_payload_from_cryptainer(
            cryptainer,
            keystore_pool=self._keystore_pool,
            passphrase_mapper=passphrase_mapper,
            verify_integrity_tags=verify_integrity_tags,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )  # Will fail if authorizations are not OK

    def check_cryptainer_sanity(self, cryptainer_name_or_idx):
        """Allows the validation of a cryptainer structure"""
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
        logger.info("Deleting cryptainer %s", cryptainer_filepath)
        delete_cryptainer_from_filesystem(cryptainer_filepath)

    def delete_cryptainer(self, cryptainer_name):
        logger.info("Intentionally deleting cryptainer %s" % cryptainer_name)
        self._delete_cryptainer(cryptainer_name=cryptainer_name)

    def purge_exceeding_cryptainers(self) -> int:  # FIXME test this shortcut
        logger.info("Intentionally purging cryptainers")
        return self._purge_exceeding_cryptainers()

    def _purge_exceeding_cryptainers(self) -> int:
        """Purge cryptainers first by date, then total quota, then count, depending on instance settings.

        Unfinished cryptainers are, for now, ALWAYS included in the purge, since we assume they are forsaken
        if they are still pending at this time.
        """

        deleted_cryptainer_count = 0

        if self._max_cryptainer_age is not None:  # FIRST these, since their deletion is unconditional
            cryptainer_dicts = self.list_cryptainer_properties(with_age=True, finished=None)
            for cryptainer_dict in cryptainer_dicts:
                ##print("COMPARING", cryptainer_dict["age"], self._max_cryptainer_age)
                if cryptainer_dict["age"] > self._max_cryptainer_age:
                    logger.info("Deleting cryptainer %s due to age", cryptainer_dict["name"])
                    self._delete_cryptainer(cryptainer_dict["name"])
                    deleted_cryptainer_count += 1

        if self._max_cryptainer_quota is not None:
            max_cryptainer_quota = self._max_cryptainer_quota

            cryptainer_dicts = self.list_cryptainer_properties(with_size=True, with_age=True, finished=None)
            cryptainer_dicts.sort(key=lambda x: (-x["age"], x["name"]), reverse=True)  # Oldest last

            total_space_consumed = sum(x["size"] for x in cryptainer_dicts)

            while total_space_consumed > max_cryptainer_quota:
                deleted_cryptainer_dict = cryptainer_dicts.pop()
                logger.info("Deleting cryptainer %s due to lack of storage space", deleted_cryptainer_dict["name"])
                self._delete_cryptainer(deleted_cryptainer_dict["name"])
                total_space_consumed -= deleted_cryptainer_dict["size"]
                deleted_cryptainer_count += 1

        if self._max_cryptainer_count is not None:
            cryptainer_dicts = self.list_cryptainer_properties(with_age=True, finished=None)
            cryptainers_count = len(cryptainer_dicts)

            if cryptainers_count > self._max_cryptainer_count:
                assert cryptainers_count > 0, cryptainers_count
                excess_count = cryptainers_count - self._max_cryptainer_count
                cryptainer_dicts.sort(key=lambda x: (-x["age"], x["name"]))  # Oldest first
                deleted_cryptainer_dicts = cryptainer_dicts[:excess_count]
                for deleted_cryptainer_dict in deleted_cryptainer_dicts:
                    logger.info(
                        "Deleting cryptainer %s due to excessive count of cryptainers", deleted_cryptainer_dict["name"]
                    )
                    self._delete_cryptainer(deleted_cryptainer_dict["name"])
                    deleted_cryptainer_count += 1

        return deleted_cryptainer_count

    def _encrypt_payload_and_stream_cryptainer_to_filesystem(
        self, payload, cryptainer_filepath, cryptainer_metadata, cryptoconf
    ):
        assert cryptoconf, cryptoconf
        encrypt_payload_and_stream_cryptainer_to_filesystem(
            cryptainer_filepath=cryptainer_filepath,
            payload=payload,
            cryptoconf=cryptoconf,
            cryptainer_metadata=cryptainer_metadata,
            keystore_pool=self._keystore_pool,
        )

    def _encrypt_payload_into_cryptainer(self, payload, cryptainer_metadata, cryptoconf):
        assert cryptoconf, cryptoconf
        return encrypt_payload_into_cryptainer(
            payload=payload,
            cryptoconf=cryptoconf,
            cryptainer_metadata=cryptainer_metadata,
            keystore_pool=self._keystore_pool,
        )

    def _do_encrypt_payload_and_dump_cryptainer(self, filename_base, payload, cryptainer_metadata, cryptoconf) -> str:
        # TODO later as a SKIP here!
        # if not payload:
        #    logger.warning("Skipping encryption of empty payload payload for file %s", filename_base)
        #    return
        assert cryptoconf, cryptoconf

        cryptainer_filepath = self._make_absolute(filename_base + CRYPTAINER_SUFFIX)

        if self._use_streaming_encryption_for_cryptoconf(cryptoconf):
            # We can use newer, low-memory, streamed API
            logger.debug(
                "Encrypting payload file %r into offloaded cryptainer directly streamed to storage file %s",
                filename_base,
                cryptainer_filepath,
            )
            # import logging_tree
            # logging_tree.printout()
            self._encrypt_payload_and_stream_cryptainer_to_filesystem(
                payload,
                cryptainer_filepath=cryptainer_filepath,
                cryptainer_metadata=cryptainer_metadata,
                cryptoconf=cryptoconf,
            )

        else:
            # We use legacy API which encrypts all and then dumps all
            logger.debug("Encrypting payload file to self-sufficient cryptainer %r", filename_base)
            # Memory warning: duplicates payload to json-compatible cryptainer
            cryptainer = self._encrypt_payload_into_cryptainer(
                payload,
                cryptainer_metadata=cryptainer_metadata,
                cryptoconf=cryptoconf,
            )
            logger.debug("Writing self-sufficient cryptainer payload to storage file %s", cryptainer_filepath)
            dump_cryptainer_to_filesystem(
                cryptainer_filepath, cryptainer=cryptainer, offload_payload_ciphertext=self._offload_payload_ciphertext
            )

        logger.info("Data file %r successfully encrypted into storage cryptainer", filename_base)
        return cryptainer_filepath.name

    @catch_and_log_exception("CryptainerStorage._offloaded_encrypt_payload_and_dump_cryptainer")
    def _offloaded_encrypt_payload_and_dump_cryptainer(self, filename_base, payload, cryptainer_metadata, cryptoconf):
        """Task to be called by background thread, which encrypts a payload into a disk cryptainer.

        Returns the cryptainer basename."""
        assert filename_base, repr(filename_base)
        self._do_encrypt_payload_and_dump_cryptainer(
            filename_base=filename_base,
            payload=payload,
            cryptainer_metadata=cryptainer_metadata,
            cryptoconf=cryptoconf,
        )
        return None

    def _use_streaming_encryption_for_cryptoconf(self, cryptoconf):
        return self._offload_payload_ciphertext and is_cryptainer_cryptoconf_streamable(cryptoconf)

    def _resolve_cryptoconf(self, cryptoconf):
        cryptoconf = cryptoconf or self._default_cryptoconf
        if not cryptoconf:
            raise RuntimeError("Either default or file-specific cryptoconf must be provided to CryptainerStorage")
        return cryptoconf

    def _cleanup_before_new_record_encryption(self):
        """
        Validate arguments for new encryption, and purge obsolete things in storage.
        """
        self._purge_exceeding_cryptainers()
        self._purge_executor_results()

    @synchronized
    def create_cryptainer_encryption_stream(
        self,
        filename_base,
        cryptainer_metadata,
        cryptoconf=None,
        dump_initial_cryptainer=True,
        cryptainer_encryption_stream_class=None,
        cryptainer_encryption_stream_extra_kwargs=None,
    ):
        """
        Create and return a cryptainer encryption stream.

        Purges exceeding cryptainers and pending results beforehand.
        """

        cryptainer_encryption_stream_class = cryptainer_encryption_stream_class or CryptainerEncryptionPipeline
        cryptainer_encryption_stream_extra_kwargs = cryptainer_encryption_stream_extra_kwargs or {}

        logger.debug("Building cryptainer stream %r", filename_base)
        cryptainer_filepath = self._make_absolute(filename_base + CRYPTAINER_SUFFIX)
        cryptoconf = self._resolve_cryptoconf(cryptoconf)
        self._cleanup_before_new_record_encryption()

        cryptainer_encryption_stream = cryptainer_encryption_stream_class(
            cryptainer_filepath,
            cryptoconf=cryptoconf,
            cryptainer_metadata=cryptainer_metadata,
            keystore_pool=self._keystore_pool,
            dump_initial_cryptainer=dump_initial_cryptainer,
            **cryptainer_encryption_stream_extra_kwargs,
        )
        return cryptainer_encryption_stream

    @synchronized
    def enqueue_file_for_encryption(
        self,
        filename_base,
        payload,
        cryptainer_metadata,
        cryptoconf=None,  # TODO add "wait/syncrhonous" argument ?
    ):
        """Enqueue a payload for asynchronous encryption and storage.

        Purges exceeding cryptainers and pending results beforehand.

        The filename of final cryptainer might be different from provided one.
        Deware, target cryptainer with the same constructed name might be overwritten.

        :param payload: Bytes string, or a file-like object open for reading, which will be automatically closed.
        :param cryptainer_metadata: Dict of metadata added (unencrypted) to cryptainer.
        :param keychain_uid: If provided, replaces autogenerated default keychain_uid for this cryptainer.
        :param cryptoconf: If provided, replaces default cryptoconf for this cryptainer.
        """
        assert is_file_basename(filename_base), filename_base
        logger.info("Enqueuing file %r for encryption and storage", filename_base)

        cryptoconf = self._resolve_cryptoconf(cryptoconf)
        self._cleanup_before_new_record_encryption()

        future = self._thread_pool_executor.submit(
            self._offloaded_encrypt_payload_and_dump_cryptainer,
            filename_base=filename_base,
            payload=payload,
            cryptainer_metadata=cryptainer_metadata,
            cryptoconf=cryptoconf,
        )
        self._pending_executor_futures.append(future)

    def encrypt_file(  # FIXME find more meaningful name?
        self, filename_base, payload, cryptainer_metadata, cryptoconf=None
    ) -> str:
        """Synchronously encrypt the provided payload into cryptainer storage.

        Does NOT purge exceeding cryptainers and pending results beforehand.

        Returns the cryptainer basename."""
        assert is_file_basename(filename_base), filename_base
        cryptoconf = self._resolve_cryptoconf(cryptoconf)
        return self._do_encrypt_payload_and_dump_cryptainer(
            filename_base=filename_base,
            payload=payload,
            cryptainer_metadata=cryptainer_metadata,
            cryptoconf=cryptoconf,
        )

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

    # FIXME add signature of cleartext payload too, directly at root of cryptainer? Or rework the whole structure of signatures?

    micro_schemas = get_validation_micro_schemas(extended_json_format=extended_json_format)

    extra_cryptainer = {}
    extra_payload_cipher_layer = {}
    extra_asymmetric_cipher_algo_block = {}
    extra_payload_signature = {}

    trustee_schemas = Or(
        LOCAL_KEYFACTORY_TRUSTEE_MARKER,
        {
            "trustee_type": CRYPTAINER_TRUSTEE_TYPES.AUTHENTICATOR_TRUSTEE,
            "keystore_uid": micro_schemas.schema_uid,
            OptionalKey("keystore_owner"): str,
            # Optional for retrocompatibility only, may be left empty even if present!
        },
        {"trustee_type": CRYPTAINER_TRUSTEE_TYPES.JSONRPC_API_TRUSTEE, "jsonrpc_url": str},
    )

    payload_signature = {
        "payload_digest_algo": Or(*SUPPORTED_HASH_ALGOS),
        "payload_signature_algo": Or(*SUPPORTED_SIGNATURE_ALGOS),
        "payload_signature_trustee": trustee_schemas,
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

        extra_asymmetric_cipher_algo_block = {"key_ciphertext": micro_schemas.schema_binary}

        extra_payload_signature = {
            OptionalKey("payload_digest_value"): micro_schemas.schema_binary,
            OptionalKey("payload_signature_struct"): {
                "signature_value": micro_schemas.schema_binary,
                "signature_timestamp_utc": micro_schemas.schema_int,
            },
        }

    ASYMMETRIC_CIPHER_ALGO_BLOCK = {
        "key_cipher_algo": Or(*SUPPORTED_ASYMMETRIC_KEY_ALGOS),
        "key_cipher_trustee": trustee_schemas,
        OptionalKey("keychain_uid"): micro_schemas.schema_uid,
    }

    _ALL_POSSIBLE_CIPHER_LAYERS_LIST = [ASYMMETRIC_CIPHER_ALGO_BLOCK]  # Built for recursive schema!
    ALL_POSSIBLE_CIPHER_LAYERS_LIST_NON_EMPTY = And(_ALL_POSSIBLE_CIPHER_LAYERS_LIST, len)

    SYMMETRIC_CIPHER_ALGO_BLOCK = Schema(
        {
            "key_cipher_algo": Or(*SUPPORTED_SYMMETRIC_KEY_ALGOS),
            "key_cipher_layers": ALL_POSSIBLE_CIPHER_LAYERS_LIST_NON_EMPTY,  # Must be non-empty!
            **extra_asymmetric_cipher_algo_block,
        },
        name="recursive_symmetric_cipher",
        as_reference=True,
    )
    _ALL_POSSIBLE_CIPHER_LAYERS_LIST.append(SYMMETRIC_CIPHER_ALGO_BLOCK)

    def validate_shared_secret_threshold(shared_secret_struct):
        threshold = shared_secret_struct["key_shared_secret_threshold"]
        if not isinstance(threshold, int):  # It's an extended-json payload
            threshold = json_util.object_hook()
        if threshold < 1:
            raise ValueError("Shared secret threshold must be strictly positive")
        if threshold > len(shared_secret_struct["key_shared_secret_shards"]):
            raise ValueError("Shared secret threshold can't be greater than number of shards")
        return True

    SHARED_SECRET_CRYPTAINER_BLOCK = Schema(
        And(
            {
                "key_cipher_algo": SHARED_SECRET_ALGO_MARKER,
                "key_shared_secret_shards": [{"key_cipher_layers": ALL_POSSIBLE_CIPHER_LAYERS_LIST_NON_EMPTY}],
                "key_shared_secret_threshold": micro_schemas.schema_int,
            },
            validate_shared_secret_threshold,
        ),
        name="recursive_shared_secret",
        as_reference=True,
    )
    _ALL_POSSIBLE_CIPHER_LAYERS_LIST.append(SHARED_SECRET_CRYPTAINER_BLOCK)

    payload_signature.update(extra_payload_signature)

    CRYPTAINER_SCHEMA = Schema(
        {
            **extra_cryptainer,
            "payload_cipher_layers": And(
                [
                    {
                        "payload_cipher_algo": Or(*SUPPORTED_CIPHER_ALGOS),
                        "payload_signatures": [payload_signature],
                        **extra_payload_cipher_layer,
                        "key_cipher_layers": ALL_POSSIBLE_CIPHER_LAYERS_LIST_NON_EMPTY,
                    }
                ],
                len,
            ),  # Must be non-empty!
            OptionalKey("keychain_uid"): micro_schemas.schema_uid,
        }
    )

    return CRYPTAINER_SCHEMA


CRYPTOCONF_SCHEMA_PYTHON = _create_cryptainer_and_cryptoconf_schema(for_cryptainer=False, extended_json_format=False)
CRYPTOCONF_SCHEMA_JSON = _create_cryptainer_and_cryptoconf_schema(
    for_cryptainer=False, extended_json_format=True
).json_schema("conf_schema.json")
CRYPTAINER_SCHEMA_PYTHON = _create_cryptainer_and_cryptoconf_schema(for_cryptainer=True, extended_json_format=False)
CRYPTAINER_SCHEMA_JSON = _create_cryptainer_and_cryptoconf_schema(
    for_cryptainer=True, extended_json_format=True
).json_schema("cryptainer_schema.json")


def _validate_data_tree(data_tree: dict, valid_schema: Union[dict, Schema]):  # Fixme why call it "valid_schema"?
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


def check_cryptainer_sanity(cryptainer: dict, jsonschema_mode=False):
    """Validate the format of a cryptainer.

    :param jsonschema_mode: If True, the cryptainer must have been loaded as raw json
           (with $binary, $numberInt and such) and will be checked using a jsonschema validator.
    """

    schema = CRYPTAINER_SCHEMA_JSON if jsonschema_mode else CRYPTAINER_SCHEMA_PYTHON

    _validate_data_tree(data_tree=cryptainer, valid_schema=schema)


def check_cryptoconf_sanity(cryptoconf: dict, jsonschema_mode=False):
    """Validate the format of a conf.

    :param jsonschema_mode: If True, the cryptainer must have been loaded as raw json
           (with $binary, $numberInt and such) and will be checked using a jsonschema validator.
    """

    schema = CRYPTOCONF_SCHEMA_JSON if jsonschema_mode else CRYPTOCONF_SCHEMA_PYTHON

    _validate_data_tree(data_tree=cryptoconf, valid_schema=schema)
