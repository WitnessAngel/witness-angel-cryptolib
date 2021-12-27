import copy


import logging
import math
import os
import threading
import uuid
import schema
from jsonschema import validate as jsonschema_validate
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from pprint import pprint
from typing import Optional, Union, List, Sequence, BinaryIO
from urllib.parse import urlparse
from uuid import UUID

import jsonschema
from schema import And, Or, Regex, Const, Schema
from schema import Optional as Optionalkey

from wacryptolib.encryption import encrypt_bytestring, decrypt_bytestring, StreamManager, STREAMABLE_ENCRYPTION_ALGOS, \
    SUPPORTED_ENCRYPTION_ALGOS
from wacryptolib.escrow import EscrowApi as LocalEscrowApi, ReadonlyEscrowApi, EscrowApi
from wacryptolib.exceptions import DecryptionError, ConfigurationError, ValidationError
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.key_generation import generate_symkey, load_asymmetric_key_from_pem_bytestring, \
    ASYMMETRIC_KEY_TYPES_REGISTRY
from wacryptolib.key_storage import KeyStorageBase, DummyKeyStoragePool, KeyStoragePoolBase
from wacryptolib.shared_secret import split_bytestring_as_shamir_shares, recombine_secret_from_shamir_shares
from wacryptolib.signature import verify_message_signature, SUPPORTED_SIGNATURE_ALGOS
from wacryptolib.utilities import (
    dump_to_json_bytes,
    load_from_json_bytes,
    dump_to_json_file,
    load_from_json_file,
    generate_uuid0,
    hash_message,
    synchronized,
    catch_and_log_exception, get_utc_now_date, consume_bytes_as_chunks, delete_filesystem_node_for_stream,
    SUPPORTED_HASH_ALGOS
)

logger = logging.getLogger(__name__)

CRYPTAINER_FORMAT = "WA_0.1a"
CRYPTAINER_SUFFIX = ".crypt"
CRYPTAINER_DATETIME_FORMAT = "%Y%m%d%H%M%S"  # For use in cryptainer names and their records
CRYPTAINER_TEMP_SUFFIX = "~"  # To name temporary, unfinalized, cryptainers

OFFLOADED_MARKER = "[OFFLOADED]"
OFFLOADED_DATA_SUFFIX = ".data"  # Added to CRYPTAINER_SUFFIX

DATA_CHUNK_SIZE = 1024 ** 2  # E.g. when streaming a big payload through encryptors

MEDIUM_SUFFIX = ".medium"  # To construct decrypted filename when no previous extensions are found in cryptainer filename

SHARED_SECRET_MARKER = "[SHARED_SECRET]"

DUMMY_KEY_STORAGE_POOL = DummyKeyStoragePool()  # Common fallback storage with in-memory keys

#: Special value in cryptainers, to invoke a device-local escrow
LOCAL_ESCROW_MARKER = dict(escrow_type="local")  # FIXME CHANGE THIS

AUTHDEVICE_ESCROW_MARKER = dict(escrow_type="authdevice")  # FIXME CHANGE THIS


class CRYPTAINER_STATES:
    STARTED = "STARTED"
    FINISHED = "FINISHED"


def get_escrow_id(escrow_conf: dict) -> str:
    """Build opaque unique identifier for a specific escrow.

    Remains the same as long as escrow dict is completely unmodified.
    """
    return str(sorted(escrow_conf.items()))


def gather_escrow_dependencies(cryptainers: Sequence) -> dict:
    """Analyse a cryptainer and return the escrows (and their keypairs) used by it.

    :return: dict with lists of keypair identifiers in fields "encryption" and "signature".
    """

    signature_dependencies = {}
    encryption_dependencies = {}

    def _add_keypair_identifiers_for_escrow(mapper, escrow_conf, keychain_uid, key_type):
        escrow_id = get_escrow_id(escrow_conf=escrow_conf)
        keypair_identifiers = dict(keychain_uid=keychain_uid, key_type=key_type)
        mapper.setdefault(escrow_id, (escrow_conf, []))
        keypair_identifiers_list = mapper[escrow_id][1]
        if keypair_identifiers not in keypair_identifiers_list:
            keypair_identifiers_list.append(keypair_identifiers)

    def _grab_key_encryption_layers_dependencies(key_encryption_layers):
        for key_encryption_layer in key_encryption_layers:
            key_type_encryption = key_encryption_layer["key_encryption_algo"]

            if key_type_encryption == SHARED_SECRET_MARKER:
                escrows = key_encryption_layer["key_shared_secret_escrows"]
                for escrow in escrows:
                    _grab_key_encryption_layers_dependencies(escrow["key_encryption_layers"])  # Recursive call
            else:
                keychain_uid_encryption = key_encryption_layer.get("keychain_uid") or keychain_uid
                escrow_conf = key_encryption_layer["key_escrow"]
                _add_keypair_identifiers_for_escrow(
                    mapper=encryption_dependencies,
                    escrow_conf=escrow_conf,
                    keychain_uid=keychain_uid_encryption,
                    key_type=key_type_encryption,
                )

    for cryptainer in cryptainers:
        keychain_uid = cryptainer["keychain_uid"]
        for data_encryption_layer in cryptainer["data_encryption_layers"]:
            for signature_conf in data_encryption_layer["data_signatures"]:
                key_type_signature = signature_conf["signature_algo"]
                keychain_uid_signature = signature_conf.get("keychain_uid") or keychain_uid
                escrow_conf = signature_conf["signature_escrow"]

                _add_keypair_identifiers_for_escrow(
                    mapper=signature_dependencies,
                    escrow_conf=escrow_conf,
                    keychain_uid=keychain_uid_signature,
                    key_type=key_type_signature,
                )

            _grab_key_encryption_layers_dependencies(data_encryption_layer["key_encryption_layers"])

    escrow_dependencies = {"signature": signature_dependencies, "encryption": encryption_dependencies}
    return escrow_dependencies


def request_decryption_authorizations(
        escrow_dependencies: dict, key_storage_pool, request_message: str, passphrases: Optional[list] = None
) -> dict:
    """Loop on encryption escrows and request decryption authorization for all the keypairs that they own.

    :return: dict mapping escrow ids to authorization result dicts.
    """
    request_authorization_result = {}
    encryption_escrows_dependencies = escrow_dependencies.get("encryption")

    for escrow_id, escrow_data in encryption_escrows_dependencies.items():
        key_escrow, keypair_identifiers = escrow_data
        proxy = get_escrow_proxy(escrow=key_escrow, key_storage_pool=key_storage_pool)
        result = proxy.request_decryption_authorization(
            keypair_identifiers=keypair_identifiers, request_message=request_message, passphrases=passphrases
        )
        request_authorization_result[escrow_id] = result

    return request_authorization_result


def get_escrow_proxy(escrow: dict, key_storage_pool: KeyStoragePoolBase):
    """
    Return an EscrowApi subclass instance (or proxy) depending on the content of `escrow` dict.
    """
    assert isinstance(escrow, dict), escrow

    escrow_type = escrow.get("escrow_type")  # Might be None

    if escrow_type == LOCAL_ESCROW_MARKER["escrow_type"]:
        return LocalEscrowApi(key_storage_pool.get_local_key_storage())
    elif escrow_type == AUTHDEVICE_ESCROW_MARKER["escrow_type"]:
        authdevice_uid = escrow["authdevice_uid"]
        key_storage = key_storage_pool.get_imported_key_storage(authdevice_uid)
        return ReadonlyEscrowApi(key_storage)
    elif escrow_type == "jsonrpc":
        return JsonRpcProxy(url=escrow["url"], response_error_handler=status_slugs_response_error_handler)
    # TODO - Implement imported storages, escrow lookup in global registry, shared-secret group, etc.
    raise ValueError("Unrecognized escrow identifiers: %s" % str(escrow))


# FIXME rename keychain_uid to default_keychain_uid where relevant!!


class CryptainerBase:
    """
    BEWARE - this class-based design is provisional and might change a lot.

    `key_storage_pool` will be used to fetch local/imported escrows necessary to encryption/decryption operations.

    `passphrase_mapper` maps escrows IDs to potential passphrases; a None key can be used to provide additional
    passphrases for all escrows.
    """

    def __init__(self, key_storage_pool: KeyStoragePoolBase = None, passphrase_mapper: Optional[dict] = None):
        if not key_storage_pool:
            logger.warning(
                "No key storage pool provided for %s instance, falling back to common DummyKeyStoragePool()",
                self.__class__.__name__,
            )
            key_storage_pool = DUMMY_KEY_STORAGE_POOL
        assert isinstance(key_storage_pool, KeyStoragePoolBase), key_storage_pool
        self._key_storage_pool = key_storage_pool
        self._passphrase_mapper = passphrase_mapper or {}


class CryptainerWriter(CryptainerBase):  #FIXME rename to CryptainerEncryptor
    """
    Contains every method used to write and encrypt a cryptainer, IN MEMORY.
    """

    def build_cryptainer_and_stream_encryptor(self, *, cryptoconf: dict, output_stream: BinaryIO, keychain_uid=None, metadata=None) -> dict:
        """
        Build a base cryptainer to store encrypted keys, as well as a stream encryptor
        meant to process heavy data chunk by chunk.

        Signatures, and final ciphertext (if not offloaded), will have to be added
        later to the cryptainer.

        :param cryptoconf: configuration tree
        :param output_stream: open file where the stream encryptor should write to
        :param keychain_uid: uuid for the set of encryption keys used
        :param metadata: additional data to store unencrypted in cryptainer

        :return: cryptainer with all the information needed to attempt data decryption
        """

        cryptainer, data_encryption_layer_extracts = self._generate_cryptainer_base_and_secrets(
           cryptoconf=cryptoconf, keychain_uid=keychain_uid, metadata=metadata
        )

        # HERE INSTANTIATE REAL ENCRYPTOR USING data_encryption_layer_extracts
        '''
        class FakeStreamEncryptor:
            def __init__(self):
                for data_encryption_layer_extract in data_encryption_layer_extracts:
                    data_encryption_algo = data_encryption_layer_extract["encryption_algo"]  # FIXME RENAME THIS
                    symkey = data_encryption_layer_extract["symkey"]
                    message_digest_algos = data_encryption_layer_extract["message_digest_algos"]
                    # DO SOMETHING WITH THESE
            def encrypt_chunk(self, chunk):
                output_stream.write(chunk)
                return None
            def finalize(self):
                output_stream.flush()
                return None
            def get_authentication_data(self):
                return [{"SHA256": b"a"*32}]  # Matches SIMPLE_CRYPTOCONF of unit test

        stream_encryptor = FakeStreamEncryptor()
        '''
        ############################################################################

        stream_encryptor = StreamManager(
            output_stream=output_stream,
            data_encryption_layer_extracts=data_encryption_layer_extracts,
        )

        return cryptainer, stream_encryptor

    def encrypt_data(self, data: Union[bytes, BinaryIO], *, cryptoconf: dict, keychain_uid=None, metadata=None) -> dict:
        """
        Shortcut when data is already available.

        This method browses through configuration tree to apply the right succession of encryption+signature algorithms to data.

        :param data: initial plaintext, or file pointer (file immediately deleted then)
        :param cryptoconf: configuration tree
        :param keychain_uid: uuid for the set of encryption keys used
        :param metadata: additional data to store unencrypted in cryptainer

        :return: cryptainer with all the information needed to attempt data decryption
        """

        data = self._load_data_bytes_and_cleanup(data)  # Ensure we get the whole data buffer

        cryptainer, data_encryption_layer_extracts = self._generate_cryptainer_base_and_secrets(
           cryptoconf=cryptoconf, keychain_uid=keychain_uid, metadata=metadata
        )

        data_ciphertext, authentication_data_list = \
            self._encrypt_and_hash_data(data, data_encryption_layer_extracts)

        cryptainer["data_ciphertext"] = data_ciphertext

        self.add_authentication_data_to_cryptainer(cryptainer, authentication_data_list)

        return cryptainer

    @staticmethod
    def _load_data_bytes_and_cleanup(data: Union[bytes, BinaryIO]):
        """Automatically deletes filesystem entry if it exists!"""
        if hasattr(data, "read"):  # File-like object
            logger.debug("Reading and deleting open file handle %s", data)
            data_stream = data
            data = data_stream.read()
            data_stream.close()
            delete_filesystem_node_for_stream(data_stream)
        assert isinstance(data, bytes), data
        ## FIXME LATER ADD THIS - assert data, data  # No encryption must be launched if we have no data to process!
        return data

    def _encrypt_and_hash_data(self, data, data_encryption_layer_extracts):
        """TODO"""
        data_current = data

        authentication_data_list = []

        for data_encryption_layer_extract in data_encryption_layer_extracts:
            data_encryption_algo = data_encryption_layer_extract["encryption_algo"]  # FIXME RENAME THIS
            symkey = data_encryption_layer_extract["symkey"]
            message_digest_algos = data_encryption_layer_extract["message_digest_algos"]

            logger.debug("Encrypting data with symmetric key of type %r", data_encryption_algo)
            data_cipherdict = encrypt_bytestring(
                plaintext=data_current, encryption_algo=data_encryption_algo, key_dict=symkey
            )
            assert isinstance(data_cipherdict, dict), data_cipherdict  # Might contain integrity/authentication data

            data_ciphertext = data_cipherdict.pop("ciphertext")  # Mandatory field
            assert isinstance(data_ciphertext, bytes), data_ciphertext  # Same raw content as would be in offloaded data file

            message_digests = {
                message_digest_algo: hash_message(data_ciphertext, hash_algo=message_digest_algo)
                for message_digest_algo in message_digest_algos
            }

            authentication_data_list.append(dict(
                    integrity_tags=data_cipherdict,  # Only remains tags, macs etc.
                    message_digests=message_digests,
            ))

            data_current = data_ciphertext

        return data_current, authentication_data_list

    def _generate_cryptainer_base_and_secrets(self, cryptoconf: dict, keychain_uid=None, metadata=None) -> tuple:
        """
        Build a data-less and signature-less cryptainer, preconfigured with a set of symmetric keys
        under their final form (encrypted by escrows). A separate extract, with symmetric keys as well as algo names, is returned so that actual data encryption and signature can be performed separately.

        :param cryptoconf: configuration tree
        :param keychain_uid: uuid for the set of encryption keys used
        :param metadata: additional data to store unencrypted in cryptainer

        :return: a (cryptainer: dict, secrets: list) tuple, where each secret has keys encryption_algo, symmetric_key and message_digest_algos.
        """

        assert metadata is None or isinstance(metadata, dict), metadata
        cryptainer_format = CRYPTAINER_FORMAT
        cryptainer_uid = generate_uuid0()  # ALWAYS UNIQUE!
        keychain_uid = keychain_uid or generate_uuid0()  # Might be shared by lots of cryptainers

        assert isinstance(cryptoconf, dict), cryptoconf
        cryptainer = copy.deepcopy(cryptoconf)  # So that we can manipulate it as new cryptainer
        del cryptoconf
        if not cryptainer["data_encryption_layers"]:
            raise ConfigurationError("Empty data_encryption_layers list is forbidden in cryptoconf")

        data_encryption_layer_extracts = []  # Sensitive info with secret keys!

        for data_encryption_layer in cryptainer["data_encryption_layers"]:
            data_encryption_algo = data_encryption_layer["data_encryption_algo"]

            data_encryption_layer["integrity_tags"] = None  # Will be filled later with tags/macs etc.

            logger.debug("Generating symmetric key of type %r", data_encryption_algo)
            symkey = generate_symkey(encryption_algo=data_encryption_algo)
            symmetric_key_bytes = dump_to_json_bytes(symkey)
            key_encryption_layers = data_encryption_layer["key_encryption_layers"]

            key_ciphertext = self._encrypt_key_through_multiple_layers(
                    keychain_uid=keychain_uid,
                    key_bytes=symmetric_key_bytes,
                    key_encryption_layers=key_encryption_layers)
            data_encryption_layer["key_ciphertext"] = key_ciphertext

            data_encryption_layer_extract = dict(
                encryption_algo=data_encryption_algo,
                symkey=symkey,
                message_digest_algos=[signature["message_digest_algo"] for signature in
                                      data_encryption_layer["data_signatures"]]
            )
            data_encryption_layer_extracts.append(data_encryption_layer_extract)

        cryptainer.update(
            # FIXME add cryptainer status, PENDING/COMPLETE!!!
            cryptainer_state=CRYPTAINER_STATES.STARTED,
            cryptainer_format=cryptainer_format,
            cryptainer_uid=cryptainer_uid,
            keychain_uid=keychain_uid,
            data_ciphertext = None,  # Must be filled asap, by OFFLOADED_MARKER if needed!
            metadata=metadata,
        )
        return cryptainer, data_encryption_layer_extracts

    def _encrypt_key_through_multiple_layers(self, keychain_uid: uuid.UUID, key_bytes: bytes,
                                             key_encryption_layers: list) -> bytes:
        # HERE KEY IS REAL KEY OR SHARE !!!

        if not key_encryption_layers:
            raise ConfigurationError("Empty key_encryption_layers list is forbidden in cryptoconf")

        key_ciphertext = key_bytes
        for key_encryption_layer in key_encryption_layers:
            key_ciphertext_dict = self._encrypt_key_through_single_layer(
                keychain_uid=keychain_uid, key_bytes=key_ciphertext, key_encryption_layer=key_encryption_layer
            )
            key_ciphertext = dump_to_json_bytes(key_ciphertext_dict)  # Thus its remains as bytes all along

        return key_ciphertext


    def _encrypt_key_through_single_layer(self, keychain_uid: uuid.UUID, key_bytes: bytes, key_encryption_layer: dict) -> dict:
        """
        Encrypt a symmetric key using an asymmetric encryption scheme.

        The symmetric key data might already be the result of previous encryption passes.
        Encryption can use a simple public key algorithm, or rely on a a set of public keys,
        by using a shared secret scheme.

        :param keychain_uid: uuid for the set of encryption keys used
        :param symmetric_key_data: symmetric key to encrypt (potentially already encrypted)
        :param cryptoconf: dictionary which contain configuration tree

        :return: if the scheme used is 'SHARED_SECRET', a list of encrypted shares is returned. If an asymmetric
        algorithm has been used, a dictionary with all the information needed to decipher the symmetric key is returned.
        """
        assert isinstance(key_bytes, bytes), key_bytes
        key_encryption_algo = key_encryption_layer["key_encryption_algo"]

        if key_encryption_algo == SHARED_SECRET_MARKER:

            key_shared_secret_escrows = key_encryption_layer["key_shared_secret_escrows"]
            shares_count = len(key_shared_secret_escrows)

            threshold_count = key_encryption_layer["key_shared_secret_threshold"]
            assert threshold_count <= shares_count

            logger.debug("Generating Shamir shared secret shares (%d needed amongst %d)", threshold_count, shares_count)

            shares = split_bytestring_as_shamir_shares(
                secret=key_bytes, shares_count=shares_count, threshold_count=threshold_count
            )

            logger.debug("Secret has been shared into %d shares", shares_count)
            assert len(shares) == shares_count

            shares_ciphertexts = []

            for share, escrow_conf in zip(shares, key_shared_secret_escrows):
                share_bytes = dump_to_json_bytes(share)  # The tuple (idx, data) of each share thus becomes encryptable
                shares_ciphertext = self._encrypt_key_through_multiple_layers(  # FIXME rename singular
                        keychain_uid=keychain_uid,
                        key_bytes=share_bytes,
                        key_encryption_layers=escrow_conf["key_encryption_layers"])  # Recursive structure
                shares_ciphertexts.append(shares_ciphertext)

            key_cipherdict = {"shares": shares_ciphertexts}  # A dict is more future-proof
            return key_cipherdict

        else:  # Using asymmetric algorithm

            keychain_uid_encryption = key_encryption_layer.get("keychain_uid") or keychain_uid
            key_cipherdict = self._encrypt_with_asymmetric_cipher(
                encryption_algo=key_encryption_algo,
                keychain_uid=keychain_uid_encryption,
                symmetric_key_data=key_bytes,
                escrow=key_encryption_layer["key_escrow"],
            )
            return key_cipherdict

    def _encrypt_with_asymmetric_cipher(
        self, encryption_algo: str, keychain_uid: uuid.UUID, symmetric_key_data: bytes, escrow  # FIXME change symmetric_key_data
    ) -> dict:
        """
        Encrypt given data with an asymmetric algorithm.

        :param encryption_algo: string with name of algorithm to use
        :param keychain_uid: uuid for the set of encryption keys used
        :param symmetric_key_data: symmetric key as bytes to encrypt
        :param escrow: escrow used for encryption (findable in configuration tree)

        :return: dictionary which contains every data needed to decrypt the ciphered data
        """
        encryption_proxy = get_escrow_proxy(escrow=escrow, key_storage_pool=self._key_storage_pool)

        logger.debug("Generating asymmetric key of type %r", encryption_algo)
        subkey_pem = encryption_proxy.fetch_public_key(keychain_uid=keychain_uid, key_type=encryption_algo)

        logger.debug("Encrypting symmetric key with asymmetric key of type %r", encryption_algo)
        subkey = load_asymmetric_key_from_pem_bytestring(key_pem=subkey_pem, key_type=encryption_algo)

        cipherdict = encrypt_bytestring(plaintext=symmetric_key_data, encryption_algo=encryption_algo, key_dict={"key": subkey})
        return cipherdict

    def ____obsolete_____encrypt_shares(self, shares: Sequence, key_shared_secret_escrows: Sequence, keychain_uid: uuid.UUID) -> list:
        """
        Make a loop through all shares from shared secret algorithm to encrypt each of them.

        :param shares: list of tuples containing an index and its share data
        :param key_shared_secret_escrows: cryptoconf subtree with share escrow information
        :param keychain_uid: uuid for the set of encryption keys used

        :return: list of encrypted shares
        """

        all_encrypted_shares = []

        assert len(shares) == len(key_shared_secret_escrows)

        for shared_idx, share in enumerate(shares):
            assert isinstance(share[1], bytes), repr(share)

            conf_share = key_shared_secret_escrows[shared_idx]
            share_encryption_algo = conf_share["share_encryption_algo"]
            share_escrow = conf_share["share_escrow"]
            keychain_uid_share = conf_share.get("keychain_uid") or keychain_uid

            share_cipherdict = self._encrypt_with_asymmetric_cipher(
                encryption_algo=share_encryption_algo,
                keychain_uid=keychain_uid_share,
                symmetric_key_data=share[1],
                escrow=share_escrow,
            )

            all_encrypted_shares.append((share[0], share_cipherdict))

        assert len(shares) == len(key_shared_secret_escrows)
        return all_encrypted_shares

    def add_authentication_data_to_cryptainer(self, cryptainer: dict, authentication_data_list: list):
        keychain_uid = cryptainer["keychain_uid"]

        data_encryption_layers = cryptainer["data_encryption_layers"]
        assert len(data_encryption_layers) == len(authentication_data_list)  # Sanity check

        for data_encryption_layer, authentication_data_list in zip(cryptainer["data_encryption_layers"], authentication_data_list):

            assert data_encryption_layer["integrity_tags"] is None  # Set at cryptainer build time
            data_encryption_layer["integrity_tags"] = authentication_data_list["integrity_tags"]

            message_digests = authentication_data_list["message_digests"]

            _encountered_message_digest_algos = set()
            for signature_conf in data_encryption_layer["data_signatures"]:
                message_digest_algo = signature_conf["message_digest_algo"]

                signature_conf["message_digest"] = message_digests[message_digest_algo]  # MUST exist, else incoherence
                # FIXME ADD THIS NEW FIELD TO SCHEMA VALIDATOR!!!!

                signature_value = self._generate_message_signature(
                    keychain_uid=keychain_uid,
                   cryptoconf=signature_conf)
                signature_conf["signature_value"] = signature_value

                _encountered_message_digest_algos.add(message_digest_algo)
            assert _encountered_message_digest_algos == set(message_digests)  # No abnormal extra digest

        cryptainer["cryptainer_state"] = CRYPTAINER_STATES.FINISHED

    def _generate_message_signature(self, keychain_uid: uuid.UUID, cryptoconf: dict) -> dict:
        """
        Generate a signature for a specific ciphered data.

        :param keychain_uid: uuid for the set of encryption keys used
        :param cryptoconf: configuration tree inside data_signatures, which MUST already contain the message digest
        :return: dictionary with information needed to verify signature
        """
        signature_algo = cryptoconf["signature_algo"]
        message_digest = cryptoconf["message_digest"]  # Must have been set before, using message_digest_algo field
        assert message_digest, message_digest

        encryption_proxy = get_escrow_proxy(escrow=cryptoconf["signature_escrow"], key_storage_pool=self._key_storage_pool)

        keychain_uid_signature = cryptoconf.get("keychain_uid") or keychain_uid

        logger.debug("Signing hash of encrypted data with algo %r", signature_algo)
        signature_value = encryption_proxy.get_message_signature(
            keychain_uid=keychain_uid_signature, message=message_digest, signature_algo=signature_algo
        )
        return signature_value


class CryptainerReader(CryptainerBase):  #FIXME rename to CryptainerDecryptor
    """
    Contains every method used to read and decrypt a cryptainer, IN MEMORY.
    """

    def extract_metadata(self, cryptainer: dict) -> Optional[dict]:
        assert isinstance(cryptainer, dict), cryptainer
        return cryptainer["metadata"]

    def decrypt_data(self, cryptainer: dict, verify: bool=True) -> bytes:
        """
        Loop through cryptainer layers, to decipher data with the right algorithms.

        :param cryptainer: dictionary previously built with CryptainerWriter method
        :param verify: whether to check tag/mac values of the ciphertext

        :return: deciphered plaintext
        """
        assert isinstance(cryptainer, dict), cryptainer

        cryptainer_format = cryptainer["cryptainer_format"]
        if cryptainer_format != CRYPTAINER_FORMAT:
            raise ValueError("Unknown cryptainer format %s" % cryptainer_format)

        cryptainer_uid = cryptainer["cryptainer_uid"]
        del cryptainer_uid  # Might be used for logging etc, later...

        keychain_uid = cryptainer["keychain_uid"]

        data_current = cryptainer["data_ciphertext"]
        assert isinstance(data_current, bytes), repr(data_current)  # Else it's still a special marker for example...

        for data_encryption_layer in reversed(cryptainer["data_encryption_layers"]):  # Non-emptiness of this will be checked by validator

            data_encryption_algo = data_encryption_layer["data_encryption_algo"]

            for signature_conf in data_encryption_layer["data_signatures"]:
                self._verify_message_signature(keychain_uid=keychain_uid, message=data_current, cryptoconf=signature_conf)

            key_ciphertext = data_encryption_layer["key_ciphertext"]  # We start fully encrypted, and unravel it

            # FIXME rename to symmetric_key_bytes
            key_bytes = self._decrypt_key_through_multiple_layers(
                keychain_uid=keychain_uid,
                key_ciphertext=key_ciphertext,
                encryption_layers=data_encryption_layer["key_encryption_layers"])
            assert isinstance(key_bytes, bytes), key_bytes
            symkey = load_from_json_bytes(key_bytes)

            integrity_tags = data_encryption_layer["integrity_tags"]  # Shall be a DICT, FIXME handle if it's still None
            data_cipherdict = dict(ciphertext=data_current, **integrity_tags)
            data_current = decrypt_bytestring(
                cipherdict=data_cipherdict, key_dict=symkey, encryption_algo=data_encryption_algo, verify=verify
            )

        data = data_current  # Now decrypted
        return data

    def _decrypt_key_through_multiple_layers(self, keychain_uid: uuid.UUID, key_ciphertext: bytes, encryption_layers: list) -> bytes:
        key_bytes = key_ciphertext

        for key_encryption_layer in reversed(encryption_layers):  # Non-emptiness of this will be checked by validator
            key_cipherdict = load_from_json_bytes(key_bytes)  # We remain as bytes all along
            key_bytes = self._decrypt_key_through_single_layer(
                keychain_uid=keychain_uid,
                key_cipherdict=key_cipherdict,
                encryption_layer=key_encryption_layer,
            )

        return key_bytes

    def _decrypt_key_through_single_layer(self, keychain_uid: uuid.UUID, key_cipherdict: dict, encryption_layer: dict) -> bytes:
        """
        Function called when decryption of a symmetric key is needed. Encryption may be made by shared secret or
        by a asymmetric algorithm.

        :param keychain_uid: uuid for the set of encryption keys used
        :param symmetric_key_cipherdict: dictionary with input ata needed to decrypt symmetric key
        :param cryptoconf: dictionary which contains crypto configuration tree

        :return: deciphered symmetric key
        """
        assert isinstance(key_cipherdict, dict), key_cipherdict
        key_encryption_algo = encryption_layer["key_encryption_algo"]

        if key_encryption_algo == SHARED_SECRET_MARKER:

            decrypted_shares = []
            decryption_errors = []
            key_shared_secret_escrows = encryption_layer["key_shared_secret_escrows"]  # FIXMe rename twice
            key_shared_secret_threshold = encryption_layer["key_shared_secret_threshold"]

            shares_ciphertexts = key_cipherdict["shares"]  # FIXME rename to share_ciphertexts

            logger.debug("Deciphering each share")

            # If some shares are missing, we won't detect it here because zip() stops at shortest list
            for share_ciphertext, escrow_conf in zip(shares_ciphertexts, key_shared_secret_escrows):

                try:
                    share_bytes = self._decrypt_key_through_multiple_layers(
                            keychain_uid=keychain_uid,
                            key_ciphertext=share_ciphertext,
                            encryption_layers=escrow_conf["key_encryption_layers"])  # Recursive structure
                    share = load_from_json_bytes(share_bytes)  # The tuple (idx, data) of each share thus becomes encryptable
                    decrypted_shares.append(share)

                # FIXME use custom exceptions here, when all are properly translated (including ValueError...)
                except Exception as exc:  # If actual escrow doesn't work, we can go to next one
                    decryption_errors.append(exc)
                    logger.error("Error when decrypting share of %s: %r" % (escrow_conf, exc), exc_info=True)

                if len(decrypted_shares) == key_shared_secret_threshold:
                    logger.debug("A sufficient number of shares has been decrypted")
                    break

            if len(decrypted_shares) < key_shared_secret_threshold:
                raise DecryptionError(
                    "%s valid share(s) missing for reconstitution of symmetric key (errors: %r)"
                    % (key_shared_secret_threshold - len(decrypted_shares), decryption_errors)
                )

            logger.debug("Recombining shared-secret shares")
            key_bytes = recombine_secret_from_shamir_shares(shares=decrypted_shares)
            return key_bytes

        else:  # Using asymmetric algorithm

            # FIXME replace by shorter form everywhere in file
            keychain_uid_encryption = (encryption_layer.get("keychain_uid") or keychain_uid)

            key_bytes = self._decrypt_with_asymmetric_cipher(
                encryption_algo=key_encryption_algo,
                keychain_uid=keychain_uid_encryption,
                cipherdict=key_cipherdict,
                escrow=encryption_layer["key_escrow"],
            )
            return key_bytes

    def _decrypt_with_asymmetric_cipher(
            self, encryption_algo: str, keychain_uid: uuid.UUID, cipherdict: dict, escrow: dict
    ) -> bytes:
        """
        Decrypt given cipherdict with an asymmetric algorithm.

        :param encryption_algo: string with name of algorithm to use
        :param keychain_uid: uuid for the set of encryption keys used
        :param cipherdict: dictionary with data components needed to decrypt the ciphered data
        :param escrow: escrow used for encryption (findable in configuration tree)

        :return: decypted data as bytes
        """
        encryption_proxy = get_escrow_proxy(escrow=escrow, key_storage_pool=self._key_storage_pool)

        escrow_id = get_escrow_id(escrow)
        passphrases = self._passphrase_mapper.get(escrow_id) or []
        assert isinstance(passphrases, list), repr(passphrases)  # No SINGLE passphrase here

        passphrases += self._passphrase_mapper.get(None) or []  # Add COMMON passphrases

        # We expect decryption authorization requests to have already been done properly
        symmetric_key_plaintext = encryption_proxy.decrypt_with_private_key(
            keychain_uid=keychain_uid, encryption_algo=encryption_algo, cipherdict=cipherdict, passphrases=passphrases
        )
        return symmetric_key_plaintext

    def ________decrypt_symmetric_key_share(self, keychain_uid: uuid.UUID, symmetric_key_cipherdict: dict, cryptoconf: dict):
        """
        Make a loop through all encrypted shares to decrypt each of them
        :param keychain_uid: uuid for the set of encryption keys used
        :param symmetric_key_cipherdict: dictionary which contains every data needed to decipher each share
        :param cryptoconf: configuration tree inside key_encryption_algo

        :return: list of tuples of deciphered shares
        """
        key_shared_secret_escrows = cryptoconf["key_shared_secret_escrows"]
        key_shared_secret_threshold = cryptoconf["key_shared_secret_threshold"]

        decrypted_shares = []
        decryption_errors = []

        assert len(symmetric_key_cipherdict["shares"]) <= len(
            key_shared_secret_escrows
        )  # During tests we erase some cryptainer shares...

        for share_idx, share_conf in enumerate(key_shared_secret_escrows):

            share_encryption_algo = share_conf["share_encryption_algo"]
            share_escrow = share_conf["share_escrow"]
            keychain_uid_share = share_conf.get("keychain_uid") or keychain_uid

            try:
                try:
                    encrypted_share = symmetric_key_cipherdict["shares"][share_idx]
                except IndexError:
                    raise ValueError("Missing share at index %s" % share_idx) from None

                share_plaintext = self._decrypt_with_asymmetric_cipher(
                    encryption_algo=share_encryption_algo,
                    keychain_uid=keychain_uid_share,
                    cipherdict=encrypted_share[1],
                    escrow=share_escrow,
                )
                share = (encrypted_share[0], share_plaintext)
                decrypted_shares.append(share)

            # FIXME use custom exceptions here, when all are properly translated (including ValueError...)
            except Exception as exc:  # If actual escrow doesn't work, we can go to next one
                decryption_errors.append(exc)
                logger.error("Error when decrypting share of %s: %r" % (share_escrow, exc), exc_info=True)

            if len(decrypted_shares) == key_shared_secret_threshold:
                logger.debug("A sufficient number of shares has been decrypted")
                break

        if len(decrypted_shares) < key_shared_secret_threshold:
            raise DecryptionError(
                "%s valid share(s) missing for reconstitution of symmetric key (errors: %r)"
                % (key_shared_secret_threshold - len(decrypted_shares), decryption_errors)
            )
        return decrypted_shares

    def _verify_message_signature(self, keychain_uid: uuid.UUID, message: bytes, cryptoconf: dict):
        """
        Verify a signature for a specific message. An error is raised if signature isn't correct.

        :param keychain_uid: uuid for the set of encryption keys used
        :param message: message as bytes on which to verify signature
        :param cryptoconf: configuration tree inside data_signatures
        """
        message_digest_algo = cryptoconf["message_digest_algo"]
        signature_algo = cryptoconf["signature_algo"]
        keychain_uid_signature = cryptoconf.get("keychain_uid") or keychain_uid
        encryption_proxy = get_escrow_proxy(escrow=cryptoconf["signature_escrow"], key_storage_pool=self._key_storage_pool)
        public_key_pem = encryption_proxy.fetch_public_key(
            keychain_uid=keychain_uid_signature, key_type=signature_algo, must_exist=True
        )
        public_key = load_asymmetric_key_from_pem_bytestring(key_pem=public_key_pem, key_type=signature_algo)

        message_hash = hash_message(message, hash_algo=message_digest_algo)
        assert message_hash == cryptoconf["message_digest"]  # Sanity check!!
        signature_value = cryptoconf["signature_value"]

        verify_message_signature(
            message=message_hash, signature_algo=signature_algo, signature=signature_value, key=public_key
        )  # Raises if troubles


class CryptainerEncryptionStream:
    """
    Helper which prebuilds a cryptainer without signatures nor data,
    affords to fill its offloaded ciphertext file chunk by chunk, and then
    dumps the final cryptainer now containing signatures.
    """

    def __init__(self,
                 cryptainer_filepath: Path,
                 *,
                cryptoconf: dict,
                metadata: Optional[dict],
                keychain_uid: Optional[uuid.UUID] = None,
                key_storage_pool: Optional[KeyStoragePoolBase] = None,
                dump_initial_cryptainer=True):

        self._cryptainer_filepath = cryptainer_filepath
        self._cryptainer_filepath_temp = cryptainer_filepath.with_suffix(cryptainer_filepath.suffix + CRYPTAINER_TEMP_SUFFIX)

        offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
        self._output_data_stream = open(offloaded_file_path, mode='wb')

        self._cryptainer_writer = CryptainerWriter(key_storage_pool=key_storage_pool)
        self._wip_cryptainer, self._stream_encryptor = self._cryptainer_writer.build_cryptainer_and_stream_encryptor(output_stream=self._output_data_stream, cryptoconf=cryptoconf, keychain_uid=keychain_uid, metadata=metadata)
        self._wip_cryptainer["data_ciphertext"] = OFFLOADED_MARKER  # Important

        if dump_initial_cryptainer:  # Savegame in case the stream is broken before finalization
            self._dump_current_cryptainer_to_filesystem(is_temporary=True)

    def _dump_current_cryptainer_to_filesystem(self, is_temporary):
        filepath = self._cryptainer_filepath_temp if is_temporary else self._cryptainer_filepath
        dump_cryptainer_to_filesystem(filepath, cryptainer=self._wip_cryptainer,
                                     offload_data_ciphertext=False)  # ALREADY offloaded
        if not is_temporary:  # Cleanup temporary cryptainer
            self._cryptainer_filepath_temp.unlink(missing_ok=True)

    def encrypt_chunk(self, chunk: bytes):
        self._stream_encryptor.encrypt_chunk(chunk)

    def finalize(self):
        self._stream_encryptor.finalize()
        self._output_data_stream.close()  # Important

        authentication_data_list = self._stream_encryptor.get_authentication_data()

        self._cryptainer_writer.add_authentication_data_to_cryptainer(self._wip_cryptainer, authentication_data_list)
        self._dump_current_cryptainer_to_filesystem(is_temporary=False)

    def __del__(self):
        # Emergency closing of open file on deletion
        if not self._output_data_stream.closed:
            logger.error("Encountered abnormal open file in __del__ of CryptainerEncryptionStream: %s" % self._output_data_stream)
            self._output_data_stream.close()


def is_cryptainer_cryptoconf_streamable(cryptoconf):  #FIXME rename and add to docs
    # FIXME test separately!
    for data_encryption_layer in cryptoconf["data_encryption_layers"]:
        if data_encryption_layer["data_encryption_algo"] not in STREAMABLE_ENCRYPTION_ALGOS:
            return False
    return True


def encrypt_data_and_dump_cryptainer_to_filesystem(
    data: Union[bytes, BinaryIO],
    *,
    cryptainer_filepath,
    cryptoconf: dict,
    metadata: Optional[dict],
    keychain_uid: Optional[uuid.UUID] = None,
    key_storage_pool: Optional[KeyStoragePoolBase] = None
) -> None:
    """
    Optimized version which directly streams encrypted data to offloaded file,
    instead of creating a whole cryptainer and then dumping it to disk.
    """
    # No need to dump initial (signature-less) cryptainer here, this is all a quick operation...
    encryptor = CryptainerEncryptionStream(cryptainer_filepath,
                cryptoconf=cryptoconf, keychain_uid=keychain_uid, metadata=metadata,
                key_storage_pool=key_storage_pool,
                dump_initial_cryptainer=False)

    for chunk in consume_bytes_as_chunks(data, chunk_size=DATA_CHUNK_SIZE):
        encryptor.encrypt_chunk(chunk)

    encryptor.finalize()  # Handles the dumping to disk


def encrypt_data_into_cryptainer(
    data: Union[bytes, BinaryIO],
    *,
    cryptoconf: dict,
    metadata: Optional[dict],
    keychain_uid: Optional[uuid.UUID] = None,
    key_storage_pool: Optional[KeyStoragePoolBase] = None
) -> dict:
    """Turn raw data into a high-security cryptainer, which can only be decrypted with
    the agreement of the owner and multiple third-party escrows.

    :param data: bytestring of media (image, video, sound...) or readable file object (file immediately deleted then)
    :param cryptoconf: tree of specific encryption settings
    :param metadata: dict of metadata describing the data (remains unencrypted in cryptainer)
    :param keychain_uid: optional ID of a keychain to reuse
    :param key_storage_pool: optional key storage pool, might be required by cryptoconf
    :return: dict of cryptainer
    """
    writer = CryptainerWriter(key_storage_pool=key_storage_pool)
    cryptainer = writer.encrypt_data(data, cryptoconf=cryptoconf, keychain_uid=keychain_uid, metadata=metadata)
    return cryptainer


def decrypt_data_from_cryptainer(
    cryptainer: dict, *, key_storage_pool: Optional[KeyStoragePoolBase] = None, passphrase_mapper: Optional[dict] = None, verify: bool=True
) -> bytes:
    """Decrypt a cryptainer with the help of third-parties.

    :param cryptainer: the cryptainer tree, which holds all information about involved keys
    :param key_storage_pool: optional key storage pool
    :param passphrase_mapper: optional dict mapping escrow IDs to their lists of passphrases
    :param verify: whether to check tag/mac values of the ciphertext

    :return: raw bytestring
    """
    reader = CryptainerReader(key_storage_pool=key_storage_pool, passphrase_mapper=passphrase_mapper)
    data = reader.decrypt_data(cryptainer=cryptainer, verify=verify)
    return data


def _get_offloaded_file_path(cryptainer_filepath: Path):
    """We also support, discreetly, TEMPORARY cryptainers"""
    return cryptainer_filepath.parent.joinpath(cryptainer_filepath.name.rstrip(CRYPTAINER_TEMP_SUFFIX) + OFFLOADED_DATA_SUFFIX)


def dump_cryptainer_to_filesystem(cryptainer_filepath: Path, cryptainer: dict, offload_data_ciphertext=True) -> None:
    """Dump a cryptainer to a file path, overwritting it if existing.

    If `offload_data_ciphertext`, actual encrypted data is dumped to a separate bytes file nearby the json-formatted cryptainer.
    """
    if offload_data_ciphertext:
        offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
        assert isinstance(cryptainer["data_ciphertext"], bytes), cryptainer["data_ciphertext"]
        offloaded_file_path.write_bytes(cryptainer["data_ciphertext"])
        cryptainer = cryptainer.copy()  # DO NOT touch original dict!
        cryptainer["data_ciphertext"] = OFFLOADED_MARKER
    dump_to_json_file(cryptainer_filepath, cryptainer)


def load_cryptainer_from_filesystem(cryptainer_filepath: Path, include_data_ciphertext=True) -> dict:
    """Load a json-formatted cryptainer from a file path, potentially loading its offloaded ciphertext from a separate nearby bytes file.

    Field `data_ciphertext` is only present in result dict if `include_data_ciphertext` is True.
    """

    cryptainer = load_from_json_file(cryptainer_filepath)

    if include_data_ciphertext:
        if cryptainer["data_ciphertext"] == OFFLOADED_MARKER:
            offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
            cryptainer["data_ciphertext"] = offloaded_file_path.read_bytes()
    else:
        del cryptainer["data_ciphertext"]

    return cryptainer


def delete_cryptainer_from_filesystem(cryptainer_filepath):
    """Delete a cryptainer file and its potential offloaded data file."""
    os.remove(cryptainer_filepath)  # TODO - additional retries if file access errors?
    offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
    if offloaded_file_path.exists():
        # We don't care about OFFLOADED_MARKER here, we go the quick way
        os.remove(offloaded_file_path)


def get_cryptainer_size_on_filesystem(cryptainer_filepath):
    """Return the total size in bytes occupied by a cryptainer and its potential offloaded data file."""
    size = cryptainer_filepath.stat().st_size  # Might fail if file got deleted concurrently
    offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
    if offloaded_file_path.exists():
        # We don't care about OFFLOADED_MARKER here, we go the quick way
        size += offloaded_file_path.stat().st_size
    return size


def extract_metadata_from_cryptainer(cryptainer: dict) -> Optional[dict]:  # FIXME move that up, like in docs
    """Read the metadata tree (possibly None) from a cryptainer.

    CURRENTLY METADATA IS NOT ENCRYPTED.

    :param cryptainer: the cryptainer tree, which also holds metadata about encrypted content

    :return: dict
    """
    reader = CryptainerReader()
    data = reader.extract_metadata(cryptainer)
    return data


# FIXME add ReadonlyCryptainerStorage!!

class CryptainerStorage:
    """
    This class encrypts file streams and stores them into filesystem, in a thread-safe way.

    Exceeding cryptainers are automatically purged when enqueuing new files or waiting for idle state.

    A thread pool is used to encrypt files in the background.

    :param cryptainers_dir: the folder where cryptainer files are stored
    :param default_encryption_cryptoconf: cryptoconf to use when none is provided when enqueuing data
    :param max_cryptainer_quota: if set, cryptainers are deleted if they exceed this size in bytes
    :param max_cryptainer_count: if set, oldest exceeding cryptainers (time taken from their name, else their file-stats) are automatically erased
    :param max_cryptainer_age: if set, cryptainers exceeding this age (taken from their name, else their file-stats) in days are automatically erased
    :param key_storage_pool: optional KeyStoragePool, which might be required by current encryptioncryptoconf
    :param max_workers: count of worker threads to use in parallel
    :param offload_data_ciphertext: whether actual encrypted data must be kept separated from structured cryptainer file
    """

    def __init__(
        self,
        cryptainer_dir: Path,
        default_cryptoconf: Optional[dict] = None,
        max_cryptainer_quota: Optional[int] = None,
        max_cryptainer_count: Optional[int] = None,
        max_cryptainer_age: Optional[timedelta] = None,
        key_storage_pool: Optional[KeyStoragePoolBase] = None,
        max_workers: int = 1,
        offload_data_ciphertext=True,
    ):
        cryptainer_dir = Path(cryptainer_dir)
        assert cryptainer_dir.is_dir(), cryptainer_dir
        cryptainer_dir = cryptainer_dir.absolute()
        assert max_cryptainer_quota is None or max_cryptainer_quota >= 0, max_cryptainer_quota
        assert max_cryptainer_count is None or max_cryptainer_count >= 0, max_cryptainer_count
        assert max_cryptainer_age is None or max_cryptainer_age >= timedelta(seconds=0), max_cryptainer_age
        self._default_cryptoconf = default_cryptoconf
        self._cryptainer_dir = cryptainer_dir
        self._max_cryptainer_quota = max_cryptainer_quota
        self._max_cryptainer_count = max_cryptainer_count
        self._max_cryptainer_age = max_cryptainer_age
        self._key_storage_pool = key_storage_pool
        self._thread_pool_executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="cryptainer_worker")
        self._pending_executor_futures = []
        self._lock = threading.Lock()
        self._offload_data_ciphertext = offload_data_ciphertext

    def __del__(self):
        self._thread_pool_executor.shutdown(wait=False)

    def __len__(self):
        """Beware, might be SLOW if many files are present in folder."""
        return len(self.list_cryptainer_names())  # No sorting, to be quicker

    def list_cryptainer_names(self, as_sorted=False, as_absolute=False):  # FIXME add annotations everywhere
        """Returns the list of encrypted cryptainers present in storage,
        sorted by name or not, absolute or not, as Path objects."""
        assert self._cryptainer_dir.is_absolute(), self._cryptainer_dir
        paths = list(self._cryptainer_dir.glob("*" + CRYPTAINER_SUFFIX))  # As list, for multiple looping on it
        assert all(p.is_absolute() for p in paths), paths
        if as_sorted:
            paths = sorted(paths)
        if not as_absolute:
            paths = (Path(p.name) for p in paths)  # beware, only works since we don't have subfolders for now!
        return list(paths)

    def _get_cryptainer_datetime(self, cryptainer_name):  # FIXME rename to _get_cryptainer_datetime_utc()
        """Returns an UTC datetime corresponding to the creation time stored in filename, or else the file-stat mtime"""
        try:
            dt = datetime.strptime(cryptainer_name.name.split("_")[0], CRYPTAINER_DATETIME_FORMAT)
            dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            mtime = self._make_absolute(cryptainer_name).stat().st_mtime  # Might fail if file got deleted concurrently
            dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
        return dt

    def _get_cryptainer_size(self, cryptainer_name):
        """Returns a size in bytes"""
        return get_cryptainer_size_on_filesystem(self._make_absolute(cryptainer_name))

    def list_cryptainer_properties(self, with_age=False, with_size=False):
        """Returns an unsorted list of dicts having the fields "name", [age] and [size], depending on requested properties."""
        cryptainer_names = self.list_cryptainer_names(as_sorted=False, as_absolute=False)

        now = get_utc_now_date()

        result = []
        for cryptainer_name in cryptainer_names:
            entry = dict(name=cryptainer_name)
            if with_age:
                cryptainer_datetime = self._get_cryptainer_datetime(cryptainer_name)
                entry["age"] = now - cryptainer_datetime   # We keep as timedelta
            if with_size:
                entry["size"] = self._get_cryptainer_size(cryptainer_name)
            result.append(entry)
        return result

    def _make_absolute(self, cryptainer_name):
        assert not Path(cryptainer_name).is_absolute()
        return self._cryptainer_dir.joinpath(cryptainer_name)

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

    def _encrypt_data_and_dump_cryptainer_to_filesystem(self, data, cryptainer_filepath, metadata, keychain_uid, cryptoconf):
        assert cryptoconf, cryptoconf
        encrypt_data_and_dump_cryptainer_to_filesystem(
                cryptainer_filepath=cryptainer_filepath,
                    data=data,
                   cryptoconf=cryptoconf,
                    metadata=metadata,
                    keychain_uid=keychain_uid,
                    key_storage_pool=self._key_storage_pool,
                )

    def _encrypt_data_into_cryptainer(self, data, metadata, keychain_uid, cryptoconf):
        assert cryptoconf, cryptoconf
        return encrypt_data_into_cryptainer(
            data=data,
           cryptoconf=cryptoconf,
            metadata=metadata,
            keychain_uid=keychain_uid,
            key_storage_pool=self._key_storage_pool,
        )

    def _decrypt_data_from_cryptainer(self, cryptainer: dict, passphrase_mapper: Optional[dict], verify: bool) -> bytes:
        return decrypt_data_from_cryptainer(
            cryptainer, key_storage_pool=self._key_storage_pool, passphrase_mapper=passphrase_mapper, verify=verify
        )  # Will fail if authorizations are not OK

    @catch_and_log_exception
    def _offloaded_encrypt_data_and_dump_cryptainer(self, filename_base, data, metadata, keychain_uid, cryptoconf):
        """Task to be called by background thread, which encrypts a payload into a disk cryptainer.

        Returns the cryptainer basename."""

        """ TODO later ass a SKIP here!
        if not data:
            logger.warning("Skipping encryption of empty data payload for file %s", filename_base)
            return
        """

        cryptainer_filepath = self._make_absolute(filename_base + CRYPTAINER_SUFFIX)

        if self._use_streaming_encryption_for_conf(cryptoconf):
            # We can use newer, low-memory, streamed API
            logger.debug("Encrypting data file %s into offloaded cryptainer directly streamed to storage file %s", filename_base, cryptainer_filepath)
            self._encrypt_data_and_dump_cryptainer_to_filesystem(
                data, cryptainer_filepath=cryptainer_filepath, metadata=metadata, keychain_uid=keychain_uid, cryptoconf=cryptoconf
            )

        else:
            # We use legacy API which encrypts all and then dumps all

            logger.debug("Encrypting data file to self-sufficient cryptainer %s", filename_base)
            # Memory warning : duplicates data to json-compatible cryptainer
            cryptainer = self._encrypt_data_into_cryptainer(
                data, metadata=metadata, keychain_uid=keychain_uid, cryptoconf=cryptoconf
            )
            logger.debug("Writing self-sufficient cryptainer data to storage file %s", cryptainer_filepath)
            dump_cryptainer_to_filesystem(
                cryptainer_filepath, cryptainer=cryptainer, offload_data_ciphertext=self._offload_data_ciphertext
            )

        logger.info("Data file %r successfully encrypted into storage cryptainer", filename_base)
        return cryptainer_filepath.name

    def _use_streaming_encryption_for_conf(self, cryptoconf):  # FIXME rename to cryptoconf
        return self._offload_data_ciphertext and is_cryptainer_cryptoconf_streamable(cryptoconf)

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
    def create_cryptainer_encryption_stream(self, filename_base, metadata, keychain_uid=None, cryptoconf=None, dump_initial_cryptainer=True):
        logger.info("Enqueuing file %r for encryption and storage", filename_base)
        cryptainer_filepath = self._make_absolute(filename_base + CRYPTAINER_SUFFIX)
        cryptoconf = self._prepare_for_new_record_encryption(cryptoconf)
        cryptainer_encryption_stream = CryptainerEncryptionStream(cryptainer_filepath,
                     cryptoconf=cryptoconf,
                     metadata=metadata,
                     keychain_uid=keychain_uid,
                     key_storage_pool=self._key_storage_pool,
                     dump_initial_cryptainer=dump_initial_cryptainer)
        return cryptainer_encryption_stream

    @synchronized
    def enqueue_file_for_encryption(self, filename_base, data, metadata, keychain_uid=None, cryptoconf=None):
        """Enqueue a data payload for asynchronous encryption and storage.

        The filename of final cryptainer might be different from provided one.
        And beware, target cryptainer with the same constructed name might be overwritten.

        :param data: Bytes string, or a file-like object open for reading, which will be automatically closed.
        :param metadata: Dict of metadata added (unencrypted) to cryptainer.
        :param keychain_uid: If provided, replaces autogenerated keychain_uid for this cryptainer.
        :param cryptoconf: If provided, replaces default cryptoconf for this cryptainer.
        """
        logger.info("Enqueuing file %r for encryption and storage", filename_base)

        cryptoconf = self._prepare_for_new_record_encryption(cryptoconf)

        future = self._thread_pool_executor.submit(
            self._offloaded_encrypt_data_and_dump_cryptainer,
            filename_base=filename_base,
            data=data,
            metadata=metadata,
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

    def load_cryptainer_from_storage(self, cryptainer_name_or_idx, include_data_ciphertext=True) -> dict:
        """
        Return the encrypted cryptainer dict for `cryptainer_name_or_idx` (which must be in `list_cryptainer_names()`,
        or an index suitable for this sorted list).
        """
        if isinstance(cryptainer_name_or_idx, int):
            cryptainer_names = self.list_cryptainer_names(as_sorted=True, as_absolute=False)
            cryptainer_name = cryptainer_names[cryptainer_name_or_idx]  # Will break if idx is out of bounds
        else:
            assert isinstance(cryptainer_name_or_idx, (Path, str)), repr(cryptainer_name_or_idx)
            cryptainer_name = Path(cryptainer_name_or_idx)
        assert not cryptainer_name.is_absolute(), cryptainer_name

        logger.info("Loading cryptainer %s from storage", cryptainer_name)
        cryptainer_filepath = self._make_absolute(cryptainer_name)
        cryptainer = load_cryptainer_from_filesystem(cryptainer_filepath, include_data_ciphertext=include_data_ciphertext)
        return cryptainer

    def decrypt_cryptainer_from_storage(self, cryptainer_name_or_idx, passphrase_mapper: Optional[dict]=None, verify: bool=True) -> bytes:
        """
        Return the decrypted content of the cryptainer `cryptainer_name_or_idx` (which must be in `list_cryptainer_names()`,
        or an index suitable for this sorted list).
        """
        logger.info("Decrypting cryptainer %r from storage", cryptainer_name_or_idx)

        cryptainer = self.load_cryptainer_from_storage(cryptainer_name_or_idx, include_data_ciphertext=True)

        result = self._decrypt_data_from_cryptainer(cryptainer, passphrase_mapper=passphrase_mapper, verify=verify)
        logger.info("Cryptainer %s successfully decrypted", cryptainer_name_or_idx)
        return result

    def check_cryptainer_sanity(self, cryptainer_name_or_idx):
        """Allows the validation of a cryptainer with a python"""
        cryptainer = self.load_cryptainer_from_storage(cryptainer_name_or_idx, include_data_ciphertext=True)

        check_cryptainer_sanity(cryptainer=cryptainer, jsonschema_mode=False)


def get_cryptoconf_summary(conf_or_cryptainer):  # FIXME move up like in docs
    """
    Returns a string summary of the layers of encryption/signature of a cryptainer or a configuration tree.
    """

    def _get_escrow_identifier(_escrow):
        if _escrow == LOCAL_ESCROW_MARKER:
            _escrow = "local device"
        elif "url" in _escrow:
            _escrow = urlparse(_escrow["url"]).netloc
        else:
            raise ValueError("Unrecognized key escrow %s" % _escrow)
        return _escrow

    lines = []
    for idx, data_encryption_layer in enumerate(conf_or_cryptainer["data_encryption_layers"], start=1):
        lines.append("Data encryption layer %d: %s" % (idx, data_encryption_layer["data_encryption_algo"]))
        lines.append("  Key encryption layers:")
        for idx2, key_encryption_layer in enumerate(data_encryption_layer["key_encryption_layers"], start=1):
            key_escrow = key_encryption_layer["key_escrow"]
            escrow_id = _get_escrow_identifier(key_escrow)
            lines.append("    %s (by %s)" % (key_encryption_layer["key_encryption_algo"], escrow_id))
        lines.append("  Signatures:")
        for idx3, data_signature in enumerate(data_encryption_layer["data_signatures"], start=1):
            signature_escrow = data_signature["signature_escrow"]
            escrow_id = _get_escrow_identifier(signature_escrow)
            lines.append(
                "    %s/%s (by %s)"
                % (data_signature["message_digest_algo"], data_signature["signature_algo"], escrow_id)
            )
    result = "\n".join(lines) + "\n"
    return result


def _create_schema(for_cryptainer: bool, extended_json_format: bool):
    """Create validation schema for confs and cryptainers.
    :param for_cryptainer: true if instance is a cryptainer
    :param extended_json_format: true if the scheme is extended to json format

    :return: a schema.
    """

    micro_schema_uid = UUID
    micro_schema_binary = bytes
    micro_schema_int = int
    micro_schema_long = int

    if extended_json_format:
        # global SCHEMA_CRYPTAINERS
        _micro_schema_hex_uid = And(str, Or(Regex(
            '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$'), Regex(
            '[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}')))
        micro_schema_uid = {
            "$binary": {
                "base64": _micro_schema_hex_uid,
                "subType": "03"}}
        micro_schema_binary = {
            "$binary": {
                "base64": And(str,
                              Regex(
                                  '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$')),
                "subType": "00"}
        }
        micro_schema_int = {
            "$numberInt": And(str, Regex(
                '^(-?\d{1,9}|-?1\d{9}|-?20\d{8}|-?21[0-3]\d{7}|-?214[0-6]\d{6}|-?2147[0-3]\d{5}|-?21474[0-7]\d{4}|-?214748[012]\d{4}|-?2147483[0-5]\d{3}|-?21474836[0-3]\d{2}|214748364[0-7]|-214748364[0-8])$'))}

        micro_schema_long = {
            "$numberLong": And(str, Regex('^([+-]?[0-9]\d*|0)$'))}

    extra_cryptainer = {}
    extra_key_ciphertext = {}
    integrity_tags = {}
    metadata = {}

    data_signature = {
        "message_digest_algo": Or(*SUPPORTED_HASH_ALGOS),
        "signature_algo": Or(*SUPPORTED_SIGNATURE_ALGOS),
        "signature_escrow": Const(LOCAL_ESCROW_MARKER),
        Optionalkey("keychain_uid"): micro_schema_uid
    }

    # check if it is a cryptainer
    if for_cryptainer:
        extra_cryptainer = {
            "cryptainer_state": Or(CRYPTAINER_STATES.STARTED, CRYPTAINER_STATES.FINISHED),
            "cryptainer_format": "WA_0.1a",
            "cryptainer_uid": micro_schema_uid,
            "data_ciphertext": micro_schema_binary
        }
        extra_key_ciphertext = {
            "key_ciphertext": micro_schema_binary
        }
        extra_signature = {
            "signature_value": {
                "digest": micro_schema_binary,
                "timestamp_utc": Or(micro_schema_int, micro_schema_long, int)}
        }
        data_signature.update(extra_signature)
        data_signature["message_digest"] = micro_schema_binary
        integrity_tags = {
            "integrity_tags": {
                Optionalkey("tag"): micro_schema_binary  # TODO USE THE REGULAR EXPRESSION OF BYTES
            }}
        metadata = {"metadata": Or(dict, None)}

    SIMPLE_CRYPTAINER_PIECE = {
        "key_encryption_algo": Or(*ASYMMETRIC_KEY_TYPES_REGISTRY.keys()),
        "key_escrow": Const(LOCAL_ESCROW_MARKER),
        Optionalkey("keychain_uid"): micro_schema_uid
    }

    RECURSIVE_SHAMIR = []

    SHAMIR_CRYPTAINER_PIECE = Schema({
        "key_encryption_algo": SHARED_SECRET_MARKER,
        "key_shared_secret_escrows": [{
            "key_encryption_layers": [SIMPLE_CRYPTAINER_PIECE]}],
        "key_shared_secret_threshold": Or(And(int, lambda n: 0 < n < math.inf), micro_schema_int),
    }, name="Recursive_shamir", as_reference=True)

    RECURSIVE_SHAMIR.append(SHAMIR_CRYPTAINER_PIECE)

    SCHEMA_CRYPTAINERS = Schema({
        **extra_cryptainer,
        "data_encryption_layers": [{
            "data_encryption_algo": Or(*SUPPORTED_ENCRYPTION_ALGOS),
            "data_signatures": [data_signature],
            **integrity_tags,
            **extra_key_ciphertext,
            "key_encryption_layers": [SIMPLE_CRYPTAINER_PIECE, SHAMIR_CRYPTAINER_PIECE]
        }],
        Optionalkey("keychain_uid"): micro_schema_uid,
        **metadata
    })

    return SCHEMA_CRYPTAINERS


CONF_SCHEMA_PYTHON = _create_schema(for_cryptainer=False, extended_json_format=False)
CONF_SCHEMA_JSON = _create_schema(for_cryptainer=False, extended_json_format=True).json_schema("conf_schema.json")
CRYPTAINER_SCHEMA_PYTHON = _create_schema(for_cryptainer=True, extended_json_format=False)
CRYPTAINER_SCHEMA_JSON = _create_schema(for_cryptainer=True, extended_json_format=True).json_schema("cryptainer_schema.json")


def _validate_data_tree(data_tree: dict, valid_schema: Union[dict, Schema]):
    """Allows the validation of a data_tree with a pythonschema or jsonschema

    :param data_tree: cryptainer or cryptoconf to validate
    :param valid_schema: validation scheme
    """
    if isinstance(valid_schema, Schema):
        # we use the python schema module
        try:
            valid_schema.validate(data_tree)
        except schema.SchemaError as exc:
            raise ValidationError("Error validating".format(exc)) from exc

    else:
        # we use the json schema module
        assert isinstance(valid_schema, dict)
        try:
            jsonschema_validate(instance=data_tree, schema=valid_schema)
        except jsonschema.exceptions.ValidationError as exc:
            raise ValidationError("Error validating with {}".format(exc)) from exc


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
