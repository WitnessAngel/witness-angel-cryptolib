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
from wacryptolib.key_generation import generate_symmetric_key_dict, load_asymmetric_key_from_pem_bytestring, \
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

CONTAINER_FORMAT = "WA_0.1a"
CONTAINER_SUFFIX = ".crypt"
CONTAINER_DATETIME_FORMAT = "%Y%m%d%H%M%S"  # For use in container names and their records

OFFLOADED_MARKER = "[OFFLOADED]"
OFFLOADED_DATA_SUFFIX = ".data"  # Added to CONTAINER_SUFFIX

DATA_CHUNK_SIZE = 1024 ** 2  # E.g. when streaming a big payload through encryptors

MEDIUM_SUFFIX = ".medium"  # To construct decrypted filename when no previous extensions are found in container filename

SHARED_SECRET_MARKER = "[SHARED_SECRET]"

DUMMY_KEY_STORAGE_POOL = DummyKeyStoragePool()  # Common fallback storage with in-memory keys

#: Special value in containers, to invoke a device-local escrow
LOCAL_ESCROW_MARKER = dict(escrow_type="local")  # FIXME CHANGE THIS

AUTHENTICATION_DEVICE_ESCROW_MARKER = dict(escrow_type="authentication_device")  # FIXME CHANGE THIS


class CONTAINER_STATES:
    STARTED = "STARTED"
    FINISHED = "FINISHED"


def get_escrow_id(escrow_conf: dict) -> str:
    """Build opaque unique identifier for a specific escrow.

    Remains the same as long as escrow dict is completely unmodified.
    """
    return str(sorted(escrow_conf.items()))


def gather_escrow_dependencies(containers: Sequence) -> dict:
    """Analyse a container and return the escrows (and their keypairs) used by it.

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

    def _grab_key_encryption_strata_dependencies(key_encryption_strata):
        for key_encryption_stratum in key_encryption_strata:
            key_type_encryption = key_encryption_stratum["key_encryption_algo"]

            if key_type_encryption == SHARED_SECRET_MARKER:
                escrows = key_encryption_stratum["key_shared_secret_escrows"]
                for escrow in escrows:
                    _grab_key_encryption_strata_dependencies(escrow["key_encryption_strata"])  # Recursive call
            else:
                keychain_uid_encryption = key_encryption_stratum.get("keychain_uid") or keychain_uid
                escrow_conf = key_encryption_stratum["key_escrow"]
                _add_keypair_identifiers_for_escrow(
                    mapper=encryption_dependencies,
                    escrow_conf=escrow_conf,
                    keychain_uid=keychain_uid_encryption,
                    key_type=key_type_encryption,
                )

    for container in containers:
        keychain_uid = container["keychain_uid"]
        for data_encryption_stratum in container["data_encryption_strata"]:
            for signature_conf in data_encryption_stratum["data_signatures"]:
                key_type_signature = signature_conf["signature_algo"]
                keychain_uid_signature = signature_conf.get("keychain_uid") or keychain_uid
                escrow_conf = signature_conf["signature_escrow"]

                _add_keypair_identifiers_for_escrow(
                    mapper=signature_dependencies,
                    escrow_conf=escrow_conf,
                    keychain_uid=keychain_uid_signature,
                    key_type=key_type_signature,
                )

            _grab_key_encryption_strata_dependencies(data_encryption_stratum["key_encryption_strata"])

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
    elif escrow_type == AUTHENTICATION_DEVICE_ESCROW_MARKER["escrow_type"]:
        authentication_device_uid = escrow["authentication_device_uid"]
        key_storage = key_storage_pool.get_imported_key_storage(authentication_device_uid)
        return ReadonlyEscrowApi(key_storage)
    elif escrow_type == "jsonrpc":
        return JsonRpcProxy(url=escrow["url"], response_error_handler=status_slugs_response_error_handler)
    # TODO - Implement imported storages, escrow lookup in global registry, shared-secret group, etc.
    raise ValueError("Unrecognized escrow identifiers: %s" % str(escrow))


# FIXME rename keychain_uid to default_keychain_uid where relevant!!


class ContainerBase:
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


class ContainerWriter(ContainerBase):  #FIXME rename to ContainerEncryptor
    """
    Contains every method used to write and encrypt a container, IN MEMORY.
    """

    def build_container_and_stream_encryptor(self, *, conf: dict, output_stream: BinaryIO, keychain_uid=None, metadata=None) -> dict:
        """
        Build a base container to store encrypted keys, as well as a stream encryptor
        meant to process heavy data chunk by chunk.

        Signatures, and final ciphertext (if not offloaded), will have to be added
        later to the container.

        :param conf: configuration tree
        :param output_stream: open file where the stream encryptor should write to
        :param keychain_uid: uuid for the set of encryption keys used
        :param metadata: additional data to store unencrypted in container

        :return: container with all the information needed to attempt data decryption
        """

        container, data_encryption_strata_extracts = self._generate_container_base_and_secrets(
            conf=conf, keychain_uid=keychain_uid, metadata=metadata
        )

        # HERE INSTANTIATE REAL ENCRYPTOR USING data_encryption_strata_extracts
        '''
        class FakeStreamEncryptor:
            def __init__(self):
                for data_encryption_stratum_extract in data_encryption_strata_extracts:
                    data_encryption_algo = data_encryption_stratum_extract["encryption_algo"]  # FIXME RENAME THIS
                    symmetric_key_dict = data_encryption_stratum_extract["symmetric_key_dict"]
                    message_digest_algos = data_encryption_stratum_extract["message_digest_algos"]
                    # DO SOMETHING WITH THESE
            def encrypt_chunk(self, chunk):
                output_stream.write(chunk)
                return None
            def finalize(self):
                output_stream.flush()
                return None
            def get_authentication_data(self):
                return [{"SHA256": b"a"*32}]  # Matches SIMPLE_CONTAINER_CONF of unit test

        stream_encryptor = FakeStreamEncryptor()
        '''
        ############################################################################

        stream_encryptor = StreamManager(
            output_stream=output_stream,
            data_encryption_strata_extracts=data_encryption_strata_extracts,
        )

        return container, stream_encryptor

    def encrypt_data(self, data: Union[bytes, BinaryIO], *, conf: dict, keychain_uid=None, metadata=None) -> dict:
        """
        Shortcut when data is already available.

        This method browses through configuration tree to apply the right succession of encryption+signature algorithms to data.

        :param data: initial plaintext, or file pointer (file immediately deleted then)
        :param conf: configuration tree
        :param keychain_uid: uuid for the set of encryption keys used
        :param metadata: additional data to store unencrypted in container

        :return: container with all the information needed to attempt data decryption
        """

        data = self._load_data_bytes_and_cleanup(data)  # Ensure we get the whole data buffer

        container, data_encryption_strata_extracts = self._generate_container_base_and_secrets(
            conf=conf, keychain_uid=keychain_uid, metadata=metadata
        )

        data_ciphertext, authentication_data_list = \
            self._encrypt_and_hash_data(data, data_encryption_strata_extracts)

        container["data_ciphertext"] = data_ciphertext

        self.add_authentication_data_to_container(container, authentication_data_list)

        return container

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

    def _encrypt_and_hash_data(self, data, data_encryption_strata_extracts):
        """TODO"""
        data_current = data

        authentication_data_list = []

        for data_encryption_stratum_extract in data_encryption_strata_extracts:
            data_encryption_algo = data_encryption_stratum_extract["encryption_algo"]  # FIXME RENAME THIS
            symmetric_key_dict = data_encryption_stratum_extract["symmetric_key_dict"]
            message_digest_algos = data_encryption_stratum_extract["message_digest_algos"]

            logger.debug("Encrypting data with symmetric key of type %r", data_encryption_algo)
            data_cipherdict = encrypt_bytestring(
                plaintext=data_current, encryption_algo=data_encryption_algo, key_dict=symmetric_key_dict
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

    def _generate_container_base_and_secrets(self, conf: dict, keychain_uid=None, metadata=None) -> tuple:
        """
        Build a data-less and signature-less container, preconfigured with a set of symmetric keys
        under their final form (encrypted by escrows). A separate extract, with symmetric keys as well as algo names, is returned so that actual data encryption and signature can be performed separately.

        :param conf: configuration tree
        :param keychain_uid: uuid for the set of encryption keys used
        :param metadata: additional data to store unencrypted in container

        :return: a (container: dict, secrets: list) tuple, where each secret has keys encryption_algo, symmetric_key and message_digest_algos.
        """

        assert metadata is None or isinstance(metadata, dict), metadata
        container_format = CONTAINER_FORMAT
        container_uid = generate_uuid0()  # ALWAYS UNIQUE!
        keychain_uid = keychain_uid or generate_uuid0()  # Might be shared by lots of containers

        assert isinstance(conf, dict), conf
        container = copy.deepcopy(conf)  # So that we can manipulate it as new container
        del conf

        if not container["data_encryption_strata"]:
            raise ConfigurationError("Empty data_encryption_strata list is forbidden in encryption conf")

        data_encryption_strata_extracts = []  # Sensitive info with secret keys!

        for data_encryption_stratum in container["data_encryption_strata"]:
            data_encryption_algo = data_encryption_stratum["data_encryption_algo"]

            data_encryption_stratum["integrity_tags"] = None  # Will be filled later with tags/macs etc.

            logger.debug("Generating symmetric key of type %r", data_encryption_algo)
            symmetric_key_dict = generate_symmetric_key_dict(encryption_algo=data_encryption_algo)
            symmetric_key_bytes = dump_to_json_bytes(symmetric_key_dict)
            key_encryption_strata = data_encryption_stratum["key_encryption_strata"]

            key_ciphertext = self._encrypt_key_through_multiple_strata(
                    keychain_uid=keychain_uid,
                    key_bytes=symmetric_key_bytes,
                    key_encryption_strata=key_encryption_strata)
            data_encryption_stratum["key_ciphertext"] = key_ciphertext

            data_encryption_stratum_extract = dict(
                encryption_algo=data_encryption_algo,
                symmetric_key_dict=symmetric_key_dict,
                message_digest_algos=[signature["message_digest_algo"] for signature in
                                      data_encryption_stratum["data_signatures"]]
            )
            data_encryption_strata_extracts.append(data_encryption_stratum_extract)

        container.update(
            # FIXME add container status, PENDING/COMPLETE!!!
            container_state=CONTAINER_STATES.STARTED,
            container_format=container_format,
            container_uid=container_uid,
            keychain_uid=keychain_uid,
            data_ciphertext = None,  # Must be filled asap, by OFFLOADED_MARKER if needed!
            metadata=metadata,
        )
        return container, data_encryption_strata_extracts

    def _encrypt_key_through_multiple_strata(self, keychain_uid: uuid.UUID, key_bytes: bytes,
                                             key_encryption_strata: list) -> bytes:
        # HERE KEY IS REAL KEY OR SHARE !!!

        if not key_encryption_strata:
            raise ConfigurationError("Empty key_encryption_strata list is forbidden in encryption conf")

        key_ciphertext = key_bytes
        for key_encryption_stratum in key_encryption_strata:
            key_ciphertext_dict = self._encrypt_key_through_single_stratum(
                keychain_uid=keychain_uid, key_bytes=key_ciphertext, key_encryption_stratum=key_encryption_stratum
            )
            key_ciphertext = dump_to_json_bytes(key_ciphertext_dict)  # Thus its remains as bytes all along

        return key_ciphertext


    def _encrypt_key_through_single_stratum(self, keychain_uid: uuid.UUID, key_bytes: bytes, key_encryption_stratum: dict) -> dict:
        """
        Encrypt a symmetric key using an asymmetric encryption scheme.

        The symmetric key data might already be the result of previous encryption passes.
        Encryption can use a simple public key algorithm, or rely on a a set of public keys,
        by using a shared secret scheme.

        :param keychain_uid: uuid for the set of encryption keys used
        :param symmetric_key_data: symmetric key to encrypt (potentially already encrypted)
        :param conf: dictionary which contain configuration tree

        :return: if the scheme used is 'SHARED_SECRET', a list of encrypted shares is returned. If an asymmetric
        algorithm has been used, a dictionary with all the information needed to decipher the symmetric key is returned.
        """
        assert isinstance(key_bytes, bytes), key_bytes
        key_encryption_algo = key_encryption_stratum["key_encryption_algo"]

        if key_encryption_algo == SHARED_SECRET_MARKER:

            key_shared_secret_escrows = key_encryption_stratum["key_shared_secret_escrows"]
            shares_count = len(key_shared_secret_escrows)

            threshold_count = key_encryption_stratum["key_shared_secret_threshold"]
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
                shares_ciphertext = self._encrypt_key_through_multiple_strata(  # FIXME rename singular
                        keychain_uid=keychain_uid,
                        key_bytes=share_bytes,
                        key_encryption_strata=escrow_conf["key_encryption_strata"])  # Recursive structure
                shares_ciphertexts.append(shares_ciphertext)

            key_cipherdict = {"shares": shares_ciphertexts}  # A dict is more future-proof
            return key_cipherdict

        else:  # Using asymmetric algorithm

            keychain_uid_encryption = key_encryption_stratum.get("keychain_uid") or keychain_uid
            key_cipherdict = self._encrypt_with_asymmetric_cipher(
                encryption_algo=key_encryption_algo,
                keychain_uid=keychain_uid_encryption,
                symmetric_key_data=key_bytes,
                escrow=key_encryption_stratum["key_escrow"],
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
        :param key_shared_secret_escrows: conf subtree with share escrow information
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

    def add_authentication_data_to_container(self, container: dict, authentication_data_list: list):
        keychain_uid = container["keychain_uid"]

        data_encryption_strata = container["data_encryption_strata"]
        assert len(data_encryption_strata) == len(authentication_data_list)  # Sanity check

        for data_encryption_stratum, authentication_data_list in zip(container["data_encryption_strata"], authentication_data_list):

            assert data_encryption_stratum["integrity_tags"] is None  # Set at container build time
            data_encryption_stratum["integrity_tags"] = authentication_data_list["integrity_tags"]

            message_digests = authentication_data_list["message_digests"]

            _encountered_message_digest_algos = set()
            for signature_conf in data_encryption_stratum["data_signatures"]:
                message_digest_algo = signature_conf["message_digest_algo"]

                signature_conf["message_digest"] = message_digests[message_digest_algo]  # MUST exist, else incoherence
                # FIXME ADD THIS NEW FIELD TO SCHEMA VALIDATOR!!!!

                signature_value = self._generate_message_signature(
                    keychain_uid=keychain_uid,
                    conf=signature_conf)
                signature_conf["signature_value"] = signature_value

                _encountered_message_digest_algos.add(message_digest_algo)
            assert _encountered_message_digest_algos == set(message_digests)  # No abnormal extra digest

        container["container_state"] = CONTAINER_STATES.FINISHED

    def _generate_message_signature(self, keychain_uid: uuid.UUID, conf: dict) -> dict:
        """
        Generate a signature for a specific ciphered data.

        :param keychain_uid: uuid for the set of encryption keys used
        :param conf: configuration tree inside data_signatures, which MUST already contain the message digest
        :return: dictionary with information needed to verify signature
        """
        signature_algo = conf["signature_algo"]
        message_digest = conf["message_digest"]  # Must have been set before, using message_digest_algo field
        assert message_digest, message_digest

        encryption_proxy = get_escrow_proxy(escrow=conf["signature_escrow"], key_storage_pool=self._key_storage_pool)

        keychain_uid_signature = conf.get("keychain_uid") or keychain_uid

        logger.debug("Signing hash of encrypted data with algo %r", signature_algo)
        signature_value = encryption_proxy.get_message_signature(
            keychain_uid=keychain_uid_signature, message=message_digest, signature_algo=signature_algo
        )
        return signature_value


class ContainerReader(ContainerBase):  #FIXME rename to ContainerDecryptor
    """
    Contains every method used to read and decrypt a container, IN MEMORY.
    """

    def extract_metadata(self, container: dict) -> Optional[dict]:
        assert isinstance(container, dict), container
        return container["metadata"]

    def decrypt_data(self, container: dict, verify: bool=True) -> bytes:
        """
        Loop through container layers, to decipher data with the right algorithms.

        :param container: dictionary previously built with ContainerWriter method
        :param verify: whether to check tag/mac values of the ciphertext

        :return: deciphered plaintext
        """
        assert isinstance(container, dict), container

        container_format = container["container_format"]
        if container_format != CONTAINER_FORMAT:
            raise ValueError("Unknown container format %s" % container_format)

        container_uid = container["container_uid"]
        del container_uid  # Might be used for logging etc, later...

        keychain_uid = container["keychain_uid"]

        data_current = container["data_ciphertext"]
        assert isinstance(data_current, bytes), repr(data_current)  # Else it's still a special marker for example...

        for data_encryption_stratum in reversed(container["data_encryption_strata"]):  # Non-emptiness of this will be checked by validator

            data_encryption_algo = data_encryption_stratum["data_encryption_algo"]

            for signature_conf in data_encryption_stratum["data_signatures"]:
                self._verify_message_signature(keychain_uid=keychain_uid, message=data_current, conf=signature_conf)

            key_ciphertext = data_encryption_stratum["key_ciphertext"]  # We start fully encrypted, and unravel it

            # FIXME rename to symmetric_key_bytes
            key_bytes = self._decrypt_key_through_multiple_strata(
                keychain_uid=keychain_uid,
                key_ciphertext=key_ciphertext,
                encryption_strata=data_encryption_stratum["key_encryption_strata"])
            assert isinstance(key_bytes, bytes), key_bytes
            symmetric_key_dict = load_from_json_bytes(key_bytes)

            integrity_tags = data_encryption_stratum["integrity_tags"]  # Shall be a DICT, FIXME handle if it's still None
            data_cipherdict = dict(ciphertext=data_current, **integrity_tags)
            data_current = decrypt_bytestring(
                cipherdict=data_cipherdict, key_dict=symmetric_key_dict, encryption_algo=data_encryption_algo, verify=verify
            )

        data = data_current  # Now decrypted
        return data

    def _decrypt_key_through_multiple_strata(self, keychain_uid: uuid.UUID, key_ciphertext: bytes, encryption_strata: list) -> bytes:
        key_bytes = key_ciphertext

        for key_encryption_stratum in reversed(encryption_strata):  # Non-emptiness of this will be checked by validator
            key_cipherdict = load_from_json_bytes(key_bytes)  # We remain as bytes all along
            key_bytes = self._decrypt_key_through_single_stratum(
                keychain_uid=keychain_uid,
                key_cipherdict=key_cipherdict,
                encryption_stratum=key_encryption_stratum,
            )

        return key_bytes

    def _decrypt_key_through_single_stratum(self, keychain_uid: uuid.UUID, key_cipherdict: dict, encryption_stratum: dict) -> bytes:
        """
        Function called when decryption of a symmetric key is needed. Encryption may be made by shared secret or
        by a asymmetric algorithm.

        :param keychain_uid: uuid for the set of encryption keys used
        :param symmetric_key_cipherdict: dictionary with input ata needed to decrypt symmetric key
        :param conf: dictionary which contains crypto configuration tree

        :return: deciphered symmetric key
        """
        assert isinstance(key_cipherdict, dict), key_cipherdict
        key_encryption_algo = encryption_stratum["key_encryption_algo"]

        if key_encryption_algo == SHARED_SECRET_MARKER:

            decrypted_shares = []
            decryption_errors = []
            key_shared_secret_escrows = encryption_stratum["key_shared_secret_escrows"]  # FIXMe rename twice
            key_shared_secret_threshold = encryption_stratum["key_shared_secret_threshold"]

            shares_ciphertexts = key_cipherdict["shares"]  # FIXME rename to share_ciphertexts

            logger.debug("Deciphering each share")

            # If some shares are missing, we won't detect it here because zip() stops at shortest list
            for share_ciphertext, escrow_conf in zip(shares_ciphertexts, key_shared_secret_escrows):

                try:
                    share_bytes = self._decrypt_key_through_multiple_strata(
                            keychain_uid=keychain_uid,
                            key_ciphertext=share_ciphertext,
                            encryption_strata=escrow_conf["key_encryption_strata"])  # Recursive structure
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
            keychain_uid_encryption = (encryption_stratum.get("keychain_uid") or keychain_uid)

            key_bytes = self._decrypt_with_asymmetric_cipher(
                encryption_algo=key_encryption_algo,
                keychain_uid=keychain_uid_encryption,
                cipherdict=key_cipherdict,
                escrow=encryption_stratum["key_escrow"],
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

    def ________decrypt_symmetric_key_share(self, keychain_uid: uuid.UUID, symmetric_key_cipherdict: dict, conf: dict):
        """
        Make a loop through all encrypted shares to decrypt each of them
        :param keychain_uid: uuid for the set of encryption keys used
        :param symmetric_key_cipherdict: dictionary which contains every data needed to decipher each share
        :param conf: configuration tree inside key_encryption_algo

        :return: list of tuples of deciphered shares
        """
        key_shared_secret_escrows = conf["key_shared_secret_escrows"]
        key_shared_secret_threshold = conf["key_shared_secret_threshold"]

        decrypted_shares = []
        decryption_errors = []

        assert len(symmetric_key_cipherdict["shares"]) <= len(
            key_shared_secret_escrows
        )  # During tests we erase some container shares...

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

    def _verify_message_signature(self, keychain_uid: uuid.UUID, message: bytes, conf: dict):
        """
        Verify a signature for a specific message. An error is raised if signature isn't correct.

        :param keychain_uid: uuid for the set of encryption keys used
        :param message: message as bytes on which to verify signature
        :param conf: configuration tree inside data_signatures
        """
        message_digest_algo = conf["message_digest_algo"]
        signature_algo = conf["signature_algo"]
        keychain_uid_signature = conf.get("keychain_uid") or keychain_uid
        encryption_proxy = get_escrow_proxy(escrow=conf["signature_escrow"], key_storage_pool=self._key_storage_pool)
        public_key_pem = encryption_proxy.fetch_public_key(
            keychain_uid=keychain_uid_signature, key_type=signature_algo, must_exist=True
        )
        public_key = load_asymmetric_key_from_pem_bytestring(key_pem=public_key_pem, key_type=signature_algo)

        message_hash = hash_message(message, hash_algo=message_digest_algo)
        assert message_hash == conf["message_digest"]  # Sanity check!!
        signature_value = conf["signature_value"]

        verify_message_signature(
            message=message_hash, signature_algo=signature_algo, signature=signature_value, key=public_key
        )  # Raises if troubles


class ContainerEncryptionStream:
    """
    Helper which prebuilds a container without signatures nor data,
    affords to fill its offloaded ciphertext file chunk by chunk, and then
    dumps the final container now containing signatures.
    """

    def __init__(self,
                 container_filepath,
                 *,
                conf: dict,
                metadata: Optional[dict],
                keychain_uid: Optional[uuid.UUID] = None,
                key_storage_pool: Optional[KeyStoragePoolBase] = None,
                dump_initial_container=True):

        self._container_filepath = container_filepath

        offloaded_file_path = _get_offloaded_file_path(container_filepath)
        self._output_data_stream = open(offloaded_file_path, mode='wb')

        self._container_writer = ContainerWriter(key_storage_pool=key_storage_pool)
        self._wip_container, self._stream_encryptor = self._container_writer.build_container_and_stream_encryptor(output_stream=self._output_data_stream , conf=conf, keychain_uid=keychain_uid, metadata=metadata)
        self._wip_container["data_ciphertext"] = OFFLOADED_MARKER  # Important

        if dump_initial_container:  # Savegame in case the stream is broken before finalization
            self._dump_current_container_to_filesystem()

    def _dump_current_container_to_filesystem(self):
        dump_container_to_filesystem(self._container_filepath, container=self._wip_container,
                                     offload_data_ciphertext=False)  # ALREADY offloaded

    def encrypt_chunk(self, chunk: bytes):
        self._stream_encryptor.encrypt_chunk(chunk)

    def finalize(self):
        self._stream_encryptor.finalize()
        self._output_data_stream.close()  # Important

        authentication_data_list = self._stream_encryptor.get_authentication_data()

        self._container_writer.add_authentication_data_to_container(self._wip_container, authentication_data_list)
        self._dump_current_container_to_filesystem()

    def __del__(self):
        # Emergency closing of open file on deletion
        if not self._output_data_stream.closed:
            logger.error("Encountered abnormal open file in __del__ of ContainerEncryptionStream: %s" % self._output_data_stream)
            self._output_data_stream.close()


def is_container_encryption_conf_streamable(conf):  #FIXME rename and add to docs
    # FIXME test separately!
    for data_encryption_stratum in conf["data_encryption_strata"]:
        if data_encryption_stratum["data_encryption_algo"] not in STREAMABLE_ENCRYPTION_ALGOS:
            return False
    return True


def encrypt_data_and_dump_container_to_filesystem(
    data: Union[bytes, BinaryIO],
    *,
    container_filepath,
    conf: dict,
    metadata: Optional[dict],
    keychain_uid: Optional[uuid.UUID] = None,
    key_storage_pool: Optional[KeyStoragePoolBase] = None
) -> None:
    """
    Optimized version which directly streams encrypted data to offloaded file,
    instead of creating a whole container and then dumping it to disk.
    """
    # No need to dump initial (signature-less) container here, this is all a quick operation...
    encryptor = ContainerEncryptionStream(container_filepath,
                 conf=conf, keychain_uid=keychain_uid, metadata=metadata,
                key_storage_pool=key_storage_pool,
                dump_initial_container=False)

    for chunk in consume_bytes_as_chunks(data, chunk_size=DATA_CHUNK_SIZE):
        encryptor.encrypt_chunk(chunk)

    encryptor.finalize()  # Handles the dumping to disk


def encrypt_data_into_container(
    data: Union[bytes, BinaryIO],
    *,
    conf: dict,
    metadata: Optional[dict],
    keychain_uid: Optional[uuid.UUID] = None,
    key_storage_pool: Optional[KeyStoragePoolBase] = None
) -> dict:
    """Turn raw data into a high-security container, which can only be decrypted with
    the agreement of the owner and multiple third-party escrows.

    :param data: bytestring of media (image, video, sound...) or readable file object (file immediately deleted then)
    :param conf: tree of specific encryption settings
    :param metadata: dict of metadata describing the data (remains unencrypted in container)
    :param keychain_uid: optional ID of a keychain to reuse
    :param key_storage_pool: optional key storage pool, might be required by encryption conf

    :return: dict of container
    """
    writer = ContainerWriter(key_storage_pool=key_storage_pool)
    container = writer.encrypt_data(data, conf=conf, keychain_uid=keychain_uid, metadata=metadata)
    return container


def decrypt_data_from_container(
    container: dict, *, key_storage_pool: Optional[KeyStoragePoolBase] = None, passphrase_mapper: Optional[dict] = None, verify: bool=True
) -> bytes:
    """Decrypt a container with the help of third-parties.

    :param container: the container tree, which holds all information about involved keys
    :param key_storage_pool: optional key storage pool
    :param passphrase_mapper: optional dict mapping escrow IDs to their lists of passphrases
    :param verify: whether to check tag/mac values of the ciphertext

    :return: raw bytestring
    """
    reader = ContainerReader(key_storage_pool=key_storage_pool, passphrase_mapper=passphrase_mapper)
    data = reader.decrypt_data(container=container, verify=verify)
    return data


def _get_offloaded_file_path(container_filepath: Path):
    return container_filepath.parent.joinpath(container_filepath.name + OFFLOADED_DATA_SUFFIX)


def dump_container_to_filesystem(container_filepath: Path, container: dict, offload_data_ciphertext=True) -> None:
    """Dump a container to a file path, overwritting it if existing.

    If `offload_data_ciphertext`, actual encrypted data is dumped to a separate bytes file nearby the json-formatted container.
    """
    if offload_data_ciphertext:
        offloaded_file_path = _get_offloaded_file_path(container_filepath)
        assert isinstance(container["data_ciphertext"], bytes), container["data_ciphertext"]
        offloaded_file_path.write_bytes(container["data_ciphertext"])
        container = container.copy()  # DO NOT touch original dict!
        container["data_ciphertext"] = OFFLOADED_MARKER
    dump_to_json_file(container_filepath, container)


def load_container_from_filesystem(container_filepath: Path, include_data_ciphertext=True) -> dict:
    """Load a json-formatted container from a file path, potentially loading its offloaded ciphertext from a separate nearby bytes file.

    Field `data_ciphertext` is only present in result dict if `include_data_ciphertext` is True.
    """

    container = load_from_json_file(container_filepath)

    if include_data_ciphertext:
        if container["data_ciphertext"] == OFFLOADED_MARKER:
            offloaded_file_path = _get_offloaded_file_path(container_filepath)
            container["data_ciphertext"] = offloaded_file_path.read_bytes()
    else:
        del container["data_ciphertext"]

    return container


def delete_container_from_filesystem(container_filepath):
    """Delete a container file and its potential offloaded data file."""
    os.remove(container_filepath)  # TODO - additional retries if file access errors?
    offloaded_file_path = _get_offloaded_file_path(container_filepath)
    if offloaded_file_path.exists():
        # We don't care about OFFLOADED_MARKER here, we go the quick way
        os.remove(offloaded_file_path)


def get_container_size_on_filesystem(container_filepath):
    """Return the total size in bytes occupied by a container and its potential offloaded data file."""
    size = container_filepath.stat().st_size  # Might fail if file got deleted concurrently
    offloaded_file_path = _get_offloaded_file_path(container_filepath)
    if offloaded_file_path.exists():
        # We don't care about OFFLOADED_MARKER here, we go the quick way
        size += offloaded_file_path.stat().st_size
    return size


def extract_metadata_from_container(container: dict) -> Optional[dict]:  # FIXME move that up, like in docs
    """Read the metadata tree (possibly None) from a container.

    CURRENTLY METADATA IS NOT ENCRYPTED.

    :param container: the container tree, which also holds metadata about encrypted content

    :return: dict
    """
    reader = ContainerReader()
    data = reader.extract_metadata(container)
    return data


class ContainerStorage:
    """
    This class encrypts file streams and stores them into filesystem, in a thread-safe way.

    Exceeding containers are automatically purged when enqueuing new files or waiting for idle state.

    A thread pool is used to encrypt files in the background.

    :param containers_dir: the folder where container files are stored
    :param default_encryption_conf: encryption conf to use when none is provided when enqueuing data
    :param max_container_quota: if set, containers are deleted if they exceed this size in bytes
    :param max_container_count: if set, oldest exceeding containers (time taken from their name, else their file-stats) are automatically erased
    :param max_container_age: if set, containers exceeding this age (taken from their name, else their file-stats) in days are automatically erased
    :param key_storage_pool: optional KeyStoragePool, which might be required by current encryption conf
    :param max_workers: count of worker threads to use in parallel
    :param offload_data_ciphertext: whether actual encrypted data must be kept separated from structured container file
    """

    def __init__(
        self,
        containers_dir: Path,
        default_encryption_conf: Optional[dict] = None,
        max_container_quota: Optional[int] = None,
        max_container_count: Optional[int] = None,
        max_container_age: Optional[timedelta] = None,
        key_storage_pool: Optional[KeyStoragePoolBase] = None,
        max_workers: int = 1,
        offload_data_ciphertext=True,
    ):
        containers_dir = Path(containers_dir)
        assert containers_dir.is_dir(), containers_dir
        containers_dir = containers_dir.absolute()
        assert max_container_quota is None or max_container_quota >= 0, max_container_quota
        assert max_container_count is None or max_container_count >= 0, max_container_count
        assert max_container_age is None or max_container_age >= timedelta(seconds=0), max_container_age
        self._default_encryption_conf = default_encryption_conf
        self._containers_dir = containers_dir
        self._max_container_quota = max_container_quota
        self._max_container_count = max_container_count
        self._max_container_age = max_container_age
        self._key_storage_pool = key_storage_pool
        self._thread_pool_executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="container_worker")
        self._pending_executor_futures = []
        self._lock = threading.Lock()
        self._offload_data_ciphertext = offload_data_ciphertext

    def __del__(self):
        self._thread_pool_executor.shutdown(wait=False)

    def __len__(self):
        """Beware, might be SLOW if many files are present in folder."""
        return len(self.list_container_names())  # No sorting, to be quicker

    def list_container_names(self, as_sorted=False, as_absolute=False):  # FIXME add annotations everywhere
        """Returns the list of encrypted containers present in storage,
        sorted by name or not, absolute or not, as Path objects."""
        assert self._containers_dir.is_absolute(), self._containers_dir
        paths = list(self._containers_dir.glob("*" + CONTAINER_SUFFIX))  # As list, for multiple looping on it
        assert all(p.is_absolute() for p in paths), paths
        if as_sorted:
            paths = sorted(paths)
        if not as_absolute:
            paths = (Path(p.name) for p in paths)  # beware, only works since we don't have subfolders for now!
        return list(paths)

    def _get_container_datetime(self, container_name):
        """Returns an UTC datetime corresponding to the creation time stored in filename, or else the file-stat mtime"""
        try:
            dt = datetime.strptime(container_name.name.split("_")[0], CONTAINER_DATETIME_FORMAT)
            dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            mtime = self._make_absolute(container_name).stat().st_mtime  # Might fail if file got deleted concurrently
            dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
        return dt

    def _get_container_size(self, container_name):
        """Returns a size in bytes"""
        return get_container_size_on_filesystem(self._make_absolute(container_name))

    def list_container_properties(self, with_age=False, with_size=False):
        """Returns an unsorted list of dicts having the fields "name", [age] and [size], depending on requested properties."""
        container_names = self.list_container_names(as_sorted=False, as_absolute=False)

        now = get_utc_now_date()

        result = []
        for container_name in container_names:
            entry = dict(name=container_name)
            if with_age:
                container_datetime = self._get_container_datetime(container_name)
                entry["age"] = now - container_datetime   # We keep as timedelta
            if with_size:
                entry["size"] = self._get_container_size(container_name)
            result.append(entry)
        return result

    def _make_absolute(self, container_name):
        assert not Path(container_name).is_absolute()
        return self._containers_dir.joinpath(container_name)

    def _delete_container(self, container_name):
        container_filepath = self._make_absolute(container_name)
        delete_container_from_filesystem(container_filepath)

    def delete_container(self, container_name):
        logger.info("Deleting container %s" % container_name)
        self._delete_container(container_name=container_name)

    def _purge_exceeding_containers(self):  # TODO LOG WHEN PURGING
        """Purge containers first by date, then total quota, then count, depending on instance settings"""

        if self._max_container_age is not None:  # FIRST these, since their deletion is unconditional
            container_dicts = self.list_container_properties(with_age=True)
            for container_dict in container_dicts:
                if container_dict["age"] > self._max_container_age:
                    self._delete_container(container_dict["name"])

        if self._max_container_quota is not None:
            max_container_quota = self._max_container_quota

            container_dicts = self.list_container_properties(with_size=True, with_age=True)
            container_dicts.sort(key=lambda x: (-x["age"], x["name"]), reverse=True)  # Oldest last

            total_space_consumed = sum(x["size"] for x in container_dicts)

            while total_space_consumed > max_container_quota:
                deleted_container_dict = container_dicts.pop()
                self._delete_container(deleted_container_dict["name"])
                total_space_consumed -= deleted_container_dict["size"]

        if self._max_container_count is not None:
            container_dicts = self.list_container_properties(with_age=True)
            containers_count = len(container_dicts)

            if containers_count > self._max_container_count:
                assert containers_count > 0, containers_count
                excess_count = containers_count - self._max_container_count
                container_dicts.sort(key=lambda x: (-x["age"], x["name"]))  # Oldest first
                deleted_container_dicts = container_dicts[:excess_count]
                for deleted_container_dict in deleted_container_dicts:
                    self._delete_container(deleted_container_dict["name"])

    def _encrypt_data_and_dump_container_to_filesystem(self, data, container_filepath, metadata, keychain_uid, encryption_conf):
        assert encryption_conf, encryption_conf
        encrypt_data_and_dump_container_to_filesystem(
                container_filepath=container_filepath,
                    data=data,
                    conf=encryption_conf,
                    metadata=metadata,
                    keychain_uid=keychain_uid,
                    key_storage_pool=self._key_storage_pool,
                )

    def _encrypt_data_into_container(self, data, metadata, keychain_uid, encryption_conf):
        assert encryption_conf, encryption_conf
        return encrypt_data_into_container(
            data=data,
            conf=encryption_conf,
            metadata=metadata,
            keychain_uid=keychain_uid,
            key_storage_pool=self._key_storage_pool,
        )

    def _decrypt_data_from_container(self, container: dict, passphrase_mapper: Optional[dict], verify: bool) -> bytes:
        return decrypt_data_from_container(
            container, key_storage_pool=self._key_storage_pool, passphrase_mapper=passphrase_mapper, verify=verify
        )  # Will fail if authorizations are not OK

    @catch_and_log_exception
    def _offloaded_encrypt_data_and_dump_container(self, filename_base, data, metadata, keychain_uid, encryption_conf):
        """Task to be called by background thread, which encrypts a payload into a disk container.

        Returns the container basename."""

        """ TODO later ass a SKIP here!
        if not data:
            logger.warning("Skipping encryption of empty data payload for file %s", filename_base)
            return
        """

        container_filepath = self._make_absolute(filename_base + CONTAINER_SUFFIX)

        if self._use_streaming_encryption_for_conf(encryption_conf):
            # We can use newer, low-memory, streamed API
            logger.debug("Encrypting data file %s into offloaded container directly streamed to storage file %s", filename_base, container_filepath)
            self._encrypt_data_and_dump_container_to_filesystem(
                data, container_filepath=container_filepath, metadata=metadata, keychain_uid=keychain_uid, encryption_conf=encryption_conf
            )

        else:
            # We use legacy API which encrypts all and then dumps all

            logger.debug("Encrypting data file to self-sufficient container %s", filename_base)
            # Memory warning : duplicates data to json-compatible container
            container = self._encrypt_data_into_container(
                data, metadata=metadata, keychain_uid=keychain_uid, encryption_conf=encryption_conf
            )
            logger.debug("Writing self-sufficient container data to storage file %s", container_filepath)
            dump_container_to_filesystem(
                container_filepath, container=container, offload_data_ciphertext=self._offload_data_ciphertext
            )

        logger.info("Data file %r successfully encrypted into storage container", filename_base)
        return container_filepath.name

    def _use_streaming_encryption_for_conf(self, encryption_conf):  # FIXME rename to cryptoconf
        return self._offload_data_ciphertext and is_container_encryption_conf_streamable(encryption_conf)

    def _prepare_for_new_record_encryption(self, encryption_conf):
        """
        Validate arguments for new encryption, and purge obsolete things in storage.
        """
        encryption_conf = encryption_conf or self._default_encryption_conf
        if not encryption_conf:
            raise RuntimeError("Either default or file-specific encryption conf must be provided to ContainerStorage")

        self._purge_exceeding_containers()
        self._purge_executor_results()
        return encryption_conf

    @synchronized
    def create_container_encryption_stream(self, filename_base, metadata, keychain_uid=None, encryption_conf=None, dump_initial_container=True):
        logger.info("Enqueuing file %r for encryption and storage", filename_base)
        container_filepath = self._make_absolute(filename_base + CONTAINER_SUFFIX)
        encryption_conf = self._prepare_for_new_record_encryption(encryption_conf)
        container_encryption_stream = ContainerEncryptionStream(container_filepath,
                     conf=encryption_conf,
                     metadata=metadata,
                     keychain_uid=keychain_uid,
                     key_storage_pool=self._key_storage_pool,
                     dump_initial_container=dump_initial_container)
        return container_encryption_stream

    @synchronized
    def enqueue_file_for_encryption(self, filename_base, data, metadata, keychain_uid=None, encryption_conf=None):
        """Enqueue a data payload for asynchronous encryption and storage.

        The filename of final container might be different from provided one.
        And beware, target container with the same constructed name might be overwritten.

        :param data: Bytes string, or a file-like object open for reading, which will be automatically closed.
        :param metadata: Dict of metadata added (unencrypted) to container.
        :param keychain_uid: If provided, replaces autogenerated keychain_uid for this container.
        :param encryption_conf: If provided, replaces default encryption conf for this container.
        """
        logger.info("Enqueuing file %r for encryption and storage", filename_base)

        encryption_conf = self._prepare_for_new_record_encryption(encryption_conf)

        future = self._thread_pool_executor.submit(
            self._offloaded_encrypt_data_and_dump_container,
            filename_base=filename_base,
            data=data,
            metadata=metadata,
            keychain_uid=keychain_uid,
            encryption_conf=encryption_conf,
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
        self._purge_exceeding_containers()  # Good to have now

    def load_container_from_storage(self, container_name_or_idx, include_data_ciphertext=True) -> dict:
        """
        Return the encrypted container dict for `container_name_or_idx` (which must be in `list_container_names()`,
        or an index suitable for this sorted list).
        """
        if isinstance(container_name_or_idx, int):
            container_names = self.list_container_names(as_sorted=True, as_absolute=False)
            container_name = container_names[container_name_or_idx]  # Will break if idx is out of bounds
        else:
            assert isinstance(container_name_or_idx, (Path, str)), repr(container_name_or_idx)
            container_name = Path(container_name_or_idx)
        assert not container_name.is_absolute(), container_name

        logger.info("Loading container %s from storage", container_name)
        container_filepath = self._make_absolute(container_name)
        container = load_container_from_filesystem(container_filepath, include_data_ciphertext=include_data_ciphertext)
        return container

    def decrypt_container_from_storage(self, container_name_or_idx, passphrase_mapper: Optional[dict]=None, verify: bool=True) -> bytes:
        """
        Return the decrypted content of the container `container_name_or_idx` (which must be in `list_container_names()`,
        or an index suitable for this sorted list).
        """
        logger.info("Decrypting container %r from storage", container_name_or_idx)

        container = self.load_container_from_storage(container_name_or_idx, include_data_ciphertext=True)

        result = self._decrypt_data_from_container(container, passphrase_mapper=passphrase_mapper, verify=verify)
        logger.info("Container %s successfully decrypted", container_name_or_idx)
        return result

    def check_container_sanity(self, container_name_or_idx):
        """Allows the validation of a container with a python"""
        container = self.load_container_from_storage(container_name_or_idx, include_data_ciphertext=True)

        check_container_sanity(container=container, jsonschema_mode=False)


def get_encryption_configuration_summary(conf_or_container):  # FIXME move up like in docs
    """
    Returns a string summary of the layers of encryption/signature of a container or a configuration tree.
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
    for idx, data_encryption_stratum in enumerate(conf_or_container["data_encryption_strata"], start=1):
        lines.append("Data encryption layer %d: %s" % (idx, data_encryption_stratum["data_encryption_algo"]))
        lines.append("  Key encryption layers:")
        for idx2, key_encryption_stratum in enumerate(data_encryption_stratum["key_encryption_strata"], start=1):
            key_escrow = key_encryption_stratum["key_escrow"]
            escrow_id = _get_escrow_identifier(key_escrow)
            lines.append("    %s (by %s)" % (key_encryption_stratum["key_encryption_algo"], escrow_id))
        lines.append("  Signatures:")
        for idx3, data_signature in enumerate(data_encryption_stratum["data_signatures"], start=1):
            signature_escrow = data_signature["signature_escrow"]
            escrow_id = _get_escrow_identifier(signature_escrow)
            lines.append(
                "    %s/%s (by %s)"
                % (data_signature["message_digest_algo"], data_signature["signature_algo"], escrow_id)
            )
    result = "\n".join(lines) + "\n"
    return result


def _create_schema(for_container: bool, extended_json_format: bool):
    """Create validation schema for confs and containers.
    :param for_container: true if instance is a container
    :param extended_json_format: true if the scheme is extended to json format

    :return: a schema.
    """

    micro_schema_uid = UUID
    micro_schema_binary = bytes
    micro_schema_int = int
    micro_schema_long = int

    if extended_json_format:
        # global SCHEMA_CONTAINERS
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

    extra_container = {}
    extra_key_ciphertext = {}
    integrity_tags = {}
    metadata = {}

    data_signature = {
        "message_digest_algo": Or(*SUPPORTED_HASH_ALGOS),
        "signature_algo": Or(*SUPPORTED_SIGNATURE_ALGOS),
        "signature_escrow": Const(LOCAL_ESCROW_MARKER),
        Optionalkey("keychain_uid"): micro_schema_uid
    }

    # check if it is a container
    if for_container:
        extra_container = {
            "container_state": Or(CONTAINER_STATES.STARTED, CONTAINER_STATES.FINISHED),
            "container_format": "WA_0.1a",
            "container_uid": micro_schema_uid,
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

    SIMPLE_CONTAINER_PIECE = {
        "key_encryption_algo": Or(*ASYMMETRIC_KEY_TYPES_REGISTRY.keys()),
        "key_escrow": Const(LOCAL_ESCROW_MARKER),
        Optionalkey("keychain_uid"): micro_schema_uid
    }

    RECURSIVE_SHAMIR = []

    SHAMIR_CONTAINER_PIECE = Schema({
        "key_encryption_algo": SHARED_SECRET_MARKER,
        "key_shared_secret_escrows": [{
            "key_encryption_strata": [SIMPLE_CONTAINER_PIECE]}],
        "key_shared_secret_threshold": Or(And(int, lambda n: 0 < n < math.inf), micro_schema_int),
    }, name="Recursive_shamir", as_reference=True)

    RECURSIVE_SHAMIR.append(SHAMIR_CONTAINER_PIECE)

    SCHEMA_CONTAINERS = Schema({
        **extra_container,
        "data_encryption_strata": [{
            "data_encryption_algo": Or(*SUPPORTED_ENCRYPTION_ALGOS),
            "data_signatures": [data_signature],
            **integrity_tags,
            **extra_key_ciphertext,
            "key_encryption_strata": [SIMPLE_CONTAINER_PIECE, SHAMIR_CONTAINER_PIECE]
        }],
        Optionalkey("keychain_uid"): micro_schema_uid,
        **metadata
    })

    return SCHEMA_CONTAINERS


CONF_SCHEMA_PYTHON = _create_schema(for_container=False, extended_json_format=False)
CONF_SCHEMA_JSON = _create_schema(for_container=False, extended_json_format=True).json_schema("conf_schema.json")
CONTAINER_SCHEMA_PYTHON = _create_schema(for_container=True, extended_json_format=False)
CONTAINER_SCHEMA_JSON = _create_schema(for_container=True, extended_json_format=True).json_schema("container_schema.json")


def _validate_data_tree(data_tree: dict, valid_schema: Union[dict, Schema]):
    """Allows the validation of a data_tree with a pythonschema or jsonschema

    :param data_tree: container or conf to validate
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


def check_container_sanity(container: dict, jsonschema_mode: False):
    """Validate the format of a container.

    :param jsonschema_mode: If True, the container must have been loaded as raw json
           (with $binary, $numberInt and such) and will be checked using a jsonschema validator.
    """

    schema = CONTAINER_SCHEMA_JSON if jsonschema_mode else CONTAINER_SCHEMA_PYTHON

    _validate_data_tree(data_tree=container, valid_schema=schema)


def check_conf_sanity(conf: dict, jsonschema_mode: False):
    """Validate the format of a conf.

    :param jsonschema_mode: If True, the container must have been loaded as raw json
           (with $binary, $numberInt and such) and will be checked using a jsonschema validator.
    """

    schema = CONF_SCHEMA_JSON if jsonschema_mode else CONF_SCHEMA_PYTHON

    _validate_data_tree(data_tree=conf, valid_schema=schema)
