import copy
import logging
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from pprint import pprint
from typing import Optional, Union, List
from urllib.parse import urlparse
from uuid import UUID

from wacryptolib.encryption import encrypt_bytestring, decrypt_bytestring
from wacryptolib.escrow import EscrowApi as LocalEscrowApi, ReadonlyEscrowApi, EscrowApi
from wacryptolib.exceptions import DecryptionError
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.key_generation import generate_symmetric_key, load_asymmetric_key_from_pem_bytestring
from wacryptolib.key_storage import KeyStorageBase, DummyKeyStoragePool, KeyStoragePoolBase
from wacryptolib.shared_secret import split_bytestring_as_shamir_shares, recombine_secret_from_shamir_shares
from wacryptolib.signature import verify_message_signature
from wacryptolib.utilities import (
    dump_to_json_bytes,
    load_from_json_bytes,
    dump_to_json_file,
    load_from_json_file,
    generate_uuid0,
    hash_message,
    synchronized,
    catch_and_log_exception,
)


logger = logging.getLogger(__name__)

CONTAINER_FORMAT = "WA_0.1a"
CONTAINER_SUFFIX = ".crypt"
OFFLOADED_DATA_SUFFIX = ".data"  # Added to CONTAINER_SUFFIX

MEDIUM_SUFFIX = ".medium"  # To construct decrypted filename when no previous extensions are found in container filename
OFFLOADED_MARKER = "[OFFLOADED]"
DUMMY_KEY_STORAGE_POOL = DummyKeyStoragePool()  # Common fallback storage with in-memory keys
SHARED_SECRET_MARKER = "[SHARED_SECRET]"

#: Special value in containers, to invoke a device-local escrow
LOCAL_ESCROW_MARKER = dict(escrow_type="local")  # FIXME CHANGE THIS

AUTHENTICATION_DEVICE_ESCROW_MARKER = dict(escrow_type="authentication_device")  # FIXME CHANGE THIS


def get_escrow_id(escrow_conf: dict) -> str:
    """Build opaque unique identifier for a specific escrow.

    Remains the same as long as escrow dict is completely unmodified.
    """
    return str(sorted(escrow_conf.items()))


def gather_escrow_dependencies(containers: list) -> dict:
    """
    Analyse a container and return the escrows (and their keypairs) used by it.

    :return: dict with lists of keypair identifiers in fields "encryption" and "signature".
    """

    def _add_keypair_identifiers_for_escrow(mapper, escrow_conf, keychain_uid, key_type):
        escrow_id = get_escrow_id(escrow_conf=escrow_conf)
        keypair_identifiers = dict(keychain_uid=keychain_uid, key_type=key_type)
        mapper.setdefault(escrow_id, (escrow_conf, []))
        keypair_identifiers_list = mapper[escrow_id][1]
        if keypair_identifiers not in keypair_identifiers_list:
            keypair_identifiers_list.append(keypair_identifiers)

    signature_dependencies = {}
    encryption_dependencies = {}

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

            for key_encryption_stratum in data_encryption_stratum["key_encryption_strata"]:
                key_type_encryption = key_encryption_stratum["key_encryption_algo"]

                if key_type_encryption == SHARED_SECRET_MARKER:
                    escrows = key_encryption_stratum["key_shared_secret_escrows"]

                    for escrow in escrows:
                        key_type_share = escrow["share_encryption_algo"]
                        keychain_uid_share = escrow.get("keychain_uid") or keychain_uid
                        escrow_conf = escrow["share_escrow"]
                        _add_keypair_identifiers_for_escrow(
                            mapper=encryption_dependencies,
                            escrow_conf=escrow_conf,
                            keychain_uid=keychain_uid_share,
                            key_type=key_type_share,
                        )
                else:
                    keychain_uid_encryption = key_encryption_stratum.get("keychain_uid") or keychain_uid
                    escrow_conf = key_encryption_stratum["key_escrow"]
                    _add_keypair_identifiers_for_escrow(
                        mapper=encryption_dependencies,
                        escrow_conf=escrow_conf,
                        keychain_uid=keychain_uid_encryption,
                        key_type=key_type_encryption,
                    )

    escrow_dependencies = {"signature": signature_dependencies, "encryption": encryption_dependencies}
    return escrow_dependencies


def request_decryption_authorizations(
    escrow_dependencies: dict, key_storage_pool, request_message: str, passphrases: Optional[list] = None
) -> dict:
    """
    Loop on encryption escrows and request decryption authorization for all the keypairs that they own.

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


def get_escrow_proxy(escrow: dict, key_storage_pool: KeyStoragePoolBase) -> EscrowApi:
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

    `passphrase_mapper` maps escrows IDs to potential passphrase; a None key can be used to provide additional
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


class ContainerWriter(ContainerBase):
    """
    Contains every method used to write and encrypt a container, IN MEMORY.
    """

    def encrypt_data(self, data: bytes, *, conf: dict, keychain_uid=None, metadata=None) -> dict:
        """
        Browse through configuration tree to apply the right succession of algorithms to data.

        :param data: initial plaintext
        :param conf: configuration tree
        :param keychain_uid: uuid for the set of encryption keys used
        :param metadata: additional data to store unencrypted in container

        :return: container with all the information needed to attempt data decryption
        """
        assert metadata is None or isinstance(metadata, dict), metadata
        container_format = CONTAINER_FORMAT
        container_uid = generate_uuid0()  # ALWAYS UNIQUE!
        keychain_uid = keychain_uid or generate_uuid0()  # Might be shared by lots of containers

        conf = copy.deepcopy(conf)  # So that we can manipulate it

        assert isinstance(data, bytes), data
        assert isinstance(conf, dict), conf

        data_current = data  # Initially unencrypted, might remain so if no strata
        result_data_encryption_strata = []

        for data_encryption_stratum in conf["data_encryption_strata"]:
            data_encryption_algo = data_encryption_stratum["data_encryption_algo"]

            logger.debug("Generating symmetric key of type %r", data_encryption_algo)
            symmetric_key = generate_symmetric_key(encryption_algo=data_encryption_algo)

            logger.debug("Encrypting data with symmetric key of type %r", data_encryption_algo)
            data_cipherdict = encrypt_bytestring(
                plaintext=data_current, encryption_algo=data_encryption_algo, key=symmetric_key
            )
            assert isinstance(data_cipherdict, dict), data_cipherdict
            data_current = dump_to_json_bytes(data_cipherdict)

            symmetric_key_data = symmetric_key  # Initially unencrypted, might remain so if no strata

            result_key_encryption_strata = []
            for key_encryption_stratum in data_encryption_stratum["key_encryption_strata"]:
                symmetric_key_cipherdict = self._encrypt_symmetric_key(
                    keychain_uid=keychain_uid, symmetric_key_data=symmetric_key_data, conf=key_encryption_stratum
                )
                symmetric_key_data = dump_to_json_bytes(symmetric_key_cipherdict)  # Remain as bytes all along
                result_key_encryption_strata.append(key_encryption_stratum)  # Unmodified for now

            data_signatures = []
            for signature_conf in data_encryption_stratum["data_signatures"]:
                signature_value = self._generate_signature(
                    keychain_uid=keychain_uid, data_ciphertext=data_current, conf=signature_conf
                )
                signature_conf["signature_value"] = signature_value
                data_signatures.append(signature_conf)

            result_data_encryption_strata.append(
                dict(
                    data_encryption_algo=data_encryption_algo,
                    key_ciphertext=symmetric_key_data,
                    key_encryption_strata=result_key_encryption_strata,
                    data_signatures=data_signatures,
                )
            )

        data_ciphertext = data_current  # New fully encrypted (unless data_encryption_strata is empty)

        return dict(
            container_format=container_format,
            container_uid=container_uid,
            keychain_uid=keychain_uid,
            data_ciphertext=data_ciphertext,
            data_encryption_strata=result_data_encryption_strata,
            metadata=metadata,
        )

    def _encrypt_symmetric_key(self, keychain_uid: uuid.UUID, symmetric_key_data: bytes, conf: dict) -> dict:
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
        assert isinstance(symmetric_key_data, bytes), symmetric_key_data
        key_encryption_algo = conf["key_encryption_algo"]

        if key_encryption_algo == SHARED_SECRET_MARKER:
            key_shared_secret_escrows = conf["key_shared_secret_escrows"]
            shares_count = len(key_shared_secret_escrows)

            threshold_count = conf["key_shared_secret_threshold"]
            assert threshold_count <= shares_count

            logger.debug("Generating Shamir shared secret shares (%d needed amongst %d)", threshold_count, shares_count)

            shares = split_bytestring_as_shamir_shares(
                secret=symmetric_key_data, shares_count=shares_count, threshold_count=threshold_count
            )

            logger.debug("Secret has been shared into %d shares", shares_count)
            assert len(shares) == shares_count

            all_encrypted_shares = self._encrypt_shares(
                shares=shares, key_shared_secret_escrows=conf["key_shared_secret_escrows"], keychain_uid=keychain_uid
            )
            key_cipherdict = {"shares": all_encrypted_shares}
            return key_cipherdict

        else:  # Using asymmetric algorithm

            keychain_uid_encryption = conf.get("keychain_uid") or keychain_uid
            key_cipherdict = self._apply_asymmetric_encryption(
                encryption_algo=key_encryption_algo,
                keychain_uid=keychain_uid_encryption,
                symmetric_key_data=symmetric_key_data,
                escrow=conf["key_escrow"],
            )

            return key_cipherdict

    def _apply_asymmetric_encryption(
        self, encryption_algo: str, keychain_uid: uuid.UUID, symmetric_key_data: bytes, escrow
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

        cipherdict = encrypt_bytestring(plaintext=symmetric_key_data, encryption_algo=encryption_algo, key=subkey)
        return cipherdict

    def _encrypt_shares(self, shares: list, key_shared_secret_escrows: list, keychain_uid: uuid.UUID) -> list:
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

            share_cipherdict = self._apply_asymmetric_encryption(
                encryption_algo=share_encryption_algo,
                keychain_uid=keychain_uid_share,
                symmetric_key_data=share[1],
                escrow=share_escrow,
            )

            all_encrypted_shares.append((share[0], share_cipherdict))

        assert len(shares) == len(key_shared_secret_escrows)
        return all_encrypted_shares

    def _generate_signature(self, keychain_uid: uuid.UUID, data_ciphertext: bytes, conf: dict) -> dict:
        """
        Generate a signature for a specific ciphered data.

        :param keychain_uid: uuid for the set of encryption keys used
        :param data_ciphertext: data as bytes on which to apply signature
        :param conf: configuration tree inside data_signatures
        :return: dictionary with information needed to verify signature
        """
        encryption_proxy = get_escrow_proxy(escrow=conf["signature_escrow"], key_storage_pool=self._key_storage_pool)
        message_prehash_algo = conf["message_prehash_algo"]
        signature_algo = conf["signature_algo"]
        keychain_uid_signature = conf.get("keychain_uid") or keychain_uid

        data_ciphertext_hash = hash_message(data_ciphertext, hash_algo=message_prehash_algo)

        logger.debug("Signing hash of encrypted data with algo %r", signature_algo)

        signature_value = encryption_proxy.get_message_signature(
            keychain_uid=keychain_uid_signature, message=data_ciphertext_hash, signature_algo=signature_algo
        )
        return signature_value


class ContainerReader(ContainerBase):
    """
    Contains every method used to read and decrypt a container, IN MEMORY.
    """

    def extract_metadata(self, container: dict) -> Optional[dict]:
        assert isinstance(container, dict), container
        return container["metadata"]

    def decrypt_data(self, container: dict) -> bytes:
        """
        Loop through container layers, to decipher data with the right algorithms.

        :param container: dictionary previously built with ContainerWriter method

        :return: deciphered plaintext
        """
        assert isinstance(container, dict), container

        container_format = container["container_format"]
        if container_format != CONTAINER_FORMAT:
            raise ValueError("Unknown container format %s" % container_format)

        container_uid = container["container_format"]
        del container_uid  # Might be used for logging etc, later...

        keychain_uid = container["keychain_uid"]

        data_current = container["data_ciphertext"]

        for data_encryption_stratum in reversed(container["data_encryption_strata"]):

            data_encryption_algo = data_encryption_stratum["data_encryption_algo"]

            for signature_conf in data_encryption_stratum["data_signatures"]:
                self._verify_message_signature(keychain_uid=keychain_uid, message=data_current, conf=signature_conf)

            symmetric_key_data = data_encryption_stratum["key_ciphertext"]  # We start fully encrypted, and unravel it
            for key_encryption_stratum in reversed(data_encryption_stratum["key_encryption_strata"]):
                symmetric_key_cipherdict = load_from_json_bytes(symmetric_key_data)  # We remain as bytes all along
                symmetric_key_data = self._decrypt_symmetric_key(
                    keychain_uid=keychain_uid,
                    symmetric_key_cipherdict=symmetric_key_cipherdict,
                    conf=key_encryption_stratum,
                )

            assert isinstance(symmetric_key_data, bytes), symmetric_key_data
            data_cipherdict = load_from_json_bytes(data_current)
            data_current = decrypt_bytestring(
                cipherdict=data_cipherdict, key=symmetric_key_data, encryption_algo=data_encryption_algo
            )

        data = data_current  # Now decrypted
        return data

    def _decrypt_symmetric_key(self, keychain_uid: uuid.UUID, symmetric_key_cipherdict: dict, conf: list):
        """
        Function called when decryption of a symmetric key is needed. Encryption may be made by shared secret or
        by a asymmetric algorithm.

        :param keychain_uid: uuid for the set of encryption keys used
        :param symmetric_key_cipherdict: dictionary with input ata needed to decrypt symmetric key
        :param conf: dictionary which contains crypto configuration tree

        :return: deciphered symmetric key
        """
        assert isinstance(symmetric_key_cipherdict, dict), symmetric_key_cipherdict
        key_encryption_algo = conf["key_encryption_algo"]

        if key_encryption_algo == SHARED_SECRET_MARKER:

            logger.debug("Deciphering each share")
            shares = self._decrypt_symmetric_key_share(
                keychain_uid=keychain_uid, symmetric_key_cipherdict=symmetric_key_cipherdict, conf=conf
            )

            logger.debug("Recombining shared-secret shares")
            symmetric_key_plaintext = recombine_secret_from_shamir_shares(shares=shares)

            return symmetric_key_plaintext

        else:  # Using asymmetric algorithm

            keychain_uid_encryption = (
                conf.get("keychain_uid") or keychain_uid
            )  # FIXME replace by shorter form everywhere in file

            symmetric_key_plaintext = self._decrypt_cipherdict_with_asymmetric_cipher(
                encryption_algo=key_encryption_algo,
                keychain_uid=keychain_uid_encryption,
                cipherdict=symmetric_key_cipherdict,
                escrow=conf["key_escrow"],
            )
            return symmetric_key_plaintext

    def _decrypt_cipherdict_with_asymmetric_cipher(
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

    def _decrypt_symmetric_key_share(self, keychain_uid: uuid.UUID, symmetric_key_cipherdict: dict, conf: list):
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

                share_plaintext = self._decrypt_cipherdict_with_asymmetric_cipher(
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
        message_prehash_algo = conf["message_prehash_algo"]
        signature_algo = conf["signature_algo"]
        keychain_uid_signature = conf.get("keychain_uid") or keychain_uid
        encryption_proxy = get_escrow_proxy(escrow=conf["signature_escrow"], key_storage_pool=self._key_storage_pool)
        public_key_pem = encryption_proxy.fetch_public_key(
            keychain_uid=keychain_uid_signature, key_type=signature_algo, must_exist=True
        )
        public_key = load_asymmetric_key_from_pem_bytestring(key_pem=public_key_pem, key_type=signature_algo)

        message_hash = hash_message(message, hash_algo=message_prehash_algo)

        verify_message_signature(
            message=message_hash, signature_algo=signature_algo, signature=conf["signature_value"], key=public_key
        )  # Raises if troubles


def encrypt_data_into_container(
    data: bytes,
    *,
    conf: dict,
    metadata: Optional[dict],
    keychain_uid: Optional[uuid.UUID] = None,
    key_storage_pool: Optional[KeyStoragePoolBase] = None
) -> dict:
    """Turn raw data into a high-security container, which can only be decrypted with
    the agreement of the owner and multiple third-party escrows.

    :param data: bytestring of media (image, video, sound...) to protect
    :param conf: tree of specific encryption settings
    :param metadata: dict of metadata describing the data
    :param keychain_uid: optional ID of a keychain to reuse
    :param key_storage_pool: optional key storage pool, might be required by encryption conf

    :return: dict of container
    """
    writer = ContainerWriter(key_storage_pool=key_storage_pool)
    container = writer.encrypt_data(data, conf=conf, keychain_uid=keychain_uid, metadata=metadata)
    return container


def decrypt_data_from_container(
    container: dict, *, key_storage_pool: Optional[KeyStoragePoolBase] = None, passphrase_mapper: Optional[dict] = None
) -> bytes:
    """Decrypt a container with the help of third-parties.

    :param container: the container tree, which holds all information about involved keys
    :param key_storage_pool: optional key storage pool
    :param passphrase_mapper: optional dict mapping urls/device_uids to their lists of passphrases

    :return: raw bytestring
    """
    reader = ContainerReader(key_storage_pool=key_storage_pool, passphrase_mapper=passphrase_mapper)
    data = reader.decrypt_data(container)
    return data


def _get_offloaded_file_path(container_filepath):
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


def extract_metadata_from_container(container: dict) -> Optional[dict]:
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
    :param max_containers_count: if set, oldest exceeding containers (when sorted by name) are automatcially erased
    :param key_storage_pool: optional KeyStoragePool, which might be required by current encryption conf
    :param max_workers: count of worker threads to use in parallel
    :param offload_data_ciphertext: whether actual encrypted data must be kept separated from structured container file
    """

    def __init__(
        self,
        containers_dir: Path,
        default_encryption_conf: Optional[dict] = None,
        max_containers_count: Optional[int] = None,
        key_storage_pool: Optional[KeyStoragePoolBase] = None,
        max_workers: int = 1,
        offload_data_ciphertext=True,
    ):
        containers_dir = Path(containers_dir)
        assert containers_dir.is_dir(), containers_dir
        containers_dir = containers_dir.absolute()
        assert max_containers_count is None or max_containers_count > 0, max_containers_count
        self._default_encryption_conf = default_encryption_conf
        self._containers_dir = containers_dir
        self._max_containers_count = max_containers_count
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

    def list_container_names(self, as_sorted=False, as_absolute=False):
        """Returns the list of encrypted containers present in storage,
        sorted or not, absolute or not, as Path objects."""
        assert self._containers_dir.is_absolute(), self._containers_dir
        paths = list(self._containers_dir.glob("*" + CONTAINER_SUFFIX))  # As list, for multiple looping on it
        assert all(p.is_absolute() for p in paths), paths
        if as_sorted:
            paths = sorted(paths)
        if not as_absolute:
            paths = (Path(p.name) for p in paths)
        return list(paths)

    def _make_absolute(self, container_name):
        assert not Path(container_name).is_absolute()
        return self._containers_dir.joinpath(container_name)

    def _delete_container(self, container_name):
        container_filepath = self._make_absolute(container_name)
        delete_container_from_filesystem(container_filepath)

    def delete_container(self, container_name):
        logger.info("Deleting container %s" % container_name)
        self._delete_container(container_name=container_name)

    def _purge_exceeding_containers(self):
        if self._max_containers_count:
            # BEWARE, due to the way we name files, alphabetical and start-datetime sorts are the same!
            container_names = self.list_container_names(as_sorted=True, as_absolute=False)
            containers_count = len(container_names)
            if containers_count > self._max_containers_count:
                excess_count = containers_count - self._max_containers_count
                containers_to_delete = container_names[:excess_count]
                for container_name in containers_to_delete:
                    self._delete_container(container_name)

    def _encrypt_data_into_container(self, data, metadata, keychain_uid, encryption_conf):
        assert encryption_conf, encryption_conf
        return encrypt_data_into_container(
            data=data,
            conf=encryption_conf,
            metadata=metadata,
            keychain_uid=keychain_uid,
            key_storage_pool=self._key_storage_pool,
        )

    def _decrypt_data_from_container(self, container: dict, passphrase_mapper: dict) -> bytes:
        return decrypt_data_from_container(
            container, key_storage_pool=self._key_storage_pool, passphrase_mapper=passphrase_mapper
        )  # Will fail if authorizations are not OK

    @catch_and_log_exception
    def _offloaded_encrypt_data_and_dump_container(self, filename_base, data, metadata, keychain_uid, encryption_conf):
        """Task to be called by background thread, which encrypts a payload into a disk container.

        Returns the container basename."""

        logger.debug("Encrypting file %s", filename_base)
        container = self._encrypt_data_into_container(
            data, metadata=metadata, keychain_uid=keychain_uid, encryption_conf=encryption_conf
        )

        container_filepath = self._make_absolute(filename_base + CONTAINER_SUFFIX)
        logger.debug("Writing container data to file %s", container_filepath)

        dump_container_to_filesystem(
            container_filepath, container=container, offload_data_ciphertext=self._offload_data_ciphertext
        )

        logger.info("File %r successfully encrypted into storage container", filename_base)
        return container_filepath.name

    @synchronized
    def enqueue_file_for_encryption(self, filename_base, data, metadata, keychain_uid=None, encryption_conf=None):
        """Enqueue a data file for encryption and storage, with its metadata tree.

        Default implementation does the encryption/output job synchronously.

        The filename of final container might be different from provided one.
        Warning, target container with the same constructed name might be overwritten.

        `keychain_uid`, if provided, replaces autogenerated keychain_uid for this data item.
        `encryption_conf`, if provided, replaces default encryption conf for this data item.
        """
        logger.info("Enqueuing file %r for encryption and storage", filename_base)

        encryption_conf = encryption_conf or self._default_encryption_conf

        if not encryption_conf:
            raise RuntimeError("Either default or file-specific encryption conf must be provided to ContainerStorage")

        self._purge_exceeding_containers()
        self._purge_executor_results()
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

        logger.info("Loading container %r from storage", container_name)
        container_filepath = self._make_absolute(container_name)
        container = load_container_from_filesystem(container_filepath, include_data_ciphertext=include_data_ciphertext)
        return container

    def decrypt_container_from_storage(self, container_name_or_idx, passphrase_mapper: Optional[dict] = None) -> bytes:
        """
        Return the decrypted content of the container `container_name_or_idx` (which must be in `list_container_names()`,
        or an index suitable for this sorted list).
        """
        logger.info("Decrypting container %r from storage", container_name_or_idx)

        container = self.load_container_from_storage(container_name_or_idx, include_data_ciphertext=True)

        result = self._decrypt_data_from_container(container, passphrase_mapper=passphrase_mapper)
        logger.info("Container %r successfully decrypted", container_name_or_idx)
        return result


def get_encryption_configuration_summary(conf_or_container):
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
                % (data_signature["message_prehash_algo"], data_signature["signature_algo"], escrow_id)
            )
    result = "\n".join(lines) + "\n"
    return result
