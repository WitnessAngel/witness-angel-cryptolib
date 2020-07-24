import copy
import logging
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional, Union, List
from urllib.parse import urlparse

from wacryptolib.encryption import encrypt_bytestring, decrypt_bytestring
from wacryptolib.escrow import EscrowApi as LocalEscrowApi, LOCAL_ESCROW_PLACEHOLDER
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.key_generation import (
    generate_symmetric_key,
    load_asymmetric_key_from_pem_bytestring,
)
from wacryptolib.key_storage import DummyKeyStorage, KeyStorageBase
from wacryptolib.shared_secret import (
    split_bytestring_as_shamir_shares,
    recombine_secret_from_samir_shares,
)
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
MEDIUM_SUFFIX = (
    ".medium"
)  # To construct decrypted filename when no previous extensions are found in container filename

DUMMY_KEY_STORAGE = DummyKeyStorage()  # Fallback storage with in-memory keys


class ContainerBase:
    """
    BEWARE - this class-based design is provisional and might change a lot.
    """

    def __init__(self, local_key_storage=None):
        if not local_key_storage:
            logger.warning(
                "No local key storage provided for %s instance, falling back to DummyKeyStorage()",
                self.__class__.__name__,
            )
            local_key_storage = DUMMY_KEY_STORAGE
        assert isinstance(local_key_storage, KeyStorageBase), local_key_storage
        self._local_escrow_api = LocalEscrowApi(key_storage=local_key_storage)

    def _get_proxy_for_escrow(self, escrow):
        if escrow == LOCAL_ESCROW_PLACEHOLDER:
            return self._local_escrow_api
        elif isinstance(escrow, dict):
            if "url" in escrow:
                return JsonRpcProxy(
                    url=escrow["url"],
                    response_error_handler=status_slugs_response_error_handler,
                )
            # TODO - Implement escrow lookup in global registry, shared-secret group, etc.
        raise ValueError("Unrecognized escrow identifiers: %s" % str(escrow))


class ContainerWriter(ContainerBase):
    """
    Contains every method used to write and encrypt a container.
    """
    def encrypt_data(
        self, data: bytes, *, conf: dict, keychain_uid=None, metadata=None
    ) -> dict:
        """
        Browse through configuration tree to apply the right succession of algorithm to data.

        :param data: initial plaintext
        :param conf: configuration tree
        :param keychain_uid: uuid which permits to identify container
        :param metadata: additional data

        :return: container with all information needed to decrypt data
        """
        assert metadata is None or isinstance(metadata, dict), metadata
        container_format = CONTAINER_FORMAT
        container_uid = generate_uuid0()  # ALWAYS UNIQUE!
        keychain_uid = (
            keychain_uid or generate_uuid0()
        )  # Might be shared by lots of containers

        conf = copy.deepcopy(conf)  # So that we can manipulate it

        assert isinstance(data, bytes), data
        assert isinstance(conf, dict), conf

        data_current = data  # Initially unencrypted, might remain so if no strata
        result_data_encryption_strata = []

        for data_encryption_stratum in conf["data_encryption_strata"]:
            data_encryption_algo = data_encryption_stratum["data_encryption_algo"]

            logger.debug("Generating symmetric key of type %r", data_encryption_algo)
            symmetric_key = generate_symmetric_key(encryption_algo=data_encryption_algo)

            logger.debug(
                "Encrypting data with symmetric key of type %r", data_encryption_algo
            )
            data_cipherdict = encrypt_bytestring(
                plaintext=data_current,
                encryption_algo=data_encryption_algo,
                key=symmetric_key,
            )
            assert isinstance(data_cipherdict, dict), data_cipherdict
            data_current = dump_to_json_bytes(data_cipherdict)

            symmetric_key_data = (
                symmetric_key
            )  # Initially unencrypted, might remain so if no strata

            result_key_encryption_strata = []
            for key_encryption_stratum in data_encryption_stratum[
                "key_encryption_strata"
            ]:
                symmetric_key_cipherdict = self._encrypt_symmetric_key(
                    keychain_uid=keychain_uid,
                    symmetric_key_data=symmetric_key_data,
                    conf=key_encryption_stratum,
                )
                symmetric_key_data = dump_to_json_bytes(
                    symmetric_key_cipherdict
                )  # Remain as bytes all along
                result_key_encryption_strata.append(
                    key_encryption_stratum
                )  # Unmodified for now

            data_signatures = []
            for signature_conf in data_encryption_stratum["data_signatures"]:
                signature_value = self._generate_signature(
                    keychain_uid=keychain_uid,
                    data_ciphertext=data_current,
                    conf=signature_conf,
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

        data_ciphertext = (
            data_current
        )  # New fully encrypted (unless data_encryption_strata is empty)

        return dict(
            container_format=container_format,
            container_uid=container_uid,
            keychain_uid=keychain_uid,
            data_ciphertext=data_ciphertext,
            data_encryption_strata=result_data_encryption_strata,
            metadata=metadata,
        )

    def _encrypt_symmetric_key(
        self, keychain_uid: uuid.UUID, symmetric_key_data: bytes, conf: dict
    ) -> Union[List[dict], dict]:
        """
        Function called when encryption of a symmetric key is needed. Encryption may be made by shared secret or
        by an asymmetric algorithm.

        :param keychain_uid: uuid which permits to identify container
        :param symmetric_key_data: symmetric key as bytes to encrypt
        :param conf: dictionary which contain configuration tree

        :return: if the algorithm used is 'shared secret', a list with encrypted shards is returned. If an asymmetric
        algorithm has been used, a dictionary with all information needed to decipher the symmetric key is returned.
        """
        assert isinstance(symmetric_key_data, bytes), symmetric_key_data
        key_encryption_algo = conf["key_encryption_algo"]

        if key_encryption_algo == "SHARED_SECRET":  # Using Shamir
            escrows = conf["key_shared_secret_escrow"]
            shares_count = len(escrows)
            threshold_count = conf["key_shared_secret_threshold"]

            logger.debug("Generating Shamir's shared secret")

            shares = split_bytestring_as_shamir_shares(
                secret=symmetric_key_data,
                shares_count=shares_count,
                threshold_count=threshold_count,
            )

            logger.debug("Secret has been shared into %d escrows", shares_count)

            all_encrypted_shards = self._encrypt_shard(
                shares=shares, conf=conf, keychain_uid=keychain_uid
            )

            return all_encrypted_shards

        else:  # Using asymmetric algorithm
            key_cipherdict = self._asymmetric_encryption(
                encryption_algo=key_encryption_algo,
                keychain_uid=keychain_uid,
                data=symmetric_key_data,
                escrow=conf["key_escrow"]
            )

            return key_cipherdict

    def _asymmetric_encryption(
            self, encryption_algo: str, keychain_uid: uuid.UUID, data: bytes, escrow
    ) -> dict:
        """
        Encrypt given data with an asymmetric algorithm.

        :param encryption_algo: string with name of algorithm to use
        :param keychain_uid: uuid which permits to identify container
        :param data: data as bytes to encrypt
        :param escrow: escrow used for encryption (findable in configuration tree)

        :return: dictionary which contains every data needed to decrypt the ciphered data
        """
        encryption_proxy = self._get_proxy_for_escrow(escrow)

        logger.debug("Generating assymetric key of type %r", encryption_algo)
        subkey_pem = encryption_proxy.get_public_key(
            keychain_uid=keychain_uid, key_type=encryption_algo
        )

        logger.debug(
            "Encrypting symmetric key with asymmetric key of type %r",
            encryption_algo,
        )
        subkey = load_asymmetric_key_from_pem_bytestring(
            key_pem=subkey_pem, key_type=encryption_algo
        )

        cipherdict = encrypt_bytestring(
            plaintext=data,
            encryption_algo=encryption_algo,
            key=subkey
        )
        return cipherdict

    def _encrypt_shard(self, shares: list, conf: dict, keychain_uid: uuid.UUID) -> dict:
        """
        Make a loop through all shards from shared secret algorithm to encrypt each of them.

        :param shares: list of tuples containing a shard and its place in the list
        :param conf: configuration tree inside key_encryption_algo
        :param keychain_uid: uuid which permits to identify container

        :return: dictionary with as key a counter and as value the corresponding encrypted shard
        """
        key_shared_secret_escrow = conf["key_shared_secret_escrow"]

        all_encrypted_shards = {}
        counter = 0
        for shard in shares:
            shard_value = shard[1]
            conf_shard = key_shared_secret_escrow[counter]
            shard_encryption_algo = conf_shard["shared_encryption_algo"]

            shard_cipherdict = self._asymmetric_encryption(
                encryption_algo=shard_encryption_algo,
                keychain_uid=keychain_uid,
                data=shard_value,
                escrow=conf_shard["shared_escrow"]
            )

            all_encrypted_shards[counter] = shard_cipherdict
            counter += 1

        return all_encrypted_shards

    def _generate_signature(
        self, keychain_uid: uuid.UUID, data_ciphertext: bytes, conf: dict
    ) -> dict:
        """
        Generate a signature for a specific ciphered data.

        :param keychain_uid: uuid which permits to identify container
        :param data_ciphertext: data as bytes on which to apply signature
        :param conf: configuration tree inside data_signatures

        :return: dictionary with information needed to verify signature
        """
        encryption_proxy = self._get_proxy_for_escrow(conf["signature_escrow"])
        message_prehash_algo = conf["message_prehash_algo"]
        signature_algo = conf["signature_algo"]

        data_ciphertext_hash = hash_message(
            data_ciphertext, hash_algo=message_prehash_algo
        )

        logger.debug("Signing hash of encrypted data with algo %r", signature_algo)

        signature_value = encryption_proxy.get_message_signature(
            keychain_uid=keychain_uid,
            message=data_ciphertext_hash,
            signature_algo=signature_algo,
        )
        return signature_value


class ContainerReader(ContainerBase):
    """
    Contains every method used to read and decrypt a container.
    """
    def extract_metadata(self, container: dict) -> Optional[dict]:
        assert isinstance(container, dict), container
        return container["metadata"]

    def decrypt_data(self, container: dict) -> bytes:
        """
        Make a loop through given container to apply right algorithm to decipher data.

        :param container: dictionary get from encrypt_data method

        :return: initial plaintext deciphered as bytes
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
                self._verify_message_signature(
                    keychain_uid=keychain_uid, message=data_current, conf=signature_conf
                )

            symmetric_key_data = data_encryption_stratum[
                "key_ciphertext"
            ]  # We start fully encrypted, and unravel it
            for key_encryption_stratum in reversed(
                data_encryption_stratum["key_encryption_strata"]
            ):
                symmetric_key_cipherdict = load_from_json_bytes(
                    symmetric_key_data
                )  # We remain as bytes all along
                symmetric_key_data = self._decrypt_symmetric_key(
                    keychain_uid=keychain_uid,
                    symmetric_key_cipherdict=symmetric_key_cipherdict,
                    conf=key_encryption_stratum,
                )

            assert isinstance(symmetric_key_data, bytes), symmetric_key_data
            data_cipherdict = load_from_json_bytes(data_current)
            data_current = decrypt_bytestring(
                cipherdict=data_cipherdict,
                key=symmetric_key_data,
                encryption_algo=data_encryption_algo,
            )

        data = data_current  # Now decrypted
        return data

    def _decrypt_symmetric_key(
        self, keychain_uid: uuid.UUID, symmetric_key_cipherdict: dict, conf: list
    ):
        """
        Function called when decryption of a symmetric key is needed. Encryption may be made by shared secret or
        by a asymmetric algorithm.

        :param keychain_uid: uuid which permits to identify container
        :param symmetric_key_cipherdict: dictionary which has data needed to decrypt symmetric key
        :param conf: dictionary which contain configuration tree

        :return: deciphered symmetric key
        """
        assert isinstance(symmetric_key_cipherdict, dict), symmetric_key_cipherdict
        key_encryption_algo = conf["key_encryption_algo"]

        if key_encryption_algo == "SHARED_SECRET":  # Using Shamir
            escrows = conf["key_shared_secret_escrow"]
            shares_count = len(escrows)
            threshold_count = conf["key_shared_secret_threshold"]

            logger.debug("Deciphering each shard")
            shares = self._decrypt_shard(
                keychain_uid=keychain_uid,
                symmetric_key_cipherdict=symmetric_key_cipherdict,
                conf=conf,
            )

            logger.debug("Recombining shards")
            symmetric_key_plaintext = recombine_secret_from_samir_shares(shares=shares)

            return symmetric_key_plaintext

        else:  # Using asymmetric algorithm
            symmetric_key_plaintext = self._asymmetric_decryption(
                encryption_algo=key_encryption_algo,
                keychain_uid=keychain_uid,
                cipherdict=symmetric_key_cipherdict,
                escrow=conf["key_escrow"]
            )
            return symmetric_key_plaintext

    def _asymmetric_decryption(
            self, encryption_algo: str, keychain_uid: uuid.UUID, cipherdict: dict, escrow
    ) -> bytes:
        """
        Decrypt given cipherdict with an assymetric algorithm

        :param encryption_algo: string with name of algorithm to use
        :param keychain_uid: uuid which permits to identify container
        :param cipherdict: dictionary which contains every data needed to decrypt the ciphered data
        :param escrow: escrow used for encryption (findable in configuration tree)

        :return: decypted data as bytes
        """
        encryption_proxy = self._get_proxy_for_escrow(escrow=escrow)

        keypair_identifiers = [
            dict(keychain_uid=keychain_uid, key_type=encryption_algo)
        ]

        request_result = encryption_proxy.request_decryption_authorization(
            keypair_identifiers=keypair_identifiers,
            request_message="Automatic decryption authorization request",
        )

        logger.info(
            "Decryption authorization request result: %s",
            request_result["response_message"],
        )

        # We attempt decryption whatever the result of request_decryption_authorization(), since a previous
        # decryption authorization might still be valid
        symmetric_key_plaintext = encryption_proxy.decrypt_with_private_key(
            keychain_uid=keychain_uid,
            encryption_algo=encryption_algo,
            cipherdict=cipherdict,
        )

        return symmetric_key_plaintext

    def _decrypt_shard(
        self, keychain_uid: uuid.UUID, symmetric_key_cipherdict: dict, conf: list
    ):
        """
        Make a loop through all encrypted shards to decrypt each of them
        :param keychain_uid: uuid which permits to identify container
        :param symmetric_key_cipherdict: dictionary which contains every data needed to decipher each shard
        :param conf: configuration tree inside key_encryption_algo

        :return: list of tuples of deciphered shards
        """
        key_shared_secret_escrow = conf["key_shared_secret_escrow"]
        counter = 1
        shares = []
        for escrow in key_shared_secret_escrow:
            ciphered_shard = symmetric_key_cipherdict[str(counter - 1)]
            shared_encryption_algo = escrow["shared_encryption_algo"]

            symmetric_key_plaintext = self._asymmetric_decryption(
                encryption_algo=shared_encryption_algo,
                keychain_uid=keychain_uid,
                cipherdict=ciphered_shard,
                escrow=escrow["shared_escrow"]
            )

            share = (counter, symmetric_key_plaintext)
            shares.append(share)

            counter += 1
        return shares

    def _verify_message_signature(
        self, keychain_uid: uuid.UUID, message: bytes, conf: dict
    ):
        """
        Verify a signature for a specific message. An error is raised if signature isn't correct.

        :param keychain_uid: uuid which permits to identify container
        :param message: message as bytes on which to verify signature
        :param conf: configuration tree inside data_signatures
        """
        message_prehash_algo = conf["message_prehash_algo"]
        signature_algo = conf["signature_algo"]
        encryption_proxy = self._get_proxy_for_escrow(conf["signature_escrow"])
        public_key_pem = encryption_proxy.get_public_key(
            keychain_uid=keychain_uid, key_type=signature_algo
        )
        public_key = load_asymmetric_key_from_pem_bytestring(
            key_pem=public_key_pem, key_type=signature_algo
        )

        message_hash = hash_message(message, hash_algo=message_prehash_algo)

        verify_message_signature(
            message=message_hash,
            signature_algo=signature_algo,
            signature=conf["signature_value"],
            key=public_key,
        )  # Raises if troubles


def encrypt_data_into_container(
    data: bytes,
    *,
    conf: dict,
    metadata: Optional[dict],
    keychain_uid: Optional[uuid.UUID] = None,
    local_key_storage: Optional[KeyStorageBase] = None
) -> dict:
    """Turn raw data into a high-security container, which can only be decrypted with
    the agreement of the owner and multiple third-party escrows.

    :param data: bytestring of media (image, video, sound...) to protect
    :param conf: tree of format-specific settings
    :param metadata: dict of metadata describing the data
    :param keychain_uid: optional ID of a keychain to reuse
    :param local_key_storage: optional local key storage

    :return: dict of container
    """
    writer = ContainerWriter(local_key_storage=local_key_storage)
    container = writer.encrypt_data(
        data, conf=conf, keychain_uid=keychain_uid, metadata=metadata
    )
    return container


def decrypt_data_from_container(
    container: dict, local_key_storage: Optional[KeyStorageBase] = None
) -> bytes:
    """Decrypt a container with the help of third-parties.

    :param container: the container tree, which holds all information about involved keys
    :param local_key_storage: optional local key storage

    :return: raw bytestring
    """
    reader = ContainerReader(local_key_storage=local_key_storage)
    data = reader.decrypt_data(container)
    return data


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
    """

    def __init__(
        self,
        encryption_conf: dict,
        containers_dir: Path,
        max_containers_count: int = None,
        local_key_storage: KeyStorageBase = None,
        max_workers=1,
    ):
        containers_dir = Path(containers_dir)
        assert containers_dir.is_dir(), containers_dir
        containers_dir = containers_dir.absolute()
        assert (
            max_containers_count is None or max_containers_count > 0
        ), max_containers_count
        self._encryption_conf = encryption_conf
        self._containers_dir = containers_dir
        self._max_containers_count = max_containers_count
        self._local_key_storage = local_key_storage
        self._thread_pool_executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="container_worker"
        )
        self._pending_executor_futures = []
        self._lock = threading.Lock()

    def __del__(self):
        self._thread_pool_executor.shutdown(wait=False)

    def __len__(self):
        """Beware, might be SLOW if many files are present in folder."""
        return len(self.list_container_names())  # No sorting, to be quicker

    def list_container_names(self, as_sorted=False, as_absolute=False):
        """Returns the list of encrypted containers present in storage,
        sorted or not, absolute or not, as Path objects."""
        assert self._containers_dir.is_absolute(), self._containers_dir
        paths = list(
            self._containers_dir.glob("*" + CONTAINER_SUFFIX)
        )  # As list, for multiple looping on it
        assert all(p.is_absolute() for p in paths), paths
        if as_sorted:
            paths = sorted(p for p in paths)
        if not as_absolute:
            paths = (Path(p.name) for p in paths)
        return list(paths)

    def _make_absolute(self, container_name):
        assert not Path(container_name).is_absolute()
        return self._containers_dir.joinpath(container_name)

    def _delete_container(self, container_name):
        container_filepath = self._make_absolute(container_name)
        os.remove(
            container_filepath
        )  # TODO - additional retries if file access errors?

    def _purge_exceeding_containers(self):
        if self._max_containers_count:
            # BEWARE, due to the way we name files, alphabetical and start-datetime sorts are the same!
            container_names = self.list_container_names(
                as_sorted=True, as_absolute=False
            )
            containers_count = len(container_names)
            if containers_count > self._max_containers_count:
                excess_count = containers_count - self._max_containers_count
                containers_to_delete = container_names[:excess_count]
                for container_name in containers_to_delete:
                    self._delete_container(container_name)

    def _encrypt_data_into_container(self, data, metadata):
        return encrypt_data_into_container(
            data=data,
            conf=self._encryption_conf,
            metadata=metadata,
            local_key_storage=self._local_key_storage,
        )

    def _decrypt_data_from_container(self, container):
        return decrypt_data_from_container(
            container, local_key_storage=self._local_key_storage
        )  # Will fail if authorizations are not OK

    @catch_and_log_exception
    def _offloaded_process_and_store_file(self, filename_base, data, metadata):
        """Task to be called by background thread, which encrypts a payload into a disk container.

        Returns the container basename."""

        logger.debug("Encrypting file %s", filename_base)
        container = self._encrypt_data_into_container(data, metadata=metadata)

        container_filepath = self._make_absolute(filename_base + CONTAINER_SUFFIX)
        logger.debug("Writing container data to file %s", container_filepath)
        dump_to_json_file(
            container_filepath, data=container, indent=4
        )  # Note that this might erase an existing file, it's OK

        logger.info(
            "File %r successfully encrypted into storage container", filename_base
        )
        return container_filepath.name

    @synchronized
    def enqueue_file_for_encryption(self, filename_base, data, metadata):
        """Enqueue a data file for encryption and storage, with its metadata tree.

        Default implementation does the encryption/output job synchronously.

        `filename` of the final container might be different from provided one.
        """
        logger.info("Enqueuing file %r for encryption and storage", filename_base)
        self._purge_exceeding_containers()
        self._purge_executor_results()
        future = self._thread_pool_executor.submit(
            self._offloaded_process_and_store_file,
            filename_base=filename_base,
            data=data,
            metadata=metadata,
        )
        self._pending_executor_futures.append(future)

    def _purge_executor_results(self):
        """Remove futures which are actually over. We don't care about their result/exception here"""
        still_pending_results = [
            future for future in self._pending_executor_futures if not future.done()
        ]
        self._pending_executor_futures = still_pending_results

    @synchronized
    def wait_for_idle_state(self):
        """Wait for each pending future to be completed."""
        self._purge_executor_results()
        for future in self._pending_executor_futures:
            future.result()  # Should NEVER raise, thanks to the @catch_and_log_exception above, and absence of cancellations
        self._purge_exceeding_containers()  # Good to have now

    def decrypt_container_from_storage(self, container_name_or_idx):
        """
        Return the decrypted content of the container `filename` (which must be in `list_container_names()`,
        or an index suitable for this list).
        """
        if isinstance(container_name_or_idx, int):
            container_names = self.list_container_names(
                as_sorted=True, as_absolute=False
            )
            container_name = container_names[
                container_name_or_idx
            ]  # Will break if idx is out of bounds
        else:

            assert isinstance(container_name_or_idx, (Path, str)), repr(
                container_name_or_idx
            )
            container_name = Path(container_name_or_idx)

        assert not container_name.is_absolute(), container_name

        logger.info("Decrypting container %r from storage", container_name)

        container_filepath = self._make_absolute(container_name)
        container = load_from_json_file(container_filepath)

        result = self._decrypt_data_from_container(container)
        logger.info("Container %r successfully decrypted", container_name)
        return result


def get_encryption_configuration_summary(conf_or_container):
    """
    Returns a string summary of the layers of encryption/signature of a container or a configuration tree.
    """

    def _get_escrow_identifier(_escrow):
        if _escrow == LOCAL_ESCROW_PLACEHOLDER:
            _escrow = "local device"
        elif "url" in _escrow:
            _escrow = urlparse(_escrow["url"]).netloc
        else:
            raise ValueError("Unrecognized key escrow %s" % _escrow)
        return _escrow

    lines = []
    for idx, data_encryption_stratum in enumerate(
        conf_or_container["data_encryption_strata"], start=1
    ):
        lines.append(
            "Data encryption layer %d: %s"
            % (idx, data_encryption_stratum["data_encryption_algo"])
        )
        lines.append("  Key encryption layers:")
        for idx2, key_encryption_stratum in enumerate(
            data_encryption_stratum["key_encryption_strata"], start=1
        ):
            key_escrow = key_encryption_stratum["key_escrow"]
            escrow_id = _get_escrow_identifier(key_escrow)
            lines.append(
                "    %s (by %s)"
                % (key_encryption_stratum["key_encryption_algo"], escrow_id)
            )
        lines.append("  Signatures:")
        for idx3, data_signature in enumerate(
            data_encryption_stratum["data_signatures"], start=1
        ):
            signature_escrow = data_signature["signature_escrow"]
            escrow_id = _get_escrow_identifier(signature_escrow)
            lines.append(
                "    %s/%s (by %s)"
                % (
                    data_signature["message_prehash_algo"],
                    data_signature["signature_algo"],
                    escrow_id,
                )
            )
    result = "\n".join(lines) + "\n"
    return result
