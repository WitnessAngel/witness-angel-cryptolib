import copy
import logging
import os
import uuid
from pathlib import Path
from typing import Optional

from wacryptolib.encryption import encrypt_bytestring, decrypt_bytestring
from wacryptolib.escrow import EscrowApi as LocalEscrowApi, LOCAL_ESCROW_PLACEHOLDER
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.key_generation import (
    generate_symmetric_key,
    load_asymmetric_key_from_pem_bytestring,
)
from wacryptolib.key_storage import DummyKeyStorage, KeyStorageBase
from wacryptolib.signature import verify_message_signature
from wacryptolib.utilities import (
    dump_to_json_bytes,
    load_from_json_bytes,
    dump_to_json_file,
    load_from_json_file,
    generate_uuid0,
    hash_message)

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
        self._local_escrow_api = LocalEscrowApi(key_storage=local_key_storage)

    def _get_proxy_for_escrow(self, escrow):
        if escrow == LOCAL_ESCROW_PLACEHOLDER:
            return self._local_escrow_api
        elif isinstance(escrow, dict):
            if "url" in escrow:
                return JsonRpcProxy(url=escrow["url"], response_error_handler=status_slugs_response_error_handler)
            # TODO - Implement escrow lookup in global registry, shared-secret group, etc.
        raise ValueError("Unrecognized escrow identifiers: %s" % str(escrow))


class ContainerWriter(ContainerBase):
    def encrypt_data(
        self, data: bytes, *, conf: dict, keychain_uid=None, metadata=None
    ) -> dict:
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
            symmetric_key = generate_symmetric_key(encryption_algo=data_encryption_algo)

            logger.debug("Encrypting data with symmetric key of type %r", data_encryption_algo)

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
    ) -> dict:
        assert isinstance(symmetric_key_data, bytes), symmetric_key_data
        escrow_key_type = conf["escrow_key_type"]
        key_encryption_algo = conf["key_encryption_algo"]
        encryption_proxy = self._get_proxy_for_escrow(conf["key_escrow"])

        logger.debug("Encrypting symmetric key with algo %r", key_encryption_algo)

        subkey_pem = encryption_proxy.get_public_key(
            keychain_uid=keychain_uid, key_type=escrow_key_type
        )
        subkey = load_asymmetric_key_from_pem_bytestring(
            key_pem=subkey_pem, key_type=escrow_key_type
        )

        key_cipherdict = encrypt_bytestring(
            plaintext=symmetric_key_data,
            encryption_algo=key_encryption_algo,
            key=subkey,
        )
        return key_cipherdict

    def _generate_signature(
        self, keychain_uid: uuid.UUID, data_ciphertext: bytes, conf: dict
    ) -> dict:
        encryption_proxy = self._get_proxy_for_escrow(conf["signature_escrow"])
        signature_key_type = conf["signature_key_type"]
        message_prehash_algo = conf["message_prehash_algo"]
        signature_algo = conf["signature_algo"]

        data_ciphertext_hash = hash_message(data_ciphertext, hash_algo=message_prehash_algo)

        logger.debug("Signing hash of encrypted data with algo %r", signature_algo)

        signature_value = encryption_proxy.get_message_signature(
            keychain_uid=keychain_uid,
            message=data_ciphertext_hash,
            key_type=signature_key_type,
            signature_algo=signature_algo,
        )
        return signature_value


class ContainerReader(ContainerBase):
    def extract_metadata(self, container: dict) -> Optional[dict]:
        assert isinstance(container, dict), container
        return container["metadata"]

    def decrypt_data(self, container: dict) -> bytes:
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
            for key_encryption_stratum in data_encryption_stratum[
                "key_encryption_strata"
            ]:
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
        assert isinstance(symmetric_key_cipherdict, dict), symmetric_key_cipherdict
        escrow_key_type = conf["escrow_key_type"]
        key_encryption_algo = conf["key_encryption_algo"]
        encryption_proxy = self._get_proxy_for_escrow(conf["key_escrow"])

        symmetric_key_plaintext = encryption_proxy.decrypt_with_private_key(
            keychain_uid=keychain_uid,
            key_type=escrow_key_type,
            encryption_algo=key_encryption_algo,
            cipherdict=symmetric_key_cipherdict,
        )
        return symmetric_key_plaintext

    def _verify_message_signature(
        self, keychain_uid: uuid.UUID, message: bytes, conf: dict
    ):
        signature_key_type = conf["signature_key_type"]
        message_prehash_algo = conf["message_prehash_algo"]
        signature_algo = conf["signature_algo"]
        encryption_proxy = self._get_proxy_for_escrow(conf["signature_escrow"])
        public_key_pem = encryption_proxy.get_public_key(
            keychain_uid=keychain_uid, key_type=signature_key_type
        )
        public_key = load_asymmetric_key_from_pem_bytestring(
            key_pem=public_key_pem, key_type=signature_key_type
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
    This class encrypts file streams and stores them into filesystem.

    Since it doesn't use in-memory aggregation structures, it's supposed to be thread-safe.

    Exceeding containers are automatically purged after each file addition.
    """

    def __init__(
        self,
        encryption_conf: dict,
        containers_dir: Path,
        max_containers_count: int = None,
        local_key_storage: KeyStorageBase = None,
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

    def _process_and_store_file(self, filename_base, data, metadata):
        """Returns the container basename."""
        container_filepath = self._make_absolute(filename_base + CONTAINER_SUFFIX)
        container = self._encrypt_data_into_container(data, metadata=metadata)
        dump_to_json_file(
            container_filepath, data=container, indent=4
        )  # Note that this might erase existing file, it's OK
        self._purge_exceeding_containers()  # AFTER new container is created
        return container_filepath.name

    def enqueue_file_for_encryption(self, filename_base, data, metadata):
        """Enqueue a data file for encryption and storage, with its metadata tree.

        Default implementation does the encryption/output job synchronously.

        `filename` of the final container might be different from provided one.
        """
        logger.info("Encrypting container %r into storage", filename_base)
        container_name = self._process_and_store_file(
            filename_base=filename_base, data=data, metadata=metadata
        )
        logger.info("Container %r successfully encrypted", container_name)

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
