import copy
import glob
import logging
import os
import uuid

from typing import Optional

from wacryptolib.encryption import encrypt_bytestring, decrypt_bytestring
from wacryptolib.escrow import DummyKeyStorage, EscrowApi, LOCAL_ESCROW_PLACEHOLDER
from wacryptolib.jsonrpc_client import JsonRpcProxy
from wacryptolib.key_generation import (
    generate_symmetric_key,
    load_asymmetric_key_from_pem_bytestring,
)
from wacryptolib.signature import verify_message_signature
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes, dump_to_json_file, load_from_json_file

logger = logging.getLogger(__name__)

CONTAINER_FORMAT = "WA_0.1a"
CONTAINER_SUFFIX = ".crypt"
MEDIUM_SUFFIX = (
    ".medium"
)  # To construct decrypted filename when no previous extensions are found in container filename

LOCAL_ESCROW_API = EscrowApi(key_storage=DummyKeyStorage())


def _get_proxy_for_escrow(escrow):
    if escrow == LOCAL_ESCROW_PLACEHOLDER:
        return LOCAL_ESCROW_API
    elif isinstance(escrow, dict):
        if "url" in escrow:
            return JsonRpcProxy(url=escrow)
        # TODO - Implement escrow lookup in global registry, shared-secret group, etc.
    raise ValueError("Unrecognized escrow identifiers: %s" % str(escrow))


class ContainerBase:
    """
    BEWARE - this class-based design is provisional and might change a lot.
    """

    pass


class ContainerWriter(ContainerBase):
    def encrypt_data(self, data: bytes, *, conf: dict, keychain_uid=None, metadata=None) -> dict:
        assert metadata is None or isinstance(metadata, dict), metadata
        container_format = CONTAINER_FORMAT
        container_uid = uuid.uuid4()  # ALWAYS UNIQUE!
        keychain_uid = (
            keychain_uid or uuid.uuid4()
        )  # Might be shared by lots of containers

        conf = copy.deepcopy(conf)  # So that we can manipulate it

        assert isinstance(data, bytes), data
        assert isinstance(conf, dict), conf

        data_current = data  # Initially unencrypted, might remain so if no strata
        result_data_encryption_strata = []

        for data_encryption_stratum in conf["data_encryption_strata"]:
            data_encryption_algo = data_encryption_stratum["data_encryption_algo"]
            symmetric_key = generate_symmetric_key(encryption_algo=data_encryption_algo)

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
        encryption_proxy = _get_proxy_for_escrow(conf["key_escrow"])

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
        encryption_proxy = _get_proxy_for_escrow(conf["signature_escrow"])
        signature_key_type = conf["signature_key_type"]
        signature_algo = conf["signature_algo"]
        signature_value = encryption_proxy.get_message_signature(
            keychain_uid=keychain_uid,
            message=data_ciphertext,
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
                self._verify_message_signatures(
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
        encryption_proxy = _get_proxy_for_escrow(conf["key_escrow"])

        symmetric_key_plaintext = encryption_proxy.decrypt_with_private_key(
            keychain_uid=keychain_uid,
            key_type=escrow_key_type,
            encryption_algo=key_encryption_algo,
            cipherdict=symmetric_key_cipherdict,
        )
        return symmetric_key_plaintext

    def _verify_message_signatures(
        self, keychain_uid: uuid.UUID, message: bytes, conf: dict
    ):
        signature_key_type = conf["signature_key_type"]
        signature_algo = conf["signature_algo"]
        encryption_proxy = _get_proxy_for_escrow(conf["signature_escrow"])
        public_key_pem = encryption_proxy.get_public_key(
            keychain_uid=keychain_uid, key_type=signature_key_type
        )
        public_key = load_asymmetric_key_from_pem_bytestring(
            key_pem=public_key_pem, key_type=signature_key_type
        )

        verify_message_signature(
            message=message,
            signature_algo=signature_algo,
            signature=conf["signature_value"],
            key=public_key,
        )  # Raises if troubles


def encrypt_data_into_container(data: bytes, *, conf: dict, metadata: Optional[dict], keychain_uid=None) -> dict:
    """Turn raw data into a high-security container, which can only be decrypted with
    the agreement of the owner and multiple third-party escrows.

    :param data: bytestring of media (image, video, sound...) to protect
    :param conf: tree of format-specific settings
    :param keychain_uid: optional ID of a keychain to reuse

    :return:
    """
    writer = ContainerWriter()
    container = writer.encrypt_data(data, conf=conf, keychain_uid=keychain_uid, metadata=metadata)
    return container


def decrypt_data_from_container(container: dict) -> bytes:
    """Decrypt a container with the help of third-parties.

    :param container: the container tree, which holds all information about involved keys

    :return: raw bytestring
    """
    reader = ContainerReader()
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
    """

    def __init__(self, encryption_conf, output_dir, max_containers_count=None):
        assert os.path.isdir(output_dir), output_dir
        output_dir = os.path.abspath(output_dir)
        assert (
            max_containers_count is None or max_containers_count > 0
        ), max_containers_count
        self._encryption_conf = encryption_conf
        self._output_dir = output_dir
        self._max_containers_count = max_containers_count

    def __len__(self):
        """Beware, might be SLOW if many files are present in folder."""
        return len(self.list_container_names())  # No sorting, to be quicker

    def list_container_names(self, as_sorted_relative_paths=False):
        """Returns the list of encrypted containers present in storage, as random absolute paths,
        or as sorted relative path."""
        assert os.path.isabs(self._output_dir), self._output_dir
        paths = glob.glob(os.path.join(self._output_dir, "*" + CONTAINER_SUFFIX))
        if as_sorted_relative_paths:
            paths = sorted(os.path.basename(x) for x in paths)
        return paths

    def _make_absolute_container_path(self, container_name):
        return os.path.join(self._output_dir, container_name)

    def _delete_container(self, container_name):
        container_filepath = self._make_absolute_container_path(container_name)
        os.remove(
            container_filepath
        )  # TODO - additional retries if file access errors?

    def _purge_exceeding_containers(self):
        if self._max_containers_count:
            # BEWARE, due to the way we name files, alphabetical and start-datetime sorts are the same!
            container_names = self.list_container_names(as_sorted_relative_paths=True)
            containers_count = len(container_names)
            if containers_count > self._max_containers_count:
                excess_count = containers_count - self._max_containers_count
                containers_to_delete = container_names[:excess_count]
                for container_name in containers_to_delete:
                    self._delete_container(container_name)

    def _encrypt_data_into_container(self, data, metadata):
        return encrypt_data_into_container(data=data, conf=self._encryption_conf, metadata=metadata)

    def _decrypt_data_from_container(self, container):
        return decrypt_data_from_container(
            container
        )  # Will fail if authorizations are not OK

    def _process_and_store_file(self, filename_base, data, metadata):
        container_filepath = self._make_absolute_container_path(
            filename_base + CONTAINER_SUFFIX
        )
        container = self._encrypt_data_into_container(data, metadata=metadata)
        dump_to_json_file(container_filepath, data=container, indent=4)  # Note that this might erase existing file, it's OK
        self._purge_exceeding_containers()  # AFTER new container is created

    def enqueue_file_for_encryption(self, filename_base, data, metadata):
        """Enqueue a data file for encryption and storage, with its metadata tree.

        Default implementation does the encryption/output job synchronously.

        `filename` of the final container might be different from provided one.
        """
        self._process_and_store_file(filename_base=filename_base, data=data, metadata=metadata)

    def decrypt_container_from_storage(self, container_name_or_idx):
        """
        Return the decrypted content of the container `filename` (which must be in `list_container_names()`,
        or an index suitable for this list).
        """
        if isinstance(container_name_or_idx, int):
            container_names = self.list_container_names(as_sorted_relative_paths=True)
            container_name = container_names[
                container_name_or_idx
            ]  # Will break if idx is out of bounds
        else:
            assert isinstance(container_name_or_idx, str), repr(container_name_or_idx)
            container_name = container_name_or_idx

        assert not os.path.isabs(container_name), container_name

        container_filepath = os.path.join(self._output_dir, container_name)
        container = load_from_json_file(container_filepath)

        return self._decrypt_data_from_container(container)
