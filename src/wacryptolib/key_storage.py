import logging
import os
import random
import re
import threading
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from os.path import join
import glob

from wacryptolib.exceptions import KeyAlreadyExists, KeyDoesNotExist, KeyStorageDoesNotExist, KeyStorageAlreadyExists
from wacryptolib.utilities import synchronized, load_from_json_file, get_metadata_file_path, safe_copy_directory

logger = logging.getLogger(__name__)


class KeyStorageBase(ABC):
    """
    Subclasses of this storage interface can be implemented to store/retrieve keys from
    miscellaneous locations (disk, database...), without permission checks.

    By construction for now, a keypair exists entirely or not at all - public and private keys
    can't exist independently.
    """

    @abstractmethod
    def set_keys(
        self, *, keychain_uid: uuid.UUID, key_type: str, public_key: bytes, private_key: bytes
    ) -> None:  # pragma: no cover
        """
        Store a pair of asymmetric keys into storage, attached to a specific UUID.

        Must raise a KeyAlreadyExists exception if a keypair already exists for these uid/type identifiers.

        :param keychain_uid: unique ID of the keychain
        :param key_type: one of SUPPORTED_ASYMMETRIC_KEY_TYPES
        :param public_key: public key in clear PEM format
        :param private_key: private key in PEM format (potentially encrypted)
        """
        raise NotImplementedError("KeyStorageBase.set_keys()")

    @abstractmethod
    def get_public_key(self, *, keychain_uid: uuid.UUID, key_type: str) -> bytes:  # pragma: no cover
        """
        Fetch a public key from persistent storage.

        :param keychain_uid: unique ID of the keychain
        :param key_type: one of SUPPORTED_ASYMMETRIC_KEY_TYPES

        :return: public key in clear PEM format, or raise KeyDoesNotExist
        """
        raise NotImplementedError("KeyStorageBase.get_public_key()")

    @abstractmethod
    def get_private_key(self, *, keychain_uid: uuid.UUID, key_type: str) -> bytes:  # pragma: no cover
        """
        Fetch a private key from persistent storage.

        :param keychain_uid: unique ID of the keychain
        :param key_type: one of SUPPORTED_ASYMMETRIC_KEY_TYPES

        :return: private key in PEM format (potentially encrypted), or raise KeyDoesNotExist
        """
        raise NotImplementedError("KeyStorageBase.get_private_key()")

    @abstractmethod
    def get_free_keypairs_count(self, key_type: str) -> int:  # pragma: no cover
        """
        Calculate the count of keypairs of type `key_type` which are free for subsequent attachment to an UUID.

        :param key_type: one of SUPPORTED_ASYMMETRIC_KEY_TYPES
        :return: count of free keypairs of said type
        """
        raise NotImplementedError("KeyStorageBase.get_free_keypairs_count()")

    @abstractmethod
    def add_free_keypair(self, *, key_type: str, public_key: bytes, private_key: bytes):  # pragma: no cover
        """
        Store a pair of asymmetric keys into storage, free for subsequent attachment to an UUID.

        :param key_type: one of SUPPORTED_ASYMMETRIC_KEY_TYPES
        :param public_key: public key in clear PEM format
        :param private_key: private key in PEM format (potentially encrypted)
        """
        raise NotImplementedError("KeyStorageBase.add_free_keypair()")

    @abstractmethod
    def attach_free_keypair_to_uuid(self, *, keychain_uid: uuid.UUID, key_type: str):  # pragma: no cover
        """
        Fetch one of the free keypairs of storage of type `key_type`, and attach it to UUID `keychain_uid`.

        If no free keypair is available, a KeyDoesNotExist is raised.

        :param keychain_uid: unique ID of the keychain
        :param key_type: one of SUPPORTED_ASYMMETRIC_KEY_TYPES
        :return: public key of the keypair, in clear PEM format
        """
        raise NotImplementedError("KeyStorageBase.attach_free_keypair_to_uuid()")


class DummyKeyStorage(KeyStorageBase):
    """
    Dummy key storage for use in tests, where keys are kepts only process-locally.

    NOT MEANT TO BE THREAD-SAFE
    """

    def __init__(self):
        self._cached_keypairs = {}  # Maps (keychain_uid, key_type) to dicts of public_key/private_key
        self._free_keypairs = {}  # Maps key types to lists of dicts of public_key/private_key

    def _get_keypair_or_none(self, *, keychain_uid, key_type):
        return self._cached_keypairs.get((keychain_uid, key_type))

    def _get_keypair_or_raise(self, *, keychain_uid, key_type):
        keypair = self._get_keypair_or_none(keychain_uid=keychain_uid, key_type=key_type)
        if keypair:
            return keypair
        raise KeyDoesNotExist("Dummy keypair %s/%s not found" % (keychain_uid, key_type))

    def _set_keypair(self, *, keychain_uid, key_type, keypair):
        assert isinstance(keypair, dict), keypair
        self._cached_keypairs[(keychain_uid, key_type)] = keypair

    def _check_keypair_does_not_exist(self, keychain_uid, key_type):
        if self._get_keypair_or_none(keychain_uid=keychain_uid, key_type=key_type):
            raise KeyAlreadyExists("Already existing dummy keypair %s/%s" % (keychain_uid, key_type))

    def set_keys(self, *, keychain_uid, key_type, public_key, private_key):
        self._check_keypair_does_not_exist(keychain_uid=keychain_uid, key_type=key_type)
        self._set_keypair(
            keychain_uid=keychain_uid, key_type=key_type, keypair=dict(public_key=public_key, private_key=private_key)
        )

    def get_public_key(self, *, keychain_uid, key_type):
        keypair = self._get_keypair_or_raise(keychain_uid=keychain_uid, key_type=key_type)
        return keypair["public_key"]

    def get_private_key(self, *, keychain_uid, key_type):
        keypair = self._get_keypair_or_raise(keychain_uid=keychain_uid, key_type=key_type)
        return keypair["private_key"]

    def get_free_keypairs_count(self, key_type):
        return len(self._free_keypairs.get(key_type, []))

    def add_free_keypair(self, *, key_type: str, public_key: bytes, private_key: bytes):
        keypair = dict(public_key=public_key, private_key=private_key)
        sublist = self._free_keypairs.setdefault(key_type, [])
        sublist.append(keypair)

    def attach_free_keypair_to_uuid(self, *, keychain_uid: uuid.UUID, key_type: str):
        self._check_keypair_does_not_exist(keychain_uid=keychain_uid, key_type=key_type)
        try:
            sublist = self._free_keypairs[key_type]
            keypair = sublist.pop()
        except LookupError:
            raise KeyDoesNotExist("No free keypair of type %s available in dummy storage" % key_type)
        else:
            self._set_keypair(keychain_uid=keychain_uid, key_type=key_type, keypair=keypair)

    # def __TODO_later_list_keypair_identifiers(self):
    #    keypair_identifiers = []
    #    for keypair_identifier in keypair_identifiers:
    #        pass


class FilesystemKeyStorage(KeyStorageBase):
    """
    Filesystem-based key storage for use in tests, where keys are kepts only instance-locally.

    Protected by a process-wide lock, but not safe to use in multiprocessing environment, or in a process which can be brutally shutdown.
    To prevent corruption, one should only persistent UUIDs when the key storage operation is successfully finished.

    Beware, public and private keys (free or not) are stored side by side, if one of these is deleted, the resulting behaviour is undefined (but buggy).
    """

    _lock = threading.Lock()

    _private_key_suffix = "_private_key.pem"
    _public_key_suffix = "_public_key.pem"
    _randint_args = (10 ** 10, 10 ** 11 - 1)

    PUBLIC_KEY_FILENAME_REGEX = r"^(?P<keychain_uid>[-0-9a-z]+)_(?P<key_type>[_A-Z]+)%s$" % _public_key_suffix

    def __init__(self, keys_dir: Path):
        keys_dir = Path(keys_dir)
        assert keys_dir.is_dir(), keys_dir
        self._keys_dir = keys_dir.absolute()

        free_keys_dir = keys_dir.joinpath("free_keys")
        free_keys_dir.mkdir(
            exist_ok=True
        )  # FIXMe - lazy-initialize this dir, instead? (useless e.g. on authentication devices)
        self._free_keys_dir = free_keys_dir

    def _get_filename(self, keychain_uid, key_type, is_public: bool):
        return "%s_%s%s" % (keychain_uid, key_type, self._public_key_suffix if is_public else self._private_key_suffix)

    def _write_to_storage_file(self, basename: str, data: bytes):
        assert os.sep not in basename, basename
        self._keys_dir.joinpath(basename).write_bytes(data)

    def _read_from_storage_file(self, basename: str):
        assert os.sep not in basename, basename
        return self._keys_dir.joinpath(basename).read_bytes()

    def _check_keypair_does_not_exist(self, keychain_uid, key_type):
        # We use PRIVATE key as marker of existence
        target_private_key_filename = self._get_filename(keychain_uid, key_type=key_type, is_public=False)
        if self._keys_dir.joinpath(target_private_key_filename).exists():
            raise KeyAlreadyExists("Already existing filesystem keypair %s/%s" % (keychain_uid, key_type))

    @synchronized
    def set_keys(self, *, keychain_uid, key_type, public_key: bytes, private_key: bytes):
        target_public_key_filename = self._get_filename(keychain_uid, key_type=key_type, is_public=True)
        target_private_key_filename = self._get_filename(keychain_uid, key_type=key_type, is_public=False)

        self._check_keypair_does_not_exist(keychain_uid=keychain_uid, key_type=key_type)

        # We override (unexpected) already existing files

        self._write_to_storage_file(basename=target_public_key_filename, data=public_key)
        self._write_to_storage_file(basename=target_private_key_filename, data=private_key)

    @synchronized
    def get_public_key(self, *, keychain_uid: uuid.UUID, key_type: str) -> bytes:
        filename_public_key = self._get_filename(keychain_uid, key_type=key_type, is_public=True)
        try:
            return self._read_from_storage_file(basename=filename_public_key)
        except FileNotFoundError:
            raise KeyDoesNotExist("Public filesystem key %s/%s not found" % (keychain_uid, key_type))

    @synchronized
    def get_private_key(self, *, keychain_uid: uuid.UUID, key_type: str) -> bytes:
        filename_private_key = self._get_filename(keychain_uid, key_type=key_type, is_public=False)
        try:
            return self._read_from_storage_file(basename=filename_private_key)
        except FileNotFoundError:
            raise KeyDoesNotExist("Private filesystem key %s/%s not found" % (keychain_uid, key_type))

    # No need for lock here
    def get_free_keypairs_count(self, key_type: str):
        subdir = self._free_keys_dir.joinpath(key_type)
        if not subdir.is_dir():
            return 0
        return len(list(subdir.glob("*" + self._private_key_suffix)))

    @synchronized
    def add_free_keypair(self, *, key_type: str, public_key: bytes, private_key: bytes):
        subdir = self._free_keys_dir.joinpath(key_type)
        subdir.mkdir(exist_ok=True)

        random_name = str(random.randint(*self._randint_args))

        # If these free keys already exist, we overwrite them, it's OK
        # We first write the public key, since the private one identifies the presence of a full free key
        # Two-steps writing is used for increased atomicity

        subdir.joinpath(random_name + self._public_key_suffix + ".temp").write_bytes(public_key)
        subdir.joinpath(random_name + self._private_key_suffix + ".temp").write_bytes(private_key)

        subdir.joinpath(random_name + self._public_key_suffix + ".temp").replace(
            subdir.joinpath(random_name + self._public_key_suffix)
        )
        subdir.joinpath(random_name + self._private_key_suffix + ".temp").replace(
            subdir.joinpath(random_name + self._private_key_suffix)
        )

    @synchronized
    def attach_free_keypair_to_uuid(self, *, keychain_uid: uuid.UUID, key_type: str):
        self._check_keypair_does_not_exist(keychain_uid=keychain_uid, key_type=key_type)

        target_public_key_filename = self._keys_dir.joinpath(
            self._get_filename(keychain_uid, key_type=key_type, is_public=True)
        )
        target_private_key_filename = self._keys_dir.joinpath(
            self._get_filename(keychain_uid, key_type=key_type, is_public=False)
        )

        subdir = self._free_keys_dir.joinpath(key_type)
        globber = subdir.glob("*" + self._private_key_suffix)
        try:
            free_private_key = next(globber)
        except StopIteration:
            raise KeyDoesNotExist("No free keypair of type %s available in filesystem storage" % key_type)
        _free_public_key_name = free_private_key.name.replace(self._private_key_suffix, self._public_key_suffix)
        free_public_key = subdir.joinpath(_free_public_key_name)

        # First move the private key, so that it's not shown anymore as "free"
        free_private_key.replace(target_private_key_filename)
        free_public_key.replace(target_public_key_filename)

    def list_keypair_identifiers(self):
        """
        List metadata of public keys present in the storage, along with their potential private key existence.
        
        Returns a SORTED list of key information dicts with standard fields "keychain_uid" and "key_type", as well as
        a boolean "private_key_present" which is True if the related private key exists in storage.
        Sorting is done by keychain_uid and then key_type.
        """

        key_information_list = []

        public_key_pem_paths = glob.glob(join(self._keys_dir, "*" + self._public_key_suffix))

        for public_key_pem_path in public_key_pem_paths:

            public_key_pem_filename = os.path.basename(public_key_pem_path)

            match = re.match(self.PUBLIC_KEY_FILENAME_REGEX, public_key_pem_filename)

            if not match:
                logger.warning(
                    "Skipping abnormally named PEM file %r when listing public keys", public_key_pem_filename
                )
                continue

            # print("MATCH FOUND", public_key_pem_filename, match.groups(), self.PUBLIC_KEY_FILENAME_REGEX)

            keychain_uid_str = match.group("keychain_uid")
            key_type = match.group("key_type")

            try:
                keychain_uid = uuid.UUID(keychain_uid_str)
            except ValueError:
                logger.warning(
                    "Skipping PEM file with abnormal UUID %r when listing public keys", public_key_pem_filename
                )
                continue

            private_key_pem_filename = public_key_pem_filename.replace(
                self._public_key_suffix, self._private_key_suffix
            )
            private_key_present = os.path.exists(join(self._keys_dir, private_key_pem_filename))

            key_information = dict(
                keychain_uid=keychain_uid, key_type=key_type, private_key_present=private_key_present
            )
            key_information_list.append(key_information)

        key_information_list.sort(key=lambda x: (x["keychain_uid"], x["key_type"]))
        return key_information_list


class KeyStoragePoolBase:
    # FIXME fill base class with signatures!! Like in KeyStorageBase!
    pass


class DummyKeyStoragePool(KeyStoragePoolBase):
    """
    Dummy key storage pool for use in tests, where keys are kepts only process-locally.

    NOT MEANT TO BE THREAD-SAFE
    """

    def __init__(self):
        self._local_key_storage = DummyKeyStorage()
        self._imported_key_storages = {}

    def get_local_key_storage(self):
        return self._local_key_storage

    def get_imported_key_storage(self, key_storage_uid):
        imported_key_storage = self._imported_key_storages.get(key_storage_uid)
        if not imported_key_storage:
            raise KeyStorageDoesNotExist("Key storage %s not found" % key_storage_uid)
        return imported_key_storage

    def list_imported_key_storage_uids(self):
        return list(self._imported_key_storages.keys())

    def _register_fake_imported_storage_uids(self, storage_uids: list):
        """Test-specific API"""
        assert not (set(storage_uids) & set(self._imported_key_storages.keys()))
        new_storages = {storage_uid: DummyKeyStorage() for storage_uid in storage_uids}
        self._imported_key_storages.update(new_storages)


class FilesystemKeyStoragePool(KeyStoragePoolBase):
    """This class handles a set of locally stored key storages.

    The local storage represents the current device/owner, and is expected to be used by read-write escrows,
    whereas imported key storages are supposed to be readonly, and only filled with keypairs imported from key-devices.
    """

    LOCAL_STORAGE_DIRNAME = "local_key_storage"
    IMPORTED_STORAGES_DIRNAME = "imported_key_storages"
    IMPORTED_STORAGE_PREFIX = "key_storage_"

    def __init__(self, root_dir):
        root_dir = Path(root_dir)
        assert root_dir.is_dir(), root_dir
        self._root_dir = root_dir.absolute()

    def get_local_key_storage(self):
        """Storage automatically created if unexisting."""
        local_key_storage_path = self._root_dir.joinpath(self.LOCAL_STORAGE_DIRNAME)
        local_key_storage_path.mkdir(exist_ok=True)
        # TODO initialize metadata for key_storage ??
        return FilesystemKeyStorage(local_key_storage_path)

    def _get_imported_key_storage_path(self, key_storage_uid):
        imported_key_storage_path = self._root_dir.joinpath(
            self.IMPORTED_STORAGES_DIRNAME, "%s%s" % (self.IMPORTED_STORAGE_PREFIX, key_storage_uid)
        )
        return imported_key_storage_path

    def get_imported_key_storage(self, key_storage_uid):
        """The selected storage MUST exist, else a KeyStorageDoesNotExist is raised."""
        imported_key_storage_path = self._get_imported_key_storage_path(key_storage_uid=key_storage_uid)
        if not imported_key_storage_path.exists():
            raise KeyStorageDoesNotExist("Key storage %s not found" % key_storage_uid)
        return FilesystemKeyStorage(imported_key_storage_path)

    def list_imported_key_storage_uids(self):  # FIXME setup signature
        """Return a sorted list of UUIDs of key storages, corresponding
        to the device_uid of their origin authentication devices."""
        imported_key_storages_dir = self._root_dir.joinpath(self.IMPORTED_STORAGES_DIRNAME)
        paths = imported_key_storages_dir.glob("%s*" % self.IMPORTED_STORAGE_PREFIX)  # This excludes TEMP folders
        return sorted([uuid.UUID(d.name.replace(self.IMPORTED_STORAGE_PREFIX, "")) for d in paths])

    def list_imported_key_storage_metadata(self) -> dict:  # FIXME doesn't return a list??
        """Return a dict mapping key storage UUIDs to the dicts of their metadata.

        Raises if any metadata loading fails.
        """
        key_storage_uids = self.list_imported_key_storage_uids()

        metadata_mapper = {}
        for key_storage_uid in key_storage_uids:
            _key_storage_path = self._get_imported_key_storage_path(key_storage_uid=key_storage_uid)
            metadata = load_from_json_file(get_metadata_file_path(_key_storage_path))  # TODO Factorize this ?
            metadata_mapper[key_storage_uid] = metadata

        return metadata_mapper

    def import_key_storage_from_folder(self, key_storage_path: Path):
        """
        Create a local import of a remote key storage folder (which must have a proper metadata file).

        Raises KeyStorageAlreadyExists if this key storage was already imported.
        """
        assert key_storage_path.exists(), key_storage_path

        metadata = load_from_json_file(get_metadata_file_path(key_storage_path))
        key_storage_uid = metadata["device_uid"]  # Fails badly if metadata file is corrupted

        if key_storage_uid in self.list_imported_key_storage_uids():
            raise KeyStorageAlreadyExists("Key storage with UUID %s was already imported locally" % key_storage_uid)

        imported_key_storage_path = self._get_imported_key_storage_path(key_storage_uid=key_storage_uid)
        safe_copy_directory(key_storage_path, imported_key_storage_path)  # Must not fail, due to previous checks
        assert imported_key_storage_path.exists()
