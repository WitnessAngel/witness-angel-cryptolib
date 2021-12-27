from collections.abc import Sequence

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

from wacryptolib.exceptions import KeyAlreadyExists, KeyDoesNotExist, KeystoreDoesNotExist, KeystoreAlreadyExists
from wacryptolib.utilities import synchronized, load_from_json_file, get_metadata_file_path, safe_copy_directory

logger = logging.getLogger(__name__)


class KeystoreBase(ABC):
    """
    Subclasses of this storage interface can be implemented to store/retrieve keys from
    miscellaneous locations (disk, database...), without permission checks.

    By construction for now, a keypair exists entirely or not at all - public and private keys
    can't exist independently.
    """

    @abstractmethod
    def set_keys(
        self, *, keychain_uid: uuid.UUID, key_algo: str, public_key: bytes, private_key: bytes
    ) -> None:  # pragma: no cover
        """
        Store a pair of asymmetric keys into storage, attached to a specific UUID.

        Must raise a KeyAlreadyExists exception if a keypair already exists for these uid/type identifiers.

        :param keychain_uid: unique ID of the keychain
        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS
        :param public_key: public key in clear PEM format
        :param private_key: private key in PEM format (potentially encrypted)
        """
        raise NotImplementedError("KeystoreBase.set_keys()")

    @abstractmethod
    def get_public_key(self, *, keychain_uid: uuid.UUID, key_algo: str) -> bytes:  # pragma: no cover
        """
        Fetch a public key from persistent storage.

        :param keychain_uid: unique ID of the keychain
        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS

        :return: public key in clear PEM format, or raise KeyDoesNotExist
        """
        raise NotImplementedError("KeystoreBase.get_public_key()")

    @abstractmethod
    def get_private_key(self, *, keychain_uid: uuid.UUID, key_algo: str) -> bytes:  # pragma: no cover
        """
        Fetch a private key from persistent storage.

        :param keychain_uid: unique ID of the keychain
        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS

        :return: private key in PEM format (potentially encrypted), or raise KeyDoesNotExist
        """
        raise NotImplementedError("KeystoreBase.get_private_key()")

    @abstractmethod
    def get_free_keypairs_count(self, key_algo: str) -> int:  # pragma: no cover
        """
        Calculate the count of keypairs of type `key_algo` which are free for subsequent attachment to an UUID.

        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS
        :return: count of free keypairs of said type
        """
        raise NotImplementedError("KeystoreBase.get_free_keypairs_count()")

    @abstractmethod
    def add_free_keypair(self, *, key_algo: str, public_key: bytes, private_key: bytes):  # pragma: no cover
        """
        Store a pair of asymmetric keys into storage, free for subsequent attachment to an UUID.

        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS
        :param public_key: public key in clear PEM format
        :param private_key: private key in PEM format (potentially encrypted)
        """
        raise NotImplementedError("KeystoreBase.add_free_keypair()")

    @abstractmethod
    def attach_free_keypair_to_uuid(self, *, keychain_uid: uuid.UUID, key_algo: str):  # pragma: no cover
        """
        Fetch one of the free keypairs of storage of type `key_algo`, and attach it to UUID `keychain_uid`.

        If no free keypair is available, a KeyDoesNotExist is raised.

        :param keychain_uid: unique ID of the keychain
        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS
        :return: public key of the keypair, in clear PEM format
        """
        raise NotImplementedError("KeystoreBase.attach_free_keypair_to_uuid()")


class DummyKeystore(KeystoreBase):
    """
    Dummy key storage for use in tests, where keys are kepts only process-locally.

    NOT MEANT TO BE THREAD-SAFE
    """

    def __init__(self):
        self._cached_keypairs = {}  # Maps (keychain_uid, key_algo) to dicts of public_key/private_key
        self._free_keypairs = {}  # Maps key types to lists of dicts of public_key/private_key

    def _get_keypair_or_none(self, *, keychain_uid, key_algo):
        return self._cached_keypairs.get((keychain_uid, key_algo))

    def _get_keypair_or_raise(self, *, keychain_uid, key_algo):
        keypair = self._get_keypair_or_none(keychain_uid=keychain_uid, key_algo=key_algo)
        if keypair:
            return keypair
        raise KeyDoesNotExist("Dummy keypair %s/%s not found" % (keychain_uid, key_algo))

    def _set_keypair(self, *, keychain_uid, key_algo, keypair):
        assert isinstance(keypair, dict), keypair
        self._cached_keypairs[(keychain_uid, key_algo)] = keypair

    def _check_keypair_does_not_exist(self, keychain_uid, key_algo):
        if self._get_keypair_or_none(keychain_uid=keychain_uid, key_algo=key_algo):
            raise KeyAlreadyExists("Already existing dummy keypair %s/%s" % (keychain_uid, key_algo))

    def set_keys(self, *, keychain_uid, key_algo, public_key, private_key):
        self._check_keypair_does_not_exist(keychain_uid=keychain_uid, key_algo=key_algo)
        self._set_keypair(
            keychain_uid=keychain_uid, key_algo=key_algo, keypair=dict(public_key=public_key, private_key=private_key)
        )

    def get_public_key(self, *, keychain_uid, key_algo):
        keypair = self._get_keypair_or_raise(keychain_uid=keychain_uid, key_algo=key_algo)
        return keypair["public_key"]

    def get_private_key(self, *, keychain_uid, key_algo):
        keypair = self._get_keypair_or_raise(keychain_uid=keychain_uid, key_algo=key_algo)
        return keypair["private_key"]

    def get_free_keypairs_count(self, key_algo):
        return len(self._free_keypairs.get(key_algo, []))

    def add_free_keypair(self, *, key_algo: str, public_key: bytes, private_key: bytes):
        keypair = dict(public_key=public_key, private_key=private_key)
        sublist = self._free_keypairs.setdefault(key_algo, [])
        sublist.append(keypair)

    def attach_free_keypair_to_uuid(self, *, keychain_uid: uuid.UUID, key_algo: str):
        self._check_keypair_does_not_exist(keychain_uid=keychain_uid, key_algo=key_algo)
        try:
            sublist = self._free_keypairs[key_algo]
            keypair = sublist.pop()
        except LookupError:
            raise KeyDoesNotExist("No free keypair of type %s available in dummy storage" % key_algo)
        else:
            self._set_keypair(keychain_uid=keychain_uid, key_algo=key_algo, keypair=keypair)

    # def __TODO_later_list_keypair_identifiers(self):
    #    keypair_identifiers = []
    #    for keypair_identifier in keypair_identifiers:
    #        pass


class FilesystemKeystore(KeystoreBase):
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

    PUBLIC_KEY_FILENAME_REGEX = r"^(?P<keychain_uid>[-0-9a-z]+)_(?P<key_algo>[_A-Z]+)%s$" % _public_key_suffix

    def _ensure_free_keys_dir_exists(self):
        self._free_keys_dir.mkdir(
            exist_ok=True
        )

    def __init__(self, keys_dir: Path):
        keys_dir = Path(keys_dir)
        assert keys_dir.is_dir(), keys_dir
        self._keys_dir = keys_dir.absolute()
        self._free_keys_dir = self._keys_dir.joinpath("free_keys")  # Might not exist yet

    def _get_filename(self, keychain_uid, key_algo, is_public: bool):
        return "%s_%s%s" % (keychain_uid, key_algo, self._public_key_suffix if is_public else self._private_key_suffix)

    def _write_to_storage_file(self, basename: str, data: bytes):
        assert os.sep not in basename, basename
        self._keys_dir.joinpath(basename).write_bytes(data)

    def _read_from_storage_file(self, basename: str):
        assert os.sep not in basename, basename
        return self._keys_dir.joinpath(basename).read_bytes()

    def _check_keypair_does_not_exist(self, keychain_uid, key_algo):
        # We use PRIVATE key as marker of existence
        target_private_key_filename = self._get_filename(keychain_uid, key_algo=key_algo, is_public=False)
        if self._keys_dir.joinpath(target_private_key_filename).exists():
            raise KeyAlreadyExists("Already existing filesystem keypair %s/%s" % (keychain_uid, key_algo))

    @synchronized
    def set_keys(self, *, keychain_uid, key_algo, public_key: bytes, private_key: bytes):
        target_public_key_filename = self._get_filename(keychain_uid, key_algo=key_algo, is_public=True)
        target_private_key_filename = self._get_filename(keychain_uid, key_algo=key_algo, is_public=False)

        self._check_keypair_does_not_exist(keychain_uid=keychain_uid, key_algo=key_algo)

        # We override (unexpected) already existing files

        self._write_to_storage_file(basename=target_public_key_filename, data=public_key)
        self._write_to_storage_file(basename=target_private_key_filename, data=private_key)

    @synchronized
    def get_public_key(self, *, keychain_uid: uuid.UUID, key_algo: str) -> bytes:
        filename_public_key = self._get_filename(keychain_uid, key_algo=key_algo, is_public=True)
        try:
            return self._read_from_storage_file(basename=filename_public_key)
        except FileNotFoundError:
            raise KeyDoesNotExist("Public filesystem key %s/%s not found" % (keychain_uid, key_algo))

    @synchronized
    def get_private_key(self, *, keychain_uid: uuid.UUID, key_algo: str) -> bytes:
        filename_private_key = self._get_filename(keychain_uid, key_algo=key_algo, is_public=False)
        try:
            return self._read_from_storage_file(basename=filename_private_key)
        except FileNotFoundError:
            raise KeyDoesNotExist("Private filesystem key %s/%s not found" % (keychain_uid, key_algo))

    # No need for lock here
    def get_free_keypairs_count(self, key_algo: str):
        subdir = self._free_keys_dir.joinpath(key_algo)  # Might not exist yet
        if not subdir.is_dir():
            return 0
        return len(list(subdir.glob("*" + self._private_key_suffix)))

    @synchronized
    def add_free_keypair(self, *, key_algo: str, public_key: bytes, private_key: bytes):
        self._ensure_free_keys_dir_exists()
        subdir = self._free_keys_dir.joinpath(key_algo)
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
    def attach_free_keypair_to_uuid(self, *, keychain_uid: uuid.UUID, key_algo: str):
        self._check_keypair_does_not_exist(keychain_uid=keychain_uid, key_algo=key_algo)

        target_public_key_filename = self._keys_dir.joinpath(
            self._get_filename(keychain_uid, key_algo=key_algo, is_public=True)
        )
        target_private_key_filename = self._keys_dir.joinpath(
            self._get_filename(keychain_uid, key_algo=key_algo, is_public=False)
        )

        subdir = self._free_keys_dir.joinpath(key_algo)  # Might not exist
        globber = subdir.glob("*" + self._private_key_suffix)
        try:
            free_private_key = next(globber)
        except StopIteration:
            raise KeyDoesNotExist("No free keypair of type %s available in filesystem storage" % key_algo)
        _free_public_key_name = free_private_key.name.replace(self._private_key_suffix, self._public_key_suffix)
        free_public_key = subdir.joinpath(_free_public_key_name)

        # First move the private key, so that it's not shown anymore as "free"
        free_private_key.replace(target_private_key_filename)
        free_public_key.replace(target_public_key_filename)

    def list_keypair_identifiers(self) -> list:
        """
        List metadata of public keys present in the storage, along with their potential private key existence.
        
        Returns a SORTED list of key information dicts with standard fields "keychain_uid" and "key_algo", as well as
        a boolean "private_key_present" which is True if the related private key exists in storage.
        Sorting is done by keychain_uid and then key_algo.
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
            key_algo = match.group("key_algo")

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
                keychain_uid=keychain_uid, key_algo=key_algo, private_key_present=private_key_present
            )
            key_information_list.append(key_information)

        key_information_list.sort(key=lambda x: (x["keychain_uid"], x["key_algo"]))
        return key_information_list


class KeystorePoolBase:
    # FIXME fill base class with signatures!! Like in KeystoreBase!
    pass


class DummyKeystorePool(KeystorePoolBase):  # FIXME rename to InMemoryKeystorePool
    """
    Dummy key storage pool for use in tests, where keys are kepts only process-locally.

    NOT MEANT TO BE THREAD-SAFE
    """

    def __init__(self):
        self._local_keystore = DummyKeystore()
        self._imported_keystores = {}

    def get_local_keystore(self):
        return self._local_keystore

    def get_imported_keystore(self, keystore_uid):
        imported_keystore = self._imported_keystores.get(keystore_uid)
        if not imported_keystore:
            raise KeystoreDoesNotExist("Key storage %s not found" % keystore_uid)
        return imported_keystore

    def list_imported_keystore_uids(self):
        return list(self._imported_keystores.keys())

    def _register_fake_imported_storage_uids(self, storage_uids: Sequence):
        """Test-specific API"""
        assert not (set(storage_uids) & set(self._imported_keystores.keys()))
        new_storages = {storage_uid: DummyKeystore() for storage_uid in storage_uids}
        self._imported_keystores.update(new_storages)


class FilesystemKeystorePool(KeystorePoolBase):
    """This class handles a set of locally stored key storages.

    The local storage represents the current device/owner, and is expected to be used by read-write escrows,
    whereas imported key storages are supposed to be readonly, and only filled with keypairs imported from key-devices.
    """

    LOCAL_STORAGE_DIRNAME = "local_keystore"
    IMPORTED_STORAGES_DIRNAME = "imported_keystores"
    IMPORTED_STORAGE_PREFIX = "keystore_"

    def __init__(self, root_dir):
        root_dir = Path(root_dir)
        assert root_dir.is_dir(), root_dir
        self._root_dir = root_dir.absolute()

    def get_local_keystore(self):
        """Storage automatically created if unexisting."""
        local_keystore_path = self._root_dir.joinpath(self.LOCAL_STORAGE_DIRNAME)
        local_keystore_path.mkdir(exist_ok=True)
        # TODO initialize metadata for keystore ??
        return FilesystemKeystore(local_keystore_path)

    def _get_imported_keystore_path(self, keystore_uid):
        imported_keystore_path = self._root_dir.joinpath(
            self.IMPORTED_STORAGES_DIRNAME, "%s%s" % (self.IMPORTED_STORAGE_PREFIX, keystore_uid)
        )
        return imported_keystore_path

    def get_imported_keystore(self, keystore_uid):
        """The selected storage MUST exist, else a KeystoreDoesNotExist is raised."""
        imported_keystore_path = self._get_imported_keystore_path(keystore_uid=keystore_uid)
        if not imported_keystore_path.exists():
            raise KeystoreDoesNotExist("Key storage %s not found" % keystore_uid)
        return FilesystemKeystore(imported_keystore_path)

    def list_imported_keystore_uids(self):  # FIXME setup signature
        """Return a sorted list of UUIDs of key storages, corresponding
        to the device_uid of their origin authentication devices."""
        imported_keystores_dir = self._root_dir.joinpath(self.IMPORTED_STORAGES_DIRNAME)
        paths = imported_keystores_dir.glob("%s*" % self.IMPORTED_STORAGE_PREFIX)  # This excludes TEMP folders
        return sorted([uuid.UUID(d.name.replace(self.IMPORTED_STORAGE_PREFIX, "")) for d in paths])

    def list_imported_keystore_metadata(self) -> dict:  # FIXME doesn't return a list??
        """Return a dict mapping key storage UUIDs to the dicts of their metadata.

        Raises if any metadata loading fails.
        """
        keystore_uids = self.list_imported_keystore_uids()

        metadata_mapper = {}
        for keystore_uid in keystore_uids:
            _keystore_path = self._get_imported_keystore_path(keystore_uid=keystore_uid)
            metadata = load_from_json_file(get_metadata_file_path(_keystore_path))  # TODO Factorize this ?
            metadata_mapper[keystore_uid] = metadata

        return metadata_mapper

    def import_keystore_from_folder(self, keystore_path: Path):
        """
        Create a local import of a remote key storage folder (which must have a proper metadata file).

        Raises KeystoreAlreadyExists if this key storage was already imported.
        """
        assert keystore_path.exists(), keystore_path

        metadata = load_from_json_file(get_metadata_file_path(keystore_path))
        keystore_uid = metadata["device_uid"]  # Fails badly if metadata file is corrupted

        if keystore_uid in self.list_imported_keystore_uids():
            raise KeystoreAlreadyExists("Key storage with UUID %s was already imported locally" % keystore_uid)

        imported_keystore_path = self._get_imported_keystore_path(keystore_uid=keystore_uid)
        safe_copy_directory(keystore_path, imported_keystore_path)  # Must not fail, due to previous checks
        assert imported_keystore_path.exists()