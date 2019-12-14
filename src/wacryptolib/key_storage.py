import logging
import os
import random
import threading
import uuid
from abc import ABC, abstractmethod
from pathlib import Path

from wacryptolib.utilities import synchronized

logger = logging.getLogger(__name__)


class KeyStorageBase(ABC):
    """
    Subclasses of this storage interface can be implemented to store/retrieve keys from
    miscellaneous locations (disk, database...), without permission checks.
    """

    # TODO use exceptions in case of key not found or unauthorized, instead of "None"!

    @abstractmethod
    def set_keys(
        self,
        *,
        keychain_uid: uuid.UUID,
        key_type: str,
        public_key: bytes,
        private_key: bytes,
    ):  # pragma: no cover
        """
        Store a pair of asymmetric keys into storage, attached to a specific UUID.

        Must raise an exception if a key pair already exists for these uid/type identifiers.

        :param keychain_uid: unique ID of the keychain
        :param key_type: one of SUPPORTED_ASYMMETRIC_KEY_TYPES
        :param public_key: public key in clear PEM format
        :param private_key: private key in PEM format (potentially encrypted)
        """
        raise NotImplementedError("KeyStorageBase.set_keys()")

    @abstractmethod
    def get_public_key(
        self, *, keychain_uid: uuid.UUID, key_type: str
    ) -> bytes:  # pragma: no cover
        """
        Fetch a public key from persistent storage.

        :param keychain_uid: unique ID of the keychain
        :param key_type: one of SUPPORTED_ASYMMETRIC_KEY_TYPES

        :return: clearpublic key in clear PEM format, or None if unexisting.
        """
        raise NotImplementedError("KeyStorageBase.get_public_key()")

    @abstractmethod
    def get_private_key(
        self, *, keychain_uid: uuid.UUID, key_type: str
    ) -> bytes:  # pragma: no cover
        """
        Fetch a private key from persistent storage.

        :param keychain_uid: unique ID of the keychain
        :param key_type: one of SUPPORTED_ASYMMETRIC_KEY_TYPES

        :return: private key in PEM format (potentially encrypted), or None if unexisting.
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
    def add_free_keypair(
        self, *, key_type: str, public_key: bytes, private_key: bytes
    ):  # pragma: no cover
        """
        Store a pair of asymmetric keys into storage, free for subsequent attachment to an UUID.

        :param key_type: one of SUPPORTED_ASYMMETRIC_KEY_TYPES
        :param public_key: public key in clear PEM format
        :param private_key: private key in PEM format (potentially encrypted)
        """
        raise NotImplementedError("KeyStorageBase.add_free_keypair()")

    @abstractmethod
    def attach_free_keypair_to_uuid(
        self, *, keychain_uid: uuid.UUID, key_type: str
    ):  # pragma: no cover
        """
        Fetch one of the free keypairs of storage of type `key_type`, and attach it to UUID `keychain_uid`.

        If no free keypair is available, a RuntimeError is raised.

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
        self._cached_keypairs = (
            {}
        )  # Maps (keychain_uid, key_type) to dicts of public_key/private_key
        self._free_keypairs = (
            {}
        )  # Maps key types to lists of dicts of public_key/private_key

    def _get_keypair(self, *, keychain_uid, key_type):
        return self._cached_keypairs.get((keychain_uid, key_type))

    def _set_keypair(self, *, keychain_uid, key_type, keypair):
        assert isinstance(keypair, dict), keypair
        self._cached_keypairs[(keychain_uid, key_type)] = keypair

    def _check_keypair_does_not_exist(self, keychain_uid, key_type):
        if self._get_keypair(keychain_uid=keychain_uid, key_type=key_type):
            raise RuntimeError(
                "Already existing dummy keypair %s/%s" % (keychain_uid, key_type)
            )

    def set_keys(self, *, keychain_uid, key_type, public_key, private_key):
        self._check_keypair_does_not_exist(keychain_uid=keychain_uid, key_type=key_type)
        self._set_keypair(
            keychain_uid=keychain_uid,
            key_type=key_type,
            keypair=dict(public_key=public_key, private_key=private_key),
        )

    def get_public_key(self, *, keychain_uid, key_type):
        keypair = self._get_keypair(keychain_uid=keychain_uid, key_type=key_type)
        return keypair["public_key"] if keypair else None

    def get_private_key(self, *, keychain_uid, key_type):
        keypair = self._get_keypair(keychain_uid=keychain_uid, key_type=key_type)
        return keypair["private_key"] if keypair else None

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
            raise RuntimeError(
                "No free keypair of type %s available in dummy storage" % key_type
            )
        else:
            self._set_keypair(
                keychain_uid=keychain_uid, key_type=key_type, keypair=keypair
            )


class FilesystemKeyStorage(KeyStorageBase):
    """
    Filesystem-based key storage for use in tests, where keys are kepts only instance-locally.

    Protected by a process-wide lock, but not safe to use in multiprocessing environment, or in a process which can be brutally shutdown.
    To prevent corruption, one should only persistent UUIDs when the key storage operation is successfully finished.

    Beware, public and private keys (free or not) are stored side by side, if one of these is deleted, the resulting behaviour is undefined (but buggy).
    """

    _lock = threading.Lock()

    _free_private_key_suffix = "_private_key.pem"
    _free_public_key_suffix = "_public_key.pem"
    _randint_args = (10 ** 10, 10 ** 11 - 1)

    def __init__(self, keys_dir):
        keys_dir = Path(keys_dir)
        assert keys_dir.is_dir(), keys_dir
        keys_dir = keys_dir.absolute()
        self._keys_dir = keys_dir

        free_keys_dir = keys_dir.joinpath("free_keys")
        free_keys_dir.mkdir(exist_ok=True)
        self._free_keys_dir = free_keys_dir

    def _get_filename(self, keychain_uid, key_type, is_public: bool):
        return "%s_%s_%s.pem" % (
            keychain_uid,
            key_type,
            "public_key" if is_public else "private_key",
        )

    def _write_to_storage_file(self, basename: str, data: bytes):
        assert os.sep not in basename, basename
        self._keys_dir.joinpath(basename).write_bytes(data)

    def _read_from_storage_file(self, basename: str):
        assert os.sep not in basename, basename
        try:
            return self._keys_dir.joinpath(basename).read_bytes()
        except FileNotFoundError:
            return None

    def _check_keypair_does_not_exist(self, keychain_uid, key_type):
        # We use PRIVATE key as marker of existence
        target_private_key_filename = self._get_filename(
            keychain_uid, key_type=key_type, is_public=False
        )
        if self._keys_dir.joinpath(target_private_key_filename).exists():
            raise RuntimeError(
                "Already existing filesystem keypair %s/%s" % (keychain_uid, key_type)
            )

    @synchronized
    def set_keys(self, *, keychain_uid, key_type, public_key, private_key):
        target_public_key_filename = self._get_filename(
            keychain_uid, key_type=key_type, is_public=True
        )
        target_private_key_filename = self._get_filename(
            keychain_uid, key_type=key_type, is_public=False
        )

        self._check_keypair_does_not_exist(keychain_uid=keychain_uid, key_type=key_type)

        # We override (unexpected) already existing files
        self._write_to_storage_file(
            basename=target_public_key_filename, data=public_key
        )
        self._write_to_storage_file(
            basename=target_private_key_filename, data=private_key
        )

    @synchronized
    def get_public_key(self, *, keychain_uid, key_type):
        filename_public_key = self._get_filename(
            keychain_uid, key_type=key_type, is_public=True
        )
        return self._read_from_storage_file(basename=filename_public_key)

    @synchronized
    def get_private_key(self, *, keychain_uid, key_type):
        filename_private_key = self._get_filename(
            keychain_uid, key_type=key_type, is_public=False
        )
        return self._read_from_storage_file(basename=filename_private_key)

    # No need for lock here
    def get_free_keypairs_count(self, key_type):
        subdir = self._free_keys_dir.joinpath(key_type)
        if not subdir.is_dir():
            return 0
        return len(list(subdir.glob("*" + self._free_private_key_suffix)))

    @synchronized
    def add_free_keypair(self, *, key_type: str, public_key: bytes, private_key: bytes):
        subdir = self._free_keys_dir.joinpath(key_type)
        subdir.mkdir(exist_ok=True)

        random_name = str(random.randint(*self._randint_args))

        # If these free keys already exist, we overwrite them, it's OK
        # We first write the public key, since the private one identifies the presence of a full free key
        # Two-steps writing is used for increased atomicity

        subdir.joinpath(
            random_name + self._free_public_key_suffix + ".temp"
        ).write_bytes(public_key)
        subdir.joinpath(
            random_name + self._free_private_key_suffix + ".temp"
        ).write_bytes(private_key)

        subdir.joinpath(random_name + self._free_public_key_suffix + ".temp").replace(
            subdir.joinpath(random_name + self._free_public_key_suffix)
        )
        subdir.joinpath(random_name + self._free_private_key_suffix + ".temp").replace(
            subdir.joinpath(random_name + self._free_private_key_suffix)
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
        globber = subdir.glob("*" + self._free_private_key_suffix)
        try:
            free_private_key = next(globber)
        except StopIteration:
            raise RuntimeError(
                "No free keypair of type %s available in filesystem storage" % key_type
            )
        _free_public_key_name = free_private_key.name.replace(
            self._free_private_key_suffix, self._free_public_key_suffix
        )
        free_public_key = subdir.joinpath(_free_public_key_name)

        # First move the private key, so that it's not shown anymore as "free"
        free_private_key.replace(target_private_key_filename)
        free_public_key.replace(target_public_key_filename)
