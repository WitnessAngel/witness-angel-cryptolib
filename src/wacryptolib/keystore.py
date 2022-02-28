import glob
import logging
import os
import random
import re
import secrets
import threading
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Sequence
from os.path import join
from pathlib import Path
from typing import AnyStr, Optional
from uuid import UUID

from schema import Or, And, Optional as OptionalKey, SchemaError, Schema

from wacryptolib.cipher import SUPPORTED_CIPHER_ALGOS
from wacryptolib.exceptions import (
    KeyAlreadyExists,
    KeyDoesNotExist,
    KeystoreDoesNotExist,
    KeystoreAlreadyExists,
    SchemaValidationError,
    ValidationError,
)
from wacryptolib.keygen import generate_keypair, SUPPORTED_ASYMMETRIC_KEY_ALGOS
from wacryptolib.utilities import (
    synchronized,
    safe_copy_directory,
    load_from_json_file,
    PeriodicTaskHandler,
    generate_uuid0,
    dump_to_json_file,
)

logger = logging.getLogger(__name__)


def non_empty(value):
    return bool(value)


KEYSTORE_FORMAT = "keystore_1.0"

_KEYSTORE_METADATA_SCHEMA = {
    "keystore_type": Or("keyfactory", "authenticator"),
    "keystore_format": KEYSTORE_FORMAT,  # For forward compatibility
    "keystore_uid": UUID,
    "keystore_owner": And(str, non_empty),
    OptionalKey("keystore_secret"): str,
    OptionalKey("keystore_passphrase_hint"): And(str, non_empty),  # For authenticators
}

# FIXME add dedicated KEYSTORE_METADATA_SCHEMA for AUTHENTICATORS

KEYSTORE_METADATA_SCHEMA = Schema({**_KEYSTORE_METADATA_SCHEMA})

KEYSTORE_TREE_SCHEMA = Schema(
    {
        **_KEYSTORE_METADATA_SCHEMA,
        "keypairs": [
            {
                "keychain_uid": UUID,
                "key_algo": Or(*SUPPORTED_CIPHER_ALGOS),
                "public_key": bytes,  # MANDATORY
                "private_key": Or(None, bytes),
            }
        ],
    }
)


def validate_keystore_metadata(keystore_metadata):
    try:
        KEYSTORE_METADATA_SCHEMA.validate(keystore_metadata)
    except SchemaError as exc:
        raise SchemaValidationError("Error validating data tree with python-schema: {}".format(exc)) from exc


def validate_keystore_tree(
    authenticator
):  # FIXME setup utility validate_with_python_schema() to handle exceptions always
    try:
        KEYSTORE_TREE_SCHEMA.validate(authenticator)
    except SchemaError as exc:
        raise SchemaValidationError("Error validating data tree with python-schema: {}".format(exc)) from exc


def _get_keystore_metadata_file_path(keystore_dir: Path):
    """
    Return path of standard metadata file for key/cryptainer storage.
    """
    return keystore_dir.joinpath(".keystore.json")


def load_keystore_metadata(keystore_dir: Path) -> dict:  # FIXME rename to advertise that it VALiDATES data too?
    """
    Return the authenticator metadata stored in the given folder, after checking that it contains at least mandatory
    (keystore_owner and keystore_uid) fields.

    Raises SchemaValidationError if device appears initialized, but has corrupted metadata (or invalid json payload).
    """
    metadata_file = _get_keystore_metadata_file_path(keystore_dir)
    try:
        metadata = load_from_json_file(metadata_file)
    except FileNotFoundError as exc:
        raise KeystoreDoesNotExist("Keystore metadata file %s does not exist" % metadata_file) from exc
    validate_keystore_metadata(metadata)
    return metadata


class KeystoreBase(ABC):

    _lock = threading.Lock()

    @abstractmethod
    def _public_key_exists(self, *, keychain_uid: uuid.UUID, key_algo: str) -> bool:  # pragma: no cover
        raise NotImplementedError("KeystoreBase._public_key_exists()")

    @abstractmethod
    def _private_key_exists(self, *, keychain_uid: uuid.UUID, key_algo: str) -> bool:  # pragma: no cover
        raise NotImplementedError("KeystoreBase._private_key_exists()")

    def _check_public_key_does_not_exist(self, keychain_uid: uuid.UUID, key_algo: str):
        if self._public_key_exists(keychain_uid=keychain_uid, key_algo=key_algo):
            raise KeyAlreadyExists("Already existing public key %s/%s" % (keychain_uid, key_algo))
        assert not self._private_key_exists(keychain_uid=keychain_uid, key_algo=key_algo)  # By construction

    def _check_private_key_does_not_exist(self, keychain_uid: uuid.UUID, key_algo: str):
        if self._private_key_exists(keychain_uid=keychain_uid, key_algo=key_algo):
            raise KeyAlreadyExists("Already existing private key %s/%s" % (keychain_uid, key_algo))


class KeystoreReadBase(KeystoreBase):
    """
    Subclasses of this storage interface can be implemented to retrieve keys from
    miscellaneous locations (disk, database...), without permission checks.
    """

    @synchronized
    def get_public_key(self, *, keychain_uid: uuid.UUID, key_algo: str) -> bytes:
        """
        Fetch a public key from persistent storage.

        :param keychain_uid: unique ID of the keychain
        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS

        :return: public key in clear PEM format, or raise KeyDoesNotExist
        """
        if not self._public_key_exists(keychain_uid=keychain_uid, key_algo=key_algo):
            raise KeyDoesNotExist("Public key %s/%s not found" % (keychain_uid, key_algo))
        return self._get_public_key(keychain_uid=keychain_uid, key_algo=key_algo)

    @synchronized
    def get_private_key(self, *, keychain_uid: uuid.UUID, key_algo: str) -> bytes:
        """
        Fetch a private key from persistent storage.

        :param keychain_uid: unique ID of the keychain
        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS

        :return: private key in PEM format (potentially passphrase-protected), or raise KeyDoesNotExist
        """
        if not self._private_key_exists(keychain_uid=keychain_uid, key_algo=key_algo):
            raise KeyDoesNotExist("Private key %s/%s not found" % (keychain_uid, key_algo))
        return self._get_private_key(keychain_uid=keychain_uid, key_algo=key_algo)

    @synchronized
    def list_keypair_identifiers(self) -> list:
        """
        List identifiers of public keys present in the storage, along with their potential private key existence.

        Might raise an OperationNotSupported exception if not supported by this keystore.

        :return: a SORTED list of key information dicts with standard fields "keychain_uid" and "key_algo", as well as
                 a boolean "private_key_present" which is True if the related private key exists in storage.
                 Sorting is done by keychain_uid and then key_algo.
        """
        key_information_list = self._list_unordered_keypair_identifiers()
        key_information_list.sort(key=lambda x: (x["keychain_uid"], x["key_algo"]))
        return key_information_list

    @abstractmethod
    def _get_public_key(self, *, keychain_uid: uuid.UUID, key_algo: str) -> bytes:  # pragma: no cover
        raise NotImplementedError("KeystoreReadBase._get_public_key()")

    @abstractmethod
    def _get_private_key(self, *, keychain_uid: uuid.UUID, key_algo: str) -> bytes:  # pragma: no cover
        raise NotImplementedError("KeystoreReadBase._get_private_key()")

    @abstractmethod
    def _list_unordered_keypair_identifiers(self) -> list:  # pragma: no cover
        raise NotImplementedError("KeystoreReadBase._list_unordered_keypair_identifiers()")


class KeystoreWriteBase(KeystoreBase):
    """
    Subclasses of this storage interface can be implemented to store keys into
    miscellaneous locations (disk, database...), without permission checks.
    """

    @synchronized
    def set_keypair(self, *, keychain_uid: uuid.UUID, key_algo: str, public_key: bytes, private_key: bytes) -> None:
        """
        Store a pair of asymmetric keys into storage, attached to a specific UUID.

        Must raise a KeyAlreadyExists exception if a public/private key already exists for these uid/type identifiers.

        :param keychain_uid: unique ID of the keychain
        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS
        :param public_key: public key in clear PEM format
        :param private_key: private key in PEM format (potentially encrypted)
        """
        assert public_key and private_key, (public_key, private_key)
        self._check_public_key_does_not_exist(keychain_uid=keychain_uid, key_algo=key_algo)
        self._set_keypair(keychain_uid=keychain_uid, key_algo=key_algo, public_key=public_key, private_key=private_key)

    def _set_keypair(self, *, keychain_uid: uuid.UUID, key_algo: str, public_key: bytes, private_key: bytes) -> None:
        self._set_public_key(keychain_uid=keychain_uid, key_algo=key_algo, public_key=public_key)
        self._set_private_key(keychain_uid=keychain_uid, key_algo=key_algo, private_key=private_key)

    @synchronized
    def set_public_key(self, *, keychain_uid, key_algo, public_key: bytes) -> None:
        """
        Store a public key, which must not already exist - else KeyAlreadyExists is raised.

        :param keychain_uid: unique ID of the keychain
        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS
        :param public_key: public key in clear PEM format
        """
        self._check_public_key_does_not_exist(keychain_uid=keychain_uid, key_algo=key_algo)
        self._set_public_key(keychain_uid=keychain_uid, key_algo=key_algo, public_key=public_key)

    @synchronized
    def set_private_key(self, *, keychain_uid, key_algo, private_key: bytes) -> None:
        """
        Store a private key, which must not already exist - else a KeyAlreadyExists is raised.

        Important : the PUBLIC key for this private key must already exist in the keystore,
        else KeyDoesNotExist is raised.

        :param keychain_uid: unique ID of the keychain
        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS
        :param private_key: private key in PEM format (potentially encrypted)
        """
        if not self._public_key_exists(
            keychain_uid=keychain_uid, key_algo=key_algo
        ):  # We don't want lonely private keys
            raise KeyDoesNotExist(
                "Public key %s/%s does not exist, cannot attach private key to it" % (keychain_uid, key_algo)
            )
        self._check_private_key_does_not_exist(keychain_uid=keychain_uid, key_algo=key_algo)
        self._set_private_key(keychain_uid=keychain_uid, key_algo=key_algo, private_key=private_key)

    @synchronized
    def get_free_keypairs_count(self, key_algo: str) -> int:
        """
        Calculate the count of keypairs of type `key_algo` which are free for subsequent attachment to an UUID.

        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS
        :return: count of free keypairs of said type
        """
        return self._get_free_keypairs_count(key_algo=key_algo)

    @synchronized
    def add_free_keypair(self, *, key_algo: str, public_key: bytes, private_key: bytes) -> None:
        """
        Store a pair of asymmetric keys into storage, free for subsequent attachment to an UUID.

        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS
        :param public_key: public key in clear PEM format
        :param private_key: private key in PEM format (potentially encrypted)
        """
        return self._add_free_keypair(key_algo=key_algo, public_key=public_key, private_key=private_key)

    @synchronized
    def attach_free_keypair_to_uuid(self, *, keychain_uid: uuid.UUID, key_algo: str) -> None:
        """
        Fetch one of the free keypairs of storage of type `key_algo`, and attach it to UUID `keychain_uid`.

        If no free keypair is available, a KeyDoesNotExist is raised.

        :param keychain_uid: unique ID of the keychain
        :param key_algo: one of SUPPORTED_ASYMMETRIC_KEY_ALGOS
        :return: public key of the keypair, in clear PEM format
        """
        self._check_public_key_does_not_exist(keychain_uid=keychain_uid, key_algo=key_algo)
        return self._attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_algo=key_algo)

    @abstractmethod
    def _set_public_key(self, *, keychain_uid: uuid.UUID, key_algo: str, public_key: bytes) -> None:  # pragma: no cover
        raise NotImplementedError("KeystoreWriteBase._set_public_key()")

    @abstractmethod
    def _set_private_key(
        self, *, keychain_uid: uuid.UUID, key_algo: str, private_key: bytes
    ) -> None:  # pragma: no cover
        raise NotImplementedError("KeystoreWriteBase._set_private_key()")

    @abstractmethod
    def _get_free_keypairs_count(self, key_algo: str) -> int:  # pragma: no cover
        raise NotImplementedError("KeystoreWriteBase._get_free_keypairs_count()")

    @abstractmethod
    def _add_free_keypair(self, *, key_algo: str, public_key: bytes, private_key: bytes) -> None:  # pragma: no cover
        raise NotImplementedError("KeystoreWriteBase._add_free_keypair()")

    @abstractmethod
    def _attach_free_keypair_to_uuid(self, *, keychain_uid: uuid.UUID, key_algo: str) -> None:  # pragma: no cover
        raise NotImplementedError("KeystoreWriteBase._attach_free_keypair_to_uuid()")


class KeystoreReadWriteBase(KeystoreWriteBase, KeystoreReadBase):
    pass  # Derive from this class to have full-featured keystores


class InMemoryKeystore(KeystoreReadWriteBase):
    """
    Dummy key storage for use in tests, where keys are kepts only process-locally.

    NOT MEANT TO BE THREAD-SAFE
    """

    def __init__(self):
        self._cached_keypairs = {}  # Maps (keychain_uid, key_algo) to dicts of public_key/private_key
        self._free_keypairs = {}  # Maps key types to lists of dicts of public_key/private_key

    def _get_keypair_dict_or_none(self, *, keychain_uid, key_algo):
        return self._cached_keypairs.get((keychain_uid, key_algo))

    def _public_key_exists(self, *, keychain_uid, key_algo):
        keypair_dict = self._get_keypair_dict_or_none(keychain_uid=keychain_uid, key_algo=key_algo)
        return bool(keypair_dict and keypair_dict.get("public_key"))

    def _private_key_exists(self, *, keychain_uid, key_algo):
        keypair_dict = self._get_keypair_dict_or_none(keychain_uid=keychain_uid, key_algo=key_algo)
        return bool(keypair_dict and keypair_dict.get("private_key"))

    def _get_public_key(self, *, keychain_uid, key_algo):
        keypair = self._get_keypair_dict_or_none(keychain_uid=keychain_uid, key_algo=key_algo)
        return keypair["public_key"]  # MUST EXIST by construction

    def _get_private_key(self, *, keychain_uid, key_algo):
        keypair = self._get_keypair_dict_or_none(keychain_uid=keychain_uid, key_algo=key_algo)
        return keypair["private_key"]  # MUST EXIST by construction

    def _list_unordered_keypair_identifiers(self):
        key_information_list = []
        for (keychain_uid, key_algo), keypair in self._cached_keypairs.items():
            key_information = dict(
                keychain_uid=keychain_uid, key_algo=key_algo, private_key_present=bool(keypair.get("private_key"))
            )
            key_information_list.append(key_information)
        return key_information_list

    def _set_public_key(self, *, keychain_uid: uuid.UUID, key_algo, public_key):
        assert (keychain_uid, key_algo) not in self._cached_keypairs
        self._cached_keypairs[(keychain_uid, key_algo)] = dict(public_key=public_key)

    def _set_private_key(self, *, keychain_uid: uuid.UUID, key_algo, private_key):
        self._cached_keypairs[(keychain_uid, key_algo)]["private_key"] = private_key

    def _get_free_keypairs_count(self, key_algo):
        return len(self._free_keypairs.get(key_algo, []))

    def _add_free_keypair(self, *, key_algo, public_key, private_key):
        keypair = dict(public_key=public_key, private_key=private_key)
        sublist = self._free_keypairs.setdefault(key_algo, [])
        sublist.append(keypair)

    def _attach_free_keypair_to_uuid(self, *, keychain_uid, key_algo):
        try:
            sublist = self._free_keypairs[key_algo]
            keypair = sublist.pop()
        except LookupError:
            raise KeyDoesNotExist("No free keypair of type %s available in dummy storage" % key_algo)
        else:
            self._set_keypair(
                keychain_uid=keychain_uid,
                key_algo=key_algo,
                public_key=keypair["public_key"],
                private_key=keypair["private_key"],
            )


# FIXME use ReadonlyFilesystemKeystore for IMPORTED keystores!!
class ReadonlyFilesystemKeystore(KeystoreReadBase):
    """
    Read-only filesystem-based key storage.
    """

    _private_key_suffix = "_private_key.pem"
    _public_key_suffix = "_public_key.pem"
    PUBLIC_KEY_FILENAME_REGEX = r"^(?P<keychain_uid>[-0-9a-z]+)_(?P<key_algo>[_a-zA-Z]+)%s$" % _public_key_suffix

    def __init__(self, keys_dir: Path):
        keys_dir = Path(keys_dir).absolute()
        assert keys_dir.is_dir(), keys_dir
        self._keys_dir = keys_dir

    def _get_filepath(self, keychain_uid, key_algo, is_public: bool):
        filename = "%s_%s%s" % (
            keychain_uid,
            key_algo,
            self._public_key_suffix if is_public else self._private_key_suffix,
        )
        return self._keys_dir.joinpath(filename)

    def _read_from_storage_file(self, filepath: Path):
        assert self._keys_dir in filepath.parents  # No weirdness with outside folders
        return filepath.read_bytes()

    def _public_key_exists(self, *, keychain_uid, key_algo):
        return self._get_filepath(keychain_uid, key_algo=key_algo, is_public=True).exists()

    def _private_key_exists(self, *, keychain_uid, key_algo):
        return self._get_filepath(keychain_uid, key_algo=key_algo, is_public=False).exists()

    def _get_public_key(self, *, keychain_uid, key_algo):
        filepath = self._get_filepath(keychain_uid, key_algo=key_algo, is_public=True)
        return self._read_from_storage_file(filepath)

    def _get_private_key(self, *, keychain_uid, key_algo):
        filepath = self._get_filepath(keychain_uid, key_algo=key_algo, is_public=False)
        return self._read_from_storage_file(filepath)

    def _list_unordered_keypair_identifiers(self):

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

        return key_information_list


class FilesystemKeystore(ReadonlyFilesystemKeystore, KeystoreReadWriteBase):
    """
    Filesystem-based key storage.

    Protected by a process-wide lock, but not safe to use in multiprocessing environment, or in a process which can be brutally shutdown.
    To prevent corruption, caller should only persist UUIDs when the key storage operation is successfully finished.
    """

    _randint_args = (10 ** 10, 10 ** 11 - 1)

    def __init__(self, keys_dir: Path):
        super().__init__(keys_dir=keys_dir)
        self._free_keys_dir = self._keys_dir.joinpath("free_keys")  # Might not exist yet

    def _write_to_storage_file(self, filepath: Path, data: bytes):
        assert self._keys_dir in filepath.parents  # No weirdness with outside folders
        filepath.write_bytes(data)

    def _set_public_key(self, *, keychain_uid, key_algo, public_key):
        filepath = self._get_filepath(keychain_uid, key_algo=key_algo, is_public=True)
        self._write_to_storage_file(filepath=filepath, data=public_key)

    def _set_private_key(self, *, keychain_uid, key_algo, private_key):
        target_private_key_filename = self._get_filepath(keychain_uid, key_algo=key_algo, is_public=False)
        self._write_to_storage_file(filepath=target_private_key_filename, data=private_key)

    def _ensure_free_keys_dir_exists(self):
        self._free_keys_dir.mkdir(exist_ok=True)

    def _get_free_keypairs_count(self, key_algo):
        subdir = self._free_keys_dir.joinpath(key_algo)  # Might not exist yet
        if not subdir.is_dir():
            return 0
        return len(list(subdir.glob("*" + self._private_key_suffix)))  # PRIVATE keys show existence of FREE keypairs

    def _add_free_keypair(self, *, key_algo, public_key, private_key):
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

    def _attach_free_keypair_to_uuid(self, *, keychain_uid, key_algo):

        target_public_key_filename = self._get_filepath(keychain_uid, key_algo=key_algo, is_public=True)
        target_private_key_filename = self._get_filepath(keychain_uid, key_algo=key_algo, is_public=False)

        subdir = self._free_keys_dir.joinpath(key_algo)  # Might not exist
        globber = subdir.glob("*" + self._private_key_suffix)
        try:
            free_private_key = next(globber)
        except StopIteration:
            raise KeyDoesNotExist("No free keypair of type %s available in filesystem storage" % key_algo)
        _free_public_key_name = free_private_key.name.replace(self._private_key_suffix, self._public_key_suffix)
        free_public_key = subdir.joinpath(_free_public_key_name)

        # First move the PRIVATE key, so that it's not shown anymore as "free"
        free_private_key.replace(target_private_key_filename)
        free_public_key.replace(target_public_key_filename)

    def export_to_keystore_tree(self, include_private_keys=True):  # TODO add include_private_keys=bool
        """
        Export keystore metadata and keys (public and, if include_private_keys is true, private)
        to a data tree.
        """

        assert self._keys_dir.exists(), self._keys_dir
        metadata = load_keystore_metadata(self._keys_dir)
        keypair_identifiers = self.list_keypair_identifiers()
        keypairs = []

        for keypair_identifier in keypair_identifiers:
            keypair = dict(
                keychain_uid=keypair_identifier["keychain_uid"],
                key_algo=keypair_identifier["key_algo"],
                public_key=self.get_public_key(
                    keychain_uid=keypair_identifier["keychain_uid"], key_algo=keypair_identifier["key_algo"]
                ),
                private_key=None,
            )
            if include_private_keys:
                keypair["private_key"] = self.get_private_key(
                    keychain_uid=keypair_identifier["keychain_uid"], key_algo=keypair_identifier["key_algo"]
                )
            keypairs.append(keypair)

        keystore_tree = metadata.copy()
        keystore_tree["keypairs"] = keypairs
        validate_keystore_tree(keystore_tree)  # Safety
        return keystore_tree

    def _initialize_metadata_from_keystore_tree(self, keystore_tree: dict):
        metadata_file = _get_keystore_metadata_file_path(self._keys_dir)
        metadata_file.parent.mkdir(parents=True, exist_ok=True)  # FIXME Create a temporary folder for ATOMIC copy

        metadata = {
            "keystore_type": "authenticator",
            "keystore_format": KEYSTORE_FORMAT,
            "keystore_uid": keystore_tree["keystore_uid"],
            "keystore_owner": keystore_tree["keystore_owner"],
            "keystore_secret": secrets.token_urlsafe(64),
        }
        validate_keystore_metadata(metadata)  # Safety
        dump_to_json_file(metadata_file, metadata)
        return metadata

    def import_from_keystore_tree(self, keystore_tree) -> bool:
        """
        Import keystore metadata and keys (public and, if included, private) fom a data tree.

        If keystore already exists, it is completed with new keys.

        Returns True if and only if keystore was updated instead of created.
        """
        validate_keystore_tree(keystore_tree)

        try:
            metadata = load_keystore_metadata(self._keys_dir)
            if keystore_tree["keystore_uid"] != metadata["keystore_uid"]:
                raise ValidationError("Mismatch between existing and incoming keystore UIDs")
            keystore_updated = True
        except KeystoreDoesNotExist:
            self._initialize_metadata_from_keystore_tree(keystore_tree)
            keystore_updated = False

        for keypair in keystore_tree["keypairs"]:

            try:
                self.set_public_key(
                    keychain_uid=keypair["keychain_uid"], key_algo=keypair["key_algo"], public_key=keypair["public_key"]
                )
            except KeyAlreadyExists:
                pass  # We ASSUME that it's the same key content

            if keypair["private_key"]:  # Field must exist, due to Schema
                try:
                    self.set_private_key(
                        keychain_uid=keypair["keychain_uid"],
                        key_algo=keypair["key_algo"],
                        private_key=keypair["private_key"],
                    )
                except KeyAlreadyExists:
                    pass  # We ASSUME that it's the same key content

        return keystore_updated


class KeystorePoolBase:
    # FIXME fill base class with Python function signatures!! Like in KeystoreBase!

    def ensure_foreign_keystore_does_not_exist(self, keystore_uid):
        """Raises KeystoreAlreadyExists if imported keystore already exists."""
        if keystore_uid in self.list_foreign_keystore_uids():
            raise KeystoreAlreadyExists("Key storage with UUID %s was already imported locally" % keystore_uid)


class InMemoryKeystorePool(KeystorePoolBase):
    """
    Dummy key storage pool for use in tests, where keys are kepts only process-locally.

    NOT MEANT TO BE THREAD-SAFE
    """

    def __init__(self):
        self._local_keystore = InMemoryKeystore()
        self._foreign_keystores = {}

    def get_local_keyfactory(self):
        return self._local_keystore

    def get_foreign_keystore(self, keystore_uid):
        foreign_keystore = self._foreign_keystores.get(keystore_uid)
        if not foreign_keystore:
            raise KeystoreDoesNotExist("Key storage %s not found" % keystore_uid)
        return foreign_keystore

    def list_foreign_keystore_uids(self):
        return list(self._foreign_keystores.keys())

    def _register_fake_imported_storage_uids(self, storage_uids: Sequence):
        """Test-specific API"""
        assert not (set(storage_uids) & set(self._foreign_keystores.keys()))
        new_storages = {storage_uid: InMemoryKeystore() for storage_uid in storage_uids}
        self._foreign_keystores.update(new_storages)


class FilesystemKeystorePool(
    KeystorePoolBase
):  # FIXME rename methods to better represent authdevices, remote authenticators etc. ??
    """This class handles a set of locally stored key storages.

    The local storage represents the current device/owner, and is expected to be used by read-write trustees,
    whereas imported key storages are supposed to be readonly, and only filled with keypairs imported from key-devices.
    """

    LOCAL_KEYFACTORY_DIRNAME = "local_keyfactory"
    FOREIGN_KEYSTORES_DIRNAME = "foreign_keystores"
    FOREIGN_KEYSTORE_PREFIX = "keystore_"

    def __init__(self, root_dir):
        root_dir = Path(root_dir)
        assert root_dir.is_dir(), root_dir
        self._root_dir = root_dir.absolute()

    def get_local_keyfactory(self):
        """Storage automatically created if unexisting."""
        local_keystore_dir = self._root_dir.joinpath(self.LOCAL_KEYFACTORY_DIRNAME)
        local_keystore_dir.mkdir(exist_ok=True)
        # TODO initialize metadata for local keystore ??
        return FilesystemKeystore(local_keystore_dir)

    def _get_foreign_keystore_dir(self, keystore_uid):
        foreign_keystore_dir = self._root_dir.joinpath(
            self.FOREIGN_KEYSTORES_DIRNAME, "%s%s" % (self.FOREIGN_KEYSTORE_PREFIX, keystore_uid)
        )
        return foreign_keystore_dir

    def _ensure_foreign_keystore_dir_exists(self, keystore_uid):  # Not always INITIALIZED
        foreign_keystore_dir = self._get_foreign_keystore_dir(keystore_uid=keystore_uid)
        if not foreign_keystore_dir.exists():
            foreign_keystore_dir.mkdir(parents=True, exist_ok=True)

    def get_foreign_keystore(self, keystore_uid):
        """The selected storage MUST exist, else a KeystoreDoesNotExist is raised."""
        foreign_keystore_dir = self._get_foreign_keystore_dir(keystore_uid=keystore_uid)
        if not foreign_keystore_dir.exists():
            raise KeystoreDoesNotExist("Key storage %s not found" % keystore_uid)
        return FilesystemKeystore(foreign_keystore_dir)

    def list_foreign_keystore_uids(self) -> list:
        """Return a sorted list of UUIDs of key storages, corresponding
        to the keystore_uid of their origin authentication devices."""
        foreign_keystores_dir = self._root_dir.joinpath(self.FOREIGN_KEYSTORES_DIRNAME)
        paths = foreign_keystores_dir.glob("%s*" % self.FOREIGN_KEYSTORE_PREFIX)  # This excludes TEMP folders
        return sorted([uuid.UUID(d.name.replace(self.FOREIGN_KEYSTORE_PREFIX, "")) for d in paths])

    def get_foreign_keystore_metadata(self) -> dict:
        """Return a dict mapping key storage UUIDs to the dicts of their metadata.

        Raises if any metadata loading fails.
        """
        keystore_uids = self.list_foreign_keystore_uids()

        metadata_mapper = {}
        for keystore_uid in keystore_uids:
            keystore_dir = self._get_foreign_keystore_dir(keystore_uid=keystore_uid)
            metadata = load_keystore_metadata(keystore_dir)
            metadata_mapper[keystore_uid] = metadata

        return metadata_mapper

    def import_foreign_keystore_from_filesystem(self, keystore_dir: Path):
        """
        Create a local import of a remote key storage folder (which must have a proper metadata file).

        Raises KeystoreAlreadyExists if this key storage was already imported.
        """
        assert keystore_dir.exists(), keystore_dir

        metadata = load_keystore_metadata(keystore_dir)
        keystore_uid = metadata["keystore_uid"]

        self.ensure_foreign_keystore_does_not_exist(keystore_uid)

        foreign_keystore_dir = self._get_foreign_keystore_dir(keystore_uid=keystore_uid)
        safe_copy_directory(keystore_dir, foreign_keystore_dir)  # Must not fail, due to previous checks
        assert foreign_keystore_dir.exists()

    def export_foreign_keystore_to_keystore_tree(self, keystore_uid, include_private_keys=True):
        """
        Exports data tree from the keystore targeted by keystore_uid.
        """
        foreign_keystore = self.get_foreign_keystore(keystore_uid)
        keystore_tree = foreign_keystore.export_to_keystore_tree(include_private_keys)
        return keystore_tree

    def import_foreign_keystore_from_keystore_tree(self, keystore_tree) -> bool:
        """
        Imports/updates data tree into the keystore targeted by keystore_uid.
        """
        self._ensure_foreign_keystore_dir_exists(keystore_tree["keystore_uid"])
        foreign_keystore = self.get_foreign_keystore(keystore_tree["keystore_uid"])
        return foreign_keystore.import_from_keystore_tree(keystore_tree)


def generate_keypair_for_storage(  # FIXME document this, or integrate to class?
    key_algo: str, *, keystore, keychain_uid: Optional[UUID] = None, passphrase: Optional[AnyStr] = None
) -> dict:
    """
    Shortcut to generate an asymmetric keypair and store it into a key storage.

    `keychain_uid` is auto-generated if not provided.

    Returns the generated keypair dict.
    """
    keychain_uid = keychain_uid or generate_uuid0()
    keypair = generate_keypair(key_algo=key_algo, serialize=True, passphrase=passphrase)
    keystore.set_keypair(
        keychain_uid=keychain_uid,
        key_algo=key_algo,
        public_key=keypair["public_key"],
        private_key=keypair["private_key"],
    )
    return keypair


def generate_free_keypair_for_least_provisioned_key_algo(
    keystore: KeystoreWriteBase,
    max_free_keys_per_algo: int,
    keygen_func=generate_keypair,
    key_algos=SUPPORTED_ASYMMETRIC_KEY_ALGOS,
):
    """
    Generate a single free keypair for the key type which is the least available in key storage, and
    add it to storage. If the "free keys" pools of the storage are full, do nothing.

    :param keystore: the key storage to use
    :param max_free_keys_per_algo: how many free keys should exist per key type
    :param keygen_func: callable to use for keypair generation
    :param key_algos: the different key types (strings) to consider
    :return: True iff a key was generated (i.e. the free keys pool was not full)
    """
    assert key_algos, key_algos
    free_keys_counts = [(keystore.get_free_keypairs_count(key_algo), key_algo) for key_algo in key_algos]
    logger.debug("Stats of free keys: %s", str(free_keys_counts))

    (count, key_algo) = min(free_keys_counts)

    if count >= max_free_keys_per_algo:
        return False

    keypair = keygen_func(key_algo=key_algo, serialize=True)
    keystore.add_free_keypair(key_algo=key_algo, public_key=keypair["public_key"], private_key=keypair["private_key"])
    logger.debug("New free key of type %s pregenerated" % key_algo)
    return True


def get_free_keypair_generator_worker(
    keystore: KeystoreWriteBase, max_free_keys_per_algo: int, sleep_on_overflow_s: float, **extra_generation_kwargs
) -> PeriodicTaskHandler:
    """
    Return a periodic task handler which will gradually fill the pools of free keys of the key storage,
    and wait longer when these pools are full.

    :param keystore: the key storage to use
    :param max_free_keys_per_algo: how many free keys should exist per key type
    :param sleep_on_overflow_s: time to wait when free keys pools are full
    :param extra_generation_kwargs: extra arguments to transmit to `generate_free_keypair_for_least_provisioned_key_algo()`
    :return: periodic task handler
    """

    def free_keypair_generator_task():  # FIXME add a @safe_catch_unhandled_exception - like mechanism
        has_generated = generate_free_keypair_for_least_provisioned_key_algo(
            keystore=keystore, max_free_keys_per_algo=max_free_keys_per_algo, **extra_generation_kwargs
        )
        # TODO - improve this with refactored multitimer, later
        if not has_generated:
            time.sleep(sleep_on_overflow_s)
        return has_generated

    periodic_task_handler = PeriodicTaskHandler(interval_s=0.001, task_func=free_keypair_generator_task)
    return periodic_task_handler
