import logging
import os
import random
import threading
import uuid
from abc import ABC, abstractmethod

from wacryptolib.encryption import _decrypt_via_rsa_oaep
from wacryptolib.key_generation import (
    generate_asymmetric_keypair,
    load_asymmetric_key_from_pem_bytestring,
)
from wacryptolib.signature import sign_message
from wacryptolib.utilities import synchronized

logger = logging.getLogger(__name__)

#: Special value in containers, to invoke a device-local escrow
LOCAL_ESCROW_PLACEHOLDER = "_local_"


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
        self,
        *,
        key_type: str,
        public_key: bytes,
        private_key: bytes,
    ):  # pragma: no cover
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

        If no free keypair is available, a RuntimeError is raised.

        :param keychain_uid: unique ID of the keychain
        :param key_type: one of SUPPORTED_ASYMMETRIC_KEY_TYPES
        :return: public key of the keypair, in clear PEM format
        """
        raise NotImplementedError("KeyStorageBase.attach_free_keypair_to_uuid()")


class EscrowApi:
    """
    This is the API meant to be exposed by escrow webservices, to allow end users to create safely encrypted containers.

    Subclasses must add their own permission checking, especially so that no decryption with private keys can occur
    outside the scope of a well defined legal procedure.
    """

    def __init__(self, key_storage: KeyStorageBase):
        self._key_storage = key_storage

    def _ensure_keypair_exists(self, keychain_uid: uuid.UUID, key_type: str):
        has_public_key = self._key_storage.get_public_key(
            keychain_uid=keychain_uid, key_type=key_type
        )
        if not has_public_key:
            keypair = generate_asymmetric_keypair(key_type=key_type, serialize=True)
            self._key_storage.set_keys(
                keychain_uid=keychain_uid,
                key_type=key_type,
                public_key=keypair["public_key"],
                private_key=keypair["private_key"],
            )

    def get_public_key(self, *, keychain_uid: uuid.UUID, key_type: str) -> bytes:
        """
        Return a public key in PEM format bytestring, that caller shall use to encrypt its own symmetric keys,
        or to check a signature.
        """
        self._ensure_keypair_exists(keychain_uid=keychain_uid, key_type=key_type)
        return self._key_storage.get_public_key(
            keychain_uid=keychain_uid, key_type=key_type
        )

    def get_message_signature(
        self,
        *,
        keychain_uid: uuid.UUID,
        message: bytes,
        key_type: str,
        signature_algo: str,
    ) -> dict:
        """
        Return a signature structure corresponding to the provided key and signature types.
        """
        self._ensure_keypair_exists(keychain_uid=keychain_uid, key_type=key_type)

        private_key_pem = self._key_storage.get_private_key(
            keychain_uid=keychain_uid, key_type=key_type
        )

        private_key = load_asymmetric_key_from_pem_bytestring(
            key_pem=private_key_pem, key_type=key_type
        )

        signature = sign_message(
            message=message, signature_algo=signature_algo, key=private_key
        )
        return signature

    def decrypt_with_private_key(
        self,
        *,
        keychain_uid: uuid.UUID,
        key_type: str,
        encryption_algo: str,
        cipherdict: dict,
    ) -> bytes:
        """
        Return the message (probably a symmetric key) decrypted with the corresponding key,
        as bytestring.
        """
        assert key_type.upper() == "RSA"  # Only supported key for now
        assert (
            encryption_algo.upper() == "RSA_OAEP"
        )  # Only supported asymmetric cipher for now
        self._ensure_keypair_exists(keychain_uid=keychain_uid, key_type=key_type)

        private_key_pem = self._key_storage.get_private_key(
            keychain_uid=keychain_uid, key_type=key_type
        )

        private_key = load_asymmetric_key_from_pem_bytestring(
            key_pem=private_key_pem, key_type=key_type
        )

        secret = _decrypt_via_rsa_oaep(cipherdict=cipherdict, key=private_key)
        return secret


class DummyKeyStorage(KeyStorageBase):
    """
    Dummy key storage for use in tests, where keys are kepts only process-locally.

    NOT THREAD-SAFE
    """

    def __init__(self):
        self._cached_keypairs = {}  # Maps (keychain_uid, key_type) to dicts of public_key/private_key
        self._free_keypairs = {}  # Maps key types to lists of dicts of public_key/private_key

    def _get_keypair(self, *, keychain_uid, key_type):
        return self._cached_keypairs.get((keychain_uid, key_type))

    def _set_keypair(self, *, keychain_uid, key_type, keypair):
        assert isinstance(keypair, dict), keypair
        self._cached_keypairs[(keychain_uid, key_type)] = keypair

    def set_keys(self, *, keychain_uid, key_type, public_key, private_key):
        if self._get_keypair(keychain_uid=keychain_uid, key_type=key_type):
            raise RuntimeError(
                "Can't save already existing dummy key %s/%s" % (keychain_uid, key_type)
            )
        self._set_keypair(keychain_uid=keychain_uid, key_type=key_type, keypair=dict(
                    public_key=public_key, private_key=private_key
                ))


    def get_public_key(self, *, keychain_uid, key_type):
        keypair = self._get_keypair(keychain_uid=keychain_uid, key_type=key_type)
        return keypair["public_key"] if keypair else None

    def get_private_key(self, *, keychain_uid, key_type):
        keypair = self._get_keypair(keychain_uid=keychain_uid, key_type=key_type)
        return keypair["private_key"] if keypair else None

    def get_free_keypairs_count(self, key_type):
        return len(self._free_keypairs.get(key_type, []))

    def add_free_keypair(
        self,
        *,
        key_type: str,
        public_key: bytes,
        private_key: bytes,
    ):
        keypair = dict(public_key=public_key, private_key=private_key)
        sublist = self._free_keypairs.setdefault(key_type, [])
        sublist.append(keypair)

    def attach_free_keypair_to_uuid(self, *, keychain_uid: uuid.UUID, key_type: str):
        try:
            sublist = self._free_keypairs[key_type]
            keypair = sublist.pop()
        except LookupError:
            raise RuntimeError("No free keypair of type %s available" % key_type)
        else:
            self._set_keypair(keychain_uid=keychain_uid, key_type=key_type, keypair=keypair)


class FilesystemKeyStorage(KeyStorageBase):
    """
    Filesystem-based key storage for use in tests, where keys are kepts only instance-locally.

    Protected by a process-wide lock (but not safe to use in multiprocessing environment).
    """

    _lock = threading.Lock()

    def __init__(self, keys_dir):
        assert os.path.isdir(keys_dir), keys_dir
        keys_dir = os.path.abspath(keys_dir)
        self._keys_dir = keys_dir

        free_keys_dir = os.path.join(keys_dir, "free_keys")
        os.makedirs(free_keys_dir, exist_ok=True)
        self._free_keys_dir = free_keys_dir

    def _get_filename(self, keychain_uid, key_type, is_public: bool):
        return "%s_%s_%s.pem" % (keychain_uid, key_type, "public_key" if is_public else "private_key")

    def _write_to_storage_file(self, basename: str, data: bytes):
        assert os.sep not in basename, basename
        with open(os.path.join(self._keys_dir, basename), "wb") as f:
            f.write(data)

    def _read_from_storage_file(self, basename: str):
        assert os.sep not in basename, basename
        try:
            with open(os.path.join(self._keys_dir, basename), "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    @synchronized
    def set_keys(self, *, keychain_uid, key_type, public_key, private_key):
        filename_public_key = self._get_filename(keychain_uid, key_type=key_type, is_public=True)
        filename_private_key = self._get_filename(keychain_uid, key_type=key_type, is_public=False)

        # We use PRIVATE key as marker of existence
        if os.path.exists(os.path.join(self._keys_dir, filename_private_key)):
            raise RuntimeError(
                "Can't save already existing filesystem key %s/%s" % (keychain_uid, key_type)
            )

        # We override (unexpected) already existing files
        self._write_to_storage_file(basename=filename_public_key, data=public_key)
        self._write_to_storage_file(basename=filename_private_key, data=private_key)

    @synchronized
    def get_public_key(self, *, keychain_uid, key_type):
        filename_public_key = self._get_filename(keychain_uid, key_type=key_type, is_public=True)
        return self._read_from_storage_file(basename=filename_public_key)

    @synchronized
    def get_private_key(self, *, keychain_uid, key_type):
        filename_private_key = self._get_filename(keychain_uid, key_type=key_type, is_public=False)
        return self._read_from_storage_file(basename=filename_private_key)

    # No need for lock here
    def get_free_keypairs_count(self, key_type):
        pass

    @synchronized
    def add_free_keypair(
        self,
        *,
        key_type: str,
        public_key: bytes,
        private_key: bytes,
    ):
        subdir = os.path.join(self._free_keys_dir, key_type)
        os.makedirs(subdir, exist_ok=True)

        random_name = str(random.randint(1000000000000, 1000000000000000))

    @synchronized
    def attach_free_keypair_to_uuid(self, *, keychain_uid: uuid.UUID, key_type: str):
        pass
