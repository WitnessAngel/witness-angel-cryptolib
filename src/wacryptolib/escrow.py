import uuid
from abc import ABC, abstractmethod

from wacryptolib.encryption import _decrypt_via_rsa_oaep
from wacryptolib.key_generation import (
    generate_asymmetric_keypair,
    load_asymmetric_key_from_pem_bytestring,
)
from wacryptolib.signature import sign_message

LOCAL_ESCROW_PLACEHOLDER = (
    "_local_"
)  # Special value in containers, to invoke a device-local escrow


class KeyStorageBase(ABC):
    """
    Subclasses of this storage interface can be implemented to store/retrieve keys from
    miscellaneous locations (disk, database...), without permission checks.
    """

    @abstractmethod
    def get_keypair(self, *, keychain_uid: uuid.UUID, key_type: str) -> dict:
        """
        Fetch a key from persistent storage.

        :param keychain_uid: unique ID of the keychain
        :param key_type: one of SUPPORTED_ASYMMETRIC_KEY_TYPES

        :return: dict with fields "private_key" and "public_key" in PEM format, or None if unexisting.
        """
        raise NotImplementedError("KeyStorageBase.get_keypair()")

    @abstractmethod
    def set_keypair(self, *, keychain_uid: uuid.UUID, key_type: str, keypair: dict):
        """
        Store a keypair into storage.

        Must raise an exception if a keypair already exists for these identifiers.

        :param keychain_uid: unique ID of the keychain
        :param key_type: one of SUPPORTED_ASYMMETRIC_KEY_TYPES
        :param keypair: dict with fields "private_key" and "public_key" in PEM format
        """
        raise NotImplementedError("KeyStorageBase.set_keypair()")


class EscrowApi:
    """
    This is the API meant to be exposed by escrow webservices, to allow end users to create safely encrypted containers.

    Subclasses must add their own permission checking, especially so that no decryption with private keys can occur
    outside the scope of a well defined legal procedure.
    """

    def __init__(self, key_storage: KeyStorageBase):
        self.key_storage = key_storage

    def _fetch_keypair_with_caching(self, keychain_uid: uuid.UUID, key_type: str):
        existing_keypair = self.key_storage.get_keypair(
            keychain_uid=keychain_uid, key_type=key_type
        )
        if existing_keypair:
            keypair = existing_keypair
        else:
            keypair = generate_asymmetric_keypair(key_type=key_type, serialize=True)
            self.key_storage.set_keypair(
                keychain_uid=keychain_uid, key_type=key_type, keypair=keypair
            )
        assert keypair, keypair
        return keypair

    def get_public_key(self, *, keychain_uid: uuid.UUID, key_type: str) -> bytes:
        """
        Return a public key in PEM format bytestring, that caller shall use to encrypt its own symmetric keys,
        or to check a signature.
        """
        keypair_pem = self._fetch_keypair_with_caching(
            keychain_uid=keychain_uid, key_type=key_type
        )
        return keypair_pem["public_key"]

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
        keypair_pem = self._fetch_keypair_with_caching(
            keychain_uid=keychain_uid, key_type=key_type
        )
        private_key = load_asymmetric_key_from_pem_bytestring(
            key_pem=keypair_pem["private_key"], key_type=key_type
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

        keypair_pem = self._fetch_keypair_with_caching(
            keychain_uid=keychain_uid, key_type=key_type
        )
        private_key = load_asymmetric_key_from_pem_bytestring(
            key_pem=keypair_pem["private_key"], key_type=key_type
        )

        secret = _decrypt_via_rsa_oaep(cipherdict=cipherdict, key=private_key)
        return secret


class DummyKeyStorage(KeyStorageBase):
    """
    Dummy key storage for use in tests, where keys are kepts only instance-locally.
    """

    def __init__(self):
        self._cached_keypairs = {}

    def get_keypair(self, *, keychain_uid, key_type):
        return self._cached_keypairs.get((keychain_uid, key_type))

    def set_keypair(self, *, keychain_uid, key_type, keypair):
        if self._cached_keypairs.get((keychain_uid, key_type)):
            raise RuntimeError(
                "Can't save already existing key %s/%s" % (keychain_uid, key_type)
            )
        self._cached_keypairs[(keychain_uid, key_type)] = keypair
