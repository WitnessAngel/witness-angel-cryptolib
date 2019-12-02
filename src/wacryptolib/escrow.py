import logging
import os
import random
import threading
import uuid
from abc import ABC, abstractmethod
from pathlib import Path

from wacryptolib.encryption import _decrypt_via_rsa_oaep
from wacryptolib.key_generation import (
    generate_asymmetric_keypair,
    load_asymmetric_key_from_pem_bytestring,
)
from wacryptolib.key_storage import KeyStorageBase as KeyStorageBase
from wacryptolib.signature import sign_message
from wacryptolib.utilities import synchronized

logger = logging.getLogger(__name__)

#: Special value in containers, to invoke a device-local escrow
LOCAL_ESCROW_PLACEHOLDER = "_local_"



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

