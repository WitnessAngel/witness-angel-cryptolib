import logging
import time
import uuid

from wacryptolib.encryption import _decrypt_via_rsa_oaep
from wacryptolib.key_generation import (
    generate_asymmetric_keypair,
    load_asymmetric_key_from_pem_bytestring,
    SUPPORTED_ASYMMETRIC_KEY_TYPES,
)
from wacryptolib.key_storage import KeyStorageBase as KeyStorageBase
from wacryptolib.signature import sign_message
from wacryptolib.utilities import PeriodicTaskHandler

logger = logging.getLogger(__name__)

#: Special value in containers, to invoke a device-local escrow
LOCAL_ESCROW_PLACEHOLDER = "_local_"

MAX_PAYLOAD_LENGTH_FOR_SIGNATURE = 128  # Max 2*SHA512 length


class EscrowApi:
    """
    This is the API meant to be exposed by escrow webservices, to allow end users to create safely encrypted containers.

    Subclasses must add their own permission checking, especially so that no decryption with private keys can occur
    outside the scope of a well defined legal procedure.
    """

    def __init__(self, key_storage: KeyStorageBase):
        self._key_storage = key_storage

    def _ensure_keypair_exists(self, keychain_uid: uuid.UUID, key_type: str):
        """Create a keypair if it doesn't exist."""
        has_public_key = self._key_storage.get_public_key(
            keychain_uid=keychain_uid, key_type=key_type
        )
        if has_public_key:
            return

        try:
            self._key_storage.attach_free_keypair_to_uuid(
                keychain_uid=keychain_uid, key_type=key_type
            )
        except RuntimeError:  # FIXME improve error discrimination
            keypair = generate_asymmetric_keypair(key_type=key_type, serialize=True)
            self._key_storage.set_keys(
                keychain_uid=keychain_uid,
                key_type=key_type,
                public_key=keypair["public_key"],
                private_key=keypair["private_key"],
            )

    def _check_keypair_exists(self, keychain_uid: uuid.UUID, key_type: str):
        """Raise if a keypair doesn't exist."""
        has_public_key = self._key_storage.get_public_key(
            keychain_uid=keychain_uid, key_type=key_type
        )
        if not has_public_key:
            raise ValueError(
                "Unexisting sql keypair %s/%s in escrow api" % (keychain_uid, key_type)
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
        self, *, keychain_uid: uuid.UUID, message: bytes, signature_algo: str
    ) -> dict:
        """
        Return a signature structure corresponding to the provided key and signature types.
        """

        if len(message) > MAX_PAYLOAD_LENGTH_FOR_SIGNATURE:  # SECURITY
            raise ValueError("Message too big for signing, only a hash should be sent")

        self._ensure_keypair_exists(keychain_uid=keychain_uid, key_type=signature_algo)

        private_key_pem = self._key_storage.get_private_key(
            keychain_uid=keychain_uid, key_type=signature_algo
        )

        private_key = load_asymmetric_key_from_pem_bytestring(
            key_pem=private_key_pem, key_type=signature_algo
        )

        signature = sign_message(
            message=message, signature_algo=signature_algo, key=private_key
        )
        return signature

    def request_decryption_authorization(
        self, keypair_identifiers: list, request_message: str
    ) -> dict:
        """
        Send a list of keypairs for which decryption access is requested, with the reason why.

        If request is immediately denied, an exception is raised, else the status of the authorization process
        (process which might involve several steps, including live encounters) is returned.

        :param keypair_identifiers: list of dicts with (keychain_uid, key_type) indices to authorize
        :param request_message: user text explaining the reasons for the decryption (and the legal procedures involved)
        :return: a dict with at least a string field "response_message" detailing the status of the request.
        """
        if not keypair_identifiers:
            raise ValueError(
                "Keypair identifiers must not be empty, when requesting decryption authorization"
            )
        return dict(
            response_message="Decryption request accepted"
        )  # TODO localize string field!

    def decrypt_with_private_key(
        self, *, keychain_uid: uuid.UUID, encryption_algo: str, cipherdict: dict
    ) -> bytes:
        """
        Return the message (probably a symmetric key) decrypted with the corresponding key,
        as bytestring.
        """
        assert (
            encryption_algo.upper() == "RSA_OAEP"
        )  # Only supported asymmetric cipher for now
        self._check_keypair_exists(keychain_uid=keychain_uid, key_type=encryption_algo)

        private_key_pem = self._key_storage.get_private_key(
            keychain_uid=keychain_uid, key_type=encryption_algo
        )

        private_key = load_asymmetric_key_from_pem_bytestring(
            key_pem=private_key_pem, key_type=encryption_algo
        )

        secret = _decrypt_via_rsa_oaep(cipherdict=cipherdict, key=private_key)
        return secret


def generate_free_keypair_for_least_provisioned_key_type(
    key_storage: KeyStorageBase,
    max_free_keys_per_type: int,
    key_generation_func=generate_asymmetric_keypair,
    key_types=SUPPORTED_ASYMMETRIC_KEY_TYPES,
):
    """
    Generate a single free keypair for the key type which is the least available in key storage, and
    add it to storage. If the "free keys" pools of the storage are full, do nothing.

    :param key_storage: the key storage to use
    :param max_free_keys_per_type: how many free keys should exist per key type
    :param key_generation_func: callable to use for keypair generation
    :param key_types: the different key types (strings) to consider
    :return: True iff a key was generated (i.e. the free keys pool was not full)
    """
    assert key_types, key_types
    free_keys_counts = [
        (key_storage.get_free_keypairs_count(key_type), key_type)
        for key_type in key_types
    ]

    (count, key_type) = min(free_keys_counts)

    if count >= max_free_keys_per_type:
        return False

    keypair = key_generation_func(key_type=key_type, serialize=True)
    key_storage.add_free_keypair(
        key_type=key_type,
        public_key=keypair["public_key"],
        private_key=keypair["private_key"],
    )
    logger.debug("New free key of type %s pregenerated" % key_type)
    return True


def get_free_keys_generator_worker(
    key_storage: KeyStorageBase,
    max_free_keys_per_type: int,
    sleep_on_overflow_s: float,
    **extra_generation_kwargs,
) -> PeriodicTaskHandler:
    """
    Return a periodic task handler which will gradually fill the pools of free keys of the key storage,
    and wait longer when these pools are full.
    
    :param key_storage: the key storage to use 
    :param max_free_keys_per_type: how many free keys should exist per key type
    :param sleep_on_overflow_s: time to wait when free keys pools are full
    :param extra_generation_kwargs: extra arguments to transmit to `generate_free_keypair_for_least_provisioned_key_type()`
    :return: periodic task handler
    """

    def free_keypair_generator_task():
        has_generated = generate_free_keypair_for_least_provisioned_key_type(
            key_storage=key_storage,
            max_free_keys_per_type=max_free_keys_per_type,
            **extra_generation_kwargs,
        )
        # FIXME - improve this with refactored multitimer, later
        if not has_generated:
            time.sleep(sleep_on_overflow_s)
        return has_generated

    periodic_task_handler = PeriodicTaskHandler(
        interval_s=0.001, task_func=free_keypair_generator_task
    )
    return periodic_task_handler
