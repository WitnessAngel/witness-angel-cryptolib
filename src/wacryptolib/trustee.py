import logging
import uuid
from typing import Optional, Sequence

from wacryptolib.cipher import decrypt_bytestring
from wacryptolib.exceptions import KeyDoesNotExist, AuthorizationError, KeyLoadingError, ValidationError
from wacryptolib.keygen import load_asymmetric_key_from_pem_bytestring
from wacryptolib.keystore import KeystoreBase, generate_keypair_for_storage
from wacryptolib.signature import sign_message

logger = logging.getLogger(__name__)


MAX_PAYLOAD_LENGTH_FOR_SIGNATURE = 128  # Max 2*SHA512 length


class TrusteeApi:
    """
    This is the API meant to be exposed by trustee webservices, to allow end users to create safely encrypted cryptainers.

    Subclasses must add their own permission checking, especially so that no decryption with private keys can occur
    outside the scope of a well defined legal procedure.
    """

    def __init__(self, keystore: KeystoreBase):
        self._keystore = keystore

    def _ensure_keypair_exists(self, keychain_uid: uuid.UUID, key_algo: str):
        """Create a keypair if it doesn't exist."""

        try:
            self._keystore.get_public_key(
                keychain_uid=keychain_uid, key_algo=key_algo
            )  # FIXME BUGGY, we might need PRIVATE KEY too, analyse this!
        except KeyDoesNotExist:
            pass
        else:
            return  # Ok the key is available!

        try:
            self._keystore.attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_algo=key_algo)
        except KeyDoesNotExist:
            generate_keypair_for_storage(
                key_algo=key_algo, keystore=self._keystore, keychain_uid=keychain_uid, passphrase=None
            )

    def fetch_public_key(self, *, keychain_uid: uuid.UUID, key_algo: str, must_exist: bool = False) -> bytes:
        """
        Return a public key in PEM format bytestring, that caller shall use to encrypt its own symmetric keys,
        or to check a signature.

        If `must_exist` is True, key is not autogenerated, and a KeyDoesNotExist might be raised.
        """
        logger.debug("Trustee proxy: fetching public key %s/%s (must_exist=%s)", key_algo, keychain_uid, must_exist)
        if not must_exist:
            self._ensure_keypair_exists(keychain_uid=keychain_uid, key_algo=key_algo)
        return self._keystore.get_public_key(
            keychain_uid=keychain_uid, key_algo=key_algo
        )  # Let the exception flow if any

    def get_message_signature(self, *, message: bytes, keychain_uid: uuid.UUID, signature_algo: str) -> dict:
        """
        Return a signature structure corresponding to the provided key and signature types.
        """
        logger.debug("Trustee proxy: getting message signature using key %s/%s", signature_algo, keychain_uid)

        if len(message) > MAX_PAYLOAD_LENGTH_FOR_SIGNATURE:  # SECURITY
            raise ValidationError("Message too big for signing, only a hash should be sent")

        self._ensure_keypair_exists(keychain_uid=keychain_uid, key_algo=signature_algo)

        private_key_pem = self._keystore.get_private_key(keychain_uid=keychain_uid, key_algo=signature_algo)

        private_key = load_asymmetric_key_from_pem_bytestring(key_pem=private_key_pem, key_algo=signature_algo)

        signature_dict = sign_message(message=message, signature_algo=signature_algo, private_key=private_key)
        return signature_dict

    def _check_keypair_authorization(self, *, keychain_uid: uuid.UUID, key_algo: str):
        """raises a proper exception if authorization is not given yet to decrypt with this keypair."""
        return  # In this base implementation we always allow decryption!

    def _decrypt_private_key_pem_with_passphrases(
        self, *, private_key_pem: bytes, keychain_uid: uuid.UUID, key_algo: str, passphrases: Optional[list]
    ):
        """
        Attempt decryption of key with and without provided passphrases, and raise if all fail.
        """
        for passphrase in [None] + passphrases:
            try:
                key_obj = load_asymmetric_key_from_pem_bytestring(
                    key_pem=private_key_pem, key_algo=key_algo, passphrase=passphrase
                )
                return key_obj
            except KeyLoadingError:
                pass
        raise KeyLoadingError(
            "Could not decrypt private key %s of type %s (passphrases provided: %d)"
            % (keychain_uid, key_algo, len(passphrases))
        )

    def request_decryption_authorization(
        self,
        keypair_identifiers: Sequence,
        request_message: str,
        passphrases: Optional[Sequence] = None,
        cryptainer_metadata: Optional[dict] = None,
    ) -> dict:
        """
        Send a list of keypairs for which decryption access is requested, with the reason why.

        If request is immediately denied, an exception is raised, else the status of the authorization process
        (process which might involve several steps, including live encounters) is returned.

        :param keypair_identifiers: list of dicts with (keychain_uid, key_algo) indices to authorize
        :param request_message: user text explaining the reasons for the decryption (and the legal procedures involved)
        :param passphrases: optional list of passphrases to be tried on private keys
        :param cryptainer_metadata: metadata of the concerned cryptainer

        :return: a dict with at least a string field "response_message" detailing the status of the request.
        """
        logger.debug(
            "Trustee proxy: requesting decryption authorization for %d keypairs (%d passphrases submitted)",
            len(keypair_identifiers),
            len(passphrases or ()),
        )

        passphrases = passphrases or []
        assert isinstance(passphrases, (tuple, list)), repr(passphrases)

        if not keypair_identifiers:
            raise ValueError("Keypair identifiers must not be empty, when requesting decryption authorization")

        missing_private_key = []
        authorization_missing = []
        missing_passphrase = []
        accepted = []

        for keypair_identifier in keypair_identifiers:
            keychain_uid = keypair_identifier["keychain_uid"]
            key_algo = keypair_identifier["key_algo"]

            try:
                self._check_keypair_authorization(keychain_uid=keychain_uid, key_algo=key_algo)
            except AuthorizationError:
                authorization_missing.append(keypair_identifier)
                continue
            else:
                pass  # It's OK, at least we are authorized now

            try:
                private_key_pem = self._keystore.get_private_key(keychain_uid=keychain_uid, key_algo=key_algo)
            except KeyDoesNotExist:
                missing_private_key.append(keypair_identifier)
                continue

            try:
                res = self._decrypt_private_key_pem_with_passphrases(
                    private_key_pem=private_key_pem,
                    keychain_uid=keychain_uid,
                    key_algo=key_algo,
                    passphrases=passphrases,
                )
                assert res, repr(res)
            except KeyLoadingError:
                missing_passphrase.append(keypair_identifier)
                continue

            accepted.append(keypair_identifier)  # Check is OVER for this keypair!

        keypair_statuses = dict(
            missing_private_key=missing_private_key,
            authorization_missing=authorization_missing,
            missing_passphrase=missing_passphrase,
            accepted=accepted,
        )

        has_errors = len(accepted) < len(keypair_identifiers)
        assert sum(len(x) for x in keypair_statuses.values()) == len(keypair_identifiers), locals()

        return dict(
            response_message="Decryption request denied" if has_errors else "Decryption request accepted",
            has_errors=has_errors,
            keypair_statuses=keypair_statuses,
        )  # TODO localize (i18n) string field someday!

    def decrypt_with_private_key(
        self,
        *,
        keychain_uid: uuid.UUID,
        cipher_algo: str,
        cipherdict: dict,
        passphrases: Optional[list] = None,
        cryptainer_metadata: Optional[dict] = None
    ) -> bytes:
        """
        Return the message (probably a symmetric key) decrypted with the corresponding key,
        as bytestring. Here again passphrases and cryptainer_metadata can be provided.

        Raises if key existence, authorization or passphrase errors occur.
        """
        assert cipher_algo.upper() == "RSA_OAEP"  # Only supported asymmetric cipher for now

        logger.debug(
            "Trustee proxy: decrypting cipherdict with private key %s/%s (%d passphrases submitted)",
            cipher_algo,
            keychain_uid,
            len(passphrases or ()),
        )

        passphrases = passphrases or []
        assert isinstance(passphrases, (tuple, list)), repr(passphrases)

        private_key_pem = self._keystore.get_private_key(keychain_uid=keychain_uid, key_algo=cipher_algo)

        private_key = self._decrypt_private_key_pem_with_passphrases(
            private_key_pem=private_key_pem, keychain_uid=keychain_uid, key_algo=cipher_algo, passphrases=passphrases
        )

        # We expect a well-formed JSON structure in key_struct_bytes, to possibly check its metadata
        key_struct_bytes = decrypt_bytestring(
            cipherdict=cipherdict, cipher_algo=cipher_algo, key_dict=dict(key=private_key)
        )
        assert isinstance(key_struct_bytes, bytes), key_struct_bytes
        return key_struct_bytes


class ReadonlyTrusteeApi(TrusteeApi):
    """
    Alternative Trustee API which relies on a fixed set of keys (e.g. imported from a key-device).

    This version never generates keys by itself, whatever the values of method parameters like `must_exist`.
    """

    def _ensure_keypair_exists(self, keychain_uid: uuid.UUID, key_algo: str):
        try:
            self._keystore.get_public_key(keychain_uid=keychain_uid, key_algo=key_algo)
        except KeyDoesNotExist:
            # Just tweak the error message here
            raise KeyDoesNotExist("Keypair %s/%s not found in readonly trustee api" % (key_algo, keychain_uid))
