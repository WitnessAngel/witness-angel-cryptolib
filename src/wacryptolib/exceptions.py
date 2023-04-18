class FunctionalError(Exception):
    """Base class for all 'normal' errors of the API"""

    pass


# ---


class ExistenceError(FunctionalError):
    pass


class KeyDoesNotExist(ExistenceError):
    pass


class KeyAlreadyExists(ExistenceError):
    pass


class KeystoreDoesNotExist(ExistenceError):
    pass


class KeystoreAlreadyExists(ExistenceError):
    pass


class KeystoreMetadataDoesNotExist(KeystoreDoesNotExist):
    pass
    # No KeystoreMetadataAlreadyExists needed for now


# ---


class AuthenticationError(FunctionalError):
    pass  # E.g. the "secret" provided with an API request doesn't match that stored


class AuthorizationError(FunctionalError):
    pass  # E.g. no authorization has been pre-obtained before a trustee.decrypt_with_private_key()


class OperationNotSupported(FunctionalError):
    pass  # E.g. listing keypairs from a big SQL database


# ---


class CryptographyError(FunctionalError):
    pass


class EncryptionError(CryptographyError):
    pass


class DecryptionError(CryptographyError):
    pass


class DecryptionIntegrityError(DecryptionError):
    pass  # E.g. MAC tags check failed


class SignatureCreationError(CryptographyError):
    pass


class SignatureVerificationError(CryptographyError):
    pass


class KeyLoadingError(CryptographyError):
    pass  # Used e.g. when decrypting a private key with a passphrase fails


# ---


class ValidationError(FunctionalError):
    pass  # Base for all errors related to corrupted data, and invalid config tree, and bad command parameters


class SchemaValidationError(ValidationError):
    pass  # When data doesn't respect json format, or an additional python-schema, or some additional security constraints
