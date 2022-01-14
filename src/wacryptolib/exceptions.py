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


# ---


class AuthorizationError(FunctionalError):
    pass


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
    pass  # Base for all errors related to corrupted data and invalid config tree


class SchemaValidationError(ValidationError):
    pass  # When data doesn't respect json format, or an additional python-schema, or some additional security constraints
