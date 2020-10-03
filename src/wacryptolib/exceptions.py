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


class KeyStorageDoesNotExist(ExistenceError):
    pass


class KeyStorageAlreadyExists(ExistenceError):
    pass


# ---


class AuthorizationError(FunctionalError):
    pass


# ---


class CryptographyError(FunctionalError):
    pass


class EncryptionError(CryptographyError):
    pass


class DecryptionError(CryptographyError):
    pass


class SignatureCreationError(CryptographyError):
    pass


class SignatureVerificationError(CryptographyError):
    pass


class KeyLoadingError(CryptographyError):
    pass  # Used e.g. when decrypting a private key with a passphrase fails


# TODO add ValidationError class, and/or WorkflowError?
