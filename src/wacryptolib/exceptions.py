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


class DecryptionIntegrityError(DecryptionError):
    pass  # E.g. MAC/tag check failed


class SignatureCreationError(CryptographyError):
    pass


class SignatureVerificationError(CryptographyError):
    pass


class KeyLoadingError(CryptographyError):
    pass  # Used e.g. when decrypting a private key with a passphrase fails


# ---

class ConfigurationError(FunctionalError):
    pass  # used e.g. if encryption strata list is empty, thus endangering confidentiality

# TODO add ValidationError class, and/or WorkflowError?

class ValidationError(FunctionalError):
    pass  # used e.g. if encryption strata list is empty, thus endangering confidentiality