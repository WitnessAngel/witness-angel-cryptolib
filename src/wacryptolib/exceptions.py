


class FunctionalError(Exception):
    """Base class for all 'normal' errors of the API"""
    pass


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
