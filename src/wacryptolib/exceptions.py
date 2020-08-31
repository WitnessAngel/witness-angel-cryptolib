


class FunctionalError(Exception):
    """Base class for all 'normal' errors of the API"""
    pass


class KeyExistenceError(FunctionalError):
    pass


class KeyDoesNotExist(KeyExistenceError):
    pass


class KeyAlreadyExists(KeyExistenceError):
    pass
