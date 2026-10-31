# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os


logger = logging.getLogger(__name__)

_FALLBACK_EXTRA_PACKAGES = ("pkcs1", "pyaes", "ecdsa", "six")  # "six" is a dependency of ecdsa


def _is_fallback_backend_forced():
    # Else e.g. "0" would silently force the slow and non-constant-time fallback backend
    return os.getenv("FORCE_WACRYPTOLIB_FALLBACK_BACKEND", "").strip().lower() not in ("", "0", "false", "no", "off")


def _is_native_backend_usable():
    if _is_fallback_backend_forced():
        return False
    try:
        # Its module body loads a native library, and raises OSError when dlopen() is forbidden (e.g. iOS)
        from Crypto.Cipher import AES
    except (ImportError, OSError):
        return False
    return True


if _is_native_backend_usable():
    from .pycryptodome import *

    BACKEND_NAME = "pycryptodome"
else:
    try:
        from .fallback import *
    except ImportError as exc:
        if (exc.name or "").split(".")[0] not in _FALLBACK_EXTRA_PACKAGES:
            raise  # E.g. another missing dependency of wacryptolib, which the 'fallbacks' extra wouldn't provide
        if _is_fallback_backend_forced():
            raise ImportError(
                "FORCE_WACRYPTOLIB_FALLBACK_BACKEND is set, but the pure-python packages of the 'fallbacks' extra "
                "are missing (%s)" % exc
            ) from exc
        raise ImportError(
            "No usable crypto backend: install pycryptodome (default dependency of wacryptolib), or, on platforms "
            "where it can't load, the pure-python packages of the 'fallbacks' extra (%s)" % exc
        ) from exc

    BACKEND_NAME = "fallback"

logger.info("Using %s crypto backend", BACKEND_NAME)


# RANDOMNESS #
def get_random_bytes(nbytes):
    """Like pycryptodome, we rely on the randomness of the OS!"""
    return os.urandom(nbytes)


# SHAMIR SHARED SECRETS #
# We always use the vendored version #

from .vendor.PycryptodomeSecretSharing import Shamir as _Shamir


def shamir_128b_split_func(*args, **kwargs):
    return _Shamir.split(*args, **kwargs)


def shamir_128b_combine_func(*args, **kwargs):
    return _Shamir.combine(*args, **kwargs)

