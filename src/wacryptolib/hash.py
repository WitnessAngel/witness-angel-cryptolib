# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
from wacryptolib import _crypto_backend

logger = logging.getLogger(__name__)


#: Hash algorithms authorized for use with `hash_message()`
SUPPORTED_HASH_ALGOS = _crypto_backend._SUPPORTED_HASH_ALGOS
logger.debug(f"Supported hash algorithms: {SUPPORTED_HASH_ALGOS}")


def hash_message(message: bytes, hash_algo: str):
    """Hash a message with the selected hash algorithm, and return the hash as bytes."""
    if hash_algo not in SUPPORTED_HASH_ALGOS:
        raise ValueError("Unsupported hash algorithm %r" % hash_algo)
    hasher = _crypto_backend.get_hasher_instance(hash_algo)
    hasher.update(message)
    digest = hasher.digest()
    assert 32 <= len(digest) <= 64, len(digest)
    return digest
