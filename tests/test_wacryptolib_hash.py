# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later
import importlib
import random

import pytest

from wacryptolib._crypto_backend import get_random_bytes, IMPLEMENTED_HASH_ALGOS
from wacryptolib.hash import SUPPORTED_HASH_ALGOS, hash_message


def test_hash_message():
    bytestring = get_random_bytes(1000)

    assert SUPPORTED_HASH_ALGOS == IMPLEMENTED_HASH_ALGOS  # On recent CPython
    assert len(SUPPORTED_HASH_ALGOS) == 4  # For now on PC OS

    for hash_algo in SUPPORTED_HASH_ALGOS:
        digest1 = hash_message(bytestring, hash_algo=hash_algo)
        assert 32 <= len(digest1) <= 64, len(digest1)
        digest2 = hash_message(bytestring, hash_algo=hash_algo)
        assert digest1 == digest2

    with pytest.raises(ValueError, match="Unsupported"):
        hash_message(bytestring, hash_algo="XYZ")


def test_compatibility_with_pycryptodome_hashers():

    assert len(SUPPORTED_HASH_ALGOS) == 4  # For now on PC OS

    for i in range(3):  # Attempt several messages

        message = get_random_bytes(random.randint(0, 10000))

        for hash_algo in SUPPORTED_HASH_ALGOS:
            local_digest = hash_message(message, hash_algo=hash_algo)

            pycryptodome_module = importlib.import_module("Crypto.Hash.%s" % hash_algo)
            pycryptodome_instance = pycryptodome_module.new()
            pycryptodome_instance.update(message)
            pycryptodome_digest = pycryptodome_instance.digest()

            assert local_digest == pycryptodome_digest  # SAME RESULT!
