import functools
import logging
from unittest.mock import patch

import pytest

logging.getLogger().setLevel(logging.DEBUG)

# Ensure that test scaffolding benefits from advanced assertions
pytest.register_assert_rewrite("wacryptolib.scaffolding")


@pytest.fixture(autouse=True, scope="session")
def monkeypatch_generate_keypair_for_tests():
    """
    Generation of RSA/DSA/ECC keys can be extremfly time-consuming, so we CACHE and
    reuse the same keys for most tests !
    """

    import wacryptolib.keygen

    original_generator = wacryptolib.keygen._do_generate_keypair
    wacryptolib.keygen.__original_do_generate_keypair = original_generator
    cached_generator = functools.lru_cache(maxsize=None)(original_generator)

    patcher = patch("wacryptolib.keygen._do_generate_keypair", cached_generator)
    wacryptolib.keygen.__original_do_generate_keypair_patcher = patcher  # To use stop()/start() in tests

    patcher.start()  # DO NOT use "with" statement here, else start/stop don't work anymore
    try:
        yield
    finally:  # Just for safety
        patcher.stop()


def import_crypto_backend(name):
    """Import a crypto backend module directly (bypassing the backend selector), or skip the test."""
    import importlib

    try:
        if name == "pycryptodome":
            from Crypto.Cipher import AES  # Its import loads native code
        return importlib.import_module("wacryptolib._crypto_backend." + name)
    except (ImportError, OSError) as exc:
        pytest.skip("%s crypto backend is unavailable (missing %s)" % (name, getattr(exc, "name", None) or exc))


@pytest.fixture(params=["pycryptodome", "fallback"])
def backend(request):
    return import_crypto_backend(request.param)


@pytest.fixture(scope="module")
def both_backends():
    return import_crypto_backend("pycryptodome"), import_crypto_backend("fallback")
