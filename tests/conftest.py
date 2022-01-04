import functools
from unittest.mock import patch

import pytest

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
