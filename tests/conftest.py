from unittest.mock import patch
import functools
import pytest


# Ensure that test scaffolding benefits from advanced assertions
pytest.register_assert_rewrite("wacryptolib.scaffolding")


@pytest.fixture(autouse=True, scope="session")
def _generate_asymmetric_keypair_caching():
    """
    Generation of RSA/DSA/ECC keys can be extremfly time-consuming, so we CACHE and
    reuse the same keys for most tests !
    """

    import wacryptolib.key_generation
    original_generator = wacryptolib.key_generation._do_generate_asymmetric_keypair
    wacryptolib.key_generation.__original_do_generate_asymmetric_keypair = original_generator
    cached_generator = functools.lru_cache(maxsize=None)(original_generator)

    patcher = patch('wacryptolib.key_generation._do_generate_asymmetric_keypair', cached_generator)
    wacryptolib.key_generation.__original_do_generate_asymmetric_keypair_patcher = patcher  # To use stop()/start() in tests

    patcher.start()  # DO NOT use "with" statement here, else start/stop don't work anymore
    try:
        yield
    finally:  # Just for safety
        patcher.stop()
