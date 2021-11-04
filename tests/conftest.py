from unittest.mock import patch
import functools
import pytest


# Ensure that test scaffolding benefits from advanced assertions
pytest.register_assert_rewrite("wacryptolib.scaffolding")


@pytest.fixture(autouse=True, scope="session")
def _generate_asymmetric_keypair_caching():

    import wacryptolib.key_generation
    original_generator = wacryptolib.key_generation._do_generate_asymmetric_keypair
    wacryptolib.key_generation.__original_do_generate_asymmetric_keypair = original_generator
    cached_generator = functools.lru_cache(original_generator)

    with patch('wacryptolib.key_generation._do_generate_asymmetric_keypair', cached_generator):
        yield
