import random

import pytest
from Crypto.Random import get_random_bytes

import wacryptolib.shared_secret


def test_shared_secret_normal_cases():

    for _ in range(5):

        bytes_length = random.randint(1, 500)

        secret = get_random_bytes(bytes_length)
        shares_count = random.randint(2, 10)
        threshold_count = random.randint(1, shares_count - 1)

        shards = wacryptolib.shared_secret.split_bytestring_as_shamir_shards(
            secret=secret, shares_count=shares_count, threshold_count=threshold_count
        )
        assert len(shards) == shares_count

        selected_shards = random.sample(shards, k=threshold_count)
        secret_reconstructed = wacryptolib.shared_secret.recombine_secret_from_shamir_shards(selected_shards)
        assert secret_reconstructed == secret  # Just enough shards

        selected_shards = random.sample(shards, k=threshold_count + 1)
        secret_reconstructed = wacryptolib.shared_secret.recombine_secret_from_shamir_shards(selected_shards)
        assert secret_reconstructed == secret  # With MORE shards it works too

        selected_shards = shards
        secret_reconstructed = wacryptolib.shared_secret.recombine_secret_from_shamir_shards(selected_shards)
        assert secret_reconstructed == secret  # With ALL shards it works too

        if threshold_count > 1:
            selected_shards = random.sample(shards, k=threshold_count - 1)
            try:
                secret_reconstructed = wacryptolib.shared_secret.recombine_secret_from_shamir_shards(selected_shards)
            except ValueError:  # Bad reconstructed padding etc.
                pass
            else:
                assert secret_reconstructed != secret  # We MIGHT get a wrong bytestring unknowingly

        with pytest.raises(ValueError, match="unique indices"):
            wacryptolib.shared_secret.recombine_secret_from_shamir_shards(selected_shards + [selected_shards[0]])


def test_shared_secret_corner_cases():

    with pytest.raises(ValueError):
        wacryptolib.shared_secret.recombine_secret_from_shamir_shards([])

    secret = get_random_bytes(50)

    with pytest.raises(ValueError):
        wacryptolib.shared_secret.split_bytestring_as_shamir_shards(secret=secret, shares_count=0, threshold_count=0)

    with pytest.raises(ValueError):
        wacryptolib.shared_secret.split_bytestring_as_shamir_shards(secret=secret, shares_count=2, threshold_count=3)

    with pytest.raises(ValueError):
        wacryptolib.shared_secret.recombine_secret_from_shamir_shards([])

    shards = wacryptolib.shared_secret.split_bytestring_as_shamir_shards(secret=secret, shares_count=3, threshold_count=3)
    assert wacryptolib.shared_secret.recombine_secret_from_shamir_shards(shards) == secret

    try:
        secret_reconstructed = wacryptolib.shared_secret.recombine_secret_from_shamir_shards(shards[:-1])
    except ValueError:  # Bad reconstructed padding etc.
        pass
    else:
        assert secret_reconstructed != secret  # We MIGHT get a wrong bytestring unknowingly
