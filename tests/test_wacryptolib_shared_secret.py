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

        shares = wacryptolib.shared_secret.split_bytestring_as_shamir_shares(
            secret=secret, shares_count=shares_count, threshold_count=threshold_count
        )
        assert len(shares) == shares_count

        selected_shares = random.sample(shares, k=threshold_count)
        secret_reconstructed = wacryptolib.shared_secret.recombine_secret_from_shamir_shares(selected_shares)
        assert secret_reconstructed == secret  # Just enough shares

        selected_shares = random.sample(shares, k=threshold_count + 1)
        secret_reconstructed = wacryptolib.shared_secret.recombine_secret_from_shamir_shares(selected_shares)
        assert secret_reconstructed == secret  # With MORE shares it works too

        selected_shares = shares
        secret_reconstructed = wacryptolib.shared_secret.recombine_secret_from_shamir_shares(selected_shares)
        assert secret_reconstructed == secret  # With ALL shares it works too

        if threshold_count > 1:
            selected_shares = random.sample(shares, k=threshold_count - 1)
            try:
                secret_reconstructed = wacryptolib.shared_secret.recombine_secret_from_shamir_shares(selected_shares)
            except ValueError:  # Bad reconstructed padding etc.
                pass
            else:
                assert secret_reconstructed != secret  # We MIGHT get a wrong bytestring unknowingly


def test_shared_secret_corner_cases():

    with pytest.raises(ValueError):
        wacryptolib.shared_secret.recombine_secret_from_shamir_shares([])

    secret = get_random_bytes(50)

    with pytest.raises(ValueError):
        wacryptolib.shared_secret.split_bytestring_as_shamir_shares(secret=secret, shares_count=0, threshold_count=0)

    with pytest.raises(ValueError):
        wacryptolib.shared_secret.split_bytestring_as_shamir_shares(secret=secret, shares_count=2, threshold_count=3)

    with pytest.raises(ValueError):
        wacryptolib.shared_secret.recombine_secret_from_shamir_shares([])
