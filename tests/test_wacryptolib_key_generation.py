import pytest
from Crypto.PublicKey import RSA, ECC, DSA

import uuid

import wacryptolib


@pytest.mark.parametrize(
    "key_type", ["RSA", "ECC"]
)  # TODO - "DSA" buggy see https://github.com/Legrandin/pycryptodome/issues/317
def test_keypair_unicity_for_provided_uid(key_type):
    uid1 = uuid.uuid4()
    uid2 = uuid.uuid4()

    keypair1 = wacryptolib.key_generation.generate_asymmetric_keypair(
        uid=uid1, key_type=key_type
    )
    keypair2 = wacryptolib.key_generation.generate_asymmetric_keypair(
        uid=uid1, key_type=key_type
    )  # Same UID
    keypair3 = wacryptolib.key_generation.generate_asymmetric_keypair(
        uid=uid2, key_type=key_type
    )

    assert keypair1 == keypair2
    assert keypair3 != keypair1


def test_rsa_asymmetric_key_generation():
    uid = uuid.uuid4()

    with pytest.raises(ValueError):
        wacryptolib.key_generation.generate_asymmetric_keypair(
            uid, key_type="RSA", key_length=1023
        )

    for key_length in (None, 1024):
        extra_parameters = dict(key_length=key_length) if key_length else {}
        keypair = wacryptolib.key_generation.generate_asymmetric_keypair(
            uid, key_type="RSA", **extra_parameters
        )
        key = RSA.import_key(keypair["private_key"])
        assert isinstance(key, RSA.RsaKey)


def test_dsa_asymmetric_key_generation():
    uid = uuid.uuid4()

    with pytest.raises(ValueError):
        wacryptolib.key_generation.generate_asymmetric_keypair(
            uid, key_type="DSA", key_length=1023
        )

    for key_length in (None, 1024):
        extra_parameters = dict(key_length=key_length) if key_length else {}
        keypair = wacryptolib.key_generation.generate_asymmetric_keypair(
            uid, key_type="DSA", **extra_parameters
        )
        key = DSA.import_key(keypair["private_key"])
        assert isinstance(key, DSA.DsaKey)


def test_ecc_asymmetric_key_generation():
    uid = uuid.uuid4()

    with pytest.raises(ValueError):
        wacryptolib.key_generation.generate_asymmetric_keypair(
            uid, key_type="ECC", curve="unexisting"
        )

    for curve in (None, "p384"):
        extra_parameters = dict(curve=curve) if curve else {}
        keypair = wacryptolib.key_generation.generate_asymmetric_keypair(
            uid, key_type="ECC", **extra_parameters
        )
        key = ECC.import_key(keypair["private_key"])
        assert isinstance(key, ECC.EccKey)
