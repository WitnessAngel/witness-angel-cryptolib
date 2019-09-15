import random

import pytest
from Crypto.PublicKey import RSA, ECC, DSA

import wacryptolib
from wacryptolib.key_generation import (
    load_asymmetric_key_from_pem_bytestring,
    SUPPORTED_ASYMMETRIC_KEY_TYPES,
)


@pytest.mark.parametrize("key_type", ["RSA", "ECC", "DSA"])
def test_keypair_unicity(key_type):

    keypair1 = wacryptolib.key_generation.generate_asymmetric_keypair(key_type=key_type)
    keypair2 = wacryptolib.key_generation.generate_asymmetric_keypair(key_type=key_type)

    assert keypair1 != keypair2


def test_generic_asymmetric_key_generation_errors():
    with pytest.raises(ValueError, match="Unknown asymmetric key type"):
        wacryptolib.key_generation.generate_asymmetric_keypair(key_type="AONEG")


def test_rsa_asymmetric_key_generation():

    with pytest.raises(ValueError):
        wacryptolib.key_generation.generate_asymmetric_keypair(
            key_type="RSA", key_length=1023
        )

    for key_length in (None, 2048):
        extra_parameters = dict(key_length=key_length) if key_length else {}
        keypair = wacryptolib.key_generation.generate_asymmetric_keypair(
            key_type="RSA", **extra_parameters
        )
        key = RSA.import_key(keypair["private_key"])
        assert isinstance(key, RSA.RsaKey)


def test_dsa_asymmetric_key_generation():

    with pytest.raises(ValueError):
        wacryptolib.key_generation.generate_asymmetric_keypair(
            key_type="DSA", key_length=2047
        )

    for key_length in (None, 2048):
        extra_parameters = dict(key_length=key_length) if key_length else {}
        keypair = wacryptolib.key_generation.generate_asymmetric_keypair(
            key_type="DSA", **extra_parameters
        )
        key = DSA.import_key(keypair["private_key"])
        assert isinstance(key, DSA.DsaKey)


def test_ecc_asymmetric_key_generation():

    with pytest.raises(ValueError):
        wacryptolib.key_generation.generate_asymmetric_keypair(
            key_type="ECC", curve="unexisting"
        )

    for curve in (None, "p384"):
        extra_parameters = dict(curve=curve) if curve else {}
        keypair = wacryptolib.key_generation.generate_asymmetric_keypair(
            key_type="ECC", **extra_parameters
        )
        key = ECC.import_key(keypair["private_key"])
        assert isinstance(key, ECC.EccKey)


def test_load_asymmetric_key_from_pem_bytestring():

    key_type = random.choice(SUPPORTED_ASYMMETRIC_KEY_TYPES)

    keypair = wacryptolib.key_generation.generate_asymmetric_keypair(key_type=key_type)

    for field in ["private_key", "public_key"]:
        key = load_asymmetric_key_from_pem_bytestring(
            key_pem=keypair[field], key_type=key_type
        )
        assert key.export_key  # Method of Key bject

    with pytest.raises(ValueError, match="Unknown key type"):
        load_asymmetric_key_from_pem_bytestring(
            key_pem=keypair["private_key"], key_type="ZHD"
        )
