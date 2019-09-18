import random

import pytest
from Crypto.PublicKey import RSA, ECC, DSA

import wacryptolib
from wacryptolib.key_generation import (
    load_asymmetric_key_from_pem_bytestring,
    SUPPORTED_ASYMMETRIC_KEY_TYPES,
    SUPPORTED_SYMMETRIC_KEY_ALGOS)


@pytest.mark.parametrize("key_type", SUPPORTED_ASYMMETRIC_KEY_TYPES)
def test_keypair_unicity(key_type):

    keypair1 = wacryptolib.key_generation.generate_asymmetric_keypair(key_type=key_type)
    keypair2 = wacryptolib.key_generation.generate_asymmetric_keypair(key_type=key_type)

    assert keypair1 != keypair2


@pytest.mark.parametrize("encryption_algo", SUPPORTED_SYMMETRIC_KEY_ALGOS)
def test_symmetric_key_generation(encryption_algo):
    key = wacryptolib.key_generation.generate_symmetric_key(encryption_algo=encryption_algo)
    assert isinstance(key, bytes)
    assert len(key) == 32  # Always max size


def test_generic_symmetric_key_generation_errors():
    with pytest.raises(ValueError, match="Unknown symmetric key algorithm"):
        wacryptolib.key_generation.generate_symmetric_key(encryption_algo="AXSX")


def test_generic_asymmetric_key_generation_errors():
    with pytest.raises(ValueError, match="Unknown asymmetric key type"):
        wacryptolib.key_generation.generate_asymmetric_keypair(key_type="AONEG")


def test_rsa_asymmetric_key_generation():

    with pytest.raises(ValueError, match="asymmetric key length"):
        wacryptolib.key_generation.generate_asymmetric_keypair(
            key_type="RSA", key_length=1024
        )

    for key_length in (None, 2048):
        extra_parameters = dict(key_length=key_length) if key_length else {}
        keypair = wacryptolib.key_generation.generate_asymmetric_keypair(
            key_type="RSA", **extra_parameters
        )
        key = RSA.import_key(keypair["private_key"])
        assert isinstance(key, RSA.RsaKey)


def test_dsa_asymmetric_key_generation():

    with pytest.raises(ValueError, match="asymmetric key length"):
        wacryptolib.key_generation.generate_asymmetric_keypair(
            key_type="DSA", key_length=1024
        )

    for key_length in (None, 2048):
        extra_parameters = dict(key_length=key_length) if key_length else {}
        keypair = wacryptolib.key_generation.generate_asymmetric_keypair(
            key_type="DSA", **extra_parameters
        )
        key = DSA.import_key(keypair["private_key"])
        assert isinstance(key, DSA.DsaKey)


def test_ecc_asymmetric_key_generation():

    with pytest.raises(ValueError, match="Unexisting ECC curve"):
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
