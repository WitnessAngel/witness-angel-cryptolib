import pytest
import unicodedata
from Crypto.PublicKey import RSA, ECC, DSA

import wacryptolib
from wacryptolib.encryption import SUPPORTED_ENCRYPTION_ALGOS
from wacryptolib.exceptions import KeyLoadingError
from wacryptolib.key_generation import (
    load_asymmetric_key_from_pem_bytestring,
    SUPPORTED_ASYMMETRIC_KEY_TYPES,
    SUPPORTED_SYMMETRIC_KEY_ALGOS,
    encode_passphrase,
)
from wacryptolib.signature import SUPPORTED_SIGNATURE_ALGOS


def test_passphrase_encoding():
    assert encode_passphrase(" hello  ") == b"hello"
    assert encode_passphrase("ｱｲｳｴｵ ") == "アイウエオ".encode("utf8")
    assert encode_passphrase("パピプペポ") == "パピプペポ".encode("utf8")
    with pytest.raises(TypeError):
        encode_passphrase(b"abcd")


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

    for key_type in ("RSA_OAEP", "RSA_PSS"):  # Both use teh same RSA keys

        with pytest.raises(ValueError, match="asymmetric key length"):
            wacryptolib.key_generation.generate_asymmetric_keypair(key_type=key_type, key_length_bits=1024)

        for key_length_bits in (None, 2048):
            extra_parameters = dict(key_length_bits=key_length_bits) if key_length_bits else {}
            keypair = wacryptolib.key_generation.generate_asymmetric_keypair(key_type=key_type, **extra_parameters)
            assert isinstance(keypair["private_key"], bytes), keypair
            assert isinstance(keypair["public_key"], bytes), keypair

            key = RSA.import_key(keypair["private_key"])
            assert isinstance(key, RSA.RsaKey)


def test_dsa_asymmetric_key_generation():

    with pytest.raises(ValueError, match="asymmetric key length"):
        wacryptolib.key_generation.generate_asymmetric_keypair(key_type="DSA_DSS", key_length_bits=1024)

    for key_length_bits in (None, 2048):
        extra_parameters = dict(key_length_bits=key_length_bits) if key_length_bits else {}
        keypair = wacryptolib.key_generation.generate_asymmetric_keypair(key_type="DSA_DSS", **extra_parameters)
        assert isinstance(keypair["private_key"], bytes), keypair
        assert isinstance(keypair["public_key"], bytes), keypair

        key = DSA.import_key(keypair["private_key"])
        assert isinstance(key, DSA.DsaKey)


def test_ecc_asymmetric_key_generation():

    with pytest.raises(ValueError, match="Unexisting ECC curve"):
        wacryptolib.key_generation.generate_asymmetric_keypair(key_type="ECC_DSS", curve="unexisting")

    for curve in (None, "p384"):
        extra_parameters = dict(curve=curve) if curve else {}
        keypair = wacryptolib.key_generation.generate_asymmetric_keypair(key_type="ECC_DSS", **extra_parameters)
        assert isinstance(keypair["private_key"], bytes), keypair
        assert isinstance(keypair["public_key"], bytes), keypair

        key = ECC.import_key(keypair["private_key"])
        assert isinstance(key, ECC.EccKey)


def test_load_asymmetric_key_from_pem_bytestring():

    for key_type in SUPPORTED_ASYMMETRIC_KEY_TYPES:

        keypair = wacryptolib.key_generation.generate_asymmetric_keypair(key_type=key_type)

        for field in ["private_key", "public_key"]:
            key = load_asymmetric_key_from_pem_bytestring(key_pem=keypair[field], key_type=key_type)
            assert key.export_key  # Method of Key object

        with pytest.raises(ValueError, match="Unknown key type"):
            load_asymmetric_key_from_pem_bytestring(key_pem=keypair["private_key"], key_type="ZHD")


def test_generate_and_load_passphrase_protected_asymmetric_key():

    # Both Unicode and Bytes are supported
    passphrases = ["Thïs is a passphrâse", b"aoh18726"]

    for passphrase in passphrases:

        for key_type in SUPPORTED_ASYMMETRIC_KEY_TYPES:

            keypair = wacryptolib.key_generation.generate_asymmetric_keypair(key_type=key_type, passphrase=passphrase)

            public_key = load_asymmetric_key_from_pem_bytestring(
                key_pem=keypair["public_key"], key_type=key_type  # NOT encrypted
            )
            assert public_key.export_key

            if isinstance(passphrase, str):  # Different unicode représentations work fine
                passphrase = unicodedata.normalize("NFD", passphrase)

            private_key = load_asymmetric_key_from_pem_bytestring(
                key_pem=keypair["private_key"], key_type=key_type, passphrase=passphrase  # Encrypted
            )
            assert private_key.export_key

            error_matcher = "key format is not supported|Invalid DER encoding"

            with pytest.raises(KeyLoadingError, match=error_matcher):
                load_asymmetric_key_from_pem_bytestring(
                    key_pem=keypair["private_key"], key_type=key_type, passphrase=b"wrong passphrase"
                )

            with pytest.raises(KeyLoadingError, match=error_matcher):
                load_asymmetric_key_from_pem_bytestring(
                    key_pem=keypair["private_key"], key_type=key_type, passphrase=None  # Missing passphrase
                )


def test_key_types_mapping_and_isolation():

    # We separate keys for encryption and signature (especially for RSA)!
    assert not set(SUPPORTED_ENCRYPTION_ALGOS) & set(SUPPORTED_SIGNATURE_ALGOS)

    # All these signature algos use asymmetric keys
    assert set(SUPPORTED_SIGNATURE_ALGOS) <= set(SUPPORTED_ASYMMETRIC_KEY_TYPES)

    # Some encryption algos are symmetric, and use simple keys of random bytes
    asymmetric_key_types = set(SUPPORTED_ENCRYPTION_ALGOS) - set(SUPPORTED_SYMMETRIC_KEY_ALGOS)
    assert asymmetric_key_types <= set(SUPPORTED_ASYMMETRIC_KEY_TYPES)
