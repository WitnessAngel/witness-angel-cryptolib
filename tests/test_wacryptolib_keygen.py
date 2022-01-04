import unicodedata

import pytest
from Crypto.PublicKey import RSA, ECC, DSA

import wacryptolib
from wacryptolib.cipher import SUPPORTED_CIPHER_ALGOS
from wacryptolib.exceptions import KeyLoadingError
from wacryptolib.keygen import (
    load_asymmetric_key_from_pem_bytestring,
    SUPPORTED_ASYMMETRIC_KEY_ALGOS,
    SUPPORTED_SYMMETRIC_KEY_ALGOS,
    _encode_passphrase,
)
from wacryptolib.signature import SUPPORTED_SIGNATURE_ALGOS


def test_passphrase_encoding():
    assert _encode_passphrase(" hello  ") == b"hello"
    assert _encode_passphrase("ｱｲｳｴｵ ") == "アイウエオ".encode("utf8")
    assert _encode_passphrase("パピプペポ") == "パピプペポ".encode("utf8")
    with pytest.raises(TypeError):
        _encode_passphrase(b"abcd")


@pytest.mark.parametrize("key_algo", SUPPORTED_ASYMMETRIC_KEY_ALGOS)
def test_keypair_unicity(key_algo):

    # We must reuse test-specific caching of asymmetric keypairs, for this test
    wacryptolib.keygen.__original_do_generate_keypair_patcher.stop()
    assert wacryptolib.keygen._do_generate_keypair == wacryptolib.keygen.__original_do_generate_keypair

    try:

        keypair1 = wacryptolib.keygen.generate_keypair(key_algo=key_algo)
        keypair2 = wacryptolib.keygen.generate_keypair(key_algo=key_algo)

        assert keypair1 != keypair2

    finally:
        wacryptolib.keygen.__original_do_generate_keypair_patcher.start()


@pytest.mark.parametrize("cipher_algo", SUPPORTED_SYMMETRIC_KEY_ALGOS)
def test_symmetric_keygen(cipher_algo):
    key_dict = wacryptolib.keygen.generate_symkey(cipher_algo=cipher_algo)
    main_key = key_dict["key"]
    assert isinstance(main_key, bytes)
    assert len(main_key) == 32  # Always max size


def test_generic_symmetric_keygen_errors():
    with pytest.raises(ValueError, match="Unknown symmetric key algorithm"):
        wacryptolib.keygen.generate_symkey(cipher_algo="AXSX")


def test_generic_keypair_generation_errors():
    with pytest.raises(ValueError, match="Unknown asymmetric key type"):
        wacryptolib.keygen.generate_keypair(key_algo="AONEG")


def test_rsa_keypair_generation():

    for key_algo in ("RSA_OAEP", "RSA_PSS"):  # Both use teh same RSA keys

        with pytest.raises(ValueError, match="asymmetric key length"):
            wacryptolib.keygen.generate_keypair(key_algo=key_algo, key_length_bits=1024)

        for key_length_bits in (None, 2048):
            extra_parameters = dict(key_length_bits=key_length_bits) if key_length_bits else {}
            keypair = wacryptolib.keygen.generate_keypair(key_algo=key_algo, **extra_parameters)
            assert isinstance(keypair["private_key"], bytes), keypair
            assert isinstance(keypair["public_key"], bytes), keypair

            key = RSA.import_key(keypair["private_key"])
            assert isinstance(key, RSA.RsaKey)


def test_dsa_keypair_generation():

    with pytest.raises(ValueError, match="asymmetric key length"):
        wacryptolib.keygen.generate_keypair(key_algo="DSA_DSS", key_length_bits=1024)

    for key_length_bits in (None, 2048):
        extra_parameters = dict(key_length_bits=key_length_bits) if key_length_bits else {}
        keypair = wacryptolib.keygen.generate_keypair(key_algo="DSA_DSS", **extra_parameters)
        assert isinstance(keypair["private_key"], bytes), keypair
        assert isinstance(keypair["public_key"], bytes), keypair

        key = DSA.import_key(keypair["private_key"])
        assert isinstance(key, DSA.DsaKey)


def test_ecc_keypair_generation():

    with pytest.raises(ValueError, match="Unexisting ECC curve"):
        wacryptolib.keygen.generate_keypair(key_algo="ECC_DSS", curve="unexisting")

    for curve in (None, "p384"):
        extra_parameters = dict(curve=curve) if curve else {}
        keypair = wacryptolib.keygen.generate_keypair(key_algo="ECC_DSS", **extra_parameters)
        assert isinstance(keypair["private_key"], bytes), keypair
        assert isinstance(keypair["public_key"], bytes), keypair

        key = ECC.import_key(keypair["private_key"])
        assert isinstance(key, ECC.EccKey)


def test_load_asymmetric_key_from_pem_bytestring():

    for key_algo in SUPPORTED_ASYMMETRIC_KEY_ALGOS:

        keypair = wacryptolib.keygen.generate_keypair(key_algo=key_algo)

        for field in ["private_key", "public_key"]:
            key = load_asymmetric_key_from_pem_bytestring(key_pem=keypair[field], key_algo=key_algo)
            assert key.export_key  # Method of Key object

        with pytest.raises(ValueError, match="Unknown key type"):
            load_asymmetric_key_from_pem_bytestring(key_pem=keypair["private_key"], key_algo="ZHD")


def test_generate_and_load_passphrase_protected_asymmetric_key():

    # Both Unicode and Bytes are supported
    passphrases = ["Thïs is a passphrâse", b"aoh18726"]

    for passphrase in passphrases:

        for key_algo in SUPPORTED_ASYMMETRIC_KEY_ALGOS:

            keypair = wacryptolib.keygen.generate_keypair(key_algo=key_algo, passphrase=passphrase)

            public_key = load_asymmetric_key_from_pem_bytestring(
                key_pem=keypair["public_key"], key_algo=key_algo  # NOT encrypted
            )
            assert public_key.export_key

            if isinstance(passphrase, str):  # Different unicode représentations work fine
                passphrase = unicodedata.normalize("NFD", passphrase)

            private_key = load_asymmetric_key_from_pem_bytestring(
                key_pem=keypair["private_key"], key_algo=key_algo, passphrase=passphrase  # Encrypted
            )
            assert private_key.export_key

            error_matcher = "key format is not supported|Invalid DER encoding"

            with pytest.raises(KeyLoadingError, match=error_matcher):
                load_asymmetric_key_from_pem_bytestring(
                    key_pem=keypair["private_key"], key_algo=key_algo, passphrase=b"wrong passphrase"
                )

            with pytest.raises(KeyLoadingError, match=error_matcher):
                load_asymmetric_key_from_pem_bytestring(
                    key_pem=keypair["private_key"], key_algo=key_algo, passphrase=None  # Missing passphrase
                )


def test_key_algos_mapping_and_isolation():

    # We separate keys for encryption and signature (especially for RSA)!
    assert not set(SUPPORTED_CIPHER_ALGOS) & set(SUPPORTED_SIGNATURE_ALGOS)

    # All these signature algos use asymmetric keys
    assert set(SUPPORTED_SIGNATURE_ALGOS) <= set(SUPPORTED_ASYMMETRIC_KEY_ALGOS)

    # Some encryption algos are symmetric, and use simple keys of random bytes
    asymmetric_key_algos = set(SUPPORTED_CIPHER_ALGOS) - set(SUPPORTED_SYMMETRIC_KEY_ALGOS)
    assert asymmetric_key_algos <= set(SUPPORTED_ASYMMETRIC_KEY_ALGOS)
