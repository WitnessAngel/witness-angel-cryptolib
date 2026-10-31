# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
import unicodedata

import wacryptolib
from wacryptolib._crypto_backend import (
    rsa_key_class_fetcher,
    dsa_key_class_fetcher,
    ecc_key_class_fetcher,
    import_ecc_key_from_pem,
    import_dsa_key_from_pem,
    import_rsa_key_from_pem,
)
from wacryptolib.cipher import SUPPORTED_CIPHER_ALGOS
from wacryptolib.exceptions import KeyLoadingError
from wacryptolib.keygen import (
    load_asymmetric_key_from_pem_bytestring,
    SUPPORTED_ASYMMETRIC_KEY_ALGOS,
    SUPPORTED_SYMMETRIC_KEY_ALGOS,
    _encode_passphrase,
)
from wacryptolib.signature import SUPPORTED_SIGNATURE_ALGOS

from _test_mockups import skip_if_fallback_backend


def _check_is_asymmetric_key_object(key):
    from wacryptolib import _crypto_backend

    assert isinstance(  # isinstance() accepts nested tuples, as returned by some fetchers
        key,
        (
            _crypto_backend.rsa_key_class_fetcher(),
            _crypto_backend.dsa_key_class_fetcher(),
            _crypto_backend.ecc_key_class_fetcher(),
        ),
    )


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
    for key_algo in ("RSA_OAEP", "RSA_PSS"):  # Both use the same RSA keys
        with pytest.raises(ValueError, match="asymmetric key length"):
            wacryptolib.keygen.generate_keypair(key_algo=key_algo, key_length_bits=1024)

        for key_length_bits in (None, 2048):
            extra_parameters = dict(key_length_bits=key_length_bits) if key_length_bits else {}
            keypair = wacryptolib.keygen.generate_keypair(key_algo=key_algo, **extra_parameters)
            assert isinstance(keypair["private_key"], bytes), keypair
            assert isinstance(keypair["public_key"], bytes), keypair

            key = import_rsa_key_from_pem(keypair["private_key"])
            assert isinstance(key, rsa_key_class_fetcher())


def test_dsa_keypair_generation():
    with pytest.raises(ValueError, match="asymmetric key length"):
        wacryptolib.keygen.generate_keypair(key_algo="DSA_DSS", key_length_bits=1024)

    for key_length_bits in (None, 2048):
        extra_parameters = dict(key_length_bits=key_length_bits) if key_length_bits else {}
        keypair = wacryptolib.keygen.generate_keypair(key_algo="DSA_DSS", **extra_parameters)
        assert isinstance(keypair["private_key"], bytes), keypair
        assert isinstance(keypair["public_key"], bytes), keypair

        key = import_dsa_key_from_pem(keypair["private_key"])
        assert isinstance(key, dsa_key_class_fetcher())


def test_ecc_keypair_generation():
    with pytest.raises(ValueError, match="Unexisting ECC curve"):
        wacryptolib.keygen.generate_keypair(key_algo="ECC_DSS", curve="unexisting")

    for curve in (None, "p384"):
        extra_parameters = dict(curve=curve) if curve else {}
        keypair = wacryptolib.keygen.generate_keypair(key_algo="ECC_DSS", **extra_parameters)
        assert isinstance(keypair["private_key"], bytes), keypair
        assert isinstance(keypair["public_key"], bytes), keypair

        key = import_ecc_key_from_pem(keypair["private_key"])
        assert isinstance(key, ecc_key_class_fetcher())


@pytest.mark.parametrize("key_algo", SUPPORTED_ASYMMETRIC_KEY_ALGOS)
def test_load_asymmetric_key_from_pem_bytestring(key_algo):
    keypair = wacryptolib.keygen.generate_keypair(key_algo=key_algo)

    for field in ["private_key", "public_key"]:
        key = load_asymmetric_key_from_pem_bytestring(key_pem=keypair[field], key_algo=key_algo)
        _check_is_asymmetric_key_object(key)

    with pytest.raises(ValueError, match="^Unknown key type ZHD$"):  # Key PEM must not leak into the message
        load_asymmetric_key_from_pem_bytestring(key_pem=keypair["private_key"], key_algo="ZHD")


def test_load_ecies_x25519_key_rejects_other_curves():
    keypair = wacryptolib.keygen.generate_keypair(key_algo="ECC_DSS", curve="p256")
    for field in ["private_key", "public_key"]:
        with pytest.raises(KeyLoadingError, match="not a NIST P-256 one"):
            load_asymmetric_key_from_pem_bytestring(key_pem=keypair[field], key_algo="ECIES_X25519")


@pytest.mark.parametrize("key_algo", SUPPORTED_ASYMMETRIC_KEY_ALGOS)
def test_generate_and_load_passphrase_protected_asymmetric_key(key_algo):
    # Both Unicode and Bytes are supported
    passphrases = ["Thïs is a passphrâse", b"aoh18726"]

    for passphrase in passphrases:
        keypair = wacryptolib.keygen.generate_keypair(key_algo=key_algo, passphrase=passphrase)

        public_key = load_asymmetric_key_from_pem_bytestring(
            key_pem=keypair["public_key"], key_algo=key_algo  # NOT encrypted
        )
        _check_is_asymmetric_key_object(public_key)

        if isinstance(passphrase, str):  # Different unicode représentations work fine
            passphrase = unicodedata.normalize("NFD", passphrase)

        private_key = load_asymmetric_key_from_pem_bytestring(
            key_pem=keypair["private_key"], key_algo=key_algo, passphrase=passphrase  # Encrypted
        )
        _check_is_asymmetric_key_object(private_key)

        error_matcher = "key format is not supported|Invalid DER encoding|Wrong passphrase|requires a passphrase"

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


# Protection settings used by previous versions of the lib (default PBKDF2 iteration count of 1000)
LEGACY_PEM_EXPORT_PARAMS = {
    "RSA_OAEP": dict(pkcs=8, protection="PBKDF2WithHMAC-SHA1AndAES256-CBC"),
    "DSA_DSS": dict(pkcs8=True, protection="PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC"),
    "ECC_DSS": dict(use_pkcs8=True, protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"),
}


@pytest.mark.parametrize("key_algo", ["RSA_OAEP", "DSA_DSS", "ECC_DSS"])
def test_legacy_passphrase_protected_pem_still_loadable(key_algo):
    skip_if_fallback_backend("legacy PEM generation via pycryptodome")
    passphrase = "Thïs is a passphrâse"
    keypair = wacryptolib.keygen.generate_keypair(key_algo=key_algo)
    key = load_asymmetric_key_from_pem_bytestring(key_pem=keypair["private_key"], key_algo=key_algo)

    legacy_pem = key.export_key(
        format="PEM", passphrase=_encode_passphrase(passphrase), **LEGACY_PEM_EXPORT_PARAMS[key_algo]
    )
    loaded = load_asymmetric_key_from_pem_bytestring(key_pem=legacy_pem, key_algo=key_algo, passphrase=passphrase)
    assert loaded.export_key(format="DER") == key.export_key(format="DER")


@pytest.mark.parametrize("key_algo", ["RSA_OAEP", "DSA_DSS", "ECC_DSS"])
def test_new_passphrase_protected_pem_uses_strong_kdf(key_algo):
    skip_if_fallback_backend("PBKDF2 parameters inspection")
    import base64

    keypair = wacryptolib.keygen.generate_keypair(key_algo=key_algo, passphrase="abc")
    pem = keypair["private_key"]
    assert pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    der = base64.b64decode(b"".join(pem.splitlines()[1:-1]))
    assert b"\x02\x03\x09\x27\xc0" in der  # DER INTEGER 600000, the PBKDF2 iteration count
    assert b"\x2a\x86\x48\x86\xf7\x0d\x02\x09" in der  # OID of hmacWithSHA256
    assert b"\x60\x86\x48\x01\x65\x03\x04\x01\x2a" in der  # OID of aes256-CBC


@pytest.mark.parametrize("key_algo", ["RSA_OAEP", "DSA_DSS", "ECC_DSS"])
def test_passphrase_protected_pem_roundtrip_is_exact_and_fast(key_algo):
    skip_if_fallback_backend("passphrase-protected PEM export")
    from wacryptolib._crypto_backend.pycryptodome import _decrypt_pkcs8_from_pem

    keypair = wacryptolib.keygen.generate_keypair(key_algo=key_algo, serialize=False)
    private_key = keypair["private_key"]

    pem = wacryptolib.keygen._serialize_key_object_to_pem_bytestring(private_key, key_algo=key_algo, passphrase=b"abc")
    # Our own PEMs must be decrypted via hashlib, not via pycryptodome's pure-python PBKDF2 (~10s per operation)
    assert _decrypt_pkcs8_from_pem(pem, b"abc") is not None

    loaded = load_asymmetric_key_from_pem_bytestring(key_pem=pem, key_algo=key_algo, passphrase=b"abc")
    assert loaded.export_key(format="DER") == private_key.export_key(format="DER")


@pytest.mark.parametrize("key_algo", ["RSA_OAEP", "DSA_DSS", "ECC_DSS"])
def test_public_key_export_with_passphrase_raises(key_algo):
    keypair = wacryptolib.keygen.generate_keypair(key_algo=key_algo, serialize=False)
    with pytest.raises(ValueError, match="Public keys"):
        wacryptolib.keygen._serialize_key_object_to_pem_bytestring(
            keypair["public_key"], key_algo=key_algo, passphrase=b"abc"
        )


def _craft_pbes2_pem(
    passphrase=b"abc",
    plaintext=b"garbage",
    iteration_count=1000,
    key_length=None,
    prf=None,
    iv=b"\x00" * 16,
    ciphertext=None,
):
    """Build a PBES2 (PBKDF2-HMAC-SHA256 + AES256-CBC) encrypted PEM, with tamperable fields.

    Uses the pure-python DER codec, so that crafted PEMs can be tested without pycryptodome too."""
    import hashlib
    from wacryptolib._crypto_backend import encrypt_via_aes_cbc
    from wacryptolib._crypto_backend.fallback import pem

    salt = b"\x01" * 16
    if ciphertext is None:
        key = hashlib.pbkdf2_hmac("sha256", passphrase, salt, iteration_count, dklen=32)
        ciphertext = encrypt_via_aes_cbc(plaintext, key=key, iv=iv)
    prf = pem.encode_algorithm_identifier(pem.OID_HMAC_SHA256, pem.encode_null()) if prf is None else prf
    pbkdf2_params = [pem.encode_octet_string(salt), pem.encode_integer(iteration_count)]
    pbkdf2_params += ([pem.encode_integer(key_length)] if key_length else []) + [prf]
    pbes2_params = pem.encode_sequence(
        pem.encode_algorithm_identifier(pem.OID_PBKDF2, pem.encode_sequence(*pbkdf2_params)),
        pem.encode_algorithm_identifier(pem.OID_AES256_CBC, pem.encode_octet_string(iv)),
    )
    der = pem.encode_sequence(
        pem.encode_algorithm_identifier(pem.OID_PBES2, pbes2_params), pem.encode_octet_string(ciphertext)
    )
    return pem.encode_pem(der, "ENCRYPTED PRIVATE KEY")


@pytest.mark.parametrize("iteration_count", [0, 10**8, 2**40])
def test_crafted_pem_iteration_count_is_bounded(iteration_count):
    pem = _craft_pbes2_pem(iteration_count=iteration_count, ciphertext=b"\x00" * 32)
    with pytest.raises(KeyLoadingError, match="Unsupported PBKDF2 iteration count"):
        load_asymmetric_key_from_pem_bytestring(key_pem=pem, key_algo="ECC_DSS", passphrase=b"abc")


def test_crafted_pem_with_optional_key_length_uses_fast_path():
    skip_if_fallback_backend("passphrase-protected PEM import")
    from wacryptolib._crypto_backend.pycryptodome import _decrypt_pkcs8_from_pem

    pem = _craft_pbes2_pem(key_length=32, iteration_count=600000)
    assert _decrypt_pkcs8_from_pem(pem, b"abc") == b"garbage"


@pytest.mark.parametrize(
    "crafting_params",
    [dict(key_length=16), dict(iv=b"\x00" * 8, ciphertext=b"\x00" * 16), dict(ciphertext=b""), dict(ciphertext=b"\x00" * 17)],
)
def test_crafted_pem_with_malformed_cipher_params_is_rejected(crafting_params):
    pem = _craft_pbes2_pem(**crafting_params)
    with pytest.raises(KeyLoadingError, match="Malformed encrypted private key"):
        load_asymmetric_key_from_pem_bytestring(key_pem=pem, key_algo="ECC_DSS", passphrase=b"abc")


def test_crafted_pem_with_empty_prf_falls_back_to_pycryptodome():
    skip_if_fallback_backend("passphrase-protected PEM import")
    from wacryptolib._crypto_backend.pycryptodome import _decrypt_pkcs8_from_pem

    pem = _craft_pbes2_pem(prf=b"\x30\x00")  # Empty SEQUENCE
    assert _decrypt_pkcs8_from_pem(pem, b"abc") is None


def test_crafted_pem_errors_do_not_reveal_padding_validity():
    skip_if_fallback_backend("passphrase-protected PEM import")
    good_padding_pem = _craft_pbes2_pem(plaintext=b"not a DER key")  # Decrypts fine, but to garbage
    bad_padding_pem = _craft_pbes2_pem(ciphertext=b"\x00" * 16)  # Padding check fails

    messages = []
    for pem in (good_padding_pem, bad_padding_pem):
        with pytest.raises(KeyLoadingError) as exc_info:
            load_asymmetric_key_from_pem_bytestring(key_pem=pem, key_algo="ECC_DSS", passphrase=b"abc")
        messages.append(str(exc_info.value))
        assert exc_info.value.__cause__.__cause__ is None  # Original error isn't chained either
    assert messages[0] == messages[1]


def test_backend_pem_functions_accept_str_passphrases():
    skip_if_fallback_backend("passphrase-protected PEM export")
    from wacryptolib._crypto_backend import export_ecc_key_to_pem

    private_key = wacryptolib.keygen.generate_keypair(key_algo="ECC_DSS", serialize=False)["private_key"]
    pem = export_ecc_key_to_pem(private_key, passphrase="abc")
    loaded = import_ecc_key_from_pem(pem, passphrase="abc")
    assert loaded.export_key(format="DER") == private_key.export_key(format="DER")
    assert import_ecc_key_from_pem(pem, passphrase=b"abc")  # Same encoding as bytes
