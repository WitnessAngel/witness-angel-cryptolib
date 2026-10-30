# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import os

import pytest

from conftest import import_crypto_backend

NIST_P256_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsW6pf1Fi5sKalrspUNpMs+tXSw6K
J/cA/LmMQfg//vB15ZYD5zIRvlEOTJO9uM+rr3ncYZD7JS/8IiwdrZYofQ==
-----END PUBLIC KEY-----"""


def test_backends_expose_the_same_names(both_backends):
    native, fallback = both_backends
    assert native.__all__ == fallback.__all__
    for backend in both_backends:
        for name in backend.__all__:
            assert hasattr(backend, name), (backend, name)
    assert native.IMPLEMENTED_HASH_ALGOS == fallback.IMPLEMENTED_HASH_ALGOS
    assert native.AES_BLOCK_SIZE == fallback.AES_BLOCK_SIZE


def test_backends_share_pem_protection_constants(both_backends):
    from wacryptolib._crypto_backend.fallback import pem

    native, _fallback = both_backends
    assert native.PEM_PBKDF2_ITERATIONS == pem.PEM_PBKDF2_ITERATIONS
    assert native.PEM_PBKDF2_MAX_ITERATIONS == pem.PEM_PBKDF2_MAX_ITERATIONS
    assert native._PEM_DECRYPTION_ERROR == pem.PEM_DECRYPTION_ERROR


def test_fallback_rejects_nist_curves_explicitly():
    fallback = import_crypto_backend("fallback")

    with pytest.raises(NotImplementedError, match="ECC key generation.*requires pycryptodome"):
        fallback.generate_ecc_keypair("p256")
    with pytest.raises(NotImplementedError, match="NIST-curve ECC.*requires pycryptodome"):
        fallback.import_ecc_key_from_pem(NIST_P256_PUBLIC_KEY_PEM)
    with pytest.raises(NotImplementedError, match="HPKE.*requires pycryptodome"):
        fallback.encrypt_via_hpke(b"abc", fallback.generate_ecc_keypair("curve25519")[0], aead_id=0x0002)

    public_key, private_key = fallback.generate_ecc_keypair("curve25519")
    hasher = fallback.get_hasher_instance("SHA512")
    with pytest.raises(ValueError, match="DSA keys"):  # Like pycryptodome, for non-NIST curves
        fallback.sign_with_dss(hasher, private_key)


def test_fallback_backend_never_imports_pycryptodome():
    import subprocess
    import sys

    script = """if True:
        import sys
        sys.modules["Crypto"] = None  # Any import of pycryptodome now fails
        import wacryptolib._crypto_backend.fallback, wacryptolib.cipher, wacryptolib.keygen, wacryptolib.signature
    """
    env = dict(os.environ, FORCE_WACRYPTOLIB_FALLBACK_BACKEND="1", PYTHONPATH=os.pathsep.join(sys.path))
    subprocess.run([sys.executable, "-c", script], env=env, check=True)


def test_failures_raise_value_error_silently(backend, capsys):
    public_key, private_key = backend.generate_rsa_keypair(2048)

    ciphertext = backend.encrypt_via_rsa_oaep([b"secret"], public_key)[0]
    for tampered in (ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), b"\x00" + ciphertext[1:], b"abc", b"\xff" * 256):
        with pytest.raises(ValueError):
            backend.decrypt_via_rsa_oaep([tampered], private_key)

    hasher = backend.get_hasher_instance("SHA512")
    hasher.update(b"message")
    signature = backend.sign_with_pss(hasher, private_key)
    for tampered in (signature[:-1] + bytes([signature[-1] ^ 1]), signature[:-1], b"\xff" * len(signature)):
        with pytest.raises(ValueError):
            backend.verify_with_pss(hasher, tampered, public_key)

    key_pem = backend.export_rsa_key_to_pem(private_key, passphrase=b"right")
    for passphrase in (b"wrong", None):
        with pytest.raises(ValueError):
            backend.import_rsa_key_from_pem(key_pem, passphrase=passphrase)

    assert capsys.readouterr() == ("", "")
