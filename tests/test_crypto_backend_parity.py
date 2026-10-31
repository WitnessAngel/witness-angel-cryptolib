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


def test_fallback_rejects_unsupported_parameters_explicitly():
    fallback = import_crypto_backend("fallback")

    with pytest.raises(NotImplementedError, match="ECC key generation.*requires pycryptodome"):
        fallback.generate_ecc_keypair("ed25519")
    with pytest.raises(ValueError, match="Unexisting ECC curve"):
        fallback.generate_ecc_keypair("p999")
    with pytest.raises(ValueError, match="Expected an X25519 key"):
        fallback.import_x25519_key_from_pem(NIST_P256_PUBLIC_KEY_PEM)
    with pytest.raises(NotImplementedError, match="HPKE.*requires pycryptodome"):
        fallback.encrypt_via_hpke(b"abc", fallback.generate_ecc_keypair("curve25519")[0], aead_id=0x0002)

    public_key, private_key = fallback.generate_ecc_keypair("curve25519")
    hasher = fallback.get_hasher_instance("SHA512")
    with pytest.raises(ValueError, match="NIST-curve ECC keys"):  # Like pycryptodome, for non-NIST curves
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
    first_byte_flipped = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    for tampered in (ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), first_byte_flipped, b"abc", b"\xff" * 256):
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


def test_passphrase_is_rejected_only_for_clear_pkcs8_private_keys(backend):
    rsa_public_key, rsa_private_key = backend.generate_rsa_keypair(2048)
    for key in (rsa_public_key, rsa_private_key):  # Clear RSA private keys are PKCS#1
        backend.import_rsa_key_from_pem(backend.export_rsa_key_to_pem(key), passphrase=b"abc")

    ecc_public_key, ecc_private_key = backend.generate_ecc_keypair("p256")
    backend.import_ecc_key_from_pem(backend.export_ecc_key_to_pem(ecc_public_key), passphrase=b"abc")
    with pytest.raises(ValueError):
        backend.import_ecc_key_from_pem(backend.export_ecc_key_to_pem(ecc_private_key), passphrase=b"abc")


def _malformed_rsa_public_key_pems():
    import base64

    import _crypto_test_vectors as vectors

    pem = vectors.PYCRYPTODOME_PEM_FIXTURES["RSA"]["public_key"]
    der = base64.b64decode(b"".join(pem.splitlines()[1:-1]))

    def armor(der_bytes, marker=b"PUBLIC KEY", headers=b""):
        body = base64.encodebytes(der_bytes)
        return b"-----BEGIN %s-----\n%s%s-----END %s-----" % (marker, headers, body, marker)

    spki_header_length = 4  # 30 82 xx xx
    return {
        "truncated": armor(der[:-1]),
        "trailing bytes": armor(der + b"\x00"),
        "indefinite length": armor(b"\x30\x80" + der[spki_header_length:] + b"\x00\x00"),
        "non-minimal length": armor(b"\x30\x83\x00" + der[2:]),
        "wrong marker": armor(der, marker=b"CERTIFICATE"),
        "mismatched end marker": pem.replace(b"-----END PUBLIC KEY-----", b"-----END PRIVATE KEY-----"),
        "invalid base64": pem.replace(pem.splitlines()[1][:4], b"!!!!"),
        "legacy encryption headers": armor(der, headers=b"Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n"),
        "not a pem": b"hello",
        "empty": b"",
    }


@pytest.mark.parametrize("case_name", sorted(_malformed_rsa_public_key_pems()))
def test_malformed_pem_is_rejected(backend, case_name):
    key_pem = _malformed_rsa_public_key_pems()[case_name]
    is_fallback = backend.__name__.endswith(".fallback")
    if case_name == "wrong marker" and not is_fallback:
        pytest.skip("pycryptodome ignores PEM markers")
    with pytest.raises(ValueError if is_fallback else (ValueError, IndexError, TypeError)):  # Like keygen's catch
        backend.import_rsa_key_from_pem(key_pem)



@pytest.mark.parametrize("p, q", [(1, 3233), (61, 61), (0, 0)])
def test_fallback_rejects_degenerate_rsa_primes_with_value_error(p, q):
    from wacryptolib._crypto_backend.fallback import pem

    fallback = import_crypto_backend("fallback")
    n, e, d = p * q, 17, 2753
    components = [0, n, e, d, p, q, 0, 0, 0]
    der = pem.encode_sequence(*(pem.encode_integer(x) for x in components))
    with pytest.raises(ValueError):
        fallback.import_rsa_key_from_pem(pem.encode_pem(der, "RSA PRIVATE KEY"))


def test_ecc_key_on_unknown_curve_oid_is_rejected_with_value_error(backend):
    import base64

    der = base64.b64decode(b"".join(NIST_P256_PUBLIC_KEY_PEM.splitlines()[1:-1]))
    p256_oid = bytes.fromhex("06082a8648ce3d030107")
    unknown_oid = bytes.fromhex("06042a030405")  # 1.2.3.4.5
    tampered = der.replace(p256_oid, unknown_oid)
    tampered = bytes([0x30, len(tampered) - 2, 0x30, der[3] - 4]) + tampered[4:]  # Shrunk outer lengths
    key_pem = b"-----BEGIN PUBLIC KEY-----\n%s-----END PUBLIC KEY-----" % base64.encodebytes(tampered)
    with pytest.raises(ValueError):
        backend.import_ecc_key_from_pem(key_pem)

@pytest.mark.parametrize(
    "der, tag",
    [
        (b"\x02\x01\x80", 0x02),  # Negative INTEGER
        (b"\x02\x02\x00\x01", 0x02),  # Non-minimal INTEGER
        (b"\x02\x00", 0x02),  # Empty INTEGER
        (b"\x30\x80\x00\x00", 0x30),  # Indefinite length
        (b"\x30\x81\x01\x00", 0x30),  # Non-minimal length
        (b"\x30\x05\x02\x01\x01", 0x30),  # Truncated
        (b"\x30\x00\x00", 0x30),  # Trailing bytes
        (b"\x04\x00", 0x30),  # Wrong tag
    ],
)
def test_fallback_der_codec_is_strict(der, tag):
    import_crypto_backend("fallback")
    from wacryptolib._crypto_backend.fallback import pem

    with pytest.raises(ValueError):
        if tag == 0x02:
            pem.decode_integer(der)
        else:
            pem.decode_sequence(der, 0, 10)


def test_fallback_der_codec_roundtrips():
    import_crypto_backend("fallback")
    from wacryptolib._crypto_backend.fallback import pem

    for value in (0, 1, 127, 128, 255, 256, 2**2048 - 1):
        assert pem.decode_integer(pem.encode_integer(value)) == value
    for oid in (pem.OID_RSA, pem.OID_DSA, pem.OID_X25519, pem.OID_PBES2, pem.OID_AES256_CBC, "2.999.1"):
        assert pem.decode_oid(pem.encode_oid(oid)) == oid
    long_sequence = pem.encode_sequence(*[pem.encode_octet_string(bytes(100))] * 3)
    assert [pem.decode_octet_string(item) for item in pem.decode_sequence(long_sequence, 3)] == [bytes(100)] * 3


def test_rsa_private_keys_are_accepted_as_public_keys(backend):
    # wacryptolib relies on this, e.g. for read-only trustees encrypting with their private key
    public_key, private_key = backend.generate_rsa_keypair(2048)
    (ciphertext,) = backend.encrypt_via_rsa_oaep([b"abc"], private_key)
    assert backend.decrypt_via_rsa_oaep([ciphertext], private_key) == [b"abc"]
    with pytest.raises(ValueError, match="Ciphertext with incorrect length"):
        backend.decrypt_via_rsa_oaep([ciphertext + b"a"], private_key)

    hasher = backend.get_hasher_instance("SHA512")
    hasher.update(b"message")
    backend.verify_with_pss(hasher, backend.sign_with_pss(hasher, private_key), private_key)
