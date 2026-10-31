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

    for curve in ("ed25519", "curve448", "X448"):
        with pytest.raises(NotImplementedError, match="ECC key generation.*requires pycryptodome"):
            fallback.generate_ecc_keypair(curve)
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


def test_public_keys_used_as_private_ones_raise_type_error(backend):
    rsa_public_key, _rsa_private_key = backend.generate_rsa_keypair(2048)
    hasher = backend.get_hasher_instance("SHA512")
    with pytest.raises(TypeError):
        backend.decrypt_via_rsa_oaep([b"\x00" * 256], rsa_public_key)
    with pytest.raises(TypeError):
        backend.sign_with_pss(hasher, rsa_public_key)
    for public_key in (backend.generate_ecc_keypair("p256")[0], backend.generate_dsa_keypair(2048)[0]):
        with pytest.raises(TypeError):
            backend.sign_with_dss(hasher, public_key)


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


_P25519 = 2**255 - 19
_X25519_LOW_ORDER_U = 325606250916557431795983626356110631294008115727848805560023387167927233504


def _x25519_public_key_pem(u):
    import base64

    spki = bytes.fromhex("302a300506032b656e032100") + u.to_bytes(32, "little")
    return b"-----BEGIN PUBLIC KEY-----\n%s-----END PUBLIC KEY-----" % base64.encodebytes(spki)


@pytest.mark.parametrize("u", [0, 1, _X25519_LOW_ORDER_U, _P25519 - 1, _P25519, _P25519 + 1, 2**255 + 1])
def test_low_order_x25519_public_keys_are_rejected(backend, u):
    with pytest.raises(ValueError):
        backend.import_ecc_key_from_pem(_x25519_public_key_pem(u))


def test_x25519_public_key_high_bit_is_ignored(backend):
    key = backend.import_ecc_key_from_pem(_x25519_public_key_pem(2**255 + 9))
    assert key == backend.import_ecc_key_from_pem(_x25519_public_key_pem(9))


def test_non_canonical_x25519_public_key_is_reduced(backend):
    key = backend.import_ecc_key_from_pem(_x25519_public_key_pem(_P25519 + 5))
    assert backend.export_ecc_key_to_pem(key) == backend.export_ecc_key_to_pem(
        backend.import_ecc_key_from_pem(_x25519_public_key_pem(5))
    )
    backend.encrypt_via_hpke(b"abc", key, aead_id=0x0003)


def test_rsa_keys_with_composite_factor_or_even_modulus_are_rejected(backend):
    import math

    import_crypto_backend("fallback")
    from wacryptolib._crypto_backend.fallback import pem
    from wacryptolib._crypto_backend.vendor.primes import get_random_prime

    e = 65537
    while True:
        p, q = get_random_prime(256) * get_random_prime(256), get_random_prime(512)  # p is composite
        if math.gcd(e, math.lcm(p - 1, q - 1)) == 1:
            break
    d = pow(e, -1, math.lcm(p - 1, q - 1))
    components = [0, p * q, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p)]
    der = pem.encode_sequence(*(pem.encode_integer(x) for x in components))
    with pytest.raises(ValueError):
        backend.import_rsa_key_from_pem(pem.encode_pem(der, "RSA PRIVATE KEY"))

    der = pem.encode_sequence(pem.encode_integer(2**2048), pem.encode_integer(e))
    with pytest.raises(ValueError):
        backend.import_rsa_key_from_pem(pem.encode_pem(der, "RSA PUBLIC KEY"))


@pytest.mark.parametrize("e, p", [(1, None), (65537, 2)])
def test_rsa_private_keys_with_bad_exponent_or_even_modulus_are_rejected(backend, e, p):
    import math

    import_crypto_backend("fallback")
    from wacryptolib._crypto_backend.fallback import pem
    from wacryptolib._crypto_backend.vendor.primes import get_random_prime

    while True:
        p, q = p or get_random_prime(512), get_random_prime(512)
        if math.gcd(e, math.lcm(p - 1, q - 1)) == 1:
            break
    d = pow(e, -1, math.lcm(p - 1, q - 1))
    components = [0, p * q, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p)]
    der = pem.encode_sequence(*(pem.encode_integer(x) for x in components))
    with pytest.raises(ValueError):
        backend.import_rsa_key_from_pem(pem.encode_pem(der, "RSA PRIVATE KEY"))


def test_ecc_private_key_with_mismatched_public_point_is_rejected(backend):
    import ecdsa

    import_crypto_backend("fallback")
    from wacryptolib._crypto_backend.fallback import pem

    def ec_private_key_items(key):  # SEC1 ECPrivateKey: version, private key, [0] curve, [1] public point
        return pem.decode_sequence(key.to_der(), 4)

    key, other_key = ecdsa.SigningKey.generate(ecdsa.NIST256p), ecdsa.SigningKey.generate(ecdsa.NIST256p)
    version, private_key, curve, _public_point = ec_private_key_items(key)
    algorithm_identifier = pem.encode_algorithm_identifier(pem.OID_EC_PUBLIC_KEY, pem.decode(curve, 0xA0))

    def pkcs8_pem(public_point):
        ec_private_key = pem.encode_sequence(version, private_key, public_point)
        return pem.encode_pem(pem.encode_pkcs8(algorithm_identifier, ec_private_key), "PRIVATE KEY")

    imported_key = backend.import_ecc_key_from_pem(pkcs8_pem(ec_private_key_items(key)[3]))
    assert backend.import_ecc_key_from_pem(backend.export_ecc_key_to_pem(imported_key))  # Sanity check
    with pytest.raises(ValueError):
        backend.import_ecc_key_from_pem(pkcs8_pem(ec_private_key_items(other_key)[3]))


def test_fallback_rsa_private_operations_are_freshly_blinded_and_checked(monkeypatch):
    import pkcs1.keys

    fallback = import_crypto_backend("fallback")
    public_key, private_key = fallback.generate_rsa_keypair(2048)
    (ciphertext,) = fallback.encrypt_via_rsa_oaep([b"abc"], public_key)

    original_rsadp = pkcs1.keys.MultiPrimeRsaPrivateKey.rsadp
    rsadp_inputs = []
    monkeypatch.setattr(
        pkcs1.keys.MultiPrimeRsaPrivateKey, "rsadp", lambda key, c: rsadp_inputs.append(c) or original_rsadp(key, c)
    )
    for _ in range(2):
        assert fallback.decrypt_via_rsa_oaep([ciphertext], private_key) == [b"abc"]
    assert rsadp_inputs[0] != rsadp_inputs[1]

    monkeypatch.setattr(pkcs1.keys.MultiPrimeRsaPrivateKey, "rsadp", lambda key, c: original_rsadp(key, c) ^ 1)
    hasher = fallback.get_hasher_instance("SHA512")
    with pytest.raises(ValueError, match="Fault detected"):
        fallback.sign_with_pss(hasher, private_key)


def test_fallback_rsa_oaep_checks_all_paddings_even_when_first_byte_is_wrong(monkeypatch):
    fallback = import_crypto_backend("fallback")
    public_key, private_key = fallback.generate_rsa_keypair(2048)
    em = b"\x01" + bytes(255)  # Invalid first byte
    ciphertext = pow(int.from_bytes(em, "big"), public_key.e, public_key.n).to_bytes(256, "big")

    compared = []
    monkeypatch.setattr(fallback.hmac, "compare_digest", lambda a, b: compared.append(a) or a == b)
    with pytest.raises(ValueError, match="Incorrect decryption"):
        fallback.decrypt_via_rsa_oaep([ciphertext], private_key)
    assert compared  # No early exit revealing the first byte through timing


@pytest.mark.parametrize("key_length_bits", [1024, 1025])
def test_rsa_keypair_has_the_requested_length(backend, key_length_bits):
    _public_key, private_key = backend.generate_rsa_keypair(key_length_bits)
    assert private_key.n.bit_length() == key_length_bits


@pytest.mark.parametrize(
    "version, optional_items",
    [(0, [b"\xa0\x00"]), (1, [b"\x81\x21\x00" + bytes(32)]), (1, [b"\xa0\x00", b"\x81\x21\x00" + bytes(32)])],
)
def test_pkcs8_private_keys_with_attributes_or_public_key_are_accepted(backend, version, optional_items):
    import_crypto_backend("fallback")
    from wacryptolib._crypto_backend.fallback import pem

    _public_key, private_key = backend.generate_ecc_keypair("curve25519")
    clear_version, algorithm_identifier, private_key_octets = pem.decode_sequence(
        pem.decode_pem(backend.export_ecc_key_to_pem(private_key))[0], 3
    )
    der = pem.encode_sequence(pem.encode_integer(version), algorithm_identifier, private_key_octets, *optional_items)
    key = backend.import_ecc_key_from_pem(pem.encode_pem(der, "PRIVATE KEY"))
    assert backend.export_ecc_key_to_pem(key) == backend.export_ecc_key_to_pem(private_key)

    for bad_version, bad_optional_items in [(0, optional_items * 2), (2, optional_items)]:
        der = pem.encode_sequence(pem.encode_integer(bad_version), algorithm_identifier, private_key_octets, *bad_optional_items)
        with pytest.raises(ValueError):
            backend.import_ecc_key_from_pem(pem.encode_pem(der, "PRIVATE KEY"))


def test_aes_eax_rejects_empty_nonce(backend):
    with pytest.raises(ValueError, match="Nonce cannot be empty"):
        backend.encrypt_via_aes_eax(b"abc", key=bytes(32), nonce=b"")


def test_backends_accept_the_same_nist_curve_names(both_backends):
    native, fallback = both_backends
    for curve in fallback._NIST_CURVES:
        native.generate_ecc_keypair(curve)  # Would raise ValueError if unknown
    for bits in (256, 384, 521):
        fallback.generate_ecc_keypair("nistp%d" % bits)


@pytest.mark.parametrize("curve", ["p256", "P256", "nist p-256", "x25519", "X25519", "CURVE25519", "curve25519"])
def test_ecc_curve_names_are_case_insensitive(backend, curve):
    public_key, _private_key = backend.generate_ecc_keypair(curve)
    assert backend.export_ecc_key_to_pem(public_key)
