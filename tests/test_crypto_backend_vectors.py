# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Known-answer tests of both crypto backends, with official vectors matching the exact parameters used by wacryptolib.

Without published vectors for these parameters, RSA/DSA/ECC/X25519 key generation and PEM serialization,
as well as Shamir secret sharing (same vendored code for both backends), are only covered by interoperability tests.
"""

import pytest

import _crypto_test_vectors as vectors
from wacryptolib._crypto_backend import hpke_x25519_seal
from wacryptolib._crypto_backend.vendor import dsa
from wacryptolib._crypto_backend.vendor.aes_eax import EaxCipher
from wacryptolib._crypto_backend.vendor.chacha20_poly1305 import ChaCha20Poly1305Cipher

h = bytes.fromhex

# NIST CSRC "Examples with Intermediate Values" for FIPS 180-4 and FIPS 202
NIST_HASH_MESSAGES = [b"abc", b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"]
NIST_HASH_VECTORS = {
    "SHA256": [
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ],
    "SHA512": [
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
        "454d4423643ce80e2a9ac94fa54ca49f",
        "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca0"
        "31ad85c7a71dd70354ec631238ca3445",
    ],
    "SHA3_256": [
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
    ],
    "SHA3_512": [
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e39340"
        "57340b4cf408d5a56592f8274eec53f0",
        "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c0863"
        "46b533b49c030d99a27daf1139d6e75e",
    ],
}


@pytest.mark.parametrize("hash_algo", sorted(NIST_HASH_VECTORS))
def test_hashes(backend, hash_algo):
    for message, expected_digest in zip(NIST_HASH_MESSAGES, NIST_HASH_VECTORS[hash_algo]):
        hasher = backend.get_hasher_instance(hash_algo)
        hasher.update(message[:1])
        hasher.update(message[1:])
        assert hasher.digest() == h(expected_digest)


# NIST SP 800-38A, F.2.5 (CBC-AES256.Encrypt) and F.2.6 (CBC-AES256.Decrypt)
SP800_38A_AES256_KEY = h("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
SP800_38A_IV = h("000102030405060708090a0b0c0d0e0f")
SP800_38A_PLAINTEXT = h(
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
)
SP800_38A_AES256_CBC_CIPHERTEXT = h(
    "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
    "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"
)


def test_aes_cbc(backend):
    encrypter = backend.build_aes_cbc_encrypter(SP800_38A_AES256_KEY, iv=SP800_38A_IV)
    assert encrypter.encrypt(SP800_38A_PLAINTEXT[:16]) + encrypter.encrypt(SP800_38A_PLAINTEXT[16:]) == (
        SP800_38A_AES256_CBC_CIPHERTEXT
    )
    decrypter = backend.build_aes_cbc_encrypter(SP800_38A_AES256_KEY, iv=SP800_38A_IV)
    assert decrypter.decrypt(SP800_38A_AES256_CBC_CIPHERTEXT) == SP800_38A_PLAINTEXT


@pytest.mark.parametrize("vector", vectors.WYCHEPROOF_AES256_EAX, ids=lambda v: "tc%d" % v["tcId"])
def test_aes_eax(backend, vector):
    key, nonce, plaintext, ciphertext, tag = (h(vector[k]) for k in ("key", "iv", "msg", "ct", "tag"))
    if vector["result"] == "valid":
        assert backend.encrypt_via_aes_eax(plaintext, key=key, nonce=nonce) == (ciphertext, tag)
        assert backend.decrypt_via_aes_eax(ciphertext, tag, key=key, nonce=nonce, verify_integrity_tags=True) == (
            plaintext
        )
    else:
        with pytest.raises(ValueError):
            backend.decrypt_via_aes_eax(ciphertext, tag, key=key, nonce=nonce, verify_integrity_tags=True)


def test_vendored_aes_eax_with_header():
    # EAX paper (Bellare, Rogaway, Wagner), first test vector: AES-128, with a header
    pyaes = pytest.importorskip("pyaes")
    block_cipher = pyaes.AES(h("233952DEE4D5ED5F9B9C6D6FF80FF478"))
    encrypt_block = lambda block: bytes(block_cipher.encrypt(block))  # noqa: E731
    cipher = EaxCipher(encrypt_block, nonce=h("62EC67F9C3A4A407FCB2A8C49031A8B3"), header=h("6BFB914FD07EAE6B"))
    assert cipher.encrypt_and_digest(b"") == (b"", h("E037830E8389F27B025A2D6527E79D01"))



def test_vendored_aes_eax_streaming_matches_one_shot():
    # Any block function will do here, the point is keystream bookkeeping across unaligned chunks
    import hashlib

    encrypt_block = lambda block: hashlib.sha256(block).digest()[:16]  # noqa: E731
    plaintext = bytes(range(256)) * 40
    expected = EaxCipher(encrypt_block, nonce=b"n" * 16).encrypt_and_digest(plaintext)

    cipher = EaxCipher(encrypt_block, nonce=b"n" * 16)
    chunks, offset = [], 0
    for size in [0, 1, 15, 16, 17, 33, 5000] * 3:
        chunks.append(cipher.encrypt(plaintext[offset : offset + size]))
        offset += size
    chunks.append(cipher.encrypt(plaintext[offset:]))
    assert (b"".join(chunks), cipher.digest()) == expected

# RFC 8439 section 2.4.2, ChaCha20 keystream with block counter 1, as used for AEAD encryption
RFC8439_KEY = bytes(range(32))
RFC8439_NONCE = h("000000000000004a00000000")
RFC8439_PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
)
RFC8439_CIPHERTEXT = h(
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b357"
    "1639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
    "5af90bbf74a35be6b40b8eedf2785e42874d"
)


def test_chacha20_keystream(backend):
    ciphertext, _tag = backend.encrypt_via_chacha20_poly1305(RFC8439_PLAINTEXT, key=RFC8439_KEY, nonce=RFC8439_NONCE)
    assert ciphertext == RFC8439_CIPHERTEXT


@pytest.mark.parametrize("vector", vectors.WYCHEPROOF_CHACHA20_POLY1305, ids=lambda v: "tc%d" % v["tcId"])
def test_chacha20_poly1305(backend, vector):
    assert vector["result"] == "valid"  # No published invalid vector without AAD, so we tamper tags ourselves
    key, nonce, plaintext, ciphertext, tag = (h(vector[k]) for k in ("key", "iv", "msg", "ct", "tag"))
    assert backend.encrypt_via_chacha20_poly1305(plaintext, key=key, nonce=nonce) == (ciphertext, tag)
    decrypt = lambda tag: backend.decrypt_via_chacha20_poly1305(  # noqa: E731
        ciphertext, tag, key=key, nonce=nonce, verify_integrity_tags=True
    )
    assert decrypt(tag) == plaintext
    with pytest.raises(ValueError):
        decrypt(tag[:-1] + bytes([tag[-1] ^ 1]))


def test_x25519_rfc7748():
    # Section 5.2, scalar multiplication
    x25519 = hpke_x25519_seal.x25519
    assert x25519(
        h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ) == h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    assert x25519(
        h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
        h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
    ) == h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")

    # Section 5.2, iterated scalar multiplication
    k = u = hpke_x25519_seal._X25519_BASE_POINT
    for iteration in range(1, 1001):
        k, u = x25519(k, u), k
        if iteration == 1:
            assert k == h("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
    assert k == h("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")

    # Section 6.1, Diffie-Hellman
    alice_private_key = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob_private_key = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    alice_public_key = x25519(alice_private_key, hpke_x25519_seal._X25519_BASE_POINT)
    bob_public_key = x25519(bob_private_key, hpke_x25519_seal._X25519_BASE_POINT)
    assert alice_public_key == h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    assert bob_public_key == h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    shared_secret = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    assert x25519(alice_private_key, bob_public_key) == x25519(bob_private_key, alice_public_key) == shared_secret


def test_hpke_key_schedule_rfc9180():
    # RFC 9180 appendix A.2.1, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, base mode
    enc, key, base_nonce = hpke_x25519_seal._derive_key_schedule(
        receiver_public_key=h("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"),
        ephemeral_private_key=h("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"),
        info=h("4f6465206f6e2061204772656369616e2055726e"),
    )
    assert enc == h("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
    assert key == h("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91")
    assert base_nonce == h("5c4d98150661b848853b547f")

    # The receiver derives the same schedule from its private key
    receiver_private_key = h("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
    dh = hpke_x25519_seal.x25519(receiver_private_key, enc)
    assert hpke_x25519_seal._derive_key_schedule_from_dh(
        dh, enc, h("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"),
        info=h("4f6465206f6e2061204772656369616e2055726e"),
    ) == (key, base_nonce)


def _hash_sha512(backend, message):
    hasher = backend.get_hasher_instance("SHA512")
    hasher.update(message)
    return hasher


@pytest.mark.parametrize("vector", vectors.WYCHEPROOF_RSA_OAEP_2048_SHA512, ids=lambda v: "tc%d" % v["tcId"])
def test_rsa_oaep_decryption(backend, vector):
    private_key = backend.import_rsa_key_from_pem(vectors.WYCHEPROOF_RSA_OAEP_2048_SHA512_PRIVATE_KEY_PEM)
    if vector["result"] == "valid":
        assert backend.decrypt_via_rsa_oaep([h(vector["ct"])], private_key) == [h(vector["msg"])]
    else:
        with pytest.raises(ValueError):
            backend.decrypt_via_rsa_oaep([h(vector["ct"])], private_key)


@pytest.mark.parametrize("vector", vectors.WYCHEPROOF_RSA_PSS_4096_SHA512, ids=lambda v: "tc%d" % v["tcId"])
def test_rsa_pss_verification(backend, vector):
    public_key = backend.import_rsa_key_from_pem(vectors.WYCHEPROOF_RSA_PSS_4096_SHA512_PUBLIC_KEY_PEM)
    hasher = _hash_sha512(backend, h(vector["msg"]))
    if vector["result"] == "valid":
        backend.verify_with_pss(hasher, h(vector["sig"]), public_key)
    else:
        with pytest.raises(ValueError):
            backend.verify_with_pss(hasher, h(vector["sig"]), public_key)


def _build_dsa_public_key(backend, domain, y):
    p, q, g = (int(domain[k], 16) for k in "PQG")
    if backend.__name__.endswith(".fallback"):
        return dsa.DsaKey(p, q, g, y)
    from Crypto.PublicKey import DSA

    return DSA.construct((y, g, p, q))


DSA_SIGVER_CASES = [
    (section_name, domain_and_cases["domain"], case)
    for section_name, domain_and_cases in vectors.CAVP_DSA_SIGVER_SHA512.items()
    for case in domain_and_cases["cases"]
]


@pytest.mark.parametrize("section_name, domain, case", DSA_SIGVER_CASES, ids=lambda x: "" if isinstance(x, dict) else x)
def test_dsa_signature_verification(backend, section_name, domain, case):
    public_key = _build_dsa_public_key(backend, domain, int(case["Y"], 16))
    q_length = len(domain["Q"]) // 2
    signature = int(case["R"], 16).to_bytes(q_length, "big") + int(case["S"], 16).to_bytes(q_length, "big")
    hasher = _hash_sha512(backend, h(case["Msg"]))
    if case["Result"] == "P":
        backend.verify_with_dss(hasher, signature, public_key)
    else:
        with pytest.raises(ValueError):
            backend.verify_with_dss(hasher, signature, public_key)


ECDSA_SIGVER_CASES = [
    (section_name, case) for section_name, cases in vectors.CAVP_ECDSA_SIGVER_SHA512.items() for case in cases
]


def _build_ecc_public_key(backend, curve_bits, x, y):
    if backend.__name__.endswith(".fallback"):
        import ecdsa

        curve = {256: ecdsa.NIST256p, 384: ecdsa.NIST384p, 521: ecdsa.NIST521p}[curve_bits]
        coordinate_length = (curve_bits + 7) // 8
        point = b"\x04" + x.to_bytes(coordinate_length, "big") + y.to_bytes(coordinate_length, "big")
        return ecdsa.VerifyingKey.from_string(point, curve=curve)
    from Crypto.PublicKey import ECC

    return ECC.construct(curve="p%d" % curve_bits, point_x=x, point_y=y)


@pytest.mark.parametrize("section_name, case", ECDSA_SIGVER_CASES, ids=lambda x: "" if isinstance(x, dict) else x)
def test_ecdsa_signature_verification(backend, section_name, case):
    curve_bits = int(section_name[3:6])  # E.g. "[P-256,SHA-512]"
    try:
        public_key = _build_ecc_public_key(backend, curve_bits, int(case["Qx"], 16), int(case["Qy"], 16))
    except Exception:  # Some failing vectors have an invalid public point
        assert case["Result"] == "F"
        return
    order_length = (curve_bits + 7) // 8
    signature = int(case["R"], 16).to_bytes(order_length, "big") + int(case["S"], 16).to_bytes(order_length, "big")
    hasher = _hash_sha512(backend, h(case["Msg"]))
    if case["Result"] == "P":
        backend.verify_with_dss(hasher, signature, public_key)
    else:
        with pytest.raises(ValueError):
            backend.verify_with_dss(hasher, signature, public_key)


@pytest.mark.parametrize("section_name", sorted(vectors.CAVP_DSA_SIGGEN_SHA512))
def test_vendored_dsa_signature_generation(section_name):
    # Pycryptodome's randomized signatures can't be given the nonce k, so only the vendored module is tested here
    import hashlib

    domain, cases = vectors.CAVP_DSA_SIGGEN_SHA512[section_name].values()
    p, q, g = (int(domain[k], 16) for k in "PQG")
    for case in cases:
        key = dsa.DsaKey(p, q, g, int(case["Y"], 16), int(case["X"], 16))
        dsa.check_dsa_key(key)
        signature = dsa.sign(key, hashlib.sha512(h(case["Msg"])).digest(), k=int(case["K"], 16))
        q_length = len(domain["Q"]) // 2
        assert signature == int(case["R"], 16).to_bytes(q_length, "big") + int(case["S"], 16).to_bytes(q_length, "big")


def test_hpke_seal_rejects_invalid_public_keys():
    # RFC 9180 section 7.1.4: an all-zero X25519 shared secret must be rejected
    with pytest.raises(ValueError, match="low order"):
        hpke_x25519_seal.seal(bytes(32), b"abc")
    with pytest.raises(ValueError, match="32 bytes"):
        hpke_x25519_seal.seal(b"abc", b"abc")
