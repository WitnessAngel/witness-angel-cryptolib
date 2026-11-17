# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate wa_backend_conformance_vectors.h, the vectors of the crypto backend conformance test (task 4.2).

Published vectors (SP 800-38A, RFC 8439, FIPS 180-4 examples, RFC 4231, RFC 7748) are written here literally, and
checked against pycryptodome / hashlib before being emitted. The other values are computed with pycryptodome from
fixed inputs: an AES-CTR counter wrapping around 2^128, raw RSA known values (4096-bit and 2048-bit moduli), and an
ML-KEM-768 deterministic encapsulation (the code pycryptodome runs is mlkem-native).

Run from the repository root, in the wacryptolib environment (pycryptodome 4.2+):
    python reimplementations/c-language/tests/unit/generate_backend_conformance_vectors.py
"""

import hashlib
import hmac
from pathlib import Path

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.PublicKey import MLKEM, RSA

OUTPUT_PATH = Path(__file__).with_name("wa_backend_conformance_vectors.h")


def _deterministic_bytes(label: bytes, length: int) -> bytes:
    output = b""
    counter = 0
    while len(output) < length:
        output += hashlib.sha256(label + counter.to_bytes(4, "big")).digest()
        counter += 1
    return output[:length]


class _DeterministicRandom:
    def __init__(self, label: bytes):
        self._label = label
        self._counter = 0

    def __call__(self, length: int) -> bytes:
        self._counter += 1
        return _deterministic_bytes(self._label + self._counter.to_bytes(8, "big"), length)


def _hex(data: bytes) -> str:
    return data.hex()


# SP 800-38A F.2.5 (CBC-AES256.Encrypt) and F.5.5 (CTR-AES256.Encrypt)
SP800_38A_KEY = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
SP800_38A_PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710"
)
SP800_38A_CBC_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
SP800_38A_CBC_CIPHERTEXT = bytes.fromhex(
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6" "9cfc4e967edb808d679f777bc6702c7d"
    "39f23369a9d9bacfa530e26304231461" "b2eb05e2c39be9fcda6c19078c6a9d1b"
)
SP800_38A_CTR_COUNTER = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
SP800_38A_CTR_CIPHERTEXT = bytes.fromhex(
    "601ec313775789a5b7a7f504bbf3d228" "f443e3ca4d62b59aca84e990cacaf5c5"
    "2b0930daa23de94ce87017ba2d84988d" "dfc9c58db67aada613c2dd08457941a6"
)

# RFC 8439 2.8.2
RFC8439_KEY = bytes(range(0x80, 0xA0))
RFC8439_NONCE = bytes.fromhex("070000004041424344454647")
RFC8439_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
RFC8439_PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
)
RFC8439_CIPHERTEXT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116"
)
RFC8439_TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

# FIPS 180-4 examples
SHA_MESSAGES = [b"", b"abc", b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"]
SHA256_KNOWN = {
    b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    SHA_MESSAGES[2]: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
}
SHA512_KNOWN = {
    b"abc": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
}

# RFC 4231 test cases 1, 2 and 6 (HMAC-SHA-256)
RFC4231_CASES = [
    (b"\x0b" * 20, b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    (b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    (
        b"\xaa" * 131,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    ),
]

# RFC 7748 5.2 (first vector) and 6.1 (Alice and Bob)
RFC7748_SCALAR = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
RFC7748_U = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
RFC7748_OUTPUT = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
RFC7748_ALICE_PRIVATE = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
RFC7748_ALICE_PUBLIC = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
RFC7748_BOB_PUBLIC = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
RFC7748_SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"


def _check_published_vectors():
    assert AES.new(SP800_38A_KEY, AES.MODE_CBC, iv=SP800_38A_CBC_IV).encrypt(SP800_38A_PLAINTEXT) == (
        SP800_38A_CBC_CIPHERTEXT
    )
    ctr = AES.new(SP800_38A_KEY, AES.MODE_CTR, nonce=b"", initial_value=SP800_38A_CTR_COUNTER)
    assert ctr.encrypt(SP800_38A_PLAINTEXT) == SP800_38A_CTR_CIPHERTEXT
    chacha = ChaCha20_Poly1305.new(key=RFC8439_KEY, nonce=RFC8439_NONCE)
    chacha.update(RFC8439_AAD)
    ciphertext, tag = chacha.encrypt_and_digest(RFC8439_PLAINTEXT)
    assert (ciphertext, tag) == (RFC8439_CIPHERTEXT, RFC8439_TAG)
    for message, digest in SHA256_KNOWN.items():
        assert hashlib.sha256(message).hexdigest() == digest
    for message, digest in SHA512_KNOWN.items():
        assert hashlib.sha512(message).hexdigest() == digest
    for key, data, mac in RFC4231_CASES:
        assert hmac.new(key, data, hashlib.sha256).hexdigest() == mac


def _compute_ctr_wraparound():
    """AES-256-CTR over 3 blocks from counter 2^128 - 2: the counter wraps to zero, on all 128 bits."""
    key = bytes(range(32))
    initial_counter = (2**128 - 2).to_bytes(16, "big")
    plaintext = bytes(range(48))
    ecb = AES.new(key, AES.MODE_ECB)
    keystream = b"".join(
        ecb.encrypt(((2**128 - 2 + index) % 2**128).to_bytes(16, "big")) for index in range(3)
    )
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
    next_counter = (1).to_bytes(16, "big")
    return key, initial_counter, plaintext, ciphertext, next_counter


def _compute_rsa_vector(bits: int, public_exponent: int, label: bytes):
    key = RSA.generate(bits, randfunc=_DeterministicRandom(label), e=public_exponent)
    modulus_length = (key.n.bit_length() + 7) // 8
    message = int.from_bytes(_deterministic_bytes(label + b"/message", modulus_length), "big") % key.n
    output = pow(message, key.e, key.n)
    exponent_bytes = key.e.to_bytes((key.e.bit_length() + 7) // 8, "big")
    return (
        key.n.to_bytes(modulus_length, "big"),
        exponent_bytes,
        message.to_bytes(modulus_length, "big"),
        output.to_bytes(modulus_length, "big"),
    )


def _compute_ml_kem_vector():
    key = MLKEM.construct(param_set=MLKEM.ML_KEM_768, seed=bytes(range(64)))
    public_key = key.public_key()
    coins = bytes(range(100, 132))
    shared_secret, ciphertext = public_key._encaps(coins)
    # Decapsulation check: the private key recovers the shared secret
    assert key._decaps(ciphertext) == shared_secret
    return public_key.ek, coins, ciphertext, shared_secret


def _c_hex_literal(data: bytes, indent: str = "    ") -> str:
    text = data.hex()
    if not text:
        return '""'
    chunks = [text[index : index + 96] for index in range(0, len(text), 96)]
    return ("\n" + indent).join('"%s"' % chunk for chunk in chunks)


def _c_text_literal(data: bytes) -> str:
    assert all(0x20 <= byte < 0x7F for byte in data)
    text = data.decode("ascii").replace("\\", "\\\\").replace('"', '\\"').replace("?", "\\?")
    return '"%s"' % text


def main():
    _check_published_vectors()
    ctr_key, ctr_counter, ctr_plaintext, ctr_ciphertext, ctr_next_counter = _compute_ctr_wraparound()
    rsa_vectors = [
        _compute_rsa_vector(4096, 65537, b"wa-flightbox-rsa-4096"),
        _compute_rsa_vector(2048, 3, b"wa-flightbox-rsa-2048"),
    ]
    ml_kem_public_key, ml_kem_coins, ml_kem_ciphertext, ml_kem_shared_secret = _compute_ml_kem_vector()

    lines = [
        "/* This file is part of Witness Angel Cryptolib",
        " * SPDX-FileCopyrightText: Copyright Prolifik SARL",
        " * SPDX-License-Identifier: GPL-2.0-or-later",
        " */",
        "",
        "/* GENERATED by generate_backend_conformance_vectors.py (published vectors checked with pycryptodome and",
        " * hashlib, other values computed with pycryptodome): do not edit. */",
        "",
        "#ifndef WA_BACKEND_CONFORMANCE_VECTORS_H",
        "#define WA_BACKEND_CONFORMANCE_VECTORS_H",
        "",
        "/* SP 800-38A F.2.5 and F.5.5 */",
        "#define WA_SP800_38A_KEY_HEX %s" % _c_hex_literal(SP800_38A_KEY),
        "#define WA_SP800_38A_PLAINTEXT_HEX \\\n    %s" % " \\\n    ".join(_c_hex_literal(SP800_38A_PLAINTEXT).split("\n    ")),
        "#define WA_SP800_38A_CBC_IV_HEX %s" % _c_hex_literal(SP800_38A_CBC_IV),
        "#define WA_SP800_38A_CBC_CIPHERTEXT_HEX \\\n    %s"
        % " \\\n    ".join(_c_hex_literal(SP800_38A_CBC_CIPHERTEXT).split("\n    ")),
        "#define WA_SP800_38A_CTR_COUNTER_HEX %s" % _c_hex_literal(SP800_38A_CTR_COUNTER),
        "#define WA_SP800_38A_CTR_CIPHERTEXT_HEX \\\n    %s"
        % " \\\n    ".join(_c_hex_literal(SP800_38A_CTR_CIPHERTEXT).split("\n    ")),
        "",
        "/* AES-256-CTR with a counter wrapping around 2^128 */",
        "#define WA_CTR_WRAP_KEY_HEX %s" % _c_hex_literal(ctr_key),
        "#define WA_CTR_WRAP_COUNTER_HEX %s" % _c_hex_literal(ctr_counter),
        "#define WA_CTR_WRAP_PLAINTEXT_HEX \\\n    %s" % " \\\n    ".join(_c_hex_literal(ctr_plaintext).split("\n    ")),
        "#define WA_CTR_WRAP_CIPHERTEXT_HEX \\\n    %s"
        % " \\\n    ".join(_c_hex_literal(ctr_ciphertext).split("\n    ")),
        "#define WA_CTR_WRAP_NEXT_COUNTER_HEX %s" % _c_hex_literal(ctr_next_counter),
        "",
        "/* RFC 8439 2.8.2 */",
        "#define WA_RFC8439_KEY_HEX %s" % _c_hex_literal(RFC8439_KEY),
        "#define WA_RFC8439_NONCE_HEX %s" % _c_hex_literal(RFC8439_NONCE),
        "#define WA_RFC8439_AAD_HEX %s" % _c_hex_literal(RFC8439_AAD),
        "#define WA_RFC8439_PLAINTEXT %s" % _c_text_literal(RFC8439_PLAINTEXT),
        "#define WA_RFC8439_CIPHERTEXT_HEX \\\n    %s"
        % " \\\n    ".join(_c_hex_literal(RFC8439_CIPHERTEXT).split("\n    ")),
        "#define WA_RFC8439_TAG_HEX %s" % _c_hex_literal(RFC8439_TAG),
        "/* Same key and nonce, empty associated data and plaintext (computed with pycryptodome) */",
        "#define WA_RFC8439_KEY_AND_NONCE_EMPTY_MESSAGE_TAG_HEX %s"
        % _c_hex_literal(ChaCha20_Poly1305.new(key=RFC8439_KEY, nonce=RFC8439_NONCE).encrypt_and_digest(b"")[1]),
        "",
        "/* FIPS 180-4 examples: message, SHA-256, SHA-512 */",
        "static const struct {",
        "    const char *message;",
        "    const char *sha256_hex;",
        "    const char *sha512_hex;",
        "} wa_sha_vectors[] = {",
    ]
    for message in SHA_MESSAGES:
        lines += [
            "    {%s," % _c_text_literal(message),
            "     %s," % _c_hex_literal(hashlib.sha256(message).digest(), "     "),
            "     %s}," % _c_hex_literal(hashlib.sha512(message).digest(), "     "),
        ]
    lines += [
        "};",
        "",
        "/* RFC 4231 test cases 1, 2 and 6: key, data, HMAC-SHA-256 */",
        "static const struct {",
        "    const char *key_hex;",
        "    const char *data;",
        "    const char *mac_hex;",
        "} wa_hmac_vectors[] = {",
    ]
    for key, data, mac in RFC4231_CASES:
        lines += [
            "    {%s," % _c_hex_literal(key, "     "),
            "     %s," % _c_text_literal(data),
            '     "%s"},' % mac,
        ]
    lines += [
        "};",
        "",
        "/* RFC 7748 5.2 and 6.1 */",
        '#define WA_RFC7748_SCALAR_HEX "%s"' % RFC7748_SCALAR,
        '#define WA_RFC7748_U_HEX "%s"' % RFC7748_U,
        '#define WA_RFC7748_OUTPUT_HEX "%s"' % RFC7748_OUTPUT,
        '#define WA_RFC7748_ALICE_PRIVATE_HEX "%s"' % RFC7748_ALICE_PRIVATE,
        '#define WA_RFC7748_ALICE_PUBLIC_HEX "%s"' % RFC7748_ALICE_PUBLIC,
        '#define WA_RFC7748_BOB_PUBLIC_HEX "%s"' % RFC7748_BOB_PUBLIC,
        '#define WA_RFC7748_SHARED_HEX "%s"' % RFC7748_SHARED,
        "",
        "/* Raw RSA known values (deterministic keys): modulus, public exponent, input, input^e mod n */",
        "static const struct {",
        "    const char *modulus_hex;",
        "    const char *public_exponent_hex;",
        "    const char *input_hex;",
        "    const char *output_hex;",
        "} wa_raw_rsa_vectors[] = {",
    ]
    for modulus, exponent, message, output in rsa_vectors:
        lines += [
            "    {%s," % _c_hex_literal(modulus, "     "),
            "     %s," % _c_hex_literal(exponent, "     "),
            "     %s," % _c_hex_literal(message, "     "),
            "     %s}," % _c_hex_literal(output, "     "),
        ]
    lines += [
        "};",
        "",
        "/* ML-KEM-768 deterministic encapsulation (pycryptodome MLKEMKey._encaps(coins), key from seed 00..3f) */",
        "static const char wa_ml_kem_768_public_key_hex[] =\n    %s;" % _c_hex_literal(ml_kem_public_key),
        "static const char wa_ml_kem_768_coins_hex[] = %s;" % _c_hex_literal(ml_kem_coins),
        "static const char wa_ml_kem_768_ciphertext_hex[] =\n    %s;" % _c_hex_literal(ml_kem_ciphertext),
        "static const char wa_ml_kem_768_shared_secret_hex[] = %s;" % _c_hex_literal(ml_kem_shared_secret),
        "",
        "#endif /* WA_BACKEND_CONFORMANCE_VECTORS_H */",
        "",
    ]
    OUTPUT_PATH.write_text("\n".join(lines), encoding="ascii", newline="\n")
    print("Written", OUTPUT_PATH)


if __name__ == "__main__":
    main()
