# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate wa_primitive_vectors.h, the vectors of the portable primitives unit tests (section 5 of the OpenSpec change
add-c-flightbox-encryptor).

Published vectors (SP 800-38B AES-256 CMAC examples, the EAX paper vectors, RFC 5869, RFC 9180 A.2.1) are written
here literally and checked with pycryptodome before being emitted. The EAX paper vectors use AES-128, which the C
library doesn't have (its backend interface is AES-256 only, design D3): pycryptodome is checked against them, then
AES-256 vectors are emitted over the same messages and nonces (the key doubled, no header, as cryptainers never use
one). Other values come from wacryptolib or pycryptodome with injected randomness: symmetric cipherdicts, RSA-OAEP
with a fixed seed, HPKE seals with given ephemeral keys or coins (checked by pycryptodome's own unseal), and Shamir
shards with given coefficients.

Run from the repository root, in the wacryptolib environment (pycryptodome 4.2+):
    python reimplementations/c-language/tests/unit/generate_primitive_vectors.py
"""

import hashlib
import hmac
import struct
from pathlib import Path

from Crypto.Cipher import AES, ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.Hash import CMAC, SHA256, SHA512
from Crypto.Protocol import HPKE, SecretSharing
from Crypto.PublicKey import ECC, MLKEM, RSA

from wacryptolib._crypto_backend import pycryptodome_secret_sharing as vendored_secret_sharing
from wacryptolib.cipher import encrypt_bytestring
from wacryptolib.shared_secret import split_secret_into_shards

OUTPUT_PATH = Path(__file__).with_name("wa_primitive_vectors.h")


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


class _ReplayedRandom:
    """Return the given bytes, in order, and record nothing else: checks that exactly all of them are consumed."""

    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    def __call__(self, length: int) -> bytes:
        chunk = self._data[self._offset : self._offset + length]
        assert len(chunk) == length, "Replayed randomness exhausted"
        self._offset += length
        return chunk

    def is_exhausted(self) -> bool:
        return self._offset == len(self._data)


# SP 800-38B D.3 (CMAC-AES256), over the messages of RFC 4493 (prefixes of the SP 800-38A plaintext)
CMAC_KEY = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
CMAC_SUBKEY_1 = "cad1ed03299eedac2e9a99808621502f"
CMAC_SUBKEY_2 = "95a3da06533ddb585d3533010c42a0d9"
CMAC_FULL_MESSAGE = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
)
CMAC_CASES = [
    (0, "028962f61b7bf89efc6b551f4667d983"),
    (16, "28a7023f452e8f82bd4bf28d8c37c35c"),
    (40, "aaf3d8f1de5640c232f5b169b9c911e6"),
    (64, "e1992190549f6ed5696a2c056c315410"),
]

# EAX paper (Bellare, Rogaway, Wagner), AES-128: message, key, nonce, header, ciphertext || tag
EAX_PAPER_VECTORS = [
    ("", "233952DEE4D5ED5F9B9C6D6FF80FF478", "62EC67F9C3A4A407FCB2A8C49031A8B3", "6BFB914FD07EAE6B",
     "E037830E8389F27B025A2D6527E79D01"),
    ("F7FB", "91945D3F4DCBEE0BF45EF52255F095A4", "BECAF043B0A23D843194BA972C66DEBD", "FA3BFD4806EB53FA",
     "19DD5C4C9331049D0BDAB0277408F67967E5"),
    ("1A47CB4933", "01F74AD64077F2E704C0F60ADA3DD523", "70C3DB4F0D26368400A10ED05D2BFF5E", "234A3463C1264AC6",
     "D851D5BAE03A59F238A23E39199DC9266626C40F80"),
    ("481C9E39B1", "D07CF6CBB7F313BDDE66B727AFD3C5E8", "8408DFFF3C1A2B1292DC199E46B7D617", "33CCE2EABFF5A79D",
     "632A9D131AD4C168A4225D8E1FF755939974A7BEDE"),
    ("40D0C07DA5E4", "35B6D0580005BBC12B0587124557D2C2", "FDB6B06676EEDC5C61D74276E1F8E816", "AEB96EAEBE2970E9",
     "071DFE16C675CB0677E536F73AFE6A14B74EE49844DD"),
    ("4DE3B35C3FC039245BD1FB7D", "BD8E6E11475E60B268784C38C62FEB22", "6EAC5C93072D8E8513F750935E46DA1B",
     "D4482D1CA78DCE0F", "835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F"),
    ("8B0A79306C9CE7ED99DAE4F87F8DD61636", "7C77D6E813BED5AC98BAA417477A2E7D", "1A8C98DCD73D38393B2BF1569DEEFC19",
     "65D2017990D62528", "02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2"),
    ("1BDA122BCE8A8DBAF1877D962B8592DD2D56", "5FFF20CAFAB119CA2FC73549E20F5B0D", "DDE59B97D722156D4D9AFF2BC7559826",
     "54B9F04E6A09189A", "2EC47B2C4954A489AFC7BA4897EDCDAE8CC33B60450599BD02C96382902AEF7F832A"),
    ("6CF36720872B8513F6EAB1A8A44438D5EF11", "A4A4782BCFFD3EC5E7EF6D8C34A56123", "B781FCF2F75FA5A8DE97A9CA48E522EC",
     "899A175897561D7E", "0DE18FD0FDD91E7AF19F1D8EE8733938B1E8E7F6D2231618102FDB7FE55FF1991700"),
    ("CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7", "8395FCF1E95BEBD697BD010BC766AAC3",
     "22E7ADD93CFC6393C57EC0B3C17D6B44", "126735FCC320D25A",
     "CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E"),
]

# RFC 5869 A.1, A.2 and A.3 (HKDF-SHA256): ikm, salt, info, length, prk, okm
RFC5869_CASES = [
    ("0b" * 22, "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
     "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
     "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
    (bytes(range(0x00, 0x50)).hex(), bytes(range(0x60, 0xB0)).hex(), bytes(range(0xB0, 0x100)).hex(), 82,
     "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
     "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09"
     "da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"),
    ("0b" * 22, "", "", 42,
     "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
     "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
]

# RFC 9180 A.2.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, Base mode), sequence number 0
RFC9180_INFO = "4f6465206f6e2061204772656369616e2055726e"
RFC9180_SKEM = "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"
RFC9180_PKRM = "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"
RFC9180_SKRM = "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"
RFC9180_ENC = "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
RFC9180_SHARED_SECRET = "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7"
RFC9180_KEY = "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91"
RFC9180_BASE_NONCE = "5c4d98150661b848853b547f"
RFC9180_PLAINTEXT = "4265617574792069732074727574682c20747275746820626561757479"
RFC9180_AAD = "436f756e742d30"
RFC9180_CIPHERTEXT = (
    "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"
)


def _hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int):
    prk = hmac.new(salt if salt else bytes(32), ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return prk, okm[:length]


def _hpke_key_schedule(shared_secret: bytes, info: bytes, kem_id: int):
    suite_id = b"HPKE" + struct.pack(">HHH", kem_id, 0x0001, 0x0003)
    psk_id_hash = HPKE._labeled_extract(b"", b"psk_id_hash", b"", suite_id, SHA256)
    info_hash = HPKE._labeled_extract(b"", b"info_hash", info, suite_id, SHA256)
    context = b"\x00" + psk_id_hash + info_hash
    secret = HPKE._labeled_extract(shared_secret, b"secret", b"", suite_id, SHA256)
    key = HPKE._labeled_expand(secret, b"key", context, 32, suite_id, SHA256)
    base_nonce = HPKE._labeled_expand(secret, b"base_nonce", context, 12, suite_id, SHA256)
    return key, base_nonce


def _chacha20_poly1305_seal(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext + tag


def _hpke_x25519_seal(receiver_private_key, ephemeral_scalar: bytes, info: bytes, aad: bytes, plaintext: bytes):
    ephemeral_key = ECC.construct(curve="Curve25519", seed=ephemeral_scalar)
    shared_secret, enc = HPKE.HPKE_Cipher._encap(
        receiver_private_key.public_key(), 0x0020, SHA256, None, ephemeral_key
    )
    key, base_nonce = _hpke_key_schedule(shared_secret, info, 0x0020)
    sealed = _chacha20_poly1305_seal(key, base_nonce, aad, plaintext)
    # pycryptodome's own receiver recovers the plaintext
    receiver = HPKE.new(receiver_key=receiver_private_key, aead_id=HPKE.AEAD.CHACHA20_POLY1305, enc=enc, info=info)
    assert receiver.unseal(sealed, aad) == plaintext
    return enc, shared_secret, key, base_nonce, sealed


def _check_published_vectors():
    cmac_subkey_1, cmac_subkey_2 = None, None
    for length, mac in CMAC_CASES:
        assert CMAC.new(CMAC_KEY, CMAC_FULL_MESSAGE[:length], ciphermod=AES).hexdigest() == mac
    # Subkeys: K1 = dbl(E_K(0)), K2 = dbl(K1)
    l_value = int.from_bytes(AES.new(CMAC_KEY, AES.MODE_ECB).encrypt(bytes(16)), "big")

    def double(value):
        value <<= 1
        if value >> 128:
            value = (value & (2**128 - 1)) ^ 0x87
        return value

    cmac_subkey_1 = double(l_value)
    cmac_subkey_2 = double(cmac_subkey_1)
    assert cmac_subkey_1.to_bytes(16, "big").hex() == CMAC_SUBKEY_1
    assert cmac_subkey_2.to_bytes(16, "big").hex() == CMAC_SUBKEY_2

    for message, key, nonce, header, expected in EAX_PAPER_VECTORS:
        cipher = AES.new(bytes.fromhex(key), AES.MODE_EAX, nonce=bytes.fromhex(nonce), mac_len=16)
        cipher.update(bytes.fromhex(header))
        ciphertext, tag = cipher.encrypt_and_digest(bytes.fromhex(message))
        assert (ciphertext + tag).hex().upper() == expected

    for ikm, salt, info, length, prk, okm in RFC5869_CASES:
        assert _hkdf_sha256(bytes.fromhex(salt), bytes.fromhex(ikm), bytes.fromhex(info), length) == (
            bytes.fromhex(prk),
            bytes.fromhex(okm),
        )

    receiver_key = ECC.construct(curve="Curve25519", seed=bytes.fromhex(RFC9180_SKRM))
    assert receiver_key.public_key().export_key(format="raw").hex() == RFC9180_PKRM
    enc, shared_secret, key, base_nonce, sealed = _hpke_x25519_seal(
        receiver_key,
        bytes.fromhex(RFC9180_SKEM),
        bytes.fromhex(RFC9180_INFO),
        bytes.fromhex(RFC9180_AAD),
        bytes.fromhex(RFC9180_PLAINTEXT),
    )
    assert (enc.hex(), shared_secret.hex(), key.hex(), base_nonce.hex(), sealed.hex()) == (
        RFC9180_ENC,
        RFC9180_SHARED_SECRET,
        RFC9180_KEY,
        RFC9180_BASE_NONCE,
        RFC9180_CIPHERTEXT,
    )


def _compute_eax_aes_256_vectors():
    vectors = []
    for message, key, nonce, _header, _expected in EAX_PAPER_VECTORS:
        key_256 = bytes.fromhex(key) * 2
        cipher = AES.new(key_256, AES.MODE_EAX, nonce=bytes.fromhex(nonce), mac_len=16)
        ciphertext, tag = cipher.encrypt_and_digest(bytes.fromhex(message))
        vectors.append((key_256, bytes.fromhex(nonce), bytes.fromhex(message), ciphertext, tag))
    return vectors


def _compute_symmetric_cipherdicts():
    plaintext = _deterministic_bytes(b"wa-flightbox-symmetric-plaintext", 100)
    vectors = []
    for algo, nonce_name, nonce_length in (
        ("AES_CBC", "iv", 16),
        ("AES_EAX", "nonce", 16),
        ("CHACHA20_POLY1305", "nonce", 12),
    ):
        key = _deterministic_bytes(b"wa-flightbox-symkey/" + algo.encode(), 32)
        nonce = _deterministic_bytes(b"wa-flightbox-nonce/" + algo.encode(), nonce_length)
        for length in (0, 15, 16, 17, 100):
            cipherdict = encrypt_bytestring(plaintext[:length], cipher_algo=algo, key_dict={"key": key, nonce_name: nonce})
            assert set(cipherdict) == ({"ciphertext"} if algo == "AES_CBC" else {"ciphertext", "tag"}), cipherdict
            vectors.append((algo, key, nonce, plaintext[:length], cipherdict["ciphertext"], cipherdict.get("tag", b"")))
    return vectors


def _compute_rsa_oaep_vector():
    key = RSA.generate(2048, randfunc=_DeterministicRandom(b"wa-flightbox-oaep-rsa-2048"))
    message = _deterministic_bytes(b"wa-flightbox-oaep-message", 60)
    seed = _deterministic_bytes(b"wa-flightbox-oaep-seed", 64)
    replayed = _ReplayedRandom(seed)
    ciphertext = PKCS1_OAEP.new(key, hashAlgo=SHA512, randfunc=replayed).encrypt(message)
    assert replayed.is_exhausted()
    modulus_length = key.size_in_bytes()
    encoded = pow(int.from_bytes(ciphertext, "big"), key.d, key.n).to_bytes(modulus_length, "big")
    assert encoded[0] == 0
    return (
        key.n.to_bytes(modulus_length, "big"),
        key.e.to_bytes((key.e.bit_length() + 7) // 8, "big"),
        message,
        seed,
        encoded,
        ciphertext,
    )


def _compute_hpke_ml_kem_768_vector():
    private_key = MLKEM.construct(param_set=MLKEM.ML_KEM_768, seed=_deterministic_bytes(b"wa-flightbox-mlkem-seed", 64))
    public_key = private_key.public_key()
    coins = _deterministic_bytes(b"wa-flightbox-mlkem-coins", 32)
    plaintext = _deterministic_bytes(b"wa-flightbox-mlkem-plaintext", 93)
    shared_secret, enc = public_key._encaps(coins)
    key, base_nonce = _hpke_key_schedule(shared_secret, b"", 0x0041)
    sealed = _chacha20_poly1305_seal(key, base_nonce, b"", plaintext)
    receiver = HPKE.new(receiver_key=private_key, aead_id=HPKE.AEAD.CHACHA20_POLY1305, enc=enc)
    assert receiver.unseal(sealed) == plaintext
    return public_key.ek, coins, plaintext, enc, sealed


def _compute_hpke_x25519_empty_info_vector():
    receiver_key = ECC.construct(curve="Curve25519", seed=_deterministic_bytes(b"wa-flightbox-x25519-receiver", 32))
    ephemeral_scalar = _deterministic_bytes(b"wa-flightbox-x25519-ephemeral", 32)
    plaintext = _deterministic_bytes(b"wa-flightbox-x25519-plaintext", 93)
    enc, _shared_secret, _key, _base_nonce, sealed = _hpke_x25519_seal(
        receiver_key, ephemeral_scalar, b"", b"", plaintext
    )
    return receiver_key.public_key().export_key(format="raw"), ephemeral_scalar, plaintext, enc, sealed


def _compute_shamir_vector():
    secret = _deterministic_bytes(b"wa-flightbox-shamir-secret", 20)  # Padded to 2 chunks
    threshold_count, shard_count = 3, 5
    coefficients = _deterministic_bytes(b"wa-flightbox-shamir-coefficients", 2 * (threshold_count - 1) * 16)
    replayed = _ReplayedRandom(coefficients)
    # wacryptolib uses a vendored copy of pycryptodome's Shamir module: both are patched
    patched_modules = (SecretSharing, vendored_secret_sharing)
    original_rngs = [module.rng for module in patched_modules]
    for module in patched_modules:
        module.rng = replayed
    try:
        shards = split_secret_into_shards(secret, shard_count=shard_count, threshold_count=threshold_count)
    finally:
        for module, original_rng in zip(patched_modules, original_rngs):
            module.rng = original_rng
    assert replayed.is_exhausted()
    assert [index for index, _ in shards] == list(range(1, shard_count + 1))
    return secret, threshold_count, shard_count, coefficients, [shard for _, shard in shards]


def _hex_literal(data: bytes, indent: str = "    ") -> str:
    text = data.hex()
    if not text:
        return '""'
    chunks = [text[index : index + 96] for index in range(0, len(text), 96)]
    return ("\n" + indent).join('"%s"' % chunk for chunk in chunks)


def _define(name: str, data: bytes) -> str:
    literal = _hex_literal(data)
    if "\n" in literal:
        return "#define %s \\\n    %s" % (name, " \\\n    ".join(literal.split("\n    ")))
    return "#define %s %s" % (name, literal)


def main():
    _check_published_vectors()
    eax_vectors = _compute_eax_aes_256_vectors()
    symmetric_vectors = _compute_symmetric_cipherdicts()
    rsa_modulus, rsa_exponent, oaep_message, oaep_seed, oaep_encoded, oaep_ciphertext = _compute_rsa_oaep_vector()
    ml_kem_public_key, ml_kem_coins, ml_kem_plaintext, ml_kem_enc, ml_kem_sealed = _compute_hpke_ml_kem_768_vector()
    x25519_public_key, x25519_ephemeral, x25519_plaintext, x25519_enc, x25519_sealed = (
        _compute_hpke_x25519_empty_info_vector()
    )
    shamir_secret, shamir_threshold, shamir_count, shamir_coefficients, shamir_shards = _compute_shamir_vector()

    lines = [
        "/* This file is part of Witness Angel Cryptolib",
        " * SPDX-FileCopyrightText: Copyright Prolifik SARL",
        " * SPDX-License-Identifier: GPL-2.0-or-later",
        " */",
        "",
        "/* GENERATED by generate_primitive_vectors.py (published vectors checked with pycryptodome, other values",
        " * computed with wacryptolib and pycryptodome): do not edit. */",
        "",
        "#ifndef WA_PRIMITIVE_VECTORS_H",
        "#define WA_PRIMITIVE_VECTORS_H",
        "",
        "#include <stddef.h>",
        "",
        "/* SP 800-38B D.3: CMAC-AES256 over the RFC 4493 messages */",
        _define("WA_CMAC_KEY_HEX", CMAC_KEY),
        '#define WA_CMAC_SUBKEY_1_HEX "%s"' % CMAC_SUBKEY_1,
        '#define WA_CMAC_SUBKEY_2_HEX "%s"' % CMAC_SUBKEY_2,
        _define("WA_CMAC_FULL_MESSAGE_HEX", CMAC_FULL_MESSAGE),
        "static const struct {",
        "    size_t message_length;",
        "    const char *mac_hex;",
        "} wa_cmac_vectors[] = {",
    ]
    lines += ['    {%d, "%s"},' % (length, mac) for length, mac in CMAC_CASES]
    lines += [
        "};",
        "",
        "/* AES-256 EAX over the messages and nonces of the EAX paper vectors: key = paper key twice, no header */",
        "static const struct {",
        "    const char *key_hex;",
        "    const char *nonce_hex;",
        "    const char *message_hex;",
        "    const char *ciphertext_hex;",
        "    const char *tag_hex;",
        "} wa_eax_vectors[] = {",
    ]
    for key, nonce, message, ciphertext, tag in eax_vectors:
        lines.append(
            '    {"%s", "%s", "%s", "%s", "%s"},' % (key.hex(), nonce.hex(), message.hex(), ciphertext.hex(), tag.hex())
        )
    lines += [
        "};",
        "",
        "/* One-shot cipherdicts of wacryptolib's encrypt_bytestring() */",
        "static const struct {",
        "    const char *cipher_algo;",
        "    const char *key_hex;",
        "    const char *iv_or_nonce_hex;",
        "    const char *plaintext_hex;",
        "    const char *ciphertext_hex;",
        "    const char *tag_hex; /* Empty for AES_CBC */",
        "} wa_symmetric_cipherdict_vectors[] = {",
    ]
    for algo, key, nonce, plaintext, ciphertext, tag in symmetric_vectors:
        lines += [
            '    {"%s", "%s", "%s",' % (algo, key.hex(), nonce.hex()),
            "     %s," % _hex_literal(plaintext, "     "),
            "     %s," % _hex_literal(ciphertext, "     "),
            '     "%s"},' % tag.hex(),
        ]
    lines += [
        "};",
        "",
        "/* RFC 5869 A.1 to A.3 (HKDF-SHA256) */",
        "static const struct {",
        "    const char *ikm_hex;",
        "    const char *salt_hex;",
        "    const char *info_hex;",
        "    size_t length;",
        "    const char *prk_hex;",
        "    const char *okm_hex;",
        "} wa_hkdf_vectors[] = {",
    ]
    for ikm, salt, info, length, prk, okm in RFC5869_CASES:
        lines += [
            "    {%s," % _hex_literal(bytes.fromhex(ikm), "     "),
            "     %s," % _hex_literal(bytes.fromhex(salt), "     "),
            "     %s," % _hex_literal(bytes.fromhex(info), "     "),
            "     %d," % length,
            '     "%s",' % prk,
            "     %s}," % _hex_literal(bytes.fromhex(okm), "     "),
        ]
    lines += [
        "};",
        "",
        "/* RFC 9180 A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, Base mode, sequence 0 */",
        '#define WA_RFC9180_INFO_HEX "%s"' % RFC9180_INFO,
        '#define WA_RFC9180_SKEM_HEX "%s"' % RFC9180_SKEM,
        '#define WA_RFC9180_PKRM_HEX "%s"' % RFC9180_PKRM,
        '#define WA_RFC9180_ENC_HEX "%s"' % RFC9180_ENC,
        '#define WA_RFC9180_SHARED_SECRET_HEX "%s"' % RFC9180_SHARED_SECRET,
        '#define WA_RFC9180_KEY_HEX "%s"' % RFC9180_KEY,
        '#define WA_RFC9180_BASE_NONCE_HEX "%s"' % RFC9180_BASE_NONCE,
        '#define WA_RFC9180_PLAINTEXT_HEX "%s"' % RFC9180_PLAINTEXT,
        '#define WA_RFC9180_AAD_HEX "%s"' % RFC9180_AAD,
        _define("WA_RFC9180_CIPHERTEXT_HEX", bytes.fromhex(RFC9180_CIPHERTEXT)),
        "",
        "/* HPKE X25519 seal with empty info and AAD, as in cryptainers (opened by pycryptodome) */",
        _define("WA_HPKE_X25519_PUBLIC_KEY_HEX", x25519_public_key),
        _define("WA_HPKE_X25519_EPHEMERAL_SCALAR_HEX", x25519_ephemeral),
        _define("WA_HPKE_X25519_PLAINTEXT_HEX", x25519_plaintext),
        _define("WA_HPKE_X25519_ENC_HEX", x25519_enc),
        _define("WA_HPKE_X25519_SEALED_HEX", x25519_sealed),
        "",
        "/* HPKE ML-KEM-768 (KEM 0x0041, pycryptodome's draft-ietf-hpke-pq) seal with given coins (opened by",
        " * pycryptodome) */",
        "static const char wa_hpke_ml_kem_768_public_key_hex[] =\n    %s;" % _hex_literal(ml_kem_public_key),
        "static const char wa_hpke_ml_kem_768_coins_hex[] = %s;" % _hex_literal(ml_kem_coins),
        "static const char wa_hpke_ml_kem_768_plaintext_hex[] =\n    %s;" % _hex_literal(ml_kem_plaintext),
        "static const char wa_hpke_ml_kem_768_enc_hex[] =\n    %s;" % _hex_literal(ml_kem_enc),
        "static const char wa_hpke_ml_kem_768_sealed_hex[] =\n    %s;" % _hex_literal(ml_kem_sealed),
        "",
        "/* RSA-OAEP (SHA-512, MGF1-SHA-512, empty label) of pycryptodome with a fixed seed: 2048-bit key */",
        "static const char wa_oaep_modulus_hex[] =\n    %s;" % _hex_literal(rsa_modulus),
        "static const char wa_oaep_public_exponent_hex[] = %s;" % _hex_literal(rsa_exponent),
        "static const char wa_oaep_message_hex[] =\n    %s;" % _hex_literal(oaep_message),
        "static const char wa_oaep_seed_hex[] =\n    %s;" % _hex_literal(oaep_seed),
        "static const char wa_oaep_encoded_message_hex[] =\n    %s;" % _hex_literal(oaep_encoded),
        "static const char wa_oaep_ciphertext_hex[] =\n    %s;" % _hex_literal(oaep_ciphertext),
        "",
        "/* wacryptolib's split_secret_into_shards() with replayed coefficients (2 chunks of k - 1 coefficients) */",
        "#define WA_SHAMIR_THRESHOLD_COUNT %d" % shamir_threshold,
        "#define WA_SHAMIR_SHARD_COUNT %d" % shamir_count,
        _define("WA_SHAMIR_SECRET_HEX", shamir_secret),
        _define("WA_SHAMIR_COEFFICIENTS_HEX", shamir_coefficients),
        "static const char *const wa_shamir_shards_hex[WA_SHAMIR_SHARD_COUNT] = {",
    ]
    lines += ["    %s," % _hex_literal(shard, "    ") for shard in shamir_shards]
    lines += ["};", "", "#endif /* WA_PRIMITIVE_VECTORS_H */", ""]
    OUTPUT_PATH.write_text("\n".join(lines), encoding="ascii", newline="\n")
    print("Written", OUTPUT_PATH)


if __name__ == "__main__":
    main()
