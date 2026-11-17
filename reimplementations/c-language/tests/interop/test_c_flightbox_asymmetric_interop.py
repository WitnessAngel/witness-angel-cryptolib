# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Asymmetric interoperability of the C library (task 9.4):
- RSA_OAEP, ECIES_X25519 and ML_KEM_768 key struct wraps by the C driver, in each document format, decrypted with the
  private keys of the 2026_post_quantum/pq_pool corpus pool;
- intermediate structures (symkeys, shards, key structs, cipherdicts) serialized by the C writers, byte-identical
  to dump_to_json_bytes() / dump_to_cbor_bytes() of the same trees;
- the ML-KEM KEM ciphertext and shared secret, compared with pycryptodome's MLKEMKey._encaps(coins);
- the RFC 9180 A.2.1 vector through the driver's HPKE seal.
"""

import uuid

import pytest

from c_flightbox_interop_support import COMPATIBILITY_ROOT, profile_helpers

ASYMMETRIC_CIPHER_ALGOS = ("RSA_OAEP", "ECIES_X25519", "ML_KEM_768")
KEYFACTORY_DIR = COMPATIBILITY_ROOT / "keystores" / "2026_post_quantum" / "pq_pool" / "local_keyfactory"
KEYCHAIN_UID = "0c0c0c0c-0000-4000-8000-000000000001"

METADATA_SAMPLES = {
    "no_metadata": None,
    "ascii_metadata": {"device_id": "fb-07", "sequence": 42, "flags": [True, False, None]},
    "non_ascii_metadata": {"label": "Café ☕ \U0001f600", "uid": uuid.UUID("0c0c0c0c-0000-4000-8000-0000000000ff"), "raw": b"\x00\xff"},
}

# RFC 9180 A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, Base mode, sequence number 0
RFC9180_PKRM = "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"
RFC9180_SKEM = "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"
RFC9180_INFO = "4f6465206f6e2061204772656369616e2055726e"
RFC9180_AAD = "436f756e742d30"
RFC9180_PLAINTEXT = "4265617574792069732074727574682c20747275746820626561757479"
RFC9180_ENC = "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
RFC9180_CIPHERTEXT = "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"


def _dump(document_format, tree):
    from wacryptolib.utilities import dump_to_cbor_bytes, dump_to_json_bytes

    return dump_to_cbor_bytes(tree) if document_format == "cbor" else dump_to_json_bytes(tree)


def _get_driver_public_key_argument(key_algo):
    export_script = profile_helpers.import_export_script()
    public_key_pem = (KEYFACTORY_DIR / ("%s_%s_public_key.pem" % (KEYCHAIN_UID, key_algo))).read_bytes()
    raw_public_key = export_script.convert_public_key_pem_to_raw(public_key_pem, key_algo)
    if key_algo == "RSA_OAEP":
        return raw_public_key["modulus"].hex() + ":" + raw_public_key["public_exponent"].hex()
    return raw_public_key.hex()


def _load_private_key(key_algo):
    from wacryptolib.keygen import load_asymmetric_key_from_pem_bytestring

    private_key_pem = (KEYFACTORY_DIR / ("%s_%s_private_key.pem" % (KEYCHAIN_UID, key_algo))).read_bytes()
    return load_asymmetric_key_from_pem_bytestring(private_key_pem, key_algo=key_algo)


def _load_trees_of_writers(c_build, output):
    """The tree printed by each writer of the build: all equal, returned once."""
    from wacryptolib.utilities import load_from_cbor_bytes, load_from_json_bytes

    trees = []
    if "cbor" in c_build.document_formats:
        trees.append(load_from_cbor_bytes(bytes.fromhex(output["cbor"])))
    if "json" in c_build.document_formats:
        trees.append(load_from_json_bytes(bytes.fromhex(output["json"])))
    assert all(tree == trees[0] for tree in trees)
    return trees[0]


@pytest.mark.parametrize("metadata_name", sorted(METADATA_SAMPLES))
@pytest.mark.parametrize("key_algo", ASYMMETRIC_CIPHER_ALGOS)
def test_wrapped_key_structs_decrypted_by_wacryptolib(c_build, document_format, key_algo, metadata_name):
    from wacryptolib.cipher import decrypt_bytestring
    from wacryptolib.utilities import dump_to_cbor_bytes, load_from_document_bytes

    metadata = METADATA_SAMPLES[metadata_name]
    key_bytes = bytes(range(32, 64))
    arguments = ["wrap-key", document_format, key_algo, _get_driver_public_key_argument(key_algo), key_bytes.hex()]
    if metadata is not None:
        arguments.append(dump_to_cbor_bytes(metadata).hex())
    output = c_build.run_driver(*arguments)
    assert output["status"] == "WA_STATUS_OK", output

    cipherdict = _load_trees_of_writers(c_build, output)
    expected_fields = {"ciphertext_chunks"} if key_algo == "RSA_OAEP" else {"kem_ciphertext", "ciphertext"}
    assert set(cipherdict) == expected_fields
    serialized_key_struct = decrypt_bytestring(cipherdict, cipher_algo=key_algo, key_dict=dict(key=_load_private_key(key_algo)))
    # The key struct is serialized in the document format, by the writer wacryptolib uses for it
    assert serialized_key_struct == _dump(document_format, {"key_bytes": key_bytes, "cryptainer_metadata": metadata})
    assert load_from_document_bytes(serialized_key_struct, format=document_format) == {
        "key_bytes": key_bytes,
        "cryptainer_metadata": metadata,
    }


def test_wrap_key_rejects_invalid_public_keys(c_build):
    key_bytes_hex = "00" * 32
    low_order_x25519_key = profile_helpers.get_low_order_x25519_public_keys()[0]
    output = c_build.run_driver("wrap-key", c_build.document_formats[0], "ECIES_X25519", low_order_x25519_key.hex(), key_bytes_hex)
    assert output == {"status": "WA_STATUS_KEY_CONSTRAINT_VIOLATION"}, output
    short_rsa_key = profile_helpers.make_rsa_public_key(1024)
    output = c_build.run_driver(
        "wrap-key",
        c_build.document_formats[0],
        "RSA_OAEP",
        short_rsa_key["modulus"].hex() + ":" + short_rsa_key["public_exponent"].hex(),
        key_bytes_hex,
    )
    assert output == {"status": "WA_STATUS_KEY_CONSTRAINT_VIOLATION"}, output


@pytest.mark.parametrize("cipher_algo", ["AES_CBC", "AES_EAX", "CHACHA20_POLY1305"])
def test_serialized_symkeys(c_build, document_format, cipher_algo):
    from wacryptolib.keygen import generate_symkey

    symkey = generate_symkey(cipher_algo)
    iv_or_nonce = symkey["iv"] if cipher_algo == "AES_CBC" else symkey["nonce"]
    output = c_build.run_driver("serialize", document_format, "symkey", cipher_algo, symkey["key"].hex(), iv_or_nonce.hex())
    assert output["status"] == "WA_STATUS_OK", output
    assert bytes.fromhex(output["serialized"]) == _dump(document_format, symkey)


@pytest.mark.parametrize("written_index,shard_length", [(1, 32), (2, 48), (255, 16), (7, 0)])
def test_serialized_shards(c_build, document_format, written_index, shard_length):
    shard = bytes((index * 7 + written_index) % 256 for index in range(shard_length))
    output = c_build.run_driver("serialize", document_format, "shard", str(written_index), shard.hex())
    assert output["status"] == "WA_STATUS_OK", output
    # A (index, bytes) tuple in wacryptolib, an array once serialized
    assert bytes.fromhex(output["serialized"]) == _dump(document_format, (written_index, shard))


@pytest.mark.parametrize("metadata_name", sorted(METADATA_SAMPLES))
def test_serialized_key_structs(c_build, document_format, metadata_name):
    from wacryptolib.utilities import dump_to_cbor_bytes

    metadata = METADATA_SAMPLES[metadata_name]
    key_bytes = bytes(range(100, 164))
    arguments = ["serialize", document_format, "key-struct", key_bytes.hex()]
    if metadata is not None:
        arguments.append(dump_to_cbor_bytes(metadata).hex())
    output = c_build.run_driver(*arguments)
    assert output["status"] == "WA_STATUS_OK", output
    assert bytes.fromhex(output["serialized"]) == _dump(document_format, {"key_bytes": key_bytes, "cryptainer_metadata": metadata})


@pytest.mark.parametrize("cipher_algo", ["AES_CBC", "AES_EAX", "CHACHA20_POLY1305"])
def test_serialized_symmetric_cipherdicts(c_build, cipher_algo):
    """Intermediate cipherdicts (symmetric key layers), through each writer, against wacryptolib's encryption."""
    from wacryptolib.cipher import encrypt_bytestring
    from wacryptolib.keygen import generate_symkey
    from wacryptolib.utilities import dump_to_cbor_bytes, dump_to_json_bytes

    symkey = generate_symkey(cipher_algo)
    iv_or_nonce = symkey["iv"] if cipher_algo == "AES_CBC" else symkey["nonce"]
    plaintext = bytes(range(77))
    expected_cipherdict = encrypt_bytestring(plaintext, cipher_algo=cipher_algo, key_dict=symkey)
    output = c_build.run_driver("symmetric-encrypt", cipher_algo, symkey["key"].hex(), iv_or_nonce.hex(), plaintext.hex())
    assert output["status"] == "WA_STATUS_OK", output
    if "cbor" in c_build.document_formats:
        assert bytes.fromhex(output["cbor"]) == dump_to_cbor_bytes(expected_cipherdict)
    if "json" in c_build.document_formats:
        assert bytes.fromhex(output["json"]) == dump_to_json_bytes(expected_cipherdict)


@pytest.mark.requires_pycryptodome
@pytest.mark.parametrize("seed_byte", [0, 1, 0xFF])
def test_ml_kem_encapsulation_against_pycryptodome(c_build, seed_byte):
    from Crypto.PublicKey import MLKEM

    key = MLKEM.construct(param_set=MLKEM.ML_KEM_768, seed=bytes((seed_byte + index) % 256 for index in range(64)))
    public_key = key.public_key()
    coins = bytes((seed_byte * 3 + index) % 256 for index in range(32))
    shared_secret, kem_ciphertext = public_key._encaps(coins)
    output = c_build.run_driver("ml-kem-encapsulate", public_key.ek.hex(), coins.hex())
    assert output == {
        "kem_ciphertext": kem_ciphertext.hex(),
        "shared_secret": shared_secret.hex(),
        "status": "WA_STATUS_OK",
    }


def test_rfc9180_vector(c_build):
    output = c_build.run_driver("hpke-seal", "x25519", RFC9180_PKRM, RFC9180_SKEM, RFC9180_INFO, RFC9180_AAD, RFC9180_PLAINTEXT)
    assert output == {
        "enc": RFC9180_ENC,
        "sealed": RFC9180_CIPHERTEXT,
        "consumed_randomness_length": 32,
        "status": "WA_STATUS_OK",
    }


def test_hpke_seal_fails_without_randomness(c_build):
    output = c_build.run_driver("hpke-seal", "x25519", RFC9180_PKRM, "", RFC9180_INFO, RFC9180_AAD, RFC9180_PLAINTEXT)
    assert output["status"] == "WA_STATUS_RANDOMNESS_FAILURE", output
