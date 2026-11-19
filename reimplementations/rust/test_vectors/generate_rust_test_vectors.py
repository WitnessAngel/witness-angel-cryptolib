# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate the JSON test vector files of the Rust flightbox encryptor, next to this script.

The values are those of the C library's unit tests: this script imports the generator modules of
reimplementations/c-language/tests/unit (published vectors checked with pycryptodome and hashlib, other values computed
with wacryptolib and pycryptodome) and writes their data as JSON instead of C headers, so that both implementations
are tested on the same vectors. Byte strings are in lowercase hex.

Run from the repository root, in the wacryptolib environment (pycryptodome 4.2+):
    python reimplementations/rust/test_vectors/generate_rust_test_vectors.py

The files are committed; tests/test_rust_flightbox_test_vectors.py checks that they are up to date.
"""

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

OUTPUT_DIR = Path(__file__).resolve().parent
C_UNIT_TESTS_DIR = OUTPUT_DIR.parents[1] / "c-language" / "tests" / "unit"


def _import_c_generator(module_name: str):
    """Import a generator script of the C unit tests, without running its main()."""
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, C_UNIT_TESTS_DIR / (module_name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def build_backend_conformance_vectors() -> dict:
    generator = _import_c_generator("generate_backend_conformance_vectors")
    from Crypto.Cipher import ChaCha20_Poly1305

    generator._check_published_vectors()
    ctr_key, ctr_counter, ctr_plaintext, ctr_ciphertext, ctr_next_counter = generator._compute_ctr_wraparound()
    rsa_vectors = [
        generator._compute_rsa_vector(4096, 65537, b"wa-flightbox-rsa-4096"),
        generator._compute_rsa_vector(2048, 3, b"wa-flightbox-rsa-2048"),
    ]
    ml_kem_public_key, ml_kem_coins, ml_kem_ciphertext, ml_kem_shared_secret = generator._compute_ml_kem_vector()
    empty_message_tag = ChaCha20_Poly1305.new(key=generator.RFC8439_KEY, nonce=generator.RFC8439_NONCE).encrypt_and_digest(
        b""
    )[1]
    return {
        "sp800_38a": {
            "key": generator.SP800_38A_KEY.hex(),
            "plaintext": generator.SP800_38A_PLAINTEXT.hex(),
            "cbc_iv": generator.SP800_38A_CBC_IV.hex(),
            "cbc_ciphertext": generator.SP800_38A_CBC_CIPHERTEXT.hex(),
            "ctr_counter": generator.SP800_38A_CTR_COUNTER.hex(),
            "ctr_ciphertext": generator.SP800_38A_CTR_CIPHERTEXT.hex(),
        },
        "ctr_wraparound": {
            "key": ctr_key.hex(),
            "counter": ctr_counter.hex(),
            "plaintext": ctr_plaintext.hex(),
            "ciphertext": ctr_ciphertext.hex(),
            "next_counter": ctr_next_counter.hex(),
        },
        "rfc8439": {
            "key": generator.RFC8439_KEY.hex(),
            "nonce": generator.RFC8439_NONCE.hex(),
            "aad": generator.RFC8439_AAD.hex(),
            "plaintext": generator.RFC8439_PLAINTEXT.hex(),
            "ciphertext": generator.RFC8439_CIPHERTEXT.hex(),
            "tag": generator.RFC8439_TAG.hex(),
            "empty_message_tag": empty_message_tag.hex(),
        },
        "sha": [
            {
                "message": message.hex(),
                "sha256": hashlib.sha256(message).hexdigest(),
                "sha512": hashlib.sha512(message).hexdigest(),
            }
            for message in generator.SHA_MESSAGES
        ],
        "hmac_sha256": [{"key": key.hex(), "data": data.hex(), "mac": mac} for key, data, mac in generator.RFC4231_CASES],
        "rfc7748": {
            "scalar": generator.RFC7748_SCALAR,
            "u": generator.RFC7748_U,
            "output": generator.RFC7748_OUTPUT,
            "alice_private": generator.RFC7748_ALICE_PRIVATE,
            "alice_public": generator.RFC7748_ALICE_PUBLIC,
            "bob_public": generator.RFC7748_BOB_PUBLIC,
            "shared": generator.RFC7748_SHARED,
        },
        "raw_rsa": [
            {"modulus": modulus.hex(), "public_exponent": exponent.hex(), "input": message.hex(), "output": output.hex()}
            for modulus, exponent, message, output in rsa_vectors
        ],
        "ml_kem_768": {
            "public_key": ml_kem_public_key.hex(),
            "coins": ml_kem_coins.hex(),
            "ciphertext": ml_kem_ciphertext.hex(),
            "shared_secret": ml_kem_shared_secret.hex(),
        },
    }


def build_primitive_vectors() -> dict:
    generator = _import_c_generator("generate_primitive_vectors")
    generator._check_published_vectors()
    rsa_modulus, rsa_exponent, oaep_message, oaep_seed, oaep_encoded, oaep_ciphertext = (
        generator._compute_rsa_oaep_vector()
    )
    ml_kem_public_key, ml_kem_coins, ml_kem_plaintext, ml_kem_enc, ml_kem_sealed = (
        generator._compute_hpke_ml_kem_768_vector()
    )
    x25519_public_key, x25519_ephemeral, x25519_plaintext, x25519_enc, x25519_sealed = (
        generator._compute_hpke_x25519_empty_info_vector()
    )
    shamir_secret, shamir_threshold, shamir_count, shamir_coefficients, shamir_shards = (
        generator._compute_shamir_vector()
    )
    return {
        "cmac": {
            "key": generator.CMAC_KEY.hex(),
            "subkey_1": generator.CMAC_SUBKEY_1,
            "subkey_2": generator.CMAC_SUBKEY_2,
            "full_message": generator.CMAC_FULL_MESSAGE.hex(),
            "cases": [{"message_length": length, "mac": mac} for length, mac in generator.CMAC_CASES],
        },
        "eax": [
            {"key": key.hex(), "nonce": nonce.hex(), "message": message.hex(), "ciphertext": ciphertext.hex(),
             "tag": tag.hex()}
            for key, nonce, message, ciphertext, tag in generator._compute_eax_aes_256_vectors()
        ],
        "symmetric_cipherdicts": [
            {"cipher_algo": algo, "key": key.hex(), "iv_or_nonce": nonce.hex(), "plaintext": plaintext.hex(),
             "ciphertext": ciphertext.hex(), "tag": tag.hex()}
            for algo, key, nonce, plaintext, ciphertext, tag in generator._compute_symmetric_cipherdicts()
        ],
        "hkdf_sha256": [
            {"ikm": ikm, "salt": salt, "info": info, "length": length, "prk": prk, "okm": okm}
            for ikm, salt, info, length, prk, okm in generator.RFC5869_CASES
        ],
        "rfc9180": {
            "info": generator.RFC9180_INFO,
            "skem": generator.RFC9180_SKEM,
            "pkrm": generator.RFC9180_PKRM,
            "enc": generator.RFC9180_ENC,
            "shared_secret": generator.RFC9180_SHARED_SECRET,
            "key": generator.RFC9180_KEY,
            "base_nonce": generator.RFC9180_BASE_NONCE,
            "plaintext": generator.RFC9180_PLAINTEXT,
            "aad": generator.RFC9180_AAD,
            "ciphertext": generator.RFC9180_CIPHERTEXT,
        },
        "hpke_x25519": {
            "public_key": x25519_public_key.hex(),
            "ephemeral_scalar": x25519_ephemeral.hex(),
            "plaintext": x25519_plaintext.hex(),
            "enc": x25519_enc.hex(),
            "sealed": x25519_sealed.hex(),
        },
        "hpke_ml_kem_768": {
            "public_key": ml_kem_public_key.hex(),
            "coins": ml_kem_coins.hex(),
            "plaintext": ml_kem_plaintext.hex(),
            "enc": ml_kem_enc.hex(),
            "sealed": ml_kem_sealed.hex(),
        },
        "rsa_oaep": {
            "modulus": rsa_modulus.hex(),
            "public_exponent": rsa_exponent.hex(),
            "message": oaep_message.hex(),
            "seed": oaep_seed.hex(),
            "encoded_message": oaep_encoded.hex(),
            "ciphertext": oaep_ciphertext.hex(),
        },
        "shamir": {
            "threshold_count": shamir_threshold,
            "shard_count": shamir_count,
            "secret": shamir_secret.hex(),
            "coefficients": shamir_coefficients.hex(),
            "shards": [shard.hex() for shard in shamir_shards],
        },
    }


def build_wacbor_specification_vectors() -> list:
    generator = _import_c_generator("generate_wacbor_specification_vectors")
    specification_text = generator.SPECIFICATION_PATH.read_text(encoding="utf-8")
    match = re.search(r"^```json wa-cbor-test-vectors\n(.*?)^```", specification_text, re.MULTILINE | re.DOTALL)
    assert match, "No test vector block found in the WA-CBOR specification"
    test_vectors = json.loads(match.group(1))
    expectations = [
        (generator.ACCEPTED_VALID_VECTORS, "accepted"),
        (generator.UNSUPPORTED_VALID_VECTORS, "unsupported"),
        (generator.DECODING_ERROR_INVALID_VECTORS, "decoding_error"),
        (generator.EITHER_STATUS_INVALID_VECTORS, "unsupported_or_decoding_error"),
        (generator.NESTING_TOO_DEEP_INVALID_VECTORS, "nesting_too_deep"),
    ]
    entries = []
    for is_valid, vectors in ((True, test_vectors["valid"]), (False, test_vectors["invalid"])):
        for vector in vectors:
            matching = [expectation for names, expectation in expectations if vector["name"] in names]
            assert len(matching) == 1, "Unclassified vector %r: add it to the C generator script" % vector["name"]
            assert is_valid == (matching[0] in ("accepted", "unsupported")), vector["name"]
            entries.append(
                {
                    "name": vector["name"],
                    "cbor": vector["cbor_hex"],
                    "expectation": matching[0],
                    "is_deterministic": bool(vector["deterministic"]) if is_valid else False,
                    "extjson": vector["extjson"] if is_valid else None,
                }
            )
    assert len({entry["name"] for entry in entries}) == len(entries)
    return entries


def build_writer_expected_outputs() -> list:
    generator = _import_c_generator("generate_writer_expected_outputs")
    import cbor2
    from wacryptolib.utilities import dump_to_cbor_bytes, dump_to_json_bytes

    entries = []
    for name, structure in generator.SAMPLES:
        expected_json = dump_to_json_bytes(structure)
        assert expected_json.isascii()
        entries.append(
            {
                "name": name,
                "unsorted_input_cbor": cbor2.dumps(structure).hex(),  # Keeps insertion order, UUIDs as tag 37
                "expected_extended_json": expected_json.decode("ascii"),
                "expected_wacbor": dump_to_cbor_bytes(structure).hex(),
            }
        )
    return entries


def build_device_profile_samples() -> list:
    generator = _import_c_generator("generate_device_profile_samples")
    return [
        {
            "name": sample["name"],
            "cbor": sample["data"].hex(),
            "expected_status": sample["status"],
            "alternative_status": sample["alternative_status"],
            "expected_location": sample["location"],
            "expected_key_entry_count": sample["key_entry_count"],
        }
        for sample in generator.collect_device_profile_samples()
    ]


VECTOR_FILE_BUILDERS = {
    "backend_conformance_vectors.json": build_backend_conformance_vectors,
    "primitive_vectors.json": build_primitive_vectors,
    "wacbor_specification_vectors.json": build_wacbor_specification_vectors,
    "writer_expected_outputs.json": build_writer_expected_outputs,
    "device_profile_samples.json": build_device_profile_samples,
}


def render_vector_files() -> dict:
    """The content of every vector file, by file name: ASCII JSON, one key or item per line."""
    return {
        file_name: json.dumps(builder(), indent=1, ensure_ascii=True) + "\n"
        for file_name, builder in VECTOR_FILE_BUILDERS.items()
    }


def main():
    for file_name, content in render_vector_files().items():
        (OUTPUT_DIR / file_name).write_text(content, encoding="ascii", newline="\n")
        print("Written", OUTPUT_DIR / file_name)


if __name__ == "__main__":
    main()
