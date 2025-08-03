# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import copy
import functools
import io
import random

import pytest

import wacryptolib
from wacryptolib._crypto_backend import get_random_bytes, generate_rsa_keypair
from wacryptolib.cipher import AUTHENTICATED_CIPHER_ALGOS, PayloadEncryptionPipeline
from wacryptolib.cipher import STREAMABLE_CIPHER_ALGOS
from wacryptolib.exceptions import DecryptionError, EncryptionError, DecryptionIntegrityError, OperationNotSupported
from wacryptolib.keygen import SUPPORTED_SYMMETRIC_KEY_ALGOS, generate_symkey
from wacryptolib.utilities import SUPPORTED_HASH_ALGOS, hash_message


def _get_binary_content():
    bytes_length = random.randint(1, 1000)
    return get_random_bytes(bytes_length)


def test_generic_encryption_and_decryption_errors():
    key_dict = {"key": get_random_bytes(32)}
    binary_content = _get_binary_content()

    with pytest.raises(ValueError, match="Unknown cipher type"):
        wacryptolib.cipher.encrypt_bytestring(key_dict=key_dict, plaintext=binary_content, cipher_algo="EXHD")

    with pytest.raises(ValueError, match="Unknown cipher type"):
        wacryptolib.cipher.decrypt_bytestring(key_dict=key_dict, cipherdict={}, cipher_algo="EXHD")


def _test_random_ciphertext_corruption(decryption_func, cipherdict, initial_content):
    initial_cipherdict = copy.deepcopy(cipherdict)

    def _check_decryption_fails(new_cipherdict):
        try:
            decrypted_content_bad = decryption_func(cipherdict=new_cipherdict)
            assert decrypted_content_bad != initial_content  # Decryption weirdly succeeded but gave bad content
        except DecryptionError as exc:
            pass  # Proper failure

    for _ in range(5):
        # Test in-place modification of encrypted data

        encryption = copy.deepcopy(initial_cipherdict)

        if encryption.get("ciphertext_chunks"):  # RSA OAEP CASE
            ciphertext_chunks = encryption["ciphertext_chunks"][:]
            idx = random.randint(0, len(ciphertext_chunks) - 1)
            encryption["ciphertext_chunks"][idx] = get_random_bytes(random.randint(1, 10))
        else:
            original_ciphertext = encryption["ciphertext"]
            editable_ciphertext = bytearray(original_ciphertext)
            idx = random.randint(0, len(editable_ciphertext) - 1)
            editable_ciphertext[idx] = (editable_ciphertext[idx] + random.randint(1, 100)) % 256
            corrupted_ciphertext = bytes(editable_ciphertext)
            encryption["ciphertext"] = corrupted_ciphertext

        _check_decryption_fails(encryption)

    for _ in range(3):
        # Test extension of encrypetd data with random bytes

        suffix = get_random_bytes(random.randint(4, 10))
        if encryption.get("ciphertext_chunks"):
            encryption["ciphertext_chunks"].append(suffix)
        else:
            encryption["ciphertext"] += suffix

        _check_decryption_fails(encryption)


@pytest.mark.parametrize("cipher_algo", SUPPORTED_SYMMETRIC_KEY_ALGOS)
@pytest.mark.parametrize("use_empty_data", [True, False])
def test_symmetric_encryption_and_decryption_for_algo(cipher_algo, use_empty_data):
    key_dict = generate_symkey(cipher_algo)

    binary_content = b"" if use_empty_data else _get_binary_content()

    cipherdict = wacryptolib.cipher.encrypt_bytestring(
        key_dict=key_dict, plaintext=binary_content, cipher_algo=cipher_algo
    )

    assert "ciphertext" in cipherdict  # Mandatory field
    assert isinstance(cipherdict["ciphertext"], bytes)

    decrypted_content = wacryptolib.cipher.decrypt_bytestring(
        key_dict=key_dict, cipherdict=cipherdict, cipher_algo=cipher_algo
    )

    assert decrypted_content == binary_content

    if not use_empty_data:
        decryption_func = functools.partial(
            wacryptolib.cipher.decrypt_bytestring, key_dict=key_dict, cipher_algo=cipher_algo
        )
        _test_random_ciphertext_corruption(decryption_func, cipherdict=cipherdict, initial_content=binary_content)

    main_key_too_short = get_random_bytes(16)

    main_key_too_short_dict = key_dict.copy()
    main_key_too_short_dict["key"] = main_key_too_short

    with pytest.raises(EncryptionError, match="symmetric key length"):
        wacryptolib.cipher.encrypt_bytestring(
            key_dict=main_key_too_short_dict, plaintext=binary_content, cipher_algo=cipher_algo
        )

    with pytest.raises(DecryptionError, match="symmetric key length"):
        wacryptolib.cipher.decrypt_bytestring(
            key_dict=main_key_too_short_dict, cipherdict=cipherdict, cipher_algo=cipher_algo
        )


def test_rsa_oaep_asymmetric_encryption_and_decryption():
    key_length_bits = random.choice([2048, 3072, 4096])
    cipher_algo = "RSA_OAEP"
    keypair = wacryptolib.keygen.generate_keypair(key_algo="RSA_OAEP", serialize=False, key_length_bits=key_length_bits)

    binary_content = _get_binary_content()

    cipherdict = wacryptolib.cipher.encrypt_bytestring(
        key_dict=dict(key=keypair["public_key"]), plaintext=binary_content, cipher_algo=cipher_algo
    )

    decrypted_content = wacryptolib.cipher.decrypt_bytestring(
        key_dict=dict(key=keypair["private_key"]), cipherdict=cipherdict, cipher_algo=cipher_algo
    )

    assert decrypted_content == binary_content

    decryption_func = functools.partial(
        wacryptolib.cipher.decrypt_bytestring, key_dict=dict(key=keypair["private_key"]), cipher_algo="RSA_OAEP"
    )
    _test_random_ciphertext_corruption(decryption_func, cipherdict=cipherdict, initial_content=binary_content)

    public_key_too_short, private_key_too_short = generate_rsa_keypair(1024)

    with pytest.raises(EncryptionError, match="asymmetric key length"):
        wacryptolib.cipher.encrypt_bytestring(
            key_dict=dict(key=public_key_too_short), plaintext=binary_content, cipher_algo=cipher_algo
        )

    with pytest.raises(DecryptionError, match="asymmetric key length"):
        wacryptolib.cipher.decrypt_bytestring(
            key_dict=dict(key=private_key_too_short), cipherdict=cipherdict, cipher_algo=cipher_algo
        )


# Test each node separately, then a pipeline with all nodes
_stream_algo_nodes = [[algo] for algo in STREAMABLE_CIPHER_ALGOS] + [STREAMABLE_CIPHER_ALGOS]


@pytest.mark.parametrize("cipher_algo_list", _stream_algo_nodes)
def test_valid_payload_encryption_pipeline(cipher_algo_list):
    output_stream = io.BytesIO()

    payload_plaintext_hash_algos = random.choices(
        SUPPORTED_HASH_ALGOS, k=random.randint(1, len(SUPPORTED_HASH_ALGOS))  # Length of the returned list
    )

    payload_cipher_layer_extracts = []
    for cipher_algo in cipher_algo_list:
        payload_cipher_layers_extract = {
            "cipher_algo": cipher_algo,
            "symkey": generate_symkey(cipher_algo),
            "hash_algos": random.choices(
                SUPPORTED_HASH_ALGOS, k=random.randint(1, len(SUPPORTED_HASH_ALGOS))  # Length of the returned list
            ),
        }
        payload_cipher_layer_extracts.append(payload_cipher_layers_extract)
    print(payload_cipher_layer_extracts)

    encryption_pipeline = PayloadEncryptionPipeline(
        output_stream=output_stream,
        secrets=dict(
            payload_plaintext_hash_algos=payload_plaintext_hash_algos,
            payload_cipher_layer_extracts=payload_cipher_layer_extracts,
        ),
    )

    plaintext_full = get_random_bytes(random.randint(10, 10000))

    _plaintext_current = plaintext_full
    while _plaintext_current:
        chunk_length = random.randint(1, 300)
        chunk = _plaintext_current[0:chunk_length]
        encryption_pipeline.encrypt_chunk(chunk)
        _plaintext_current = _plaintext_current[chunk_length:]

    encryption_pipeline.finalize()

    current_ciphertext = output_stream.getvalue()

    payload_integrity_tags = encryption_pipeline.get_payload_integrity_tags()

    plaintext_digests = payload_integrity_tags["plaintext_digests"]
    for hash_algo, expected_digest in plaintext_digests.items():
        real_digest = hash_message(message=plaintext_full, hash_algo=hash_algo)
        assert real_digest == expected_digest

    ciphertext_integrity_tags = payload_integrity_tags["ciphertext_integrity_tags"]

    for payload_encryption_node, authentication_data in zip(
        reversed(payload_cipher_layer_extracts), reversed(ciphertext_integrity_tags)
    ):
        for hash_algo in payload_encryption_node["hash_algos"]:
            real_digest  = hash_message(message=current_ciphertext, hash_algo=hash_algo)
            expected_digest = authentication_data["payload_digests"][hash_algo]
            assert real_digest == expected_digest
        assert set(payload_encryption_node["hash_algos"]) == set(authentication_data["payload_digests"])

        cipherdict = {"ciphertext": current_ciphertext}
        cipherdict.update(authentication_data["payload_macs"])

        decrypted_ciphertext = wacryptolib.cipher.decrypt_bytestring(
            cipherdict=cipherdict,
            cipher_algo=payload_encryption_node["cipher_algo"],
            key_dict=payload_encryption_node["symkey"],
        )

        current_ciphertext = decrypted_ciphertext

    assert decrypted_ciphertext == plaintext_full


def test_invalid_payload_encryption_pipeline():
    payload_cipher_layers_extract = {
        "cipher_algo": "RSA_OAEP",
        "symkey": b"123",
        "hash_algos": SUPPORTED_HASH_ALGOS[0],
    }
    secrets = dict(
        payload_plaintext_hash_algos=[],
        payload_cipher_layer_extracts=[payload_cipher_layers_extract],
    )

    output_stream = io.BytesIO()
    with pytest.raises(OperationNotSupported):
        PayloadEncryptionPipeline(output_stream=output_stream, secrets=secrets)


@pytest.mark.parametrize("cipher_algo", SUPPORTED_SYMMETRIC_KEY_ALGOS)
def test_symmetric_decryption_verify(cipher_algo):
    attribute_to_corrupt = "tag"  # For now it's the only kind of authentication marker
    is_corruptable = cipher_algo in AUTHENTICATED_CIPHER_ALGOS

    key_dict = generate_symkey(cipher_algo)
    binary_content = _get_binary_content()

    cipherdict = wacryptolib.cipher.encrypt_bytestring(
        key_dict=key_dict, plaintext=binary_content, cipher_algo=cipher_algo
    )

    if is_corruptable:
        assert attribute_to_corrupt in cipherdict, cipherdict
        # Replace the attribute with random bytes
        cipherdict[attribute_to_corrupt] = get_random_bytes(len(cipherdict[attribute_to_corrupt]))

    # Decryption should not fail if verify_integrity_tags==False
    decrypted_content = wacryptolib.cipher.decrypt_bytestring(
        key_dict=key_dict, cipherdict=cipherdict, cipher_algo=cipher_algo, verify_integrity_tags=False
    )
    assert decrypted_content == binary_content

    decryption_callable = lambda: wacryptolib.cipher.decrypt_bytestring(
        key_dict=key_dict, cipherdict=cipherdict, cipher_algo=cipher_algo, verify_integrity_tags=True
    )

    # Decryption should fail if verify_integrity_tags==True, but only for algorithms that enforce an authentication check
    if is_corruptable:
        with pytest.raises(DecryptionIntegrityError):
            decryption_callable()
    else:
        decryption_callable()
