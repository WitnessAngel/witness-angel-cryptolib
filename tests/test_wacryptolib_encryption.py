import copy
import functools
import random

import pytest
from Crypto.Random import get_random_bytes

import wacryptolib


def _get_binary_content():
    bytes_length = random.randint(1, 1000)
    return get_random_bytes(bytes_length)


def test_generic_encryption_and_decryption_errors():
    key = get_random_bytes(16)

    binary_content = _get_binary_content()

    with pytest.raises(ValueError, match="Unknown cipher type"):
        wacryptolib.encryption.encrypt_bytestring(
            key=key, plaintext=binary_content, encryption_algo="EXHD"
        )

    with pytest.raises(ValueError, match="Unknown cipher type"):
        wacryptolib.encryption.decrypt_bytestring(
            key=key, cipherdict={}, encryption_algo="EXHD"
        )


def _test_random_ciphertext_corruption(decryption_func, cipherdict, initial_content):

    initial_cipherdict = copy.deepcopy(cipherdict)

    def _ensure_decryption_fails(new_cipherdict):
        try:
            decrypted_content_bad = decryption_func(cipherdict=new_cipherdict)
            assert decrypted_content_bad != initial_content
        except ValueError as exc:
            msg = str(exc).lower()
            assert (
                "mac" in msg or "padded" in msg or "padding" in msg or "length" in msg
            )

    for _ in range(5):

        # Test in-place modification of encrypted data

        encryption = copy.deepcopy(initial_cipherdict)

        if encryption.get("digest_list"):  # RSA OAEP CASE
            digest_list = encryption["digest_list"][:]
            idx = random.randint(0, len(digest_list) - 1)
            encryption["digest_list"][idx] = get_random_bytes(random.randint(1, 10))
        else:
            original_ciphertext = encryption["ciphertext"]
            editable_ciphertext = bytearray(original_ciphertext)
            idx = random.randint(0, len(editable_ciphertext) - 1)
            editable_ciphertext[idx] = (
                editable_ciphertext[idx] + random.randint(1, 100)
            ) % 256
            corrupted_ciphertext = bytes(editable_ciphertext)
            encryption["ciphertext"] = corrupted_ciphertext

        _ensure_decryption_fails(encryption)

    for _ in range(3):

        # Test extension of encrypetd data with random bytes

        suffix = get_random_bytes(random.randint(4, 10))
        if encryption.get("digest_list"):
            encryption["digest_list"].append(suffix)
        else:
            encryption["ciphertext"] += suffix

        _ensure_decryption_fails(encryption)


def test_aes_cbc_encryption_and_decryption():
    key = get_random_bytes(16)

    binary_content = _get_binary_content()

    cipherdict = wacryptolib.encryption.encrypt_bytestring(
        key=key, plaintext=binary_content, encryption_algo="AES_CBC"
    )

    decrypted_content = wacryptolib.encryption.decrypt_bytestring(
        key=key, cipherdict=cipherdict, encryption_algo="AES_CBC"
    )

    assert decrypted_content == binary_content

    decryption_func = functools.partial(
        wacryptolib.encryption.decrypt_bytestring, key=key, encryption_algo="AES_CBC"
    )
    _test_random_ciphertext_corruption(
        decryption_func, cipherdict=cipherdict, initial_content=binary_content
    )


def test_aes_eax_encryption_and_decryption():
    key = get_random_bytes(16)

    binary_content = _get_binary_content()

    cipherdict = wacryptolib.encryption.encrypt_bytestring(
        key=key, plaintext=binary_content, encryption_algo="AES_EAX"
    )

    decrypted_content = wacryptolib.encryption.decrypt_bytestring(
        key=key, cipherdict=cipherdict, encryption_algo="AES_EAX"
    )

    assert decrypted_content == binary_content

    decryption_func = functools.partial(
        wacryptolib.encryption.decrypt_bytestring, key=key, encryption_algo="AES_EAX"
    )
    _test_random_ciphertext_corruption(
        decryption_func, cipherdict=cipherdict, initial_content=binary_content
    )


def test_chacha20_poly1305_encryption_and_decryption():
    key = get_random_bytes(32)  # ONLY length allowed for chacha20

    binary_content = _get_binary_content()

    cipherdict = wacryptolib.encryption.encrypt_bytestring(
        key=key, plaintext=binary_content, encryption_algo="CHACHA20_POLY1305"
    )

    decrypted_content = wacryptolib.encryption.decrypt_bytestring(
        key=key, cipherdict=cipherdict, encryption_algo="CHACHA20_POLY1305"
    )

    assert decrypted_content == binary_content

    decryption_func = functools.partial(
        wacryptolib.encryption.decrypt_bytestring,
        key=key,
        encryption_algo="CHACHA20_POLY1305",
    )
    _test_random_ciphertext_corruption(
        decryption_func, cipherdict=cipherdict, initial_content=binary_content
    )


def test_rsa_oaep_encryption_and_decryption():
    key_length = random.choice([2048, 4096])

    keypair = wacryptolib.key_generation._generate_rsa_keypair_as_objects(
        key_length=key_length
    )

    binary_content = _get_binary_content()

    cipherdict = wacryptolib.encryption.encrypt_bytestring(
        key=keypair["public_key"], plaintext=binary_content, encryption_algo="RSA_OAEP"
    )

    decrypted_content = wacryptolib.encryption.decrypt_bytestring(
        key=keypair["private_key"], cipherdict=cipherdict, encryption_algo="RSA_OAEP"
    )

    assert decrypted_content == binary_content

    decryption_func = functools.partial(
        wacryptolib.encryption.decrypt_bytestring,
        key=keypair["private_key"],
        encryption_algo="RSA_OAEP",
    )
    _test_random_ciphertext_corruption(
        decryption_func, cipherdict=cipherdict, initial_content=binary_content
    )
