import random

import pytest
from Crypto.PublicKey import RSA, ECC, DSA
from Crypto.Random import get_random_bytes

import uuid

import wacryptolib


def _get_binary_content():
    bytes_length = random.randint(1, 1000)
    return get_random_bytes(bytes_length)


def test_generic_encryption_and_decryption_errors():
    key = get_random_bytes(16)

    binary_content = _get_binary_content()

    with pytest.raises(ValueError, match="Unknown cipher type"):
        wacryptolib.encryption.encrypt_bytestring(
            key=key, plaintext=binary_content, encryption_type="EXHD"
        )

    with pytest.raises(ValueError, match="Unknown cipher type"):
        wacryptolib.encryption.decrypt_bytestring(
            key=key, encryption={}, encryption_type="EXHD"
        )


def test_aes_cbc_encryption_and_decryption():
    key = get_random_bytes(16)

    binary_content = _get_binary_content()

    encryption = wacryptolib.encryption.encrypt_bytestring(
        key=key, plaintext=binary_content, encryption_type="AES_CBC"
    )

    decrypted_content = wacryptolib.encryption.decrypt_bytestring(
        key=key, encryption=encryption, encryption_type="AES_CBC"
    )

    assert decrypted_content == binary_content


def test_aes_eax_encryption_and_decryption():
    key = get_random_bytes(16)

    binary_content = _get_binary_content()

    encryption = wacryptolib.encryption.encrypt_bytestring(
        key=key, plaintext=binary_content, encryption_type="AES_EAX"
    )

    decrypted_content = wacryptolib.encryption.decrypt_bytestring(
        key=key, encryption=encryption, encryption_type="AES_EAX"
    )

    assert decrypted_content == binary_content


def test_chacha20_poly1305_encryption_and_decryption():
    key = get_random_bytes(32)  # ONLY length allowed for chacha20

    binary_content = _get_binary_content()

    encryption = wacryptolib.encryption.encrypt_bytestring(
        key, binary_content, encryption_type="CHACHA20_POLY1305"
    )

    decrypted_content = wacryptolib.encryption.decrypt_bytestring(
        key=key, encryption=encryption, encryption_type="CHACHA20_POLY1305"
    )

    assert decrypted_content == binary_content


def test_rsa_oaep_encryption_and_decryption():
    uid = uuid.uuid4()
    key_length = random.choice([1024, 2048, 4096])

    keypair = wacryptolib.key_generation._generate_rsa_keypair_as_objects(
        uid, key_length=key_length
    )

    binary_content = _get_binary_content()

    encryption = wacryptolib.encryption.encrypt_bytestring(
        key=keypair["public_key"], plaintext=binary_content, encryption_type="RSA_OAEP"
    )

    decrypted_content = wacryptolib.encryption.decrypt_bytestring(
        key=keypair["private_key"], encryption=encryption, encryption_type="RSA_OAEP"
    )

    assert decrypted_content == binary_content
