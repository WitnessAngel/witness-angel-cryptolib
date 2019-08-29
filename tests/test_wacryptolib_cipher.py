import random

from Crypto.PublicKey import RSA, ECC, DSA
from Crypto.Random import get_random_bytes

import uuid

import wacryptolib


def _get_binary_content():
    bytes_length = random.randint(1, 1000)
    return get_random_bytes(bytes_length)


def test_aes_cbc_encryption_and_decryption():
    key = get_random_bytes(16)

    binary_content = _get_binary_content()

    iv_and_ciphertext = wacryptolib.cipher.encrypt_via_aes_cbc(
        key=key, plaintext=binary_content
    )

    decrypted_content = wacryptolib.cipher.decrypt_via_aes_cbc(
        key=key, iv_and_ciphertext=iv_and_ciphertext
    )

    assert decrypted_content == binary_content


def test_aes_eax_encryption_and_decryption():
    key = get_random_bytes(16)

    binary_content = _get_binary_content()

    encryption = wacryptolib.cipher.encrypt_via_aes_eax(
        key=key, plaintext=binary_content
    )

    decrypted_content = wacryptolib.cipher.decrypt_via_aes_eax(key=key, encryption=encryption)

    assert decrypted_content == binary_content


def test_chacha20_symetric_encryption_and_decryption():
    key = get_random_bytes(32)  # ONLY length allowed for chacha20

    binary_content = _get_binary_content()

    encryption = wacryptolib.cipher.encrypt_via_chacha20_poly1305(
        key, binary_content, header=b"header"
    )

    decrypted_content = wacryptolib.cipher.decrypt_via_chacha20_poly1305(
        key=key, encryption=encryption
    )

    assert decrypted_content == binary_content


def test_rsa_oaep_encryption_and_decryption():
    uid = uuid.uuid4()
    key_length = random.choice([1024]) #, 2048, 4096])

    keypair = wacryptolib.key_generation._generate_rsa_keypair_as_objects(uid, key_length=key_length)

    binary_content = _get_binary_content()

    encryption = wacryptolib.cipher.encrypt_via_rsa_oaep(
        key=keypair["public_key"], plaintext=binary_content
    )

    decrypted_content = wacryptolib.cipher.decrypt_via_rsa_oaep(
        key=keypair["private_key"], encryption=encryption
    )

    assert decrypted_content == binary_content
