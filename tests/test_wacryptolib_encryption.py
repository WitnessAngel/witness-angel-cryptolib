import copy
import functools
import random

import pytest
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import wacryptolib
from wacryptolib.exceptions import DecryptionError, EncryptionError
from wacryptolib.key_generation import SUPPORTED_SYMMETRIC_KEY_ALGOS


def _get_binary_content():
    bytes_length = random.randint(1, 1000)
    return get_random_bytes(bytes_length)


def test_generic_encryption_and_decryption_errors():
    key = get_random_bytes(32)

    binary_content = _get_binary_content()

    with pytest.raises(ValueError, match="Unknown cipher type"):
        wacryptolib.encryption.encrypt_bytestring(key=key, plaintext=binary_content, encryption_algo="EXHD")

    with pytest.raises(ValueError, match="Unknown cipher type"):
        wacryptolib.encryption.decrypt_bytestring(key=key, cipherdict={}, encryption_algo="EXHD")


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

        if encryption.get("digest_list"):  # RSA OAEP CASE
            digest_list = encryption["digest_list"][:]
            idx = random.randint(0, len(digest_list) - 1)
            encryption["digest_list"][idx] = get_random_bytes(random.randint(1, 10))
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
        if encryption.get("digest_list"):
            encryption["digest_list"].append(suffix)
        else:
            encryption["ciphertext"] += suffix

        _check_decryption_fails(encryption)


@pytest.mark.parametrize("encryption_algo", SUPPORTED_SYMMETRIC_KEY_ALGOS)
def test_symmetric_encryption_and_decryption_for_algo(encryption_algo):

    key = get_random_bytes(32)  # ALWAYS this length as a minimum

    binary_content = _get_binary_content()

    cipherdict = wacryptolib.encryption.encrypt_bytestring(
        key=key, plaintext=binary_content, encryption_algo=encryption_algo
    )

    decrypted_content = wacryptolib.encryption.decrypt_bytestring(
        key=key, cipherdict=cipherdict, encryption_algo=encryption_algo
    )

    assert decrypted_content == binary_content

    decryption_func = functools.partial(
        wacryptolib.encryption.decrypt_bytestring, key=key, encryption_algo=encryption_algo
    )
    _test_random_ciphertext_corruption(decryption_func, cipherdict=cipherdict, initial_content=binary_content)

    key_too_short = get_random_bytes(16)

    with pytest.raises(EncryptionError, match="symmetric key length"):
        wacryptolib.encryption.encrypt_bytestring(
            key=key_too_short, plaintext=binary_content, encryption_algo=encryption_algo
        )

    with pytest.raises(DecryptionError, match="symmetric key length"):
        wacryptolib.encryption.decrypt_bytestring(
            key=key_too_short, cipherdict=cipherdict, encryption_algo=encryption_algo
        )


def test_rsa_oaep_asymmetric_encryption_and_decryption():
    key_length_bits = random.choice([2048, 3072, 4096])
    encryption_algo = "RSA_OAEP"
    keypair = wacryptolib.key_generation.generate_asymmetric_keypair(
        key_type="RSA_OAEP", serialize=False, key_length_bits=key_length_bits
    )

    binary_content = _get_binary_content()

    cipherdict = wacryptolib.encryption.encrypt_bytestring(
        key=keypair["public_key"], plaintext=binary_content, encryption_algo=encryption_algo
    )

    decrypted_content = wacryptolib.encryption.decrypt_bytestring(
        key=keypair["private_key"], cipherdict=cipherdict, encryption_algo=encryption_algo
    )

    assert decrypted_content == binary_content

    decryption_func = functools.partial(
        wacryptolib.encryption.decrypt_bytestring, key=keypair["private_key"], encryption_algo="RSA_OAEP"
    )
    _test_random_ciphertext_corruption(decryption_func, cipherdict=cipherdict, initial_content=binary_content)

    private_key_too_short = RSA.generate(1024)
    public_key_too_short = private_key_too_short.publickey()

    with pytest.raises(EncryptionError, match="asymmetric key length"):
        wacryptolib.encryption.encrypt_bytestring(
            key=public_key_too_short, plaintext=binary_content, encryption_algo=encryption_algo
        )

    with pytest.raises(DecryptionError, match="asymmetric key length"):
        wacryptolib.encryption.decrypt_bytestring(
            key=private_key_too_short, cipherdict=cipherdict, encryption_algo=encryption_algo
        )
