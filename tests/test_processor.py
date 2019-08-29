import processor
import random


def test_do_encrypt():
    plaintext = "Mon hât èst joli".encode("utf-8")
    algorithms = {
        "cipher_algo": [("aes", "chacha", "aes")],
        "signature_algo": [("RSA", "DSA", "RSA")],
        "key_cipher_algo": [("RSA", "RSA", "RSA")],
    }
    container = processor._do_encrypt(plaintext, algorithms=algorithms)
    plaintext_deciphered = processor._do_decrypt(container)
    assert plaintext == plaintext_deciphered
