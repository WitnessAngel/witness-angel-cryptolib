# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import hashlib
import pkcs1
import pyaes


def encrypt_via_aes_cbc(plaintext, key, iv):
    # Default padding is PKCS7
    cipher = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv=iv))
    ciphertext = cipher.feed(plaintext)
    ciphertext += cipher.feed()
    return ciphertext


def encrypt_via_rsa_oaep(plaintext_chunks: list[bytes], public_key) -> list[bytes]:
    """We expect each plaintext chunk to be small enough for the RSA key size"""
    encrypter = lambda chunk: pkcs1.rsaes_oaep.encrypt(public_key, message=chunk, label=b'',
                             hash_class=hashlib.sha512)
                    # TODO: ARGUMENTS mgf=mgf.mgf1, seed=None, rnd=default_crypto_random))
    ciphertext_chunks = [encrypter(chunk) for chunk in plaintext_chunks]
    return ciphertext_chunks
