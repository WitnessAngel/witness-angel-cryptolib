import importlib

import Crypto.Hash.SHA512
from Crypto.Cipher import AES, ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Util.Padding import pad, unpad
import Crypto.Random


RSA_OAEP_HASHER = Crypto.Hash.SHA512

AES_BLOCK_SIZE = AES.block_size

get_random_bytes = Crypto.Random.get_random_bytes


# AES CBC CIPHER #

def build_aes_cbc_cipher(key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher


def encrypt_via_aes_cbc(plaintext, key, iv):
    cipher = build_aes_cbc_cipher(key=key, iv=iv)
    plaintext_padded = pad(plaintext, block_size=AES_BLOCK_SIZE)
    ciphertext = cipher.encrypt(plaintext_padded)
    return ciphertext


def decrypt_via_aes_cbc(ciphertext, key, iv):
    cipher = build_aes_cbc_cipher(key=key, iv=iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded, block_size=AES_BLOCK_SIZE)
    return plaintext


# AES EAX CIPHER #

def build_aes_eax_cipher(key, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher


def encrypt_via_aes_eax(plaintext, key, nonce):
    cipher = build_aes_eax_cipher(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag


def decrypt_via_aes_eax(ciphertext, tag, key, nonce, verify_integrity_tags):
    cipher = build_aes_eax_cipher(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    if verify_integrity_tags:
        cipher.verify(tag)
    return plaintext


# CHACHA20 POLY1305 CIPHER #

def build_chacha20_poly1305_cipher(key, nonce):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    # cipher.update(aad)  NOPE UNUSED
    return cipher


def encrypt_via_chacha20_poly1305(plaintext, key, nonce):
    cipher = build_chacha20_poly1305_cipher(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag


def decrypt_via_chacha20_poly1305(ciphertext, tag, key, nonce, verify_integrity_tags):
    cipher = build_chacha20_poly1305_cipher(key=key, nonce=nonce)
    if verify_integrity_tags:
        plaintext = cipher.decrypt_and_verify(ciphertext=ciphertext, received_mac_tag=tag)
    else:
        plaintext = cipher.decrypt(ciphertext=ciphertext)
    return plaintext


# RSA OAEP CIPHER #

def build_rsa_oaep_cipher(key):
    # Returned object has encrypt() and decrypt() methods
    return PKCS1_OAEP.new(key=key, hashAlgo=RSA_OAEP_HASHER)


# HASHER FACTORY #

def get_hasher_instance(hash_algo):
    module = importlib.import_module("Crypto.Hash.%s" % hash_algo)
    hasher_instance = module.new()
    return hasher_instance


# RSA KEY GENERATION, AND IMPORT/EXPORT #

def generate_rsa_keypair(key_length_bits):
    private_key = RSA.generate(key_length_bits)
    public_key = private_key.publickey()
    return public_key, private_key


def generate_dsa_keypair(key_length_bits):
    private_key = DSA.generate(key_length_bits)
    public_key = private_key.publickey()
    return public_key, private_key


def generate_ecc_keypair(curve):
    if curve not in ECC._curves:
        raise ValueError("Unexisting ECC curve '%s', must be one of '%s'" % (curve, sorted(ECC._curves.keys())))
    private_key = ECC.generate(curve=curve)
    public_key = private_key.public_key()
    return public_key, private_key


import_rsa_key_from_pem = RSA.import_key
import_dsa_key_from_pem = DSA.import_key
import_ecc_key_from_pem = ECC.import_key


def export_rsa_key_to_pem(private_key, passphrase=None):
    extra_params = dict(passphrase=passphrase, pkcs=8, protection="PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC") if passphrase else {}
    return private_key.export_key(format="PEM", **extra_params)

def export_dsa_key_to_pem(private_key, passphrase=None):
    extra_params = dict(passphrase=passphrase, pkcs8=True, protection="PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC") if passphrase else {}
    return private_key.export_key(format="PEM", **extra_params)

def export_ecc_key_to_pem(private_key, passphrase=None):
    extra_params = dict(passphrase=passphrase, use_pkcs8=True, protection="PBKDF2WithHMAC-SHA1AndAES128-CBC") if passphrase else {}
    return private_key.export_key(format="PEM", **extra_params)


# SHAMIR SHARED SECRETS #

from Crypto.Protocol.SecretSharing import Shamir

shamir_split = Shamir.split
shamir_combine= Shamir.combine
