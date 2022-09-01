"""
import Crypto.Hash.SHA512
from Crypto.Cipher import AES, ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pss, DSS
from Crypto.Util.Padding import pad, unpad
import Crypto.Random
"""


AES_BLOCK_SIZE = 16


# Utilities #


def get_random_bytes(nbytes):
    import Crypto.Random

    return Crypto.Random.get_random_bytes(nbytes)


def pad(*args, **kwargs):
    from Crypto.Util.Padding import pad

    return pad(*args, **kwargs)


def unpad(*args, **kwargs):
    from Crypto.Util.Padding import unpad

    return unpad(*args, **kwargs)


# AES CBC CIPHER #


def build_aes_cbc_cipher(key, iv):
    from Crypto.Cipher import AES

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher


def encrypt_via_aes_cbc(plaintext, key, iv):
    from Crypto.Util.Padding import pad

    cipher = build_aes_cbc_cipher(key=key, iv=iv)
    plaintext_padded = pad(plaintext, block_size=AES_BLOCK_SIZE)
    ciphertext = cipher.encrypt(plaintext_padded)
    return ciphertext


def decrypt_via_aes_cbc(ciphertext, key, iv):
    from Crypto.Util.Padding import unpad

    cipher = build_aes_cbc_cipher(key=key, iv=iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded, block_size=AES_BLOCK_SIZE)
    return plaintext


# AES EAX CIPHER #


def build_aes_eax_cipher(key, nonce):
    from Crypto.Cipher import AES

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
    from Crypto.Cipher import ChaCha20_Poly1305

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
    import Crypto.Hash.SHA512
    from Crypto.Cipher import PKCS1_OAEP

    rsa_oaep_hasher = Crypto.Hash.SHA512
    return PKCS1_OAEP.new(key=key, hashAlgo=rsa_oaep_hasher)


# HASHER FACTORY #


def get_hasher_instance(hash_algo):
    import importlib

    module = importlib.import_module("Crypto.Hash.%s" % hash_algo)
    hasher_instance = module.new()
    return hasher_instance


# RSA KEY GENERATION, AND IMPORT/EXPORT #


def rsa_key_class_fetcher():
    from Crypto.PublicKey import RSA

    return RSA.RsaKey


def dsa_key_class_fetcher():
    from Crypto.PublicKey import DSA

    return DSA.DsaKey


def ecc_key_class_fetcher():
    from Crypto.PublicKey import ECC

    return ECC.EccKey


def generate_rsa_keypair(key_length_bits):
    from Crypto.PublicKey import RSA

    private_key = RSA.generate(key_length_bits)
    public_key = private_key.publickey()
    return public_key, private_key


def generate_dsa_keypair(key_length_bits):
    from Crypto.PublicKey import DSA

    private_key = DSA.generate(key_length_bits)
    public_key = private_key.publickey()
    return public_key, private_key


def generate_ecc_keypair(curve):
    from Crypto.PublicKey import ECC

    if curve not in ECC._curves:
        raise ValueError("Unexisting ECC curve '%s', must be one of '%s'" % (curve, sorted(ECC._curves.keys())))
    private_key = ECC.generate(curve=curve)
    public_key = private_key.public_key()
    return public_key, private_key


def import_rsa_key_from_pem(*args, **kwargs):
    from Crypto.PublicKey import RSA

    return RSA.import_key(*args, **kwargs)


def import_dsa_key_from_pem(*args, **kwargs):
    from Crypto.PublicKey import DSA

    return DSA.import_key(*args, **kwargs)


def import_ecc_key_from_pem(*args, **kwargs):
    from Crypto.PublicKey import ECC

    return ECC.import_key(*args, **kwargs)


def export_rsa_key_to_pem(private_key, passphrase=None):
    extra_params = (
        dict(passphrase=passphrase, pkcs=8, protection="PBKDF2WithHMAC-SHA1AndAES256-CBC") if passphrase else {}
    )  # FIXME
    return private_key.export_key(format="PEM", **extra_params)


def export_dsa_key_to_pem(private_key, passphrase=None):
    extra_params = (
        dict(passphrase=passphrase, pkcs8=True, protection="PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC") if passphrase else {}
    )  # FIXME
    return private_key.export_key(format="PEM", **extra_params)


def export_ecc_key_to_pem(private_key, passphrase=None):
    extra_params = (
        dict(passphrase=passphrase, use_pkcs8=True, protection="PBKDF2WithHMAC-SHA1AndAES128-CBC") if passphrase else {}
    )  # FIXME
    return private_key.export_key(format="PEM", **extra_params)


# SHAMIR SHARED SECRETS #


def shamir_split(*args, **kwargs):
    from Crypto.Protocol.SecretSharing import Shamir

    return Shamir.split(*args, **kwargs)


def shamir_combine(*args, **kwargs):
    from Crypto.Protocol.SecretSharing import Shamir

    return Shamir.combine(*args, **kwargs)


# MESSAGE SIGNATURES #


def sign_with_pss(message, private_key):
    from Crypto.Signature import pss

    signer = pss.new(private_key)
    signature = signer.sign(message)
    return signature


def verify_with_pss(message, signature, public_key):
    from Crypto.Signature import pss

    verifier = pss.new(public_key)
    verifier.verify(message, signature)  # Raise ValueError if failure


def sign_with_dss(message, private_key):
    from Crypto.Signature import DSS

    signer = DSS.new(private_key, "fips-186-3")
    signature = signer.sign(message)
    return signature


def verify_with_dss(message, signature, public_key):
    from Crypto.Signature import DSS

    verifier = DSS.new(public_key, "fips-186-3")
    verifier.verify(message, signature)  # Raise ValueError if failure
