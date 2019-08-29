from base64 import b64decode, b64encode

import Crypto.Hash
from Crypto.Cipher import AES, ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from wacryptolib.utilities import split_as_chunks

RSA_OAEP_CHUNKS_SIZE = 60
RSA_OAEP_HASH_ALGO = Crypto.Hash.SHA256


def encrypt_via_aes_cbc(key: bytes, plaintext: bytes) -> dict:
    """Encrypt a bytestring using AES (CBC mode).

    :param key: AES cryptographic key of a proper length for chose AES flavour.
    :param plaintext: the bytes to cipher

    :return: dict with fields "iv" and "ciphertext" as base64 strings"""

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, block_size=AES.block_size))
    iv_and_ciphertext = {"iv": b64encode(iv), "ciphertext": b64encode(ciphertext)}
    return iv_and_ciphertext


def decrypt_via_aes_cbc(key: bytes, iv_and_ciphertext: dict) -> bytes:
    """Decrypt a bytestring using AES (CBC mode).

    :param key: the cryptographic key used to decipher
    :param iv_and_ciphertext: dict with fields "iv" and "ciphertext" as base64 strings

    :return: the decrypted bytestring"""

    iv = iv_and_ciphertext["iv"]
    ciphertext = iv_and_ciphertext["ciphertext"]
    decipher = AES.new(key, AES.MODE_CBC, b64decode(iv))
    plaintext = unpad(
        decipher.decrypt(b64decode(ciphertext)), block_size=AES.block_size
    )
    return plaintext


def encrypt_via_aes_eax(key: bytes, plaintext: bytes) -> dict:
    """Encrypt a bytestring using AES (EAX mode).

    :param key: AES cryptographic key of a proper length for chose AES flavour.
    :param plaintext: the bytes to cipher

    :return: dict with fields "ciphertext", "tag" and "nonce" as base64 strings"""

    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    encryption = {
        "ciphertext": b64encode(ciphertext),
        "tag": b64encode(tag),
        "nonce": b64encode(nonce),
    }
    return encryption


def decrypt_via_aes_eax(key: bytes, encryption: dict) -> bytes:
    """Decrypt a bytestring using AES (EAX mode).

    :param key: the cryptographic key used to decipher
    :param encryption: dict with fields "ciphertext", "tag" and "nonce" as base64 strings

    :return: the decrypted bytestring"""

    decipher = AES.new(key, AES.MODE_EAX, nonce=b64decode(encryption["nonce"]))
    plaintext = decipher.decrypt(b64decode(encryption["ciphertext"]))
    decipher.verify(b64decode(encryption["tag"]))
    return plaintext


def encrypt_via_chacha20_poly1305(
    key: bytes, plaintext: bytes, header: bytes = b"header"
) -> dict:
    """Encrypt a bytestring with the stream cipher ChaCha20.

    :param key: 32 bytes long cryptographic key
    :param plaintext: the bytes to cipher
    :param header: optional "additional authenticated data" (AAD)

    :return: dict with fields "ciphertext", "tag", "nonce" and "header" as base64 strings"""

    cipher = ChaCha20_Poly1305.new(key=key)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce
    encryption = {
        "ciphertext": b64encode(ciphertext),
        "tag": b64encode(tag),
        "nonce": b64encode(nonce),
        "header": b64encode(header),
    }
    return encryption


def decrypt_via_chacha20_poly1305(key: bytes, encryption: dict) -> bytes:
    """Decrypt a bytestring with the stream cipher ChaCha20.

    :param key: the cryptographic key used to decipher
    :param encryption: dict with fields "ciphertext", "tag", "nonce" and "header" as base64 strings

    :return: the decrypted bytestring"""

    decipher = ChaCha20_Poly1305.new(key=key, nonce=b64decode(encryption["nonce"]))
    decipher.update(b64decode(encryption["header"]))
    plaintext = decipher.decrypt_and_verify(
        ciphertext=b64decode(encryption["ciphertext"]),
        received_mac_tag=b64decode(encryption["tag"]),
    )
    return plaintext


def encrypt_via_rsa_oaep(key: RSA.RsaKey, plaintext: bytes) -> bytes:
    """Encrypt a bytestring with PKCS#1 RSA OAEP (asymmetric algo).

    :param key: public RSA key
    :param plaintext: the bytes to cipher

    :return: a list of base64-encoded chunks of variable width"""

    cipher = PKCS1_OAEP.new(key=key, hashAlgo=RSA_OAEP_HASH_ALGO)
    chunks = split_as_chunks(
        plaintext,
        chunk_size=RSA_OAEP_CHUNKS_SIZE,
        must_pad=False,
        accept_incomplete_chunk=True,
    )

    encryption = []
    for chunk in chunks:
        encrypted_chunk = cipher.encrypt(chunk)
        encryption.append(b64encode(encrypted_chunk))
    return encryption


def decrypt_via_rsa_oaep(key: RSA.RsaKey, encryption: bytes) -> bytes:
    """Decrypt a bytestring with PKCS#1 RSA OAEP (asymmetric algo).

    :param key: private RSA key
    :param encryption: list of base64-encoded ciphertext chunks

    :return: the decrypted bytestring"""

    decipher = PKCS1_OAEP.new(key, hashAlgo=RSA_OAEP_HASH_ALGO)

    chunks = [b64decode(chunk) for chunk in encryption]

    decrypted_chunks = []
    for chunk in chunks:
        decrypted_chunk = decipher.decrypt(chunk)
        decrypted_chunks.append(decrypted_chunk)
    return b"".join(decrypted_chunks)
