from base64 import b64decode, b64encode

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ---- AES/CBC ----
def encrypt_via_aes_cbc(key: bytes, plaintext: bytes) -> bytes:
    """Permits to encrypt a `plaintext `thanks to a `key` with the CBC mode
    :param key:
    :param plaintext:
    :return: The initialization vector and the cipher text encoded in bytes encoded in base 64"""

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return b64encode(iv + ciphertext)


def decrypt_via_aes_cbc(key: bytes, ciphertext: bytes) -> bytes:
    """Permits to decrypt a `ciphertext` in base 64 thanks to a `key`
    :param key:
    :param ciphertext:
    :return: The decrypted text as bytes"""

    raw = b64decode(ciphertext)
    decipher = AES.new(key, AES.MODE_CBC, raw[: AES.block_size])
    decrypted_text = unpad(decipher.decrypt(raw[AES.block_size :]), AES.block_size)
    return decrypted_text


# ---- AES/EAX ----
def encrypt_via_aes_eax(key: bytes, plaintext: bytes) -> bytes:
    """Permits to encrypt a `plaintext `thanks to a `key` with the EAX mode
    :param key:
    :param plaintext:
    :return: the ciphertext as bytes, the tag and the nonce"""

    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag, nonce


def decrypt_via_aes_eax(key: bytes, ciphertext: bytes, tag, nonce) -> bytes:
    """Permits to decrypt a `ciphertext` in base 64 thanks to a `key`
    :param key:
    :param ciphertext:
    :param tag:
    :param nonce:
    :return: the text deciphered"""

    decipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    deciphertext = decipher.decrypt(ciphertext)
    decipher.verify(tag)
    return deciphertext
