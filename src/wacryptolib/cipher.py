from base64 import b64decode, b64encode

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad


# ---- AES/CBC ----
def encrypt_via_aes_cbc(key: bytes, plaintext: bytes) -> bytes:
    """Permits to encrypt a `plaintext` thanks to a `key` with the CBC mode

    :param key: the cryptographic key which will serve to decipher the cipher text
    :param plaintext: the text to cipher

    :return: The initialization vector and the cipher text encoded in bytes encoded in base 64"""

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return b64encode(iv + ciphertext)


def decrypt_via_aes_cbc(key: bytes, ciphertext: bytes) -> bytes:
    """Permits to decrypt a `ciphertext` in base 64 thanks to a `key`

    :param key: the cryptographic key which will serve to cipher the plain text
    :param ciphertext: the text to decipher

    :return: The decrypted text as bytes"""

    raw = b64decode(ciphertext)
    decipher = AES.new(key, AES.MODE_CBC, raw[: AES.block_size])
    decrypted_text = unpad(decipher.decrypt(raw[AES.block_size:]), AES.block_size)
    return decrypted_text


# ---- AES/EAX ----
def encrypt_via_aes_eax(key: bytes, plaintext: bytes) -> bytes:
    """Permits to encrypt a `plaintext` thanks to a `key` with the EAX mode

    :param key: the cryptographic key which will serve to cipher the plain text
    :param plaintext: the text to cipher

    :return: the ciphertext as bytes, the tag and the nonce"""

    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag, nonce


def decrypt_via_aes_eax(key: bytes, ciphertext: bytes, tag: bytes, nonce: bytes) -> bytes:
    """Permits to decrypt a `ciphertext` in base 64 thanks to a `key`

    :param key: the cryptographic key which will serve to decipher the cipher text
    :param ciphertext: the text to decipher
    :param tag: authentication tag which permit to verify the decryption
    :param nonce: the value of the fixed nonce. It must be unique for the combination message/key

    :return: the text deciphered"""

    decipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    deciphertext = decipher.decrypt(ciphertext)
    decipher.verify(tag)
    return deciphertext


# ---- ChaCha20 ----
def encrypt_via_chacha20_poly1305(key: bytes, plaintext: bytes) -> bytes:
    """Permits to encrypt a `plaintext` thanks to a `key` of 32 bytes long
    with ChaCha20 which is a stream cipher.

    :param key: the cryptographic key which will serve to cipher the plain text
    :param plaintext: the text to cipher

    :return: the ciphertext as bytes and the nonce"""

    header = b"header"
    cipher = ChaCha20_Poly1305.new(key=key)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce
    return ciphertext, tag, nonce, header


def decrypt_via_chacha20_poly1305(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes, header: bytes) -> bytes:
    """Permits to decrypt a `ciphertext` thanks to a `key` of 32 bytes long

    :param header: additional authenticated data (AAD)
    :param tag: binary authentication tag (MAC)
    :param key: the cryptographic key which will serve to decipher the cipher text
    :param ciphertext: the text to decipher
    :param nonce: the value of the fixed nonce of 8 bytes long

    :return: the text deciphered"""

    decipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    decipher.update(header)
    deciphertext = decipher.decrypt_and_verify(ciphertext=ciphertext, received_mac_tag=tag)
    return deciphertext


# ---- PKCS#1 OAEP ----
def encrypt_via_rsa_oaep(key: bytes, plaintext: bytes) -> bytes:
    """Permits to encrypt a `plaintext` thanks to a public RSA key

    :param key: the cryptographic key which will serve to cipher the plain text
    :param plaintext: the text to cipher

    :return: the ciphertext as bytes"""

    cipher = PKCS1_OAEP.new(key=key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def decrypt_via_rsa_oaep(key: bytes, ciphertext: bytes) -> bytes:
    """Permits to decrypt a `ciphertext` thanks to a private RSA key

    :param key: the cryptographic key which will serve to decipher the cipher text
    :param ciphertext: the text to decipher

    :return: the text deciphered"""

    decipher = PKCS1_OAEP.new(key)
    deciphertext = decipher.decrypt(ciphertext=ciphertext)
    return deciphertext
