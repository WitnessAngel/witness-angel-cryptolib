from base64 import b64decode, b64encode

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA


# ---- AES/CBC ----
def encrypt_via_aes_cbc(key: bytes, plaintext: bytes) -> dict:
    """Permits to encrypt a `plaintext` thanks to a `key` with the CBC mode

    :param key: the cryptographic key which will serve to decipher the cipher text
    :param plaintext: the text to cipher

    :return: concatenation of initialization vector and ciphertext encoded in base 64"""

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    iv_and_ciphertext = {"iv": b64encode(iv), "ciphertext": b64encode(ciphertext)}
    return iv_and_ciphertext


def decrypt_via_aes_cbc(key: bytes, iv_and_ciphertext: dict) -> bytes:
    """Permits to decrypt a `ciphertext` in base 64 thanks to a `key`

    :param key: the cryptographic key which will serve to cipher the plain text
    :param iv_and_ciphertext: concatenation of the initialization vector and the text to decipher

    :return: The decrypted text as bytes"""

    iv = iv_and_ciphertext["iv"]
    ciphertext = iv_and_ciphertext["ciphertext"]
    decipher = AES.new(key, AES.MODE_CBC, b64decode(iv))
    decrypted_text = unpad(decipher.decrypt(b64decode(ciphertext)), AES.block_size)
    return decrypted_text


# ---- AES/EAX ----
def encrypt_via_aes_eax(key: bytes, plaintext: bytes) -> dict:
    """Permits to encrypt a `plaintext` thanks to a `key` with the EAX mode

    :param key: the cryptographic key which will serve to cipher the plain text
    :param plaintext: the text to cipher

    :return: the ciphertext as bytes, the tag and the nonce"""

    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    encryption = {"ciphertext": ciphertext, "tag": tag, "nonce": nonce}
    return encryption


def decrypt_via_aes_eax(key: bytes, encryption: dict) -> bytes:
    """Permits to decrypt a `ciphertext` in base 64 thanks to a `key`

    :param key: the cryptographic key which will serve to decipher the cipher text
    :param encryption: dictionary composed of a ciphertext, tag and nonce

    :return: the text deciphered"""

    decipher = AES.new(key, AES.MODE_EAX, nonce=encryption["nonce"])
    deciphertext = decipher.decrypt(encryption["ciphertext"])
    decipher.verify(encryption["tag"])
    return deciphertext


# ---- ChaCha20 ----
def encrypt_via_chacha20_poly1305(
    key: bytes, plaintext: bytes, header: bytes = b"header"
) -> dict:
    """Permits to encrypt a `plaintext` thanks to a `key` of 32 bytes long
    with ChaCha20 which is a stream cipher.

    :param header: additional authenticated data (AAD)
    :param key: the cryptographic key which will serve to cipher the plain text
    :param plaintext: the text to cipher

    :return: the ciphertext as bytes and the nonce"""

    cipher = ChaCha20_Poly1305.new(key=key)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce
    encryption = {
        "ciphertext": ciphertext,
        "tag": tag,
        "nonce": nonce,
        "header": header,
    }
    return encryption


def decrypt_via_chacha20_poly1305(key: bytes, encryption: dict) -> bytes:
    """Permits to decrypt a `ciphertext` thanks to a `key` of 32 bytes long

    :param encryption: dictionary with a ciphertext, tag, nonce and header
    :param key: cryptographic key which will serve to decipher the cipher text

    :return: the text deciphered"""

    decipher = ChaCha20_Poly1305.new(key=key, nonce=encryption["nonce"])
    decipher.update(encryption["header"])
    deciphertext = decipher.decrypt_and_verify(
        ciphertext=encryption["ciphertext"], received_mac_tag=encryption["tag"]
    )
    return deciphertext


# ---- PKCS#1 OAEP ----
def encrypt_via_rsa_oaep(key: RSA.RsaKey, plaintext: bytes) -> bytes:
    """Permits to encrypt a `plaintext` thanks to a public RSA key

    :param key: the cryptographic key which will serve to cipher the plain text
    :param plaintext: the text to cipher

    :return: the ciphertext as bytes"""

    cipher = PKCS1_OAEP.new(key=key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def decrypt_via_rsa_oaep(key: RSA.RsaKey, encryption: bytes) -> bytes:
    """Permits to decrypt a `ciphertext` thanks to a private RSA key

    :param key: the cryptographic key which will serve to decipher the cipher text
    :param ciphertext: the text to decipher

    :return: data deciphered"""

    decipher = PKCS1_OAEP.new(key)
    deciphertext = decipher.decrypt(ciphertext=encryption)
    return deciphertext
