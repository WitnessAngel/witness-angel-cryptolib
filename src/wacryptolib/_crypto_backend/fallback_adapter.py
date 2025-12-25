
import hashlib
import rsa
from wacryptolib._crypto_backend.vendor import pkcs1
from wacryptolib._crypto_backend.vendor import pyaes

'''
# Any mode of operation can be used; for this example CBC
key = b"This_key_for_demo_purposes_only!"
iv = b"InitializationVe"

ciphertext = b''

# We can encrypt one line at a time, regardles of length
encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv))
ciphertext += encrypter.feed(b"hello ")
ciphertext += encrypter.feed(b"kitty")
# Make a final call to flush any remaining bytes and add paddin
ciphertext += encrypter.feed()

print("CIPHERTEXT IS", repr(ciphertext))

# We can decrypt the cipher text in chunks (here we split it in half)
decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key, iv))
decrypted = decrypter.feed(ciphertext[:len(ciphertext) // 2])
decrypted += decrypter.feed(ciphertext[len(ciphertext) // 2:])
# Again, make a final call to flush any remaining bytes and strip padding
decrypted += decrypter.feed()

print("RESULT IS", repr(decrypted))
'''


class AESModeCBCCompatibilityLayer:
    def __init__(self, key, iv):
        self._cipher = cipher = pyaes.Encrypter(
            pyaes.AESModeOfOperationCBC(key, iv=iv),
            # For compatibility with pycryptodome,
            # we do not want any padding at this level
            padding=pyaes.PADDING_NONE)

    def encrypt(self, plaintext):
        print(">>>>", bytes(plaintext))
        assert len(plaintext) % 16 == 0  # ALREADY PADDED TO BLOCK SIZE
        ciphertext = self._cipher.feed(plaintext)
        _buffer = self._cipher._buffer
        # Normalized buffer (because plaintext was already padded):
        assert len(_buffer) in (0, 16), len(_buffer)
        return ciphertext

    def finalize(self):
        # Returns last bytes (with NO padding)
        return self._cipher.feed(None)


def build_aes_cbc_encrypter(key, iv):
    return AESModeCBCCompatibilityLayer(key, iv=iv)


def encrypt_via_aes_cbc(plaintext, key, iv):
    # Default padding is PKCS7
    cipher = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv=iv))
    ciphertext = cipher.feed(plaintext)
    ciphertext += cipher.feed()
    return ciphertext


def decrypt_via_aes_cbc(ciphertext, key, iv):
    # Default padding is PKCS7
    decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key, iv))
    decrypted = decrypter.feed(ciphertext)
    decrypted += decrypter.feed()
    return decrypted


def import_rsa_key_from_pem(key_pem, passphrase=None):
    if passphrase:
        raise NotImplementedError(
            "RSA key with passphrase is not supported in fallback implementation")

    # We use python-rsa for parsing, but then pkcs1 package for encryption/decryption
    _pyrsa_format_public_key = rsa.PublicKey.load_pkcs1_openssl_pem(key_pem)
    _pkcs1_format_public_key = pkcs1.keys.RsaPublicKey(
        _pyrsa_format_public_key.n, _pyrsa_format_public_key.e)
    return _pkcs1_format_public_key

''' TODO
def export_rsa_key_to_pem(private_key, passphrase=None):  # FIXME not always private key
    extra_params = (
        dict(passphrase=passphrase, pkcs=8, protection="PBKDF2WithHMAC-SHA1AndAES256-CBC") if passphrase else {}
    )
    return private_key.export_key(format="PEM", **extra_params)
'''

def encrypt_via_rsa_oaep(plaintext_chunks: list[bytes], public_key) -> list[bytes]:
    """We expect each plaintext chunk to be small enough for the RSA key size"""
    encrypter = lambda chunk: pkcs1.rsaes_oaep.encrypt(public_key, message=chunk, label=b'',
                             hash_class=hashlib.sha512)
                    # TODO: ARGUMENTS mgf=mgf.mgf1, seed=None, rnd=default_crypto_random))
    ciphertext_chunks = [encrypter(chunk) for chunk in plaintext_chunks]
    return ciphertext_chunks


def decrypt_via_rsa_oaep(ciphertext_chunks: list[bytes], private_key) -> list[bytes]:
    decrypter = lambda chunk: pkcs1.rsaes_oaep.decrypt(private_key, message=chunk,
                                         label=b'', hash_class=hashlib.sha512)
                     # TODO: ARGUMENTS mgf=mgf.mgf1, seed=None, rnd=default_crypto_random))
    cleartext_chunks = [decrypter(chunk) for chunk in ciphertext_chunks]
    return cleartext_chunks