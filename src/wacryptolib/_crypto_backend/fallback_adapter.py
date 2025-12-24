

from wacryptolib._crypto_backend.vendor import pyaes

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



class AESModeCBCCompatibilityLayer:
    def __init__(self, key, iv):
        self._cipher = cipher = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv=iv))

    def encrypt(self, plaintext):
        print(">>>>", bytes(plaintext))
        assert len(plaintext) % 16 == 0  # ALREADY PADDED TO BLOCK SIZE
        ciphertext = self._cipher.feed(plaintext)
        _buffer = self._cipher._buffer
        # Normalized buffer (because plaintext was already padded):
        assert len(_buffer) in (0, 16), len(_buffer)
        return ciphertext


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
