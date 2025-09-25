import pyaes

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