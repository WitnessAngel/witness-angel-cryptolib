import binascii
import uuid

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import wacryptolib

def test_generate_keypair():
    """Generate a (public_key, private_key) pair for a user ID,
    cipher then decipher a message (msg in parameters)."""

    uid = None
    binary_content = "Mon hât èst joli".encode('utf-8')

    keys = wacryptolib.generate_keypair(uid)
    public_key = keys["public_key"]
    private_key = keys["private_key"]

    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(binary_content)

    decipher = PKCS1_OAEP.new(private_key)
    deciphertext = decipher.decrypt(ciphertext)

    assert deciphertext == binary_content


def test_generate_shared_secret():
    """Generate a shared secret of `keys_count` keys, where `threshold_count`
    of them are required to recompute the private key corresponding to the public key.
    Result has fields "public_key" as bytes, and "shares" as a sequence of bytes."""

    try:
        assert threshold_count < keys_count  # Check if we have enough shares
        public_key_shares = {}  # Initialize the dict
        keypair = generate_keypair("oui", uid)
        public_key = keypair.get("public_key")
        key = get_random_bytes(16)  # Random key of 16 bytes
        # private_key = base64.b64decode(str(keypair.get("private_key"))) bytes; 21
        # private_key = int(binascii.rlecode_hqx(binascii.a2b_base64(str(keypair.get("private_key")))))
        private_key = binascii.a2b_base64(str(keypair.get("private_key")))
        private_key = int(private_key)
        print(len(private_key))

        shares = Shamir.split(threshold_count, keys_count, private_key)  # Spliting the key
        combined_key = Shamir.combine(shares)
        combined_key = str(combined_key)
        cipher = PKCS1_OAEP.new(combined_key)
        print("Initial message :", msg)
        ciphertext = cipher.encrypt(msg.encode())
        print("ciphered text :", ciphertext)

        decipher = PKCS1_OAEP.new(private_key)
        result = decipher.decrypt(ciphertext)
        print("result :", result.decode())

        # fi = open("clear_file.txt", "rb")
        # fo = open("enc_file.txt", "wb")
        # cipher = AES.new(key, AES.MODE_EAX)
        # ct, tag = cipher.encrypt(fi.read()), cipher.digest()
        # fo.write(tag + ct)

        public_key_shares["public_key"] = public_key
        public_key_shares["shares"] = shares
        return public_key_shares

    except AssertionError:
        print("Not enough keys count")

