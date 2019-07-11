# coding : utf-8

import uuid
from Crypto.PublicKey import RSA
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import binascii
import ecdsa
import hashlib


def generate_keypair(uid: uuid.UUID) -> dict:
    """Generate a (public_key, private_key) pair for a user ID.
    Result has fields "public_key" and "private_key" as bytes."""
    del uid
    private_key = RSA.generate(2048)  # Generate private key
    public_key = private_key.publickey()  # Generate the corresponding public key

    keypair = {"public_key": public_key, "private_key": private_key}

    return keypair


def generate_shared_secret(msg: str, uid: uuid.UUID, keys_count: int, threshold_count: int) -> dict:
    """Generate a shared secret of `keys_count` keys, where `threshold_count`
    of them are required to recompute the private key corresponding to the public key.
    Result has fields "public_key" as bytes, and "shares" as a sequence of bytes."""

    #try:
    assert threshold_count < keys_count  # Check if we have enough shares
    public_key_shares = {}  # Initialize the dict
    keypair = generate_keypair("oui", uid)
    public_key = str(keypair.get("public_key"))
    key = get_random_bytes(16)  # Random key of 16 bytes
    private_key = str(keypair.get("private_key")).encode()
    # private_key = binascii.unhexlify((binascii.rlecode_hqx(binascii.a2b_base64(str(keypair.get("private_key"))))))
    sk = ecdsa.SigningKey.from_string(public_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    msg = binascii.hexlify(b'hello')
    sign_msg = sk.sign(msg)
    try:
        assert vk.verify(sign_msg, msg)
        print("bon")
    except AssertionError:
        print("pas bon")
        # ripemd160 = hashlib.new('ripemd160')
        # ripemd160.update(hashlib.sha256(binascii.unhexlify(public_key))).digest()

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

    #except AssertionError:
    #    print("Not enough keys count : ")


if __name__ == '__main__':
    id1 = uuid.uuid4()
    # generate_keypair("Je veux crypter ce message", id1)
    generate_shared_secret("oui", id1, 3, 2)
