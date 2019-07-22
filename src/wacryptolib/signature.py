from datetime import datetime

from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import DSS


def sign_rsa(private_key: bytes, plaintext: bytes):
    """Permits to sign a message with a private RSA key as bytes.

    :param private_key: the cryptographic key which will serve to sign the plain text
    :param plaintext: the text to sign

    :return: The hash of the data and the signature"""

    private_key = RSA.import_key(private_key)
    data_hash = SHA256.new(plaintext)
    signature = pss.new(private_key).sign(data_hash)
    return data_hash, signature


def verify_rsa_signature(public_key: bytes, data_hash: bytes, signature: bytes):
    """Permits to verify the authenticity of a RSA signature

    :param data_hash: hash of the plain text
    :param public_key: the cryptographic key which will serve to verify the signature
    :param signature: signature done by the private key matching with the public key in parameter"""

    public_key = RSA.import_key(public_key)
    verifier = pss.new(public_key)
    verifier.verify(data_hash, signature)


def sign_dsa(private_key: bytes, plaintext: bytes):
    """Permits to sign a message with a private DSA key as bytes

    :param private_key: the cryptographic key which will serve to sign the plain text
    :param plaintext: the text to sign

    :return: The signature and the timestamp corresponding to the signature"""

    timestamp = datetime.timestamp(datetime.now())
    hash_obj = SHA256.new(plaintext)
    signer = DSS.new(private_key, "fips-186-3")
    signature = signer.sign(hash_obj)
    return signature, timestamp


def verify_dsa_signature(
    public_key: bytes, plaintext: bytes, signature: bytes, timestamp: int
):
    """Permits to verify the authenticity of a DSA signature

    :param timestamp: timestamp corresponding to the signature of the plain text
    :param public_key: the cryptographic key which will serve to verify the signature
    :param plaintext: the text to sign
    :param signature: signature done by the private key matching with the public key in parameter

    :return: the timestamp"""

    hash_obj = SHA256.new(plaintext)
    verifier = DSS.new(public_key, "fips-186-3")
    verifier.verify(hash_obj, signature)

    return timestamp
