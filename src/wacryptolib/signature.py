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


def sign_dsa(private_key: bytes, plaintext: bytes) -> dict:
    """Permits to sign a message with a private DSA key as bytes

    :param private_key: the cryptographic key which will serve to sign the plain text
    :param plaintext: the text to sign

    :return: The signature and the timestamp corresponding to the signature"""

    timestamp = bytes(_get_timestamp())
    hash_payload = timestamping_authority(plaintext=plaintext, timestamp=timestamp)
    signer = DSS.new(private_key, "fips-186-3")
    digest = signer.sign(hash_payload)  # Signature of the hash concatenated to the timestamp
    signature = {
        "type": "DSA",
        "timestamp_utc": timestamp,
        "digest": digest
    }
    return signature


def verify_dsa_signature(public_key: bytes, plaintext: bytes, signature: dict):
    """Permits to verify the authenticity of a DSA signature

    :param public_key: the cryptographic key which will serve to verify the signature
    :param plaintext: the text to sign
    :param signature: signature done by the private key matching with the public key in parameter

    :return: the timestamp"""

    hash_payload = timestamping_authority(plaintext=plaintext, timestamp=signature["timestamp_utc"])
    verifier = DSS.new(public_key, "fips-186-3")
    verifier.verify(hash_payload, signature["digest"])


def _get_timestamp():
    """Get timestamp

    :return: timestamp in bytes
    """
    return bytes(int(datetime.timestamp(datetime.now())))


def timestamping_authority(plaintext: bytes, timestamp: bytes):
    """Permits to do a Time Stamping Authority (TSA)

    :param plaintext: text to sign
    :param timestamp: modification timestamp of a document as bytes
    :return: digital signature of the hash concatenated to the timestamp
    """
    hash_plaintext = SHA256.new(plaintext)
    digest_pt_ts = SHA256.SHA256Hash.digest(hash_plaintext) + timestamp
    hash_pt_ts = SHA256.new(digest_pt_ts)
    return hash_pt_ts
