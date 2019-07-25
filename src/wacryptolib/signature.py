from datetime import datetime

from Crypto.Signature import pss, DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA, DSA

from typing import Union


def sign_rsa(private_key: RSA.RsaKey, plaintext: bytes):
    """Permits to sign a message with a private RSA key as bytes.

    :param private_key: the cryptographic key which will serve to sign the plain text
    :param plaintext: the text to sign

    :return: digest, timestamp and type of method used corresponding to the signature"""

    timestamp = _get_timestamp()
    hash_payload = timestamping_authority(plaintext=plaintext, timestamp=timestamp)
    signer = pss.new(private_key)
    digest = signer.sign(hash_payload)
    signature = {
        "type": "RSA",
        "timestamp_utc": timestamp,
        "digest": digest
    }
    return signature


def sign_dsa(private_key: DSA.DsaKey, plaintext: bytes) -> dict:
    """Permits to sign a message with a private DSA key as bytes. We use the `fips-186-3` mode
    for the signer because key generation is randomized, while it is not the case for the mode
    `deterministic-rfc6979`.

    :param private_key: the cryptographic key which will serve to sign the plain text
    :param plaintext: the text to sign

    :return: digest, timestamp and type of method used corresponding to the signature"""

    timestamp = _get_timestamp()
    hash_payload = timestamping_authority(plaintext=plaintext, timestamp=timestamp)
    signer = DSS.new(private_key, "fips-186-3")
    digest = signer.sign(hash_payload)  # Signature of the hash concatenated to the timestamp
    signature = {
        "type": "DSA",
        "timestamp_utc": timestamp,
        "digest": digest
    }
    return signature


def verify_signature(public_key: Union[DSA.DsaKey, RSA.RsaKey], plaintext: bytes, signature: dict):
    """Permits to verify the authenticity of a signature

    :param public_key: the cryptographic key which will serve to verify the signature
    :param plaintext: the text to sign
    :param signature: digest, timestamp and type of method used corresponding to the signature

    :return: the timestamp"""

    hash_payload = timestamping_authority(plaintext=plaintext, timestamp=signature["timestamp_utc"])
    if signature["type"] == "RSA":
        verifier = pss.new(public_key)
    elif signature["type"] == "DSA":
        verifier = DSS.new(public_key, "fips-186-3")
    else:
        verifier = None
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
    payload_digest = SHA256.SHA256Hash.digest(hash_plaintext) + timestamp
    payload_hash = SHA256.new(payload_digest)
    return payload_hash
