from datetime import datetime
from typing import Union

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pss, DSS


# FIXME rename RSAPSS machin chose
def sign_with_rsa(private_key: RSA.RsaKey, plaintext: bytes) -> dict:
    """Sign a bytes message with a private RSA key.

    :param private_key: the private key
    :param plaintext: the bytestring to sign

    :return: dict with keys "digest" (bytestring), "timestamp_utc" (integer) and "type" (string) of signature"""

    timestamp_utc = _get_utc_timestamp()
    hash_payload = _compute_timestamped_hash(
        plaintext=plaintext, timestamp_utc=timestamp_utc
    )
    signer = pss.new(private_key)
    digest = signer.sign(hash_payload)
    signature = {"type": "RSA", "timestamp_utc": timestamp_utc, "digest": digest}
    return signature


# FIXME rename DSS machin chose
def sign_with_dsa_or_ecc(
    private_key: Union[DSA.DsaKey, ECC.EccKey], plaintext: bytes
) -> dict:
    """Sign a bytes message with a private DSA or ECC key.

    We use the `fips-186-3` mode for the signer because signature is randomized,
    while it is not the case for the mode `deterministic-rfc6979`.

    :param private_key: the private key
    :param plaintext: the bytestring to sign

    :return: dict with keys "digest" (bytestring), "timestamp_utc" (integer) and "type" (string) of signature"""

    timestamp = _get_utc_timestamp()
    hash_payload = _compute_timestamped_hash(
        plaintext=plaintext, timestamp_utc=timestamp
    )
    signer = DSS.new(private_key, "fips-186-3")
    digest = signer.sign(hash_payload)
    signature = {
        "type": "DSA_OR_ECC",
        "timestamp_utc": timestamp,
        "digest": digest,
    }  # FIXME find better TYPE
    return signature


def verify_signature(
    public_key: Union[RSA.RsaKey, DSA.DsaKey, ECC.EccKey],
    plaintext: bytes,
    signature: dict,
):
    """Verify the authenticity of a signature.

    Raises if signature is invalid.

    :param public_key: the cryptographic key used to verify the signature
    :param plaintext: the text which was signed
    :param signature: dict describing the signature
    """

    hash_payload = _compute_timestamped_hash(
        plaintext=plaintext, timestamp_utc=signature["timestamp_utc"]
    )
    if signature["type"] == "RSA":
        verifier = pss.new(public_key)
    elif signature["type"] == "DSA_OR_ECC":
        verifier = DSS.new(public_key, "fips-186-3")
    else:
        raise ValueError("Unknown signature type '%s'" % signature["type"])
    verifier.verify(hash_payload, signature["digest"])


def _get_utc_timestamp():
    """Get current UTC timestamp.

    :return: timestamp as an integer
    """
    timestamp_utc = int(datetime.utcnow().timestamp())
    return timestamp_utc


def _compute_timestamped_hash(plaintext: bytes, timestamp_utc: int):
    """Create a hash of content, including the timestamp.

    :param plaintext: text to sign
    :param timestamp: integer UTC timestamp

    :return: stdlib hash object
    """
    hash_plaintext = SHA256.new(plaintext)
    timestamp_bytes = str(timestamp_utc).encode("ascii")
    payload_digest = SHA256.SHA256Hash.digest(hash_plaintext) + timestamp_bytes
    payload_hash = SHA256.new(payload_digest)
    return payload_hash
