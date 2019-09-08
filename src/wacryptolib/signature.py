from datetime import datetime
from typing import Union

from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pss, DSS

KNOWN_KEY_TYPES = Union[RSA.RsaKey, DSA.DsaKey, ECC.EccKey]


def sign_message(plaintext: bytes, signature_type: str, key: KNOWN_KEY_TYPES) -> dict:
    """
    Return a timestamped signature of the chosen type for the given payload,
    with the provided key (which must be of a compatible type).

    :return: dictionary with signature data, and
        a "type" field echoing `signature_type`."""

    assert signature_type, signature_type
    signature_type = signature_type.upper()
    signature_conf = SIGNATURE_TYPES_REGISTRY.get(signature_type)
    if signature_conf is None:
        raise ValueError("Unknown signature type '%s'" % signature_type)
    if not isinstance(key, tuple(signature_conf["compatible_key_types"])):
        raise ValueError(
            "Incompatible key type %s for %s signature" % (type(key), signature_type)
        )
    signature_function = signature_conf["signature_function"]
    signature = signature_function(key=key, plaintext=plaintext)
    signature["type"] = signature_type
    return signature  # FIXME encode as base64 the bytes!!!!


def _sign_with_pss(plaintext: bytes, key: RSA.RsaKey) -> dict:
    """Sign a bytes message with a private RSA key.

    :param private_key: the private key
    :param plaintext: the bytestring to sign

    :return: dict with keys "digest" (bytestring), "timestamp_utc" (integer) and "type" (string) of signature"""

    timestamp_utc = _get_utc_timestamp()
    hash_payload = _compute_timestamped_hash(
        plaintext=plaintext, timestamp_utc=timestamp_utc
    )
    signer = pss.new(key)
    digest = signer.sign(hash_payload)
    signature = {"timestamp_utc": timestamp_utc, "digest": digest}
    return signature


def _sign_with_dss(plaintext: bytes, key: Union[DSA.DsaKey, ECC.EccKey]) -> dict:
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
    signer = DSS.new(key, "fips-186-3")
    digest = signer.sign(hash_payload)
    signature = {"timestamp_utc": timestamp, "digest": digest}
    return signature


def verify_signature(plaintext: bytes, signature: dict, key: Union[KNOWN_KEY_TYPES]):
    """Verify the authenticity of a signature.

    Raises if signature is invalid.

    :param public_key: the cryptographic key used to verify the signature
    :param plaintext: the text which was signed
    :param signature: structure describing the signature
    """

    if signature["type"] == "PSS":
        verifier = pss.new(key)
    elif signature["type"] == "DSS":
        verifier = DSS.new(key, "fips-186-3")
    else:
        raise ValueError("Unknown signature type '%s'" % signature["type"])

    hash_payload = _compute_timestamped_hash(
        plaintext=plaintext, timestamp_utc=signature["timestamp_utc"]
    )
    verifier.verify(hash_payload, signature["digest"])


def _get_utc_timestamp() -> int:
    """Get current UTC timestamp.

    :return: timestamp as an integer
    """
    timestamp_utc = int(datetime.utcnow().timestamp())
    return timestamp_utc


def _compute_timestamped_hash(plaintext: bytes, timestamp_utc: int):
    """Create a hash of content, including the timestamp.

    :param plaintext: bytestring to sign
    :param timestamp: integer UTC timestamp

    :return: stdlib hash object
    """
    plaintext_hash_bytes = SHA512.new(plaintext).digest()
    timestamp_bytes = str(timestamp_utc).encode("ascii")
    timestamped_payload = plaintext_hash_bytes + timestamp_bytes
    payload_hash = SHA512.new(timestamped_payload)
    return payload_hash


SIGNATURE_TYPES_REGISTRY = dict(
    PSS={"signature_function": _sign_with_pss, "compatible_key_types": [RSA.RsaKey]},
    DSS={
        "signature_function": _sign_with_dss,
        "compatible_key_types": [DSA.DsaKey, ECC.EccKey],
    },
)

#: These values can be used as 'signature_type'.
SUPPORTED_SIGNATURE_TYPES = sorted(SIGNATURE_TYPES_REGISTRY.keys())
