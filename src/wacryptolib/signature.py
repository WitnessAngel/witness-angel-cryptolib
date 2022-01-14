import logging
from datetime import datetime
from typing import Union

import Crypto.Hash.SHA512
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pss, DSS

from wacryptolib.exceptions import SignatureCreationError, SignatureVerificationError

KNOWN_KEY_ALGOS = Union[RSA.RsaKey, DSA.DsaKey, ECC.EccKey]
SIGNATURE_HASHER = Crypto.Hash.SHA512

logger = logging.getLogger(__name__)


def sign_message(message: bytes, *, signature_algo: str, key: KNOWN_KEY_ALGOS) -> dict:
    """
    Return a timestamped signature of the chosen type for the given payload,
    with the provided key (which must be of a compatible type).

    :return: dictionary with signature data"""

    assert signature_algo, signature_algo
    signature_algo = signature_algo.upper()
    signature_conf = SIGNATURE_ALGOS_REGISTRY.get(signature_algo)
    if signature_conf is None:
        raise ValueError("Unknown signature algorithm '%s'" % signature_algo)
    if not isinstance(key, signature_conf["compatible_key_algo"]):
        raise ValueError("Incompatible key type %s for signature algorithm %s" % (type(key), signature_algo))
    signature_function = signature_conf["signature_function"]
    timestamp_utc = _get_utc_timestamp()
    try:
        signature = signature_function(key=key, message=message, timestamp_utc=timestamp_utc)
    except ValueError as exc:
        raise SignatureCreationError("Failed %s signature creation (%s)" % (signature_algo, exc)) from exc
    return {"signature_timestamp_utc": timestamp_utc, "signature_value": signature}


def _sign_with_pss(message: bytes, key: RSA.RsaKey, timestamp_utc: int) -> bytes:
    """Sign a bytes message with a private RSA key.

    :param message: the bytestring to sign
    :param key: the private RSA key
    :param timestamp_utc: the UTC timestamp of current time

    :return: signature as a bytestring"""

    hash_payload = _compute_timestamped_hash(message=message, timestamp_utc=timestamp_utc)
    signer = pss.new(key)
    signature = signer.sign(hash_payload)
    return signature


def _sign_with_dss(message: bytes, key: Union[DSA.DsaKey, ECC.EccKey], timestamp_utc: int) -> bytes:
    """Sign a bytes message with a private DSA or ECC key.

    We use the `fips-186-3` mode for the signer because signature is randomized,
    while it is not the case for the mode `deterministic-rfc6979`.

    :param message: the bytestring to sign
    :param key: the private DSA/ECC key
    :param timestamp_utc: the UTC timestamp of current time

    :return: signature as a bytestring"""

    hash_payload = _compute_timestamped_hash(message=message, timestamp_utc=timestamp_utc)
    signer = DSS.new(key, "fips-186-3")
    signature = signer.sign(hash_payload)
    return signature


def verify_message_signature(*, message: bytes, signature_algo: str, signature: dict, key: Union[KNOWN_KEY_ALGOS]):
    """Verify the authenticity of a signature.

    Raises if signature is invalid.

    :param message: the bytestring which was signed
    :param signature_algo: the name of the signing algorithm
    :param signature: structure describing the signature
    :param key: the cryptographic key used to verify the signature
    """
    # TODO refactor this with new SIGNATURE_ALGOS_REGISTRY fields to be added
    signature_algo = signature_algo.upper()
    if signature_algo == "RSA_PSS":
        verifier = pss.new(key)
    elif signature_algo in ["DSA_DSS", "ECC_DSS"]:
        verifier = DSS.new(key, "fips-186-3")
    else:
        raise ValueError("Unknown signature algorithm %s" % signature_algo)

    hash_payload = _compute_timestamped_hash(message=message, timestamp_utc=signature["signature_timestamp_utc"])

    try:
        verifier.verify(hash_payload, signature["signature_value"])
    except ValueError as exc:
        raise SignatureVerificationError("Failed %s signature verification (%s)" % (signature_algo, exc)) from exc


def _get_utc_timestamp() -> int:
    """Get current UTC timestamp.

    :return: timestamp as an integer
    """
    timestamp_utc = int(datetime.utcnow().timestamp())
    return timestamp_utc


def _compute_timestamped_hash(message: bytes, timestamp_utc: int):
    """Create a hash of content, including the timestamp.

    :param message: bytestring to sign
    :param timestamp_utc: integer UTC timestamp

    :return: stdlib hash object
    """
    plaintext_hash_bytes = SIGNATURE_HASHER.new(message).digest()
    timestamp_bytes = str(timestamp_utc).encode("ascii")
    timestamped_payload = plaintext_hash_bytes + timestamp_bytes
    payload_hash = SIGNATURE_HASHER.new(timestamped_payload)
    return payload_hash


SIGNATURE_ALGOS_REGISTRY = dict(
    RSA_PSS={"signature_function": _sign_with_pss, "compatible_key_algo": RSA.RsaKey},
    DSA_DSS={"signature_function": _sign_with_dss, "compatible_key_algo": DSA.DsaKey},
    ECC_DSS={"signature_function": _sign_with_dss, "compatible_key_algo": ECC.EccKey},
)

#: These values can be used as 'payload_signature_algo' parameters.
SUPPORTED_SIGNATURE_ALGOS = sorted(SIGNATURE_ALGOS_REGISTRY.keys())
