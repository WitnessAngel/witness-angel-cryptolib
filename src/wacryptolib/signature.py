import logging
from datetime import datetime
from typing import Union

import Crypto.Hash.SHA512
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pss, DSS

from wacryptolib.exceptions import SignatureCreationError, SignatureVerificationError

KNOWN_KEY_TYPES = Union[RSA.RsaKey, DSA.DsaKey, ECC.EccKey]
SIGNATURE_HASHER = Crypto.Hash.SHA512

logger = logging.getLogger(__name__)


def sign_message(message: bytes, *, signature_algo: str, key: KNOWN_KEY_TYPES) -> dict:
    """
    Return a timestamped signature of the chosen type for the given payload,
    with the provided key (which must be of a compatible type).

    :return: dictionary with signature data"""

    assert signature_algo, signature_algo
    signature_algo = signature_algo.upper()
    signature_conf = SIGNATURE_ALGOS_REGISTRY.get(signature_algo)
    if signature_conf is None:
        raise ValueError("Unknown signature algorithm '%s'" % signature_algo)
    if not isinstance(key, signature_conf["compatible_key_type"]):
        raise ValueError("Incompatible key type %s for signature algorithm %s" % (type(key), signature_algo))
    signature_function = signature_conf["signature_function"]
    try:
        signature = signature_function(key=key, message=message)
    except ValueError as exc:
        raise SignatureCreationError("Failed %s signature creation (%s)" % (signature_algo, exc)) from exc
    return signature


def _sign_with_pss(message: bytes, key: RSA.RsaKey) -> dict:
    """Sign a bytes message with a private RSA key.

    :param message: the bytestring to sign
    :param private_key: the private key

    :return: signature dict with keys "digest" (bytestring) and "timestamp_utc" (integer)"""

    timestamp_utc = _get_utc_timestamp()
    hash_payload = _compute_timestamped_hash(message=message, timestamp_utc=timestamp_utc)
    signer = pss.new(key)
    digest = signer.sign(hash_payload)
    signature = {"timestamp_utc": timestamp_utc, "digest": digest}
    return signature


def _sign_with_dss(message: bytes, key: Union[DSA.DsaKey, ECC.EccKey]) -> dict:
    """Sign a bytes message with a private DSA or ECC key.

    We use the `fips-186-3` mode for the signer because signature is randomized,
    while it is not the case for the mode `deterministic-rfc6979`.

    :param message: the bytestring to sign
    :param private_key: the private key

    :return: signature dict with keys "digest" (bytestring) and "timestamp_utc" (integer)"""

    timestamp = _get_utc_timestamp()
    hash_payload = _compute_timestamped_hash(message=message, timestamp_utc=timestamp)
    signer = DSS.new(key, "fips-186-3")
    digest = signer.sign(hash_payload)
    signature = {"timestamp_utc": timestamp, "digest": digest}
    return signature


def verify_message_signature(*, message: bytes, signature_algo: str, signature: dict, key: Union[KNOWN_KEY_TYPES]):
    """Verify the authenticity of a signature.

    Raises if signature is invalid.

    :param message: the bytestring which was signed
    :param signature_algo: the name of the signing algorithm
    :param signature: structure describing the signature
    :param key: the cryptographic key used to verify the signature
    """
    # TODO refactor this with new SIGNATURE_ALGOS_REGISTRY fields
    signature_algo = signature_algo.upper()
    if signature_algo == "RSA_PSS":
        verifier = pss.new(key)
    elif signature_algo in ["DSA_DSS", "ECC_DSS"]:
        verifier = DSS.new(key, "fips-186-3")
    else:
        raise ValueError("Unknown signature algorithm %s" % signature_algo)

    hash_payload = _compute_timestamped_hash(message=message, timestamp_utc=signature["timestamp_utc"])

    try:
        verifier.verify(hash_payload, signature["digest"])
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
    :param timestamp: integer UTC timestamp

    :return: stdlib hash object
    """
    plaintext_hash_bytes = SIGNATURE_HASHER.new(message).digest()
    timestamp_bytes = str(timestamp_utc).encode("ascii")
    timestamped_payload = plaintext_hash_bytes + timestamp_bytes
    payload_hash = SIGNATURE_HASHER.new(timestamped_payload)
    return payload_hash


SIGNATURE_ALGOS_REGISTRY = dict(
    RSA_PSS={"signature_function": _sign_with_pss, "compatible_key_type": RSA.RsaKey},
    DSA_DSS={"signature_function": _sign_with_dss, "compatible_key_type": DSA.DsaKey},
    ECC_DSS={"signature_function": _sign_with_dss, "compatible_key_type": ECC.EccKey},
)

#: These values can be used as 'signature_algo' parameters.
SUPPORTED_SIGNATURE_ALGOS = sorted(SIGNATURE_ALGOS_REGISTRY.keys())
