import logging
from datetime import datetime
from typing import Union

from wacryptolib.backends import sign_with_pss, verify_with_pss, sign_with_dss, verify_with_dss, RSA_KEY_CLASS, \
    DSA_KEY_CLASS, ECC_KEY_CLASS, get_hasher_instance

from wacryptolib.exceptions import SignatureCreationError, SignatureVerificationError

KNOWN_KEY_CLASSES = Union[RSA_KEY_CLASS, DSA_KEY_CLASS, ECC_KEY_CLASS]

SIGNATURE_HASHER = get_hasher_instance("SHA512")  # ALWAYS USE THIS ONE!

logger = logging.getLogger(__name__)


def _get_signature_conf(signature_algo, key):
    assert signature_algo, signature_algo
    signature_algo = signature_algo.upper()
    signature_conf = SIGNATURE_ALGOS_REGISTRY.get(signature_algo)
    if signature_conf is None:
        raise ValueError("Unknown signature algorithm '%s'" % signature_algo)
    if not isinstance(key, signature_conf["compatible_key_class"]):
        raise ValueError("Incompatible key type %s for signature algorithm %s" % (type(key), signature_algo))
    return signature_conf


# FIXME rename "key" to "private_key", here? Or no need?
def sign_message(message: bytes, *, signature_algo: str, key: KNOWN_KEY_CLASSES) -> dict:
    """
    Return a timestamped signature of the chosen type for the given payload,
    with the provided key (which must be of a compatible type).

    Signature is actually performed on a SHA512 DIGEST of the message.

    :return: dictionary with signature data"""

    signature_conf = _get_signature_conf(signature_algo=signature_algo, key=key)
    signature_function = signature_conf["signature_function"]
    timestamp_utc = _get_utc_timestamp()

    try:
        hash_payload = _compute_timestamped_hash(message=message, timestamp_utc=timestamp_utc)
        signature = signature_function(message=hash_payload, private_key=key)
    except ValueError as exc:
        raise SignatureCreationError("Failed %s signature creation (%s)" % (signature_algo, exc)) from exc
    return {"signature_timestamp_utc": timestamp_utc, "signature_value": signature}


# FIXME rename "key" to "public_key", here? Or no need?
def verify_message_signature(*, message: bytes, signature_algo: str, signature: dict, key: KNOWN_KEY_CLASSES):
    """Verify the authenticity of a signature.

    Raises if signature is invalid.

    :param message: the bytestring which was signed
    :param signature_algo: the name of the signing algorithm
    :param signature: structure describing the signature
    :param key: the cryptographic key used to verify the signature
    """

    signature_conf = _get_signature_conf(signature_algo=signature_algo, key=key)
    verification_function = signature_conf["verification_function"]

    try:
        hash_payload = _compute_timestamped_hash(message=message, timestamp_utc=signature["signature_timestamp_utc"])
        verification_function(message=hash_payload, signature=signature["signature_value"], public_key=key)
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
    RSA_PSS={"signature_function": sign_with_pss, "verification_function": verify_with_pss, "compatible_key_class": RSA_KEY_CLASS},
    DSA_DSS={"signature_function": sign_with_dss, "verification_function": verify_with_dss, "compatible_key_class": DSA_KEY_CLASS},
    ECC_DSS={"signature_function": sign_with_dss, "verification_function": verify_with_dss, "compatible_key_class": ECC_KEY_CLASS},
)

#: These values can be used as 'payload_signature_algo' parameters.
SUPPORTED_SIGNATURE_ALGOS = sorted(SIGNATURE_ALGOS_REGISTRY.keys())
