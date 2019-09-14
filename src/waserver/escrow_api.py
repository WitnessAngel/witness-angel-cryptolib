import uuid

from wacryptolib.encryption import _decrypt_via_rsa_oaep
from wacryptolib.key_generation import generate_asymmetric_keypair, load_asymmetric_key_from_pem_bytestring
from wacryptolib.signature import sign_message


_CACHED_KEYS = {}  # DIRTY process-local caching for tests


def _fetch_pem_keypair_with_caching(uid, key_type):  # FIXME - hack to turn into DB lookup
    existing_keypair = _CACHED_KEYS.get((uid, key_type))
    if existing_keypair:
        keypair = existing_keypair
    else:
        keypair = generate_asymmetric_keypair(key_type=key_type, serialize=True)
        _CACHED_KEYS[(uid, key_type)] = keypair
    return keypair


def get_public_key(uid: uuid.UUID, key_type: str) -> bytes:
    """
    Return a public key in PEM format bytestring, that caller shall use to encrypt its own symmetric keys,
    or to check a signature.
    """
    keypair_pem = _fetch_pem_keypair_with_caching(uid=uid, key_type=key_type)
    return keypair_pem["public_key"]


def get_message_signature(
    uid: uuid.UUID, message: bytes, key_type: str, signature_algo: str
) -> dict:
    """
    Return a signature structure corresponding to the provided key and signature types.
    """
    keypair_pem = _fetch_pem_keypair_with_caching(uid=uid, key_type=key_type)
    private_key = load_asymmetric_key_from_pem_bytestring(key_pem=keypair_pem["private_key"], key_type=key_type)

    signature = sign_message(
        message=message,
        signature_algo=signature_algo,
        key=private_key,
    )
    return signature


def decrypt_with_private_key(
    uid: uuid.UUID, key_type: str, encryption_algo: str, cipherdict: dict
) -> bytes:
    """
    Return the message (probably a symmetric key) decrypted with the corresponding key,
    as bytestring.
    """
    assert key_type.upper() == "RSA"  # Only supported key for now
    assert (
        encryption_algo.upper() == "RSA_OAEP"
    )  # Only supported asymmetric cipher for now

    keypair_pem = _fetch_pem_keypair_with_caching(uid=uid, key_type=key_type)
    private_key = load_asymmetric_key_from_pem_bytestring(key_pem=keypair_pem["private_key"], key_type=key_type)

    secret = _decrypt_via_rsa_oaep(cipherdict=cipherdict, key=private_key)
    return secret
