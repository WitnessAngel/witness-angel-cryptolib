import uuid

from wacryptolib.encryption import _decrypt_via_rsa_oaep
from wacryptolib.key_generation import generate_asymmetric_keypair
from wacryptolib.signature import sign_message


def get_public_key(uid: uuid.UUID, key_type: str) -> bytes:
    """
    Return a public key in PEM format bytestring, that caller shall use to encrypt its own symmetric keys,
    or to check a signature.
    """
    keypair = generate_asymmetric_keypair(uid=uid, key_type=key_type, serialize=True)
    del keypair["private_key"]  # Security
    return keypair["public_key"]


def get_message_signature(
    uid: uuid.UUID, message: bytes, key_type: str, signature_algo: str
) -> dict:
    """
    Return a signature structure corresponding to the provided key and signature types.
    """
    keypair = generate_asymmetric_keypair(uid=uid, key_type=key_type, serialize=False)
    private_key = keypair["private_key"]

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
    keypair = generate_asymmetric_keypair(uid=uid, key_type=key_type, serialize=False)
    private_key = keypair["private_key"]
    secret = _decrypt_via_rsa_oaep(cipherdict=cipherdict, key=private_key)
    return secret
