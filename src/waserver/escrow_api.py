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
    print(">>>>>>>>> PUBLIC KEY OF TYPE %s is %s" % (key_type, keypair["public_key"]))
    return keypair["public_key"]


def get_message_signature(  # FIXME rename "plaintext" here, inadequate
    uid: uuid.UUID, plaintext: bytes, key_type: str, signature_type: str
) -> dict:
    """
    Return a signature structure corresponding to the provided key and signature types.
    """
    keypair = generate_asymmetric_keypair(uid=uid, key_type=key_type, serialize=False)
    private_key = keypair["private_key"]
    print(
        "\n> SIGNING MESSAGE \n%s with %s key of public form %s"
        % (
            plaintext,
            keypair["public_key"].__class__,
            keypair["public_key"].export_key(format="PEM"),
        )
    )
    signature = sign_message(
        plaintext=plaintext,
        signature_type=signature_type,
        key=private_key,  # FIXME rename "plaintext" here, inadequate
    )
    return signature


def decrypt_with_private_key(uid: uuid.UUID, key_type: str, encryption_type:str, cipherdict: dict) -> str:
    """
    Return the message (probably a symmetric key) decrypted with the corresponding key,
    as bytestring.
    """
    assert key_type.upper() == "RSA"  # Only supported key for now
    assert encryption_type.upper() == "RSA_OAEP"  # Only supported asymmetric cipher for now
    keypair = generate_asymmetric_keypair(uid=uid, key_type=key_type, serialize=False)
    private_key = keypair["private_key"]
    secret = _decrypt_via_rsa_oaep(cipherdict=cipherdict, key=private_key)
    return secret
