import uuid

import pytest
from Crypto.Random import get_random_bytes

from wacryptolib.encryption import _encrypt_via_rsa_oaep
from wacryptolib.key_generation import KEY_TYPES_REGISTRY
from wacryptolib.signature import verify_signature
from waserver.escrow_api import (
    get_public_key,
    get_message_signature,
    decrypt_with_private_key,
)


def test_waserver_escrow_api_workflow():

    uid = uuid.uuid4()
    secret = get_random_bytes(101)

    public_key_pem = get_public_key(uid=uid, key_type="RSA")
    public_key = KEY_TYPES_REGISTRY["RSA"]["pem_import_function"](public_key_pem)

    signature = get_message_signature(
        uid=uid, message=secret, key_type="RSA", signature_algo="PSS"
    )
    verify_signature(
        message=secret, signature=signature, key=public_key, signature_algo="PSS"
    )

    signature["digest"] += b"xyz"
    with pytest.raises(ValueError, match="Incorrect signature"):
        verify_signature(
            message=secret, signature=signature, key=public_key, signature_algo="PSS"
        )

    cipherdict = _encrypt_via_rsa_oaep(plaintext=secret, key=public_key)

    decrypted = decrypt_with_private_key(
        uid=uid, key_type="RSA", encryption_algo="RSA_OAEP", cipherdict=cipherdict
    )

    cipherdict["digest_list"].append(b"aaabbbccc")
    with pytest.raises(ValueError, match="Ciphertext with incorrect length"):
        decrypt_with_private_key(
            uid=uid, key_type="RSA", encryption_algo="RSA_OAEP", cipherdict=cipherdict
        )

    assert decrypted == secret
