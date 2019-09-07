import uuid
from base64 import b64decode, b64encode

import pytest
from Crypto.Random import get_random_bytes

from wacryptolib.encryption import _encrypt_via_rsa_oaep
from wacryptolib.key_generation import KEY_TYPES_REGISTRY
from wacryptolib.signature import verify_signature
from waserver.escrow_api import get_public_key, get_message_signature, unravel_secret


def test_waserver_escrow_api_workflow():

    uid = uuid.uuid4()
    secret = get_random_bytes(101)

    public_key_pem = b64decode(get_public_key(uid=uid, key_type="RSA"))
    public_key = KEY_TYPES_REGISTRY["RSA"]["pem_import_function"](public_key_pem)

    signature = get_message_signature(
        uid=uid, plaintext=secret, key_type="RSA", signature_type="PSS"
    )
    verify_signature(plaintext=secret, signature=signature, key=public_key)

    signature["digest"] += b"xyz"
    with pytest.raises(ValueError, match="Incorrect signature"):
        verify_signature(plaintext=secret, signature=signature, key=public_key)

    cipherdict = _encrypt_via_rsa_oaep(plaintext=secret, key=public_key)

    decrypted_base64 = unravel_secret(uid=uid, key_type="RSA", cipherdict=cipherdict)
    decrypted = b64decode(decrypted_base64)

    cipherdict["digest_list"].append(b64encode(b"aaabbbccc"))
    with pytest.raises(ValueError, match="Ciphertext with incorrect length"):
        unravel_secret(uid=uid, key_type="RSA", cipherdict=cipherdict)

    assert decrypted == secret
