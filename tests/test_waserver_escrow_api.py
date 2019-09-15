import uuid

import pytest
from Crypto.Random import get_random_bytes
from django.test import Client
from jsonrpc.proxy import TestingServiceProxy

from wacryptolib.encryption import _encrypt_via_rsa_oaep
from wacryptolib.key_generation import load_asymmetric_key_from_pem_bytestring
from wacryptolib.signature import verify_signature
from waserver import escrow_api


# MONKEY-PATCH django-jsonrpc package so that it uses Extended Json on proxy requests
from bson.json_util import dumps, loads
from jsonrpc import proxy
assert proxy.loads
proxy.loads = loads
assert proxy.dumps
proxy.dumps = dumps



direct_api_proxy = escrow_api
jsronrpc_proxy = TestingServiceProxy(client=Client(), service_url="/json/", version='2.0')


@pytest.mark.parametrize("escrow_proxy", [direct_api_proxy])   #, jsronrpc_proxy])
def test_waserver_escrow_api_workflow(escrow_proxy):

    uid = uuid.uuid4()
    secret = get_random_bytes(101)

    public_key_pem = escrow_proxy.get_public_key(uid=uid, key_type="RSA")
    public_key = load_asymmetric_key_from_pem_bytestring(key_pem=public_key_pem, key_type="RSA")

    signature = escrow_proxy.get_message_signature(
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

    decrypted = escrow_proxy.decrypt_with_private_key(
        uid=uid, key_type="RSA", encryption_algo="RSA_OAEP", cipherdict=cipherdict
    )

    cipherdict["digest_list"].append(b"aaabbbccc")
    with pytest.raises(ValueError, match="Ciphertext with incorrect length"):
        escrow_proxy.decrypt_with_private_key(
            uid=uid, key_type="RSA", encryption_algo="RSA_OAEP", cipherdict=cipherdict
        )

    assert decrypted == secret
