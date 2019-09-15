from jsonrpc import jsonrpc_method

from wacryptolib import key_generation

from . import escrow_api

# MONKEY-PATCH django-jsonrpc package so that it uses Extended Json on responses
from bson.json_util import dumps, loads
from jsonrpc import site
assert site.loads
site.loads = loads
assert site.dumps
site.dumps = dumps


'''

@jsonrpc_method("waserver.sayhelloworld")
def sayhelloworld(request):
    return "Hello world"


@jsonrpc_method("generate_keypair(str) -> str")
def get_public_key(request, algo):
    pem_keypair = key_generation.generate_assymetric_keypair(uid=None, key_type=algo)
    return pem_keypair["public_key"]

'''


@jsonrpc_method
def get_public_key(uid, key_type):
    return escrow_api.get_public_key(uid=uid, key_type=key_type)


@jsonrpc_method
def get_message_signature(uid, message, key_type, signature_algo):
    return escrow_api.get_message_signature(uid=uid, message=message, key_type=key_type, signature_algo=signature_algo)


@jsonrpc_method
def decrypt_with_private_key(uid, key_type, encryption_algo, cipherdict):
        return escrow_api.decrypt_with_private_key(uid=uid, key_type=key_type, encryption_algo=encryption_algo, cipherdict=cipherdict)
