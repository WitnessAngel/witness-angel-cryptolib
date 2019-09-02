from jsonrpc import jsonrpc_method

from wacryptolib import key_generation


@jsonrpc_method("waserver.sayhelloworld")
def sayhelloworld(request):
    return "Hello world"


@jsonrpc_method("generate_keypair(str) -> str")
def generate_keypair(request, algo):
    pem_keypair = key_generation.generate_assymetric_keypair(uid=None, key_type=algo)
    return pem_keypair["public_key"]
