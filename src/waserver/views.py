from jsonrpc import jsonrpc_method
from wacryptolib import *


@jsonrpc_method('sayhelloworld')
def helloworld(request):
    return "Hello world"


@jsonrpc_method('generatekeypair(str) -> bytes')
def keypairs(request, algo):
    if algo == "RSA":
        pem_keypair = key_generation._serialize_rsa_key_objects_to_pem(
            key_generation.generate_rsa_keypair(None))
    elif algo == "DSA":
        pem_keypair = key_generation._serialize_dsa_key_objects_to_pem(
            key_generation.generate_dsa_keypair(None))
    elif algo == "ECC":
        pem_keypair = key_generation._serialize_ecc_key_objects_to_pem(
            key_generation.generate_ecc_keypair(None, "p256"))
    print(type(pem_keypair["public_key"]))
    return pem_keypair["public_key"]
