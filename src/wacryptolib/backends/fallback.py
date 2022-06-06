

#import rsa
##from secrets import token_bytes as get_random_bytes

'''
from rsa.key import AbstractKey as RSA_KEY_CLASS

from ._vendored_padding import pad, unpad
'''

##AES_BLOCK_SIZE = 16  # SAME as in pycryptodome

'''
def generate_rsa_keypair(key_length_bits):
    import rsa
    public_key, private_key = rsa.newkeys(key_length_bits)
    return public_key, private_key
'''

def get_hasher_instance(hash_algo):
    import hashlib
    hasher_class = getattr(hashlib, hash_algo.lower())
    hasher_instance = hasher_class()
    return hasher_instance
