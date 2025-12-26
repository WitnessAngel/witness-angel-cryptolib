# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os


logger = logging.getLogger(__name__)


from .pycryptodome import (
    AES_BLOCK_SIZE,
    build_aes_cbc_encrypter,
    encrypt_via_aes_cbc,
    decrypt_via_aes_cbc,
    build_aes_eax_cipher,
    encrypt_via_aes_eax,
    decrypt_via_aes_eax,
    build_chacha20_poly1305_cipher,
    encrypt_via_chacha20_poly1305,
    decrypt_via_chacha20_poly1305,
    # No cipher builder for (asymmetric) RSA
    encrypt_via_rsa_oaep,
    decrypt_via_rsa_oaep,
)
from .pycryptodome import (
    generate_rsa_keypair,
    generate_dsa_keypair,
    generate_ecc_keypair,
    import_rsa_key_from_pem,
    import_dsa_key_from_pem,
    import_ecc_key_from_pem,
    export_rsa_key_to_pem,
    export_dsa_key_to_pem,
    export_ecc_key_to_pem,
    rsa_key_class_fetcher,
    dsa_key_class_fetcher,
    ecc_key_class_fetcher,
)
from .pycryptodome import sign_with_pss, verify_with_pss, sign_with_dss, verify_with_dss

#from .fallback_adapter import (build_aes_cbc_encrypter, encrypt_via_aes_cbc, decrypt_via_aes_cbc,)
                                #import_rsa_key_from_pem, encrypt_via_rsa_oaep, decrypt_via_rsa_oaep,
                                #generate_rsa_keypair, rsa_key_class_fetcher)


# RANDOMNESS #
def get_random_bytes(nbytes):
    """Like pycryptodome, we rely on the randomness of the OS!"""
    return os.urandom(nbytes)


# BYTE PADDING (PKCS7 by default) #
from .vendor.Padding import pad as pad_bytes, unpad as unpad_bytes


# SHAMIR SHARED SECRETS #
# We always use the vendored version #

from .vendor.SecretSharing import Shamir


def shamir_split(*args, **kwargs):
    return Shamir.split(*args, **kwargs)


def shamir_combine(*args, **kwargs):
    return Shamir.combine(*args, **kwargs)


# HASHER FACTORY #


import hashlib  # MUST exist, even in micropython
_DESIRED_HASH_ALGOS =  ["SHA256", "SHA512", "SHA3_256", "SHA3_512"]
_SUPPORTED_HASH_ALGOS = [_x for _x in _DESIRED_HASH_ALGOS if hasattr(hashlib, _x.lower())]

_HASH_ALGO_TO_OID = {
    # See Pycryptodome sources for OIDs
    "SHA256": "2.16.840.1.101.3.4.2.1",
    "SHA512": "2.16.840.1.101.3.4.2.3",
    "SHA3_256": "2.16.840.1.101.3.4.2.8",
    "SHA3_512": "2.16.840.1.101.3.4.2.10",
}


class HasherCompatibilityLayer():
    def __init__(self, hasher):
        self._hasher = hasher

    def __getattr__(self, attr):
        return getattr(self._hasher, attr)

    @property
    def oid(self):
        return _HASH_ALGO_TO_OID[self._hasher.name.upper()]

    def new(self, *args, **kwargs):
        # HASH instances can't be normally instantiated when C-based...
        return hashlib.new(self._hasher.name.lower())


def get_hasher_instance(hash_algo: str) -> HasherCompatibilityLayer:
    hasher_instance = hashlib.new(hash_algo.lower())
    return HasherCompatibilityLayer(hasher_instance)
