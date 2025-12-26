# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os


logger = logging.getLogger(__name__)

from .pycryptodome import IMPLEMENTED_HASH_ALGOS, get_hasher_instance
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


# SHAMIR SHARED SECRETS #
# We always use the vendored version #

from .vendor.PycryptodomeSecretSharing import Shamir as _Shamir


def shamir_128b_split_func(*args, **kwargs):
    return _Shamir.split(*args, **kwargs)


def shamir_128b_combine_func(*args, **kwargs):
    return _Shamir.combine(*args, **kwargs)

