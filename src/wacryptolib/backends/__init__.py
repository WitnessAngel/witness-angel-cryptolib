import sys

try:
    # Impossible to use pycryptodome package on iOS due to forbidden dlopen()...
    import os  #ios
    use_fallback_backend = True
except ImportError:
    use_fallback_backend = False


if use_fallback_backend :

    print("Couldn't import full pycryptodome utilities, falling back to fake C extensions")

    # MONKEY PATCH PYCRYPTODOME INTERNALS TO BYPASS ".so" objects
    class FakePycryptodomeExtensionLib:

        @staticmethod
        def have_aes_ni():
            return False

        @staticmethod
        def have_clmul():
            return False

    def fake_load_pycryptodome_raw_lib(name, cdecl):
        if name in ["Crypto.Math._modexp"]:  # We force automatic fallback for some libs, inside pycryptodome
            raise ImportError("Fake ImportError to force failure on non-vital extension %s" % name)
        return FakePycryptodomeExtensionLib()


    assert not sys.modules.get("Crypto.Util._raw_api")  # Must NOT have been already imported by another submodule
    import Crypto.Util._raw_api
    Crypto.Util._raw_api.load_pycryptodome_raw_lib = fake_load_pycryptodome_raw_lib


from .pycryptodome import encrypt_via_aes_cbc, decrypt_via_aes_cbc, encrypt_via_aes_eax, decrypt_via_aes_eax,\
    encrypt_via_chacha20_poly1305, decrypt_via_chacha20_poly1305, build_rsa_oaep_cipher,\
    build_aes_cbc_cipher, build_aes_eax_cipher, build_chacha20_poly1305_cipher, AES_BLOCK_SIZE
from .pycryptodome import generate_rsa_keypair, generate_dsa_keypair, generate_ecc_keypair, import_rsa_key_from_pem, import_dsa_key_from_pem, import_ecc_key_from_pem, export_rsa_key_to_pem, export_dsa_key_to_pem, export_ecc_key_to_pem, rsa_key_class_fetcher, dsa_key_class_fetcher, ecc_key_class_fetcher
from .pycryptodome import get_random_bytes, pad, unpad, get_hasher_instance
from .pycryptodome import shamir_split, shamir_combine
from .pycryptodome import sign_with_pss, verify_with_pss, sign_with_dss, verify_with_dss


if use_fallback_backend:


    ##from .fallback import AES_BLOCK_SIZE
    ###from .fallback import generate_rsa_keypair, RSA_KEY_CLASS
    ##from .fallback import get_random_bytes, pad, unpad

    # DUMMY PLACEHOLDERS SO THAT ERRORS DON'T POP IMEMDIATELY WHEN LOADING WACRYPTOLIB #

    '''
    class NotImplementedClass:
        pass

    def not_implemented_function(*args, **kwargs):
        raise NotImplementedError("No backend utility found for this functionality")

    import_rsa_key_from_pem = export_rsa_key_to_pem = not_implemented_function  #FIXMEEE

    encrypt_via_aes_cbc = decrypt_via_aes_cbc = encrypt_via_aes_eax = decrypt_via_aes_eax = encrypt_via_chacha20_poly1305 = decrypt_via_chacha20_poly1305 = build_rsa_oaep_cipher = build_aes_cbc_cipher = build_aes_eax_cipher = build_chacha20_poly1305_cipher = not_implemented_function

    generate_dsa_keypair = generate_ecc_keypair = import_dsa_key_from_pem = import_ecc_key_from_pem = export_dsa_key_to_pem = export_ecc_key_to_pem = not_implemented_function

    DSA_KEY_CLASS = ECC_KEY_CLASS = NotImplementedClass

    get_hasher_instance = not_implemented_function
    shamir_split = shamir_combine = not_implemented_function
    sign_with_pss = verify_with_pss = sign_with_dss = verify_with_dss = not_implemented_function
    '''
