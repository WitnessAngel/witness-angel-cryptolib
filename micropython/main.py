import sys

## MONKEY PATCHING
IS_MICROPYTHON = (sys.implementation.name == "micropython")

# Vendored dependencies, see vendor_dependencies.py
_LIB_DIR = (sys.path[0] or ".") + "/lib"
if IS_MICROPYTHON:
    sys.path.insert(0, _LIB_DIR)
else:
    sys.path.append(_LIB_DIR)  # Stdlib and installed packages take precedence over our stubs
print("SYSPATHS", sys.path)

import logging

if IS_MICROPYTHON:
    import typing
    typing.TypeVar = lambda *args, **kwargs: None
    typing.TYPE_CHECKING = False

    import hmac
    def _compare_digest(a, b) : return a == b  # No timing-attack protection
    hmac.compare_digest = _compare_digest

    import os, random as _builtin_random
    class _SystemRandom:
        # Builtin random is read-only and pseudo-random, so crypto randomness is taken from os.urandom()
        def getrandbits(self, k):
            return int.from_bytes(os.urandom((k + 7) // 8), "big") >> (-k % 8)
        def randint(self, a, b):
            span = b - a
            while True:  # Rejection sampling, to avoid modulo bias
                candidate = self.getrandbits(len(bin(span)) - 2)
                if candidate <= span:
                    return a + candidate
    class _RandomModule:
        SystemRandom = Random = _SystemRandom
        def __getattr__(self, name):
            return getattr(_builtin_random, name)
    sys.modules["random"] = _RandomModule()

    sys.modules["textwrap"] = dict(_msg="WRONGMODULEFAKED")

    import threading
    class _DummyLock:
        # DUMMY LOCK, TO PLEASE RSA PACKAGE
        pass
    threading.Lock = _DummyLock
###########

from flightbox import FlightBox
from flightbox_utilities_implementation import FlightboxUtilitiesImpl, AUTHENTICATOR_TRUSTEE

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()


TRUSTEE_UID_1 = "5e840838-7532-4b32-ba72-ccd17f7c923a"
KEYCHAIN_UID_1 = "acd7f9f7-849b-44af-9765-9d4913b7f8dd"


# Used as fallback when no proper cryptoconf is provided
SIMPLE_CRYPTOCONF = dict(
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[
                dict(key_cipher_algo="RSA_OAEP",
                    key_cipher_trustee=dict(
                                            trustee_type=AUTHENTICATOR_TRUSTEE,
                                            keystore_uid=TRUSTEE_UID_1,
                                        ),
                     keychain_uid=KEYCHAIN_UID_1),
                # dict(
                #     key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
                #     key_shared_secret_threshold=1,
                #     key_shared_secret_shards=[
                #         dict(
                #             key_cipher_layers=[
                #                 dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                #             ]
                #         ),
                #         dict(
                #             key_cipher_layers=[
                #                 dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                #             ]
                #         ),
                #     ],  # Beware, same trustee for the 2 shards, for now
                # ),
            ],
            payload_ciphertext_signatures=[],
        )
    ]
)


____public_key_pem_from_wacryptolib = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkvHRJ3KYCiNsjFGBQOJT
Rbx4W/WJ7f5N8Jn+yKW08y/9ERMkcM9imqRDVr5oYMTvKxyxVSsWj39ClhOojTGG
ZdlT6vgwtKgi7yHniUED6yxaABs60kIMF6W2CfS0RCtZY5LjVQpPhxmX3fy1g6n+
MJ0Y9PvGWVqDaBnoCFm4t17n2YKqzKLSO13HZwEnpisV14cxwSuK/0x8hjwRZkod
rFWPt+e1iCtqr+a0y5pQjZkSS1LY6BDsVz83vkoGUqsDnyQ+v4fuc3vklX9Z91Dx
dSnSbxX8IwJJ7kQEUi3O/kO7bGPTmcWbRAuYbH/6rFkMafVcgeaLBZG6h3CGR6nH
IwIDAQAB
-----END PUBLIC KEY-----"""


n = 18550036936074777576745860692222929823309849339732419768654179699291152139495559922834976621735536311921517873134983260454935762117010713780022370715702782337501169317789855286485787891194144971453027165749472806656521816427794317257818177125547356250896811776665398428028265103962501107999670516354789549043186362295800968855400059275817415069429507150398646058973164280273097890283834820569305921523093272920020136655934918036481615681408018554452207478475696785278942743360661011323663161746160689975622147380453637216164274299383628735318891050050778834528526183812215083531500158856576001965730296948614878578467
e = 65537

KEYSTORE_DATA = {
    TRUSTEE_UID_1: {
        KEYCHAIN_UID_1: dict(n=n, e=e)
    }
}

_fbutils = FlightboxUtilitiesImpl(logger=logger, keystore_data=KEYSTORE_DATA)
flightbox = FlightBox(flightbox_utilities=_fbutils)

cryptainer, secrets = flightbox.generate_cryptainer_base_and_secrets(
            cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_metadata=dict(SOME_METADATA=2726562425242)
        )

try:
    from pprint import pprint
except ImportError:
    def pprint(x, *args, **kwargs):
        print(x)

print("CRYPTAINER:\n")
pprint(cryptainer, width=120)
print()
print("SECRETS:\n", secrets)
