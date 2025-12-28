import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

from flightbox import SHARED_SECRET_ALGO_MARKER, FlightBox
from flightbox_utilities_implementation import FlightboxUtilitiesImpl, AUTHENTICATOR_TRUSTEE


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


_public_key_pem_from_wacryptolib = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkvHRJ3KYCiNsjFGBQOJT
Rbx4W/WJ7f5N8Jn+yKW08y/9ERMkcM9imqRDVr5oYMTvKxyxVSsWj39ClhOojTGG
ZdlT6vgwtKgi7yHniUED6yxaABs60kIMF6W2CfS0RCtZY5LjVQpPhxmX3fy1g6n+
MJ0Y9PvGWVqDaBnoCFm4t17n2YKqzKLSO13HZwEnpisV14cxwSuK/0x8hjwRZkod
rFWPt+e1iCtqr+a0y5pQjZkSS1LY6BDsVz83vkoGUqsDnyQ+v4fuc3vklX9Z91Dx
dSnSbxX8IwJJ7kQEUi3O/kO7bGPTmcWbRAuYbH/6rFkMafVcgeaLBZG6h3CGR6nH
IwIDAQAB
-----END PUBLIC KEY-----"""

KEYSTORE_DATA = {
    TRUSTEE_UID_1: {
        KEYCHAIN_UID_1: _public_key_pem_from_wacryptolib
    }
}

_fbutils = FlightboxUtilitiesImpl(logger=logger, keystore_data=KEYSTORE_DATA)
flightbox = FlightBox(flightbox_utilities=_fbutils)

cryptainer, secrets = flightbox.generate_cryptainer_base_and_secrets(
            cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_metadata=dict(SOME_METADATA=2726562425242)
        )

print("CRYPTAINER:\n", cryptainer)
print()
print("SECRETS:\n", secrets)
