from wacryptolib.cryptainer import check_cryptoconf_sanity, encrypt_payload_into_cryptainer
from wacryptolib.keystore import KeystorePoolBase
from wacryptolib.utilities import dump_to_json_bytes


# ENCRYPTION-DECRYPTION OPERATIONS


def encrypt_payload_to_bytes(payload: bytes, cryptoconf: dict, keystore_pool: KeystorePoolBase) -> bytes:

    check_cryptoconf_sanity(cryptoconf)

    cryptainer = encrypt_payload_into_cryptainer(
        payload, cryptoconf=cryptoconf, cryptainer_metadata=None, keystore_pool=keystore_pool
    )

    cryptainer_bytes = dump_to_json_bytes(cryptainer, indent=4)
    return cryptainer_bytes






























# FOREIGN-KEYSTORE OPERATIONS































# OTHER OPERATIONS


































##