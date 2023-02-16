from wacryptolib.cryptainer import check_cryptoconf_sanity, encrypt_payload_into_cryptainer, check_cryptainer_sanity, \
    decrypt_payload_from_cryptainer
from wacryptolib.keystore import KeystorePoolBase
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes


# ENCRYPTION-DECRYPTION OPERATIONS


def encrypt_payload_to_bytes(payload: bytes, cryptoconf: dict, keystore_pool: KeystorePoolBase) -> bytes:
    check_cryptoconf_sanity(cryptoconf)

    cryptainer = encrypt_payload_into_cryptainer(
        payload, cryptoconf=cryptoconf, cryptainer_metadata=None, keystore_pool=keystore_pool
    )

    cryptainer_bytes = dump_to_json_bytes(cryptainer, indent=4)
    return cryptainer_bytes


def decrypt_payload_from_bytes(cryptainer_bytes: bytes, keystore_pool: KeystorePoolBase) -> tuple:
    cryptainer = load_from_json_bytes(cryptainer_bytes)
    check_cryptainer_sanity(cryptainer)

    payload, error_report = decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)
    return payload, error_report  # Payload might be None




























# FOREIGN-KEYSTORE OPERATIONS































# OTHER OPERATIONS


































##