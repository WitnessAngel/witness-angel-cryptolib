import logging

from wacryptolib.authdevice import list_available_authdevices
from wacryptolib.authenticator import SENSITIVE_KEYSTORE_FIELDS, is_authenticator_initialized
from wacryptolib.cryptainer import check_cryptoconf_sanity, encrypt_payload_into_cryptainer, check_cryptainer_sanity, \
    decrypt_payload_from_cryptainer
from wacryptolib.exceptions import SchemaValidationError, ValidationError
from wacryptolib.keystore import KeystorePoolBase, ReadonlyFilesystemKeystore
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes


logger = logging.getLogger(__name__)


def ___encrypt_payload_to_bytes(payload: bytes, cryptoconf: dict, keystore_pool: KeystorePoolBase) -> bytes:
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


def import_keystores_from_initialized_authdevices(keystore_pool, include_private_keys: bool):

    authdevices = list_available_authdevices()
    authdevices_initialized = [x for x in authdevices if is_authenticator_initialized(x["authenticator_dir"])]

    foreign_keystore_metadata = []
    already_existing_keystore_metadata = []
    corrupted_keystore_count = 0

    for authdevice in authdevices_initialized:

        remote_keystore_dir = authdevice["authenticator_dir"]

        try:
            remote_keystore = ReadonlyFilesystemKeystore(remote_keystore_dir)
            keystore_tree = remote_keystore.export_to_keystore_tree(include_private_keys=include_private_keys)

            # Special operation: we remove optional sensitive data from this "foreign" keystore...
            for sensitive_key in SENSITIVE_KEYSTORE_FIELDS:
                if sensitive_key in keystore_tree:
                    del keystore_tree[sensitive_key]

        except ValidationError as exc:
            corrupted_keystore_count += 1
            continue

        try:

            updated = keystore_pool.import_foreign_keystore_from_keystore_tree(keystore_tree)

            keystore_metadata = keystore_tree.copy()
            del keystore_metadata["keypairs"]

            if updated:
                already_existing_keystore_metadata.append(keystore_metadata)
            else:
                foreign_keystore_metadata.append(keystore_metadata)

        except ValidationError:  # Mismatch between keystore UIDs
            corrupted_keystore_count += 1

    return dict(
        foreign_keystore_count=len(foreign_keystore_metadata),
        already_existing_keystore_count=len(already_existing_keystore_metadata),
        corrupted_keystore_count=corrupted_keystore_count,
    )
