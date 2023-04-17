import logging

from wacryptolib.authdevice import list_available_authdevices
from wacryptolib.authenticator import SENSITIVE_KEYSTORE_FIELDS, is_authenticator_initialized
from wacryptolib.cryptainer import (
    check_cryptoconf_sanity,
    encrypt_payload_into_cryptainer,
    check_cryptainer_sanity,
    decrypt_payload_from_cryptainer,
)
from wacryptolib.exceptions import ValidationError
from wacryptolib.jsonrpc_client import JsonRpcProxy
from wacryptolib.keystore import KeystorePoolBase, ReadonlyFilesystemKeystore, KEYSTORE_FORMAT, validate_keystore_tree
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes

logger = logging.getLogger(__name__)


def ___encrypt_payload_to_bytes(payload: bytes, cryptoconf: dict, keystore_pool: KeystorePoolBase) -> bytes:
    check_cryptoconf_sanity(cryptoconf)

    cryptainer = encrypt_payload_into_cryptainer(
        payload, cryptoconf=cryptoconf, cryptainer_metadata=None, keystore_pool=keystore_pool
    )
    cryptainer_bytes = dump_to_json_bytes(cryptainer, indent=4)
    return cryptainer_bytes


def ___decrypt_payload_from_bytes(
    cryptainer_bytes: bytes, keystore_pool: KeystorePoolBase, passphrase_mapper=None
) -> tuple:  # FIXME useless?
    cryptainer = load_from_json_bytes(cryptainer_bytes)
    check_cryptainer_sanity(cryptainer)

    payload, error_report = decrypt_payload_from_cryptainer(
        cryptainer, keystore_pool=keystore_pool, passphrase_mapper=passphrase_mapper
    )
    return payload, error_report  # Payload might be None


def import_keystore_from_path(keystore_pool, keystore_path, include_private_keys: bool):
    """Might raise ValidationError while loading remote keystore, or while importing it
    (if mismatch between keystore UIDs).

    Returns True iff keystore was updated instead of created.
    """

    remote_keystore = ReadonlyFilesystemKeystore(keystore_path)
    keystore_tree = remote_keystore.export_to_keystore_tree(include_private_keys=include_private_keys)

    # Special operation: we remove optional sensitive data from this "foreign" keystore...
    for sensitive_key in SENSITIVE_KEYSTORE_FIELDS:
        if sensitive_key in keystore_tree:
            del keystore_tree[sensitive_key]

    updated = keystore_pool.import_foreign_keystore_from_keystore_tree(keystore_tree)

    keystore_metadata = _extract_metadata_from_keystore_tree(keystore_tree)

    return keystore_metadata, updated


def import_keystores_from_initialized_authdevices(keystore_pool, include_private_keys: bool):
    authdevices = list_available_authdevices()
    authdevices_initialized = [x for x in authdevices if is_authenticator_initialized(x["authenticator_dir"])]

    foreign_keystore_metadata = []
    already_existing_keystore_metadata = []
    corrupted_keystore_count = 0

    for authdevice in authdevices_initialized:
        remote_keystore_dir = authdevice["authenticator_dir"]

        try:
            keystore_metadata, updated = import_keystore_from_path(
                keystore_pool, keystore_path=remote_keystore_dir, include_private_keys=include_private_keys
            )
        except ValidationError as exc:
            corrupted_keystore_count += 1
            continue

        if updated:
            already_existing_keystore_metadata.append(keystore_metadata)
        else:
            foreign_keystore_metadata.append(keystore_metadata)

    return dict(
        foreign_keystore_count=len(foreign_keystore_metadata),
        already_existing_keystore_count=len(already_existing_keystore_metadata),
        corrupted_keystore_count=corrupted_keystore_count,
    )


def _extract_metadata_from_keystore_tree(keystore_tree):
    keystore_metadata = keystore_tree.copy()
    del keystore_metadata["keypairs"]
    return keystore_metadata


def _convert_public_authenticator_to_keystore_tree(public_authenticator) -> dict:
    keypairs = []

    for public_key in public_authenticator["public_keys"]:
        keypairs.append(
            dict(
                keychain_uid=public_key["keychain_uid"],
                key_algo=public_key["key_algo"],
                public_key=public_key["key_value"],
                private_key=None,  # FIXME invalid??
            )
        )

    keystore_tree = {
        "keystore_type": "authenticator",
        "keystore_format": KEYSTORE_FORMAT,
        "keystore_owner": public_authenticator["keystore_owner"],
        "keystore_uid": public_authenticator["keystore_uid"],
        "keypairs": keypairs,
    }
    if public_authenticator["keystore_creation_datetime"]:  # NULLABLE
        keystore_tree["keystore_creation_datetime"] = public_authenticator["keystore_creation_datetime"]

    # No confidential fields, like passphrase hint or keystore secret, are present in public authenticator!
    validate_keystore_tree(keystore_tree)  # SAFETY
    return keystore_tree


def import_keystore_from_web_gateway(keystore_pool, gateway_url, keystore_uid) -> tuple:
    gateway_proxy = JsonRpcProxy(url=gateway_url)

    public_authenticator = gateway_proxy.get_public_authenticator(keystore_uid=keystore_uid)

    keystore_tree = _convert_public_authenticator_to_keystore_tree(public_authenticator)

    updated = keystore_pool.import_foreign_keystore_from_keystore_tree(keystore_tree)

    keystore_metadata = _extract_metadata_from_keystore_tree(keystore_tree)

    return keystore_metadata, updated
