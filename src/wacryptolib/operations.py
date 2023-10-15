import logging
import shutil
from pathlib import Path

from wacryptolib.authdevice import list_available_authdevices
from wacryptolib.authenticator import SENSITIVE_KEYSTORE_FIELDS, is_authenticator_initialized, initialize_authenticator
from wacryptolib.cryptainer import (
    check_cryptoconf_sanity,
    encrypt_payload_into_cryptainer,
    check_cryptainer_sanity,
    decrypt_payload_from_cryptainer,
)
from wacryptolib.exceptions import ValidationError, KeyLoadingError
from wacryptolib.jsonrpc_client import JsonRpcProxy
from wacryptolib.keygen import generate_keypair, load_asymmetric_key_from_pem_bytestring
from wacryptolib.keystore import (
    KeystorePoolBase,
    ReadonlyFilesystemKeystore,
    KEYSTORE_FORMAT,
    validate_keystore_tree,
    FilesystemKeystore,
    load_keystore_metadata,
)
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes, generate_uuid0

logger = logging.getLogger(__name__)


def _check_target_authenticator_parameters_validity(authenticator_dir, keypair_count, exception_cls=ValidationError):
    if authenticator_dir.is_dir():
        raise exception_cls("Target directory %s must not exist yet" % authenticator_dir)

    authenticator_dir_parent = authenticator_dir.parent
    if not authenticator_dir_parent.is_dir():
        raise exception_cls("Parent directory %s must already exist" % authenticator_dir_parent)

    if keypair_count < 1:
        raise exception_cls("At least 1 keypair must be created")


def create_authenticator(
    authenticator_dir: Path,
    keypair_count: int,
    keystore_owner: str,
    keystore_passphrase_hint: str,
    keystore_passphrase: str,
):
    _check_target_authenticator_parameters_validity(authenticator_dir, keypair_count=keypair_count)
    assert keypair_count >= 1, keypair_count

    authenticator_dir.mkdir(parents=False)  # Only 1 level of folder will be created here!
    assert authenticator_dir and authenticator_dir.is_dir(), authenticator_dir

    # We initialize FIRST, to avoid troubles on retry, if process gets interrupted
    logger.debug("Initializing authenticator directory %s", authenticator_dir)
    initialize_authenticator(
        authenticator_dir,
        keystore_owner=keystore_owner,
        keystore_passphrase_hint=keystore_passphrase_hint,
    )

    filesystem_keystore = FilesystemKeystore(authenticator_dir)

    key_algo = "RSA_OAEP"  # No choice for now
    keychain_uids = []

    try:
        for i in range(1, keypair_count + 1):
            logger.debug("Generating %s keypair %d into directory %s", (key_algo, i, authenticator_dir))
            new_key_pair = generate_keypair(key_algo=key_algo, passphrase=keystore_passphrase)
            new_keychain_uid = generate_uuid0()
            keychain_uids.append(new_keychain_uid)

            filesystem_keystore.set_keypair(
                keychain_uid=new_keychain_uid,
                key_algo=key_algo,
                public_key=new_key_pair["public_key"],
                private_key=new_key_pair["private_key"],
            )
    except Exception as exc:
        logger.warning(
            "Exception encountered while creating authenticator keypairs, deleting authenticator %s", authenticator_dir
        )
        delete_authenticator(authenticator_dir)  # Shouldn't raise, since we just initialized authenticator above
        raise


def check_authenticator(authenticator_dir: Path, keystore_passphrase: str):  # FIXME rename to validate_xx
    authenticator_metadata = load_keystore_metadata(authenticator_dir)  # Might raise SchemaValidationError

    filesystem_keystore = ReadonlyFilesystemKeystore(authenticator_dir)
    metadata = filesystem_keystore.get_keystore_metadata(include_keypair_identifiers=True)
    keypair_identifiers = metadata["keypair_identifiers"]
    missing_private_keys = []
    undecodable_private_keys = []

    for key_information in keypair_identifiers:
        key_algo = key_information["key_algo"]
        keychain_uid = key_information["keychain_uid"]
        keypair_identifier = (key_algo, keychain_uid)

        if not key_information["private_key_present"]:
            missing_private_keys.append(keypair_identifier)
            continue
        private_key_pem = filesystem_keystore.get_private_key(keychain_uid=keychain_uid, key_algo=key_algo)
        try:
            key_obj = load_asymmetric_key_from_pem_bytestring(
                key_pem=private_key_pem, key_algo=key_algo, passphrase=keystore_passphrase
            )
            assert key_obj, key_obj
        except KeyLoadingError:
            undecodable_private_keys.append(keypair_identifier)

    return dict(
        authenticator_metadata=authenticator_metadata,
        keypair_identifiers=keypair_identifiers,
        missing_private_keys=missing_private_keys,
        undecodable_private_keys=undecodable_private_keys,
    )


def delete_authenticator(authenticator_dir: Path):
    """Deletion works even if authenticator metadata are corrupted, but the metadata file must be present."""
    if not is_authenticator_initialized(authenticator_dir):
        raise ValidationError("Directory %s is not an initialized authenticator" % authenticator_dir)
    shutil.rmtree(authenticator_dir)  # VIOLENT


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

    payload = decrypt_payload_from_cryptainer(
        cryptainer, keystore_pool=keystore_pool, passphrase_mapper=passphrase_mapper
    )
    return payload  # Payload might be None


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
