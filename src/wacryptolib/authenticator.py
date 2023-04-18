import logging
import secrets
from pathlib import Path

from wacryptolib.exceptions import KeystoreAlreadyExists
from wacryptolib.keystore import (
    validate_keystore_metadata,
    _get_keystore_metadata_file_path,
    KEYSTORE_FORMAT,
    _get_legacy_keystore_metadata_file_path,
)
from wacryptolib.utilities import dump_to_json_file, generate_uuid0, get_utc_now_date

logger = logging.getLogger(__name__)


SENSITIVE_KEYSTORE_FIELDS = ["keystore_secret", "keystore_passphrase_hint"]


def initialize_authenticator(authenticator_dir: Path, keystore_owner: str, keystore_passphrase_hint: str) -> dict:
    """
    BEWARE - PRIVATE API FOR NOW

    Initialize a specific folder by creating a metadata file in it.

    The folder must not be already initialized.
    It may not exist yet, but its parents must exist.

    :param authenticator_dir: Folder where the metadata file is expected.
    :param keystore_owner: owner name to store in device.
    :param keystore_passphrase_hint: hint for the passphrase used on private keys.

    :return: (dict) Metadata for this authenticator.
    """

    if is_authenticator_initialized(authenticator_dir):
        raise KeystoreAlreadyExists("Authenticator at path %s is already initialized" % authenticator_dir)

    metadata = _initialize_authenticator_metadata(
        authenticator_dir=authenticator_dir,
        keystore_owner=keystore_owner,
        keystore_passphrase_hint=keystore_passphrase_hint,
    )
    return metadata


def _initialize_authenticator_metadata(authenticator_dir: Path, keystore_owner: str, keystore_passphrase_hint: str):
    legacy_metadata_file = _get_legacy_keystore_metadata_file_path(authenticator_dir)
    assert not legacy_metadata_file.exists(), legacy_metadata_file
    metadata_file = _get_keystore_metadata_file_path(authenticator_dir)
    assert not metadata_file.exists(), metadata_file
    metadata_file.parent.mkdir(parents=False, exist_ok=True)  # Only LAST directory might be created
    metadata = {
        "keystore_type": "authenticator",
        "keystore_format": KEYSTORE_FORMAT,
        "keystore_uid": generate_uuid0(),
        "keystore_owner": keystore_owner,
        "keystore_passphrase_hint": keystore_passphrase_hint,
        "keystore_secret": secrets.token_urlsafe(64),  # Recent field
        "keystore_creation_datetime": get_utc_now_date(),  # Recent field
    }
    validate_keystore_metadata(metadata)  # Ensure no weird metadata is added!
    dump_to_json_file(metadata_file, metadata)
    return metadata


def is_authenticator_initialized(authenticator_dir: Path):
    """
    BEWARE - PRIVATE API FOR NOW

    Check if an authenticator folder SEEMS initialized.

    Doesn't actually load the authenticator metadata file, nor check related keypairs.

    :param authenticator_dir: (Path) folder where the metadata file is expected.

    :return: (bool) True if and only if the authenticator seems initialized.
    """
    legacy_metadata_file = _get_legacy_keystore_metadata_file_path(authenticator_dir)
    metadata_file = _get_keystore_metadata_file_path(authenticator_dir)
    is_initialized = False
    if legacy_metadata_file.is_file() or metadata_file.is_file():
        is_initialized = True
    return is_initialized
