import logging
import secrets
from pathlib import Path

from wacryptolib.exceptions import KeystoreAlreadyExists
from wacryptolib.keystore import validate_keystore_metadata, _get_keystore_metadata_file_path, KEYSTORE_FORMAT
from wacryptolib.utilities import dump_to_json_file, generate_uuid0

logger = logging.getLogger(__name__)


def initialize_authenticator(authenticator_dir: Path, keystore_owner: str, keystore_passphrase_hint: str) -> dict:
    """
    BEWARE - PRIVATE API FOR NOW

    Initialize a specific folder, by creating an internal structure with keys and their metadata.

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

    # FIXME - do HERE the creation of digital keypairs!!!


def _initialize_authenticator_metadata(authenticator_dir: Path, keystore_owner: str, keystore_passphrase_hint: str):
    metadata_file = _get_keystore_metadata_file_path(authenticator_dir)
    assert not metadata_file.exists(), metadata_file
    metadata_file.parent.mkdir(parents=False, exist_ok=True)  # Only LAST directory might be created
    metadata = {
        "keystore_type": "authenticator",
        "keystore_format": KEYSTORE_FORMAT,
        "keystore_uid": generate_uuid0(),
        "keystore_owner": keystore_owner,
        "keystore_passphrase_hint": keystore_passphrase_hint,
        "keystore_secret": secrets.token_urlsafe(64),
    }
    validate_keystore_metadata(metadata)  # Ensure no weird metadata is added!
    dump_to_json_file(metadata_file, metadata)
    return metadata


# TODO go farther, and add flags to report errors if JSON or RSA keys are missing/corrupted?
def is_authenticator_initialized(authenticator_dir: Path):
    """
    BEWARE - PRIVATE API FOR NOW

    Check if an authenticator folder seems initialized.

    Doesn't actually load the authenticator metadata.

    :param authenticator_dir: (Path) folder where the metadata file is expected.

    :return: (bool) True if and only if the authenticator is initialized.
    """
    metadata_file = _get_keystore_metadata_file_path(authenticator_dir)
    return metadata_file.is_file()
