import logging
from sys import platform as sys_platform
from pathlib import Path
from pathlib import PurePath
from typing import Optional

from wacryptolib.keystore import _validate_keystore_metadata, _get_keystore_metadata_file_path
from wacryptolib.utilities import dump_to_json_file, generate_uuid0


logger = logging.getLogger(__name__)


def initialize_authenticator(authenticator_dir: Path, keystore_owner: str, extra_metadata: Optional[dict] = None) -> dict:
    """
    Initialize a specific folder, by creating an internal structure with keys and their metadata.

    The folder must not be already initialized.
    It may not exist yet, but its parents must exist.

    :param authenticator_dir: (Path) Folder where the metadata file is expected.
    :param keystore_owner: (str) owner name to store in device.

    :return: (dict) Metadata for this authenticator.
    """
    extra_metadata = extra_metadata or {}

    assert keystore_owner and isinstance(keystore_owner, str), keystore_owner
    assert not extra_metadata or isinstance(extra_metadata, dict), extra_metadata

    if is_authenticator_initialized(authenticator_dir):
        raise RuntimeError("Authenticator at path %s is already initialized" % authenticator_dir)

    metadata = _do_initialize_authenticator(authenticator_dir=authenticator_dir, keystore_owner=keystore_owner, extra_metadata=extra_metadata)
    return metadata


def _do_initialize_authenticator(authenticator_dir: Path, keystore_owner: str, extra_metadata: dict):
    assert isinstance(keystore_owner, str) and keystore_owner, repr(keystore_owner)
    metadata_file = _get_keystore_metadata_file_path(authenticator_dir)
    metadata_file.parent.mkdir(parents=False, exist_ok=True)  # Only LAST directory might be created
    metadata = extra_metadata.copy()
    metadata.update({"keystore_type": "authenticator",
                     "keystore_format": 'keystore_1.0',
                     "keystore_uid": generate_uuid0(),
                     "keystore_owner": keystore_owner})  # Overrides these keys if present!
    _validate_keystore_metadata(metadata)  # Ensure no weird metadata is added!
    dump_to_json_file(metadata_file, metadata)
    return metadata


# TODO go farther, and add flags to report errors if json or RSA keys are missing/corrupted?
def is_authenticator_initialized(authenticator_dir: Path):
    """
    Check if an authenticator folder seems initialized.

    Doesn't actually load the authenticator metadata.

    :param authenticator_dir: (Path) folder where the metadata file is expected.

    :return: (bool) True if and only if the authenticator is initialized.
    """
    metadata_file = _get_keystore_metadata_file_path(authenticator_dir)
    return metadata_file.is_file()
