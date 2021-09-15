import logging
from sys import platform as sys_platform
from pathlib import Path
from pathlib import PurePath
from typing import Optional

from wacryptolib.utilities import dump_to_json_file, load_from_json_file, get_metadata_file_path, generate_uuid0


logger = logging.getLogger(__name__)


def initialize_authenticator(authenticator_path: Path, user: str, extra_metadata: Optional[dict] = None) -> dict:
    """
    Initialize a specific folder, by creating an internal structure with keys and their metadata.

    The folder must not be already initialized.
    It may not exist yet, but its parents must exist.

    :param authenticator_path: (Path) Folder where the metadata file is expected.
    :param user: (str) User name to store in device.

    :return: (dict) Metadata for this authenticator.
    """
    extra_metadata = extra_metadata or {}

    assert user and isinstance(user, str), user
    assert not extra_metadata or isinstance(extra_metadata, dict), extra_metadata

    if is_authenticator_initialized(authenticator_path):
        raise RuntimeError("Authenticator at path %s is already initialized" % authenticator_path)

    metadata = _do_initialize_authenticator(authenticator_path=authenticator_path, user=user, extra_metadata=extra_metadata)
    return metadata


def _do_initialize_authenticator(authenticator_path: Path, user: str, extra_metadata: dict):
    assert isinstance(user, str) and user, repr(user)
    metadata_file = get_metadata_file_path(authenticator_path)
    metadata_file.parent.mkdir(parents=False, exist_ok=True)  # Only LAST directory might be created
    metadata = extra_metadata.copy()
    metadata.update({"device_uid": generate_uuid0(), "user": user})  # Override these keys if present!
    dump_to_json_file(metadata_file, metadata)
    return metadata


def is_authenticator_initialized(authenticator_path: Path):
    """
    Check if an authenticator folder seems initialized.

    Doesn't actually load the authenticator metadata.

    :param authenticator_path: (Path) folder where the metadata file is expected.

    :return: (bool) True if and only if the authenticator is initialized.
    """
    metadata_file = get_metadata_file_path(authenticator_path)
    return metadata_file.is_file()


def load_authenticator_metadata(authenticator_path: Path) -> dict:
    """
    Return the authenticator metadata stored in the given folder, after checking that it contains at least mandatory
    (user and device_uid) fields.

    Raises `ValueError` or json decoding exceptions if device appears initialized, but has corrupted metadata.
    """
    metadata_file = get_metadata_file_path(authenticator_path)

    metadata = load_from_json_file(metadata_file)

    _check_authentication_device_metadata(metadata)  # Raises if troubles
    return metadata


def _check_authentication_device_metadata(metadata: dict):
    if not (
        isinstance(metadata, dict) and metadata.get("user") and metadata.get("device_uid")
    ):  # Only lightweight checkup for now
        raise ValueError("Abnormal key device metadata: %s" % str(metadata))
