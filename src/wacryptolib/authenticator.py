import logging
from sys import platform as sys_platform
from pathlib import Path
from pathlib import PurePath
from typing import Optional

from wacryptolib.utilities import dump_to_json_file, load_from_json_file, generate_uuid0


logger = logging.getLogger(__name__)


def initialize_authenticator(authenticator_dir: Path, authenticator_owner: str, extra_metadata: Optional[dict] = None) -> dict:
    """
    Initialize a specific folder, by creating an internal structure with keys and their metadata.

    The folder must not be already initialized.
    It may not exist yet, but its parents must exist.

    :param authenticator_dir: (Path) Folder where the metadata file is expected.
    :param authenticator_owner: (str) owner name to store in device.

    :return: (dict) Metadata for this authenticator.
    """
    extra_metadata = extra_metadata or {}

    assert authenticator_owner and isinstance(authenticator_owner, str), authenticator_owner
    assert not extra_metadata or isinstance(extra_metadata, dict), extra_metadata

    if is_authenticator_initialized(authenticator_dir):
        raise RuntimeError("Authenticator at path %s is already initialized" % authenticator_dir)

    metadata = _do_initialize_authenticator(authenticator_dir=authenticator_dir, authenticator_owner=authenticator_owner, extra_metadata=extra_metadata)
    return metadata


def _do_initialize_authenticator(authenticator_dir: Path, authenticator_owner: str, extra_metadata: dict):
    assert isinstance(authenticator_owner, str) and authenticator_owner, repr(authenticator_owner)
    metadata_file = _get_metadata_file_path(authenticator_dir)
    metadata_file.parent.mkdir(parents=False, exist_ok=True)  # Only LAST directory might be created
    metadata = extra_metadata.copy()
    metadata.update({"authenticator_version": "authenticator_1.0",   # Might be useful later
                     "authenticator_uid": generate_uuid0(),
                     "authenticator_owner": authenticator_owner})  # Overrides these keys if present!
    dump_to_json_file(metadata_file, metadata)
    return metadata


def is_authenticator_initialized(authenticator_dir: Path):
    """
    Check if an authenticator folder seems initialized.

    Doesn't actually load the authenticator metadata.

    :param authenticator_dir: (Path) folder where the metadata file is expected.

    :return: (bool) True if and only if the authenticator is initialized.
    """
    metadata_file = _get_metadata_file_path(authenticator_dir)
    return metadata_file.is_file()


def load_authenticator_metadata(authenticator_dir: Path) -> dict:
    """
    Return the authenticator metadata stored in the given folder, after checking that it contains at least mandatory
    (authenticator_owner and authenticator_uid) fields.

    Raises `ValueError` or json decoding exceptions if device appears initialized, but has corrupted metadata.
    """
    metadata_file = _get_metadata_file_path(authenticator_dir)

    metadata = load_from_json_file(metadata_file)

    _check_authdevice_metadata(metadata)  # Raises if troubles
    return metadata


def _check_authdevice_metadata(metadata: dict):  # FIXME use python-schema instead!!!
    if not (
        isinstance(metadata, dict) and metadata.get("authenticator_owner") and metadata.get("authenticator_uid")
    ):  # Only lightweight checkup for now
        raise ValueError("Abnormal key device metadata: %s" % str(metadata))


def _get_metadata_file_path(authenticator_dir: Path):
    """
    Return path of standard metadata file for key/cryptainer storage.
    """
    return authenticator_dir.joinpath(".metadata.json")
