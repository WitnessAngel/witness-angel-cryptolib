from pathlib import Path
from uuid import UUID

import pytest

from wacryptolib.authenticator import initialize_authenticator, is_authenticator_initialized, load_authenticator_metadata


def test_authenticator_basic_workflow(tmp_path):

    assert tmp_path.exists()

    wrong_path = tmp_path / "subfolder1" / "subsubfolder1"
    assert not is_authenticator_initialized(wrong_path)
    with pytest.raises(FileNotFoundError):
        initialize_authenticator(wrong_path, user="myuser")  # Too many missing parent folders
    with pytest.raises(FileNotFoundError):
        load_authenticator_metadata(wrong_path)

    acceptable_path1 = tmp_path / "subfolder2"
    acceptable_path2 = tmp_path / "subfolder3"
    acceptable_path2.mkdir()

    for idx, acceptable_path in enumerate([acceptable_path1, acceptable_path2]):
        assert not is_authenticator_initialized(acceptable_path)
        initialize_authenticator(acceptable_path, user="myuserX%s" % idx)  # Too many missing parent folders
        is_authenticator_initialized(acceptable_path)
        metadata = load_authenticator_metadata(acceptable_path)
        assert isinstance(metadata["device_uid"], UUID)
        assert metadata["user"] == "myuserX%s" % idx

