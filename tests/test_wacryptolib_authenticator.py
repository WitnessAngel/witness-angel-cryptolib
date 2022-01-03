from pathlib import Path
from uuid import UUID

import pytest

from wacryptolib.authenticator import initialize_authenticator, is_authenticator_initialized
from wacryptolib.keystore import load_keystore_metadata


def test_authenticator_basic_workflow(tmp_path):

    assert tmp_path.exists()

    wrong_dir = tmp_path / "subfolder1" / "subsubfolder1"
    assert not is_authenticator_initialized(wrong_dir)
    with pytest.raises(FileNotFoundError):
        initialize_authenticator(wrong_dir, keystore_owner="myuser")  # Too many missing parent folders
    with pytest.raises(FileNotFoundError):
        load_keystore_metadata(wrong_dir)

    acceptable_path1 = tmp_path / "subfolder2"
    acceptable_path2 = tmp_path / "subfolder3"
    acceptable_path2.mkdir()

    for idx, acceptable_path in enumerate([acceptable_path1, acceptable_path2]):
        assert not is_authenticator_initialized(acceptable_path)
        initialize_authenticator(acceptable_path, keystore_owner="myuserX%s" % idx)  # Too many missing parent folders
        is_authenticator_initialized(acceptable_path)
        metadata = load_keystore_metadata(acceptable_path)
        assert len(metadata) == 4
        assert metadata["keystore_type"] == "authenticator"
        assert isinstance(metadata["keystore_uid"], UUID)
        assert metadata["keystore_owner"] == "myuserX%s" % idx
        assert metadata["keystore_format"] == 'keystore_1.0'
