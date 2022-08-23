from datetime import datetime
from uuid import UUID

import pytest

from wacryptolib.authenticator import initialize_authenticator, is_authenticator_initialized
from wacryptolib.exceptions import ValidationError, KeystoreAlreadyExists, KeystoreDoesNotExist
from wacryptolib.keystore import load_keystore_metadata, _get_keystore_metadata_file_path, \
    _get_legacy_keystore_metadata_file_path, KEYSTORE_FORMAT
from wacryptolib.utilities import generate_uuid0, dump_to_json_bytes


def test_authenticator_basic_workflow(tmp_path):
    assert tmp_path.exists()

    wrong_dir = tmp_path / "subfolder1" / "subsubfolder1"
    assert not is_authenticator_initialized(wrong_dir)
    with pytest.raises(FileNotFoundError):
        # Too many missing parent folders
        initialize_authenticator(wrong_dir, keystore_owner="myuser", keystore_passphrase_hint="stuffs")
    with pytest.raises(KeystoreDoesNotExist):
        load_keystore_metadata(wrong_dir)
    assert not is_authenticator_initialized(wrong_dir)

    acceptable_path1 = tmp_path / "subfolder2"
    acceptable_path2 = tmp_path / "subfolder3"
    acceptable_path2.mkdir()  # Directory already exists on this one only

    for idx, acceptable_dir in enumerate([acceptable_path1, acceptable_path2]):

        assert not is_authenticator_initialized(acceptable_dir)
        with pytest.raises(KeystoreDoesNotExist):
            load_keystore_metadata(acceptable_dir)  # Not initialized yet!

        initialize_authenticator(acceptable_dir, keystore_owner="myuserX%s" % idx, keystore_passphrase_hint="Some hïnt")
        assert is_authenticator_initialized(acceptable_dir)

        with pytest.raises(KeystoreAlreadyExists):
            initialize_authenticator(acceptable_dir, keystore_owner="sdsdfsfxx", keystore_passphrase_hint="ze zsddqs")

        metadata = load_keystore_metadata(acceptable_dir)
        assert len(metadata) == 7
        assert metadata["keystore_type"] == "authenticator"
        assert isinstance(metadata["keystore_uid"], UUID)
        assert metadata["keystore_owner"] == "myuserX%s" % idx
        assert metadata["keystore_format"] == "keystore_1.0"
        assert metadata["keystore_passphrase_hint"] == "Some hïnt"
        assert isinstance(metadata["keystore_secret"], str)
        assert isinstance(metadata["keystore_creation_datetime"], datetime)

        keystore_metadata_file_path = _get_keystore_metadata_file_path(acceptable_dir)

        for wrong_payload in (b"abc", b'{"a": "b"}'):  # Corrupted Json file, or Json schema
            keystore_metadata_file_path.write_bytes(wrong_payload)
            assert is_authenticator_initialized(acceptable_dir)  # Still seen as "initialized"
            with pytest.raises(ValidationError):
                load_keystore_metadata(acceptable_dir)


def test_authenticator_metadata_backward_compatibility(tmp_path):
    acceptable_path = tmp_path / "subfolder"
    assert not is_authenticator_initialized(acceptable_path)

    # initialize metadata in .keystore.json
    legacy_metadata_file_path = _get_legacy_keystore_metadata_file_path(acceptable_path)
    legacy_metadata_file_path.parent.mkdir(parents=False, exist_ok=True)

    legacy_metadata = {
        "keystore_type": "authenticator",
        "keystore_format": KEYSTORE_FORMAT,
        "keystore_uid": generate_uuid0(),
        "keystore_owner": "keystore_owner",
        "keystore_passphrase_hint": "This is a hint",
        "keystore_secret": "keystore_secret",
        "keystore_creation_datetime": datetime.now()
    }
    legacy_metadata_bytes = dump_to_json_bytes(legacy_metadata)
    legacy_metadata_file_path.write_bytes(legacy_metadata_bytes)

    with pytest.raises(KeystoreAlreadyExists):
        initialize_authenticator(acceptable_path, keystore_owner="myuser", keystore_passphrase_hint="hïnt")

    metadata = load_keystore_metadata(acceptable_path)

    assert len(metadata) == 7
    assert metadata["keystore_type"] == "authenticator"
    assert isinstance(metadata["keystore_uid"], UUID)
    assert metadata["keystore_owner"] == "keystore_owner"
    assert metadata["keystore_format"] == "keystore_1.0"
    assert metadata["keystore_passphrase_hint"] == "This is a hint"
    assert metadata["keystore_secret"] == "keystore_secret"
    assert isinstance(metadata["keystore_secret"], str)
    assert isinstance(metadata["keystore_creation_datetime"], datetime)
