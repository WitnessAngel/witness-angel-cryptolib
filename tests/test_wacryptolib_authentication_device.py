from pathlib import Path
from uuid import UUID

from _test_mockups import get_fake_authentication_device
from wacryptolib.authentication_device import (
    list_available_authentication_devices,
    is_authentication_device_initialized,
    _get_metadata_file_path,
)
from wacryptolib.authentication_device import initialize_authentication_device, load_authentication_device_metadata


def test_list_available_authentication_devices():  # FIXME add mockups to simulate real USB key?

    authentication_devices_list = list_available_authentication_devices()
    assert isinstance(authentication_devices_list, list)

    for authentication_device in authentication_devices_list:
        print(">> USB key detected:", authentication_device)
        assert isinstance(authentication_device, dict) or isinstance(authentication_device, None)

        assert isinstance(authentication_device["drive_type"], str)  # UNDOCUMENTED FIELD
        assert authentication_device["drive_type"] == "USBSTOR"

        assert isinstance(authentication_device["path"], str)
        assert Path(authentication_device["path"]).exists()

        assert isinstance(authentication_device["label"], str)  # Might be empty

        assert isinstance(authentication_device["format"], str)
        assert authentication_device["format"]

        assert isinstance(authentication_device["size"], int)
        assert authentication_device["size"] > 0

        assert isinstance(authentication_device["is_initialized"], bool)

        if authentication_device["metadata"]:
            assert isinstance(authentication_device["metadata"]["user"], str)  # Might be empty
            assert isinstance(authentication_device["metadata"]["device_uid"], (type(None), UUID))  # Might be empty


def test_authentication_device_initialization_and_checkers(tmp_path):

    authentication_device = get_fake_authentication_device(tmp_path)
    authentication_device_original = authentication_device.copy()

    assert not is_authentication_device_initialized(authentication_device)
    initialize_authentication_device(authentication_device, user="Michél Dûpont")
    assert is_authentication_device_initialized(authentication_device)

    # UNCHANGED fields
    assert authentication_device["drive_type"] == "USBSTOR"
    assert authentication_device["path"] == tmp_path
    assert authentication_device["label"] == "TOSHIBA"
    assert authentication_device["size"] == 31000166400
    assert authentication_device["format"] == "fat32"

    # UPDATED fields
    assert authentication_device["is_initialized"] == True
    assert len(authentication_device["metadata"]) == 2
    assert authentication_device["metadata"]["user"] == "Michél Dûpont"
    assert isinstance(authentication_device["metadata"]["device_uid"], UUID)

    # REAL metadata file content
    metadata = load_authentication_device_metadata(authentication_device)
    assert len(metadata) == 2
    assert metadata["user"] == "Michél Dûpont"
    assert isinstance(metadata["device_uid"], UUID)

    # We ensure the code doesn't do any weird shortcut
    authentication_device["is_initialized"] = False
    authentication_device["metadata"] = None  # Revert to original
    assert authentication_device == authentication_device_original
    metadata = load_authentication_device_metadata(authentication_device)
    assert authentication_device == authentication_device_original  # Untouched
    assert metadata["user"] == "Michél Dûpont"
    assert isinstance(metadata["device_uid"], UUID)

    assert is_authentication_device_initialized(authentication_device)
    metadata_file_path = _get_metadata_file_path(authentication_device)
    metadata_file_path.unlink()
    assert not is_authentication_device_initialized(authentication_device)
    metadata_file_path.write_text("ZJSJS")
    assert is_authentication_device_initialized(authentication_device)  # No checkup of json file here!

    # Test extra metadata

    metadata_file_path.unlink()
    assert not is_authentication_device_initialized(authentication_device)
    initialize_authentication_device(
        authentication_device, user="Johnny", extra_metadata=dict(passphrase_hint="big passphrâse \n aboùt bïrds")
    )
    assert is_authentication_device_initialized(authentication_device)

    metadata = load_authentication_device_metadata(authentication_device)
    assert len(metadata) == 3
    assert metadata["user"] == "Johnny"
    assert isinstance(metadata["device_uid"], UUID)
    assert metadata["passphrase_hint"] == "big passphrâse \n aboùt bïrds"
