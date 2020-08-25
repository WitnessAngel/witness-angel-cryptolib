from pathlib import Path
from uuid import UUID

from wacryptolib.key_device import list_available_key_devices, is_key_device_initialized, _get_metadata_file_path
from wacryptolib.key_device import initialize_key_device, load_key_device_metadata


def test_list_available_key_devices():  # FIXME add mockups to simulate real USB key?

    key_devices_list = list_available_key_devices()
    assert isinstance(key_devices_list, list)

    for key_device in key_devices_list:
        print(">> USB key detected:", key_device)
        assert isinstance(key_device, dict) or isinstance(key_device, None)

        assert isinstance(key_device["drive_type"], str)  # UNDOCUMENTED FIELD
        assert key_device["drive_type"] == "USBSTOR"

        assert isinstance(key_device["path"], str)
        assert Path(key_device["path"]).exists()

        assert isinstance(key_device["label"], str)  # Might be empty

        assert isinstance(key_device["format"], str)
        assert key_device["format"]

        assert isinstance(key_device["size"], int)
        assert key_device["size"] > 0

        assert isinstance(key_device["is_initialized"], bool)

        assert isinstance(key_device["user"], str)  # Might be empty
        assert isinstance(key_device["device_uid"], (type(None), UUID))  # Might be empty


def test_key_device_initialization_and_checkers(tmp_path):

    key_device = {
        "drive_type": "USBSTOR",
        "path": tmp_path,
        "label": "TOSHIBA",
        "size": 31000166400,
        "format": "fat32",
        "is_initialized": False,
    }
    key_device_original = key_device.copy()

    assert not is_key_device_initialized(key_device)
    initialize_key_device(key_device, user="Michél Dûpont")
    assert is_key_device_initialized(key_device)

    # UNCHANGED fields
    assert key_device["drive_type"] == "USBSTOR"
    assert key_device["path"] == tmp_path
    assert key_device["label"] == "TOSHIBA"
    assert key_device["size"] == 31000166400
    assert key_device["format"] == "fat32"

    # UPDATED fields
    assert key_device["is_initialized"] == True
    assert key_device["user"] == "Michél Dûpont"
    assert isinstance(key_device["device_uid"], UUID)

    # REAL metadata file content
    metadata = load_key_device_metadata(key_device)
    assert metadata["user"] == "Michél Dûpont"
    assert isinstance(metadata["device_uid"], UUID)

    # We ensure the code doesn't do any weird shortcut
    key_device["is_initialized"] = False
    del key_device["user"]
    del key_device["device_uid"]
    assert key_device == key_device_original
    metadata = load_key_device_metadata(key_device)
    assert key_device == key_device_original  # Untouched
    assert metadata["user"] == "Michél Dûpont"
    assert isinstance(metadata["device_uid"], UUID)

    assert is_key_device_initialized(key_device)
    metadata_file_path = _get_metadata_file_path(key_device)
    metadata_file_path.unlink()
    assert not is_key_device_initialized(key_device)
    metadata_file_path.write_text("ZJSJS")
    assert is_key_device_initialized(key_device)  # No checkup of json file here!
