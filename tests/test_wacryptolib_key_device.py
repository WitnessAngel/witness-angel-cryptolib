from pathlib import Path
from wacryptolib.key_device import list_available_key_devices
from wacryptolib.key_device import initialize_key_device, load_key_device_metadata
import re


def test_list_available_key_devices():
    key_devices_list = list_available_key_devices()
    assert isinstance(key_devices_list, list)

    assert key_devices_list or not (key_devices_list)

    for key_device in key_devices_list:
        print(">> USB key detected:", key_device)
        assert isinstance(key_device, dict) or isinstance(key_device, None)

        assert isinstance(key_device["path"], str)
        assert Path(key_device["path"]).exists()

        assert isinstance(key_device["label"], str)

        assert isinstance(key_device["size"], int)
        assert key_device["size"] >= 0

        assert isinstance(key_device["format"], str)

        assert isinstance(key_device["drive_type"], str)
        assert key_device["drive_type"] == "USBSTOR"

        assert (key_device["is_initialized"] == True) or (
            key_device["is_initialized"] == False
        )

        assert isinstance(key_device["user"], str)

        assert key_device["format"] in ("fat32", "exfat", "vfat", "ntfs")


def test_initialize_key_device(tmp_path):

    temp_path = tmp_path / "sub1"
    temp_path.mkdir()
    temp_path = str(temp_path)
    key_device1 = {
        "drive_type": "USBSTOR",
        "path": temp_path,
        "label": "TOSHIBA",
        "size": 31000166400,
        "format": "fat32",
        "is_initialized": False,
    }

    temp_path = tmp_path / "sub2"
    temp_path.mkdir()
    temp_path = str(temp_path)
    key_device2 = {
        "drive_type": "USBSTOR",
        "path": temp_path,
        "label": "",
        "size": 100166400,
        "format": "vfat",
        "is_initialized": False,
    }

    initialize_key_device(key_device1, "Michel Dupont")
    assert isinstance(key_device1["drive_type"], str)
    assert key_device1["drive_type"] == "USBSTOR"

    assert key_device1["is_initialized"] == True

    assert isinstance(key_device1["user"], str)

    assert isinstance(key_device1["label"], str)

    assert isinstance(key_device1["size"], int)
    assert key_device1["size"] >= 0

    assert isinstance(key_device1["format"], str)
    assert key_device1["format"] in ("fat32", "exfat", "vfat", "ntfs")

    initialize_key_device(key_device2, "Michel Dupont")
    assert isinstance(key_device1["drive_type"], str)
    assert key_device2["drive_type"] == "USBSTOR"

    assert isinstance(key_device1["user"], str)

    assert key_device2["is_initialized"] == True
    assert isinstance(key_device1["label"], str)

    assert isinstance(key_device1["size"], int)
    assert key_device2["size"] >= 0

    assert isinstance(key_device1["format"], str)
    assert key_device2["format"] in ("fat32", "exfat", "vfat", "ntfs")

    metadata = load_key_device_metadata(key_device1["path"])
    assert isinstance(metadata["user"], str)
    regex_UUID = (
        "("
        + "[a-z0-9]" * 8
        + "-"
        + "[a-z0-9]" * 4
        + "-"
        + "[a-z0-9]" * 4
        + "-"
        + "[a-z0-9]" * 4
        + "-"
        + "[a-z0-9]" * 12
        + ")"
    )
    metadata_device_uid = str(metadata["device_uid"])
    epoch_regex = re.compile(regex_UUID)
    assert epoch_regex.match(metadata_device_uid)
