from pathlib import Path
from wacryptolib.key_device import list_available_key_devices
from wacryptolib.key_device import initialize_key_device


def test_list_available_key_devices():

    key_devices_list = list_available_key_devices()
    assert isinstance(key_devices_list, list)

    assert key_devices_list, "No USB key detected during test"  # Uncomment this to ensure a REAL usb key is detected during tests

    for usb_dev in key_devices_list:
        print(">> USB key detected:", usb_dev)
        assert isinstance(usb_dev, dict) or isinstance(usb_dev, None)

        assert isinstance(usb_dev["path"], str)
        assert Path(usb_dev["path"]).exists, "This path doesn't exist"

        assert isinstance(usb_dev["label"], str)
        assert isinstance(usb_dev["size"], int)
        assert isinstance(usb_dev["format"], str)
        assert isinstance(usb_dev["drive_type"], str)

        assert usb_dev["size"] >= 0, "must be greater or equal to zero"
        assert usb_dev["drive_type"] == "USBSTOR"
        assert usb_dev["format"] in ("fat32", "exfat", "vfat", "ntfs")


def test_initialize_key_device(tmp_path):

    temp_path = tmp_path / "sub1"
    temp_path.mkdir()
    temp_path = str(temp_path)
    key_device1 = {
        "Drive_type": "USBSTOR",
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
        "Drive_type": "USBSTOR",
        "path": temp_path,
        "label": "",
        "size": 100166400,
        "format": "vfat",
        "is_initialized": False,
    }

    initialize_key_device(key_device1, "Michel Dupont")
    initialize_key_device(key_device2, "Michel Dupont")

    # TODO check the result of directories, of key_device2["is_initializd"] etc.
