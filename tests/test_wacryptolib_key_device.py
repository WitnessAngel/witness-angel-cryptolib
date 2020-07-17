import pytest
from pathlib import Path
from wacryptolib.key_device import list_available_key_devices
from wacryptolib.key_device import _initialize_key_device_win32

# import commented for the test in the Linux operating system
# from wacryptolib.key_device import _initialize_key_device_linux


def test_list_available_key_devices():
    usb_dev_list = list_available_key_devices()
    assert isinstance(usb_dev_list, list)
    for usb_dev in usb_dev_list:
        assert isinstance(usb_dev, dict) or isinstance(usb_dev, None)

        assert isinstance(usb_dev["path"], str)  # FIXME regroup checks for each field
        assert Path(usb_dev["path"]).exists, "This path doesn't exist"

        assert isinstance(usb_dev["label"], str)
        assert isinstance(usb_dev["size"], int)
        assert isinstance(usb_dev["format"], str)
        assert isinstance(usb_dev["drive_type"], str)

        assert usb_dev["size"] >= 0, "must be greater or equal to zero"
        assert usb_dev["drive_type"] == "USBSTOR"
        assert (
            (usb_dev["format"] == "fat32")
            or (usb_dev["format"] == "exfat")
            or (usb_dev["format"] == "vfat")
        )


def test_initialize_key_device(temp_path):  # FIXME use https://docs.pytest.org/en/latest/tmpdir.html#the-tmp-path-fixture

    temp_path = str(temp_path)  # temp_path is a Pathlib.Path, more powerful but tricky

    key_device1 = {
        "Drive_type": "USBSTOR",
        "path": "I:",  # TODO use temp_path
        "label": "TOSHIBA",
        "size": 31000166400,
        "format": "fat32",
    }
    # with empty path
    key_device2 = {
        "Drive_type": "USBSTOR",
        "path": "",
        "label": "Path empty",
        "size": 31000166400,
        "format": "fat32",
    }
    # with empty label
    key_device3 = {
        "Drive_type": "USBSTOR",
        "path": "I:",
        "label": "TOSHIBA",
        "size": 31000166400,
        "format": "fat32",
    }

    _initialize_key_device_win32(key_device1, "Michel Dupont")  # TODO use public API initialize...()
    _initialize_key_device_win32(key_device2, "Michel Dupont")
    _initialize_key_device_win32(key_device3, "")


# function commented for the test in the Linux operating system  # FIXME tests must be generic!
"""
def test_initialize_key_device():

    key_device1 = {
        "drive_type": "USBSTOR",
        "label": "UBUNTU",
        "path": "/media/akram/UBUNTU",
        "size": 30986469376,
        "format": "vfat",
        "partition": "/dev/sdb1",
    }
    # with empty path
    key_device2 = {
        "drive_type": "USBSTOR",
        "label": "UBUNTU 20_0",
        "path": "",
        "size": 309864,
        "format": "vfat",
        "partition": "/dev/sdb1",
    }
    # with empty label
    key_device3 = {
        "drive_type": "USBSTOR",
        "label": "TOSHIBA",
        "path": "/media/akram/DEVICE1",
        "size": 309864,
        "format": "vfat",
        "partition": "/dev/sdb1",
    }

    # device already initialised, meta_data exist
    key_device4 = {
        "drive_type": "USBSTOR",
        "label": "DEVICE3",
        "path": "",
        "size": 30986469376,
        "format": "vfat",
        "partition": "/dev/sdb1",
    }

    _initialize_key_device_linux(key_device1, "Michel Dupont")
    _initialize_key_device_linux(key_device2, "Michel Dupont")
    _initialize_key_device_linux(key_device3, "Michel Dupont")
    _initialize_key_device_linux(key_device4, "")

"""

test_list_available_key_devices()
