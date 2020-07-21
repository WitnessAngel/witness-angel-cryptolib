from sys import platform as sys_platform
from pathlib import Path
from pathlib import PurePath
from wacryptolib.utilities import dump_to_json_file, load_from_json_file
from wacryptolib.utilities import generate_uuid0


def list_available_key_devices(): 
    """
    Generate a list of dictionaries representing mounted partitions of USB keys.

    :return: ( list ) : Dictionaries have at least these fields:'path','label','format','size','is_initialized'.
    
    The linux environment has an additional field which is 'partition'."""
    if sys_platform == "win32":  # All Windows versions
        return _list_available_key_devices_win32()
    else:  # We assume a POSIX compatible OS
        return _list_available_key_devices_linux()


def initialize_key_device(key_device: dict, user: str):
    """
    key_device ( dict ) - mounted partitions of USB keys.
    
    user ( str )        - user name."""

    if sys_platform == "win32":  # All Windows versions
        return _initialize_key_device_win32(key_device=key_device, user=user)
    else:  # We assume a POSIX compatible OS
        return _initialize_key_device_linux(key_device=key_device, user=user)


def _is_key_device_initialized(key_device: dict):
    """
    Check if a key device is initialized.
    
    key_device ( dict ) -mounted partitions of USB keys.
    
    :return: ( bool ) : If 'True', the key device is initialized. Otherwise, it is not initialized."""
    if sys_platform == "win32":  # All Windows versions
        return _is_key_device_initialized_win32(key_device)
    else:  # We assume a POSIX compatible OS
        return _is_key_device_initialized_linux(key_device)

def _is_key_device_initialized_win32(key_device: dict):
    
    if not Path(key_device["path"] + "\.key_storage\.metadata.json").exists():

        return False
    else:
        meta = load_from_json_file(key_device["path"]+"\.key_storage\.metadata.json")
        user = meta["user"]
        id_uuid = meta["uuid"]
        if isinstance(user, str) and user != "" and id_uuid != None:
            return True
        else:
            raise ValueError("Username and uuid are not in the correct form")

def _is_key_device_initialized_linux(key_device: dict):
    
    if not Path(key_device["path"] + "/.key_storage/.metadata.json").exists():

        return False
    else:
        meta = load_from_json_file(key_device["path"]+"/.key_storage/.metadata.json")
        user = meta["user"]
        id_uuid = meta["uuid"]
        if isinstance(user, str) and user != "" and id_uuid != None:
            return True
        else:
            raise ValueError("Username and uuid are not in the correct form")


def _list_available_key_devices_win32():
    import pywintypes
    import win32api
    import wmi

    usb_dev_list = []
    for drive in wmi.WMI().Win32_DiskDrive():
        pnp_dev_id = drive.PNPDeviceID.split("\\")

        if pnp_dev_id[0] != "USBSTOR":
            continue

        for partition in drive.associators("Win32_DiskDriveToDiskPartition"):
            for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                if drive.Size is None:  # FIXME when does it happen?
                    continue
                key_device = {}
                key_device["drive_type"] = pnp_dev_id[0]  # type like 'USBSTOR'
                logical_address = logical_disk.Caption
                key_device["path"] = logical_address  # E.g. 'E:'
                key_device["label"] = win32api.GetVolumeInformation(
                    logical_disk.Caption + "\\"
                )[0]
                key_device["size"] = int(partition.Size)  # In bytes
                key_device["format"] = logical_disk.FileSystem.lower()  # E.g 'fat32'
                key_device["is_initialized"] = _is_key_device_initialized(
                    key_device
                )  # E.g 'True'
                usb_dev_list.append(key_device)

    return usb_dev_list


def _list_available_key_devices_linux():  # Rename as "xxx_posix" ?

    # TODO add these to pyproject.tml with https://python-poetry.org/docs/dependency-specification/#using-environment-markers , windows ones too

    # Linux-specific imports
    import pyudev
    import psutil

    context = pyudev.Context()
    usb_dev_list = []
    removable = [
        device
        for device in context.list_devices(subsystem="block", DEVTYPE="disk")
        if device.attributes.asstring("removable") == "1"
    ]
    for device in removable:
        partitions = [
            device.device_node
            for device in context.list_devices(
                subsystem="block", DEVTYPE="partition", parent=device
            )
        ]
        for p in psutil.disk_partitions():
            # check is device is mounted
            if p.device in partitions:
                key_device = {}
                key_device["drive_type"] = "USBSTOR"
                key_device["label"] = str(
                    PurePath(p.mountpoint).name
                )  # E.g: 'UBUNTU 20_0'
                key_device["path"] = p.mountpoint  # E.g: '/media/akram/UBUNTU 20_0',
                key_device["size"] = psutil.disk_usage(
                    key_device["path"]
                ).total  # E.g: 30986469376
                key_device["format"] = p.fstype  # E.g: 'vfat'
                key_device["partition"] = p.device  # E.g: '/dev/sda1'
                key_device["is_initialized"] = _is_key_device_initialized(
                    key_device
                )  # E.g 'False'
                usb_dev_list.append(key_device)

            else:
                pass
        return usb_dev_list


def _initialize_key_device_win32(key_device: dict, user: str):
    
    import win32api
    import win32.lib.win32con as win32con
    

    assert isinstance(user, str) and user, repr(user)

    if key_device["is_initialized"] == False:
        hidden_folder = key_device["path"] + "\.key_storage"
        hidden_file = hidden_folder + "\.metadata.json"

        if not Path(hidden_folder).exists():
            Path(hidden_folder).mkdir()
        metadata = {}
        metadata[
            "uuid"
        ] = (
            generate_uuid0()
        )  # E.g : {'uuid': UUID('0e7ee05d-07ad-75bc-c1f9-05db3e0680ca'), 'user': 'John Doe'}
        metadata["user"] = user
        dump_to_json_file(hidden_file, metadata)
        win32api.SetFileAttributes(hidden_folder, win32con.FILE_ATTRIBUTE_HIDDEN)
        win32api.SetFileAttributes(hidden_file, win32con.FILE_ATTRIBUTE_HIDDEN)
        key_device["is_initialized"] = True
    else:
        raise RuntimeError("'" + key_device["path"] + " : key is already initialized")


def _initialize_key_device_linux(key_device: dict, user: str):

    if key_device["is_initialized"] == False:
        hidden_folder = key_device["path"] + "/.key_storage"
        hidden_file = hidden_folder + "/.metadata.json"

        if not Path(hidden_folder).exists():
            Path(hidden_folder).mkdir()

        metadata = {}
        metadata[
            "uuid"
        ] = (
            generate_uuid0()
        )  # eg : {'uuid': UUID('0e7ee05d-07ad-75bc-c1f9-05db3e0680ca'), 'user': 'John Doe'}
        metadata["user"] = user
        dump_to_json_file(hidden_file, metadata)
        key_device["is_initialized"] = True
    else:
        raise RuntimeError("'" + key_device["path"] + " : key is already initialized")
        
        
