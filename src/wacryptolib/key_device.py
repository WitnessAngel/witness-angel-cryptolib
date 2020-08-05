from sys import platform as sys_platform
from pathlib import Path
from pathlib import PurePath
from wacryptolib.utilities import dump_to_json_file, load_from_json_file
from wacryptolib.utilities import generate_uuid0



def list_available_key_devices():

    """
    Generate a list of dictionaries representing mounted partitions of USB keys.

    :return: (list) Dictionaries having at least these fields: path, label, format, size, is_initialized, initialized_user, initialized_device_uid
    
        - "path"  : string, mount point on the filesystem.
        - "label" : string of characters, possibly empty, label of the partition
        - "format": lowercase character string for filesystem type, like "ext2", "fat32" ...
        - "size"  : filesystem size in bytes
        - "is_initialized"  : if the device has been initialized with the ".metadata.json" file
        - "initialized_user": empty if device not initialized, otherwise value of “user” from metadata
        - "initialized_device_uid": empty if device not initialized, otherwise value of “device_uid” from metadata
   
    
    The linux environment has an additional field which is 'partition'.
    """

    if sys_platform == "win32":
        return _list_available_key_devices_win32()
    elif sys_platform.startswith("linux"):
        return _list_available_key_devices_linux()
    else:
        raise RuntimeError("%s OS not supported" % sys_platform)


def initialize_key_device(key_device: dict, user: str):
    """
    Initialize a specific USB key, by creating an internal structure with key device metadata.

    The device must not be already initialized.

    :param key_device: (dict) Mounted partition of USB key.
    :param user: (str) User name to store in device.

    On success, update 'key_device' to mark it as initialized.
    """

    if key_device["is_initialized"]:
        raise RuntimeError("%s : key is already initialized" % key_device["path"])
    if sys_platform == "win32":  # All Windows versions
        _initialize_key_device_win32(key_device=key_device, user=user)
    elif sys_platform.startswith("linux"):
        _initialize_key_device_linux(key_device=key_device, user=user)
    else:
        raise RuntimeError("%s OS not supported" % sys_platform)

    key_device["is_initialized"] = True  
    metadata_file = _get_metadata_file_path(key_device)
    meta = load_from_json_file(metadata_file)
    key_device["initialized_user"] = meta["user"]
    key_device["initialized_device_uid"] = meta["device_uid"]


def is_key_device_initialized(key_device: dict):
    """
    Check if a key device is initialized.

    Raises ValueError if device appears initialized, but has corrupted metadata.
    
    :param key_device: (dict) Mounted partition of USB keys.
    
    :return: (bool) If True, the key device is initialized. Otherwise, it is not initialized.
    """
    metadata_file = _get_metadata_file_path(key_device)

    if not metadata_file.exists():
        return False

    meta = load_from_json_file(metadata_file)

    if isinstance(meta, dict) and meta.get("user") and meta.get("device_uid"):  # Lightweight checkup
        return True
    raise ValueError("Abnormal key device metadata: %s" % str(meta))


def _list_available_key_devices_win32():
    import pywintypes  # Import needed just to help win32api to load
    import win32api
    import wmi

    del pywintypes

    key_device_list = []
    for drive in wmi.WMI().Win32_DiskDrive():
        pnp_dev_id = drive.PNPDeviceID.split("\\")

        if pnp_dev_id[0] != "USBSTOR":
            continue

        for partition in drive.associators("Win32_DiskDriveToDiskPartition"):
            for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                assert drive.Size, drive.Size
                key_device = {}
                key_device["drive_type"] = pnp_dev_id[0]  # type like 'USBSTOR'
                logical_address = logical_disk.Caption
                key_device["path"] = logical_address  # E.g. 'E:'
                key_device["label"] = win32api.GetVolumeInformation(
                    logical_disk.Caption + "\\"
                )[0]
                key_device["size"] = int(partition.Size)  # In bytes
                key_device["format"] = logical_disk.FileSystem.lower()  # E.g 'fat32'
                key_device["is_initialized"] = is_key_device_initialized(
                    key_device
                )  # E.g True

                key_device["initialized_user"] = ""
                key_device["initialized_uuid"] = ""
                
                if key_device["is_initialized"]:
                    metadata_file = _get_metadata_file_path(key_device)
                    meta = load_from_json_file(metadata_file)
                    key_device["initialized_user"] = meta["user"]
                    key_device["initialized_uuid"] = meta["uuid"]
                key_device_list.append(key_device)

    return key_device_list


def _list_available_key_devices_linux():
    import pyudev
    import psutil

    context = pyudev.Context()
    key_device_list = []
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

            if p.device not in partitions:  # Check if device is mounted
                continue

            key_device = {}
            key_device["drive_type"] = "USBSTOR"
            key_device["label"] = str(PurePath(p.mountpoint).name)  # E.g: 'UBUNTU 20_0'
            key_device["path"] = p.mountpoint  # E.g: '/media/akram/UBUNTU 20_0',
            key_device["size"] = psutil.disk_usage(
                key_device["path"]
            ).total  # E.g: 30986469376
            key_device["format"] = p.fstype  # E.g: 'vfat'
            key_device["partition"] = p.device  # E.g: '/dev/sda1'
            key_device["is_initialized"] = is_key_device_initialized(
                key_device
            )  # E.g False

            key_device["initialized_user"] = ""
            key_device["initialized_uuid"] = ""
            if key_device["is_initialized"]:
                metadata_file = _get_metadata_file_path(key_device)
                meta = load_from_json_file(metadata_file)
                key_device["initialized_user"] = meta["user"]
                key_device["initialized_uuid"] = meta["uuid"]
            key_device_list.append(key_device)

        return key_device_list


def _common_key_device_initialization(hidden_file: Path, user: str):
    assert isinstance(user, str) and user, repr(user)
    hidden_folder = hidden_file.parent
    if not Path(hidden_folder).exists():
        Path(hidden_file.parent).mkdir()
    metadata = {}  # FIXME directly create the whole dict here, no need to insert values later
    # E.g {'device_uid': device_uid('0e7ee05d-07ad-75bc-c1f9-05db3e0680ca'), 'user': 'John Doe'}
    metadata["device_uid"] = generate_uuid0()
    metadata["user"] = user
    dump_to_json_file(hidden_file, metadata)
  



def _get_metadata_file_path(key_device: dict):
    return Path(key_device["path"]).joinpath(".key_storage", ".metadata.json")


def _initialize_key_device_win32(key_device: dict, user: str):

    import win32api
    import win32.lib.win32con as win32con

    hidden_file = _get_metadata_file_path(key_device)
    _common_key_device_initialization(hidden_file, user)

    win32api.SetFileAttributes(str(hidden_file.parent), win32con.FILE_ATTRIBUTE_HIDDEN)
    win32api.SetFileAttributes(str(hidden_file), win32con.FILE_ATTRIBUTE_HIDDEN)
    


def _initialize_key_device_linux(key_device: dict, user: str):

    hidden_file = _get_metadata_file_path(key_device)
    _common_key_device_initialization(hidden_file, user)

    

