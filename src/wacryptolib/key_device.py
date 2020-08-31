import logging
from sys import platform as sys_platform
from pathlib import Path
from pathlib import PurePath
from wacryptolib.utilities import dump_to_json_file, load_from_json_file
from wacryptolib.utilities import generate_uuid0


logger = logging.getLogger(__name__)

# FIXME regroup all metadata and is_initialized in single "metadata" field

def list_available_key_devices():
    """
    Generate a list of dictionaries representing mounted partitions of USB keys.

    :return: (list) Dictionaries having at least these fields: path, label, format, size, is_initialized, initialized_user, initialized_device_uid
    
        - "path" (str):  mount point on the filesystem.
        - "label" (str): possibly empty, label of the partition
        - "format" (str): lowercase character string for filesystem type, like "ext2", "fat32" ...
        - "size" (int): filesystem size in bytes
        - "is_initialized" (bool): if the device has been initialized with metadata
        - "user" (str): empty if device not initialized, otherwise value of “user” from metadata
        - "device_uid" (None or UUID): None if device not initialized, otherwise value of “device_uid” from metadata

    The linux environment has an additional field which is 'partition' (str) e.g. "/dev/sda1".
    """

    if sys_platform == "win32":
        key_devices = _list_available_key_devices_win32()
    elif sys_platform.startswith("linux"):
        key_devices = _list_available_key_devices_linux()
    else:
        raise RuntimeError("%s OS not supported" % sys_platform)

    for key_device in key_devices:
        if key_device["is_initialized"]:
            # FIXME this makes a double metadata file reading, we should factorize it
            metadata = load_key_device_metadata(key_device)
            key_device.update(metadata)
        else:
            key_device["user"] = ""
            key_device["device_uid"] = None

    return key_devices


def initialize_key_device(key_device: dict, user: str):
    """
    Initialize a specific USB key, by creating an internal structure with key device metadata.

    The device must not be already initialized.

    :param key_device: (dict) Mounted partition of USB key.
    :param user: (str) User name to store in device.

    On success, updates 'key_device' to mark it as initialized, and to contain device metadata.
    """

    if key_device["is_initialized"]:
        raise RuntimeError("%s key-device is already initialized" % key_device["path"])

    if sys_platform == "win32":  # All Windows versions
        metadata = _initialize_key_device_win32(key_device=key_device, user=user)
    elif sys_platform.startswith("linux"):
        metadata = _initialize_key_device_linux(key_device=key_device, user=user)
    else:
        raise RuntimeError("%s OS not supported" % sys_platform)

    key_device["is_initialized"] = True
    key_device.update(metadata)


# FIXME add flags to report errors if json or RSA keys are missing/corrupted?
def is_key_device_initialized(key_device: dict):
    """
    Check if a key device appears initialized (by ignoring, of course, its "is_initialized" field).

    Doesn't actually load the device metadata.
    Dooesn't modify `key_device` content.
    
    :param key_device: (dict) Key device information.
    
    :return: (bool) True if and only if the key device is initialized.
    """
    metadata_file = _get_metadata_file_path(key_device=key_device)
    return metadata_file.exists()


def load_key_device_metadata(key_device: dict) -> dict:
    """
    Return the device metadata stored in the given mountpoint, after checking that it contains at least mandatory
    (user and device_uid) fields.

    Raises `ValueError` or json decoding exceptions if device appears initialized, but has corrupted metadata.
    """
    metadata_file = _get_metadata_file_path(key_device=key_device)

    if sys_platform == "win32":
        import win32api
        import win32.lib.win32con as win32con
        win32api.SetFileAttributes(
            str(metadata_file.parent), win32con.FILE_ATTRIBUTE_NORMAL
        )
        win32api.SetFileAttributes(str(metadata_file), win32con.FILE_ATTRIBUTE_NORMAL)  # FIXME do we really need this??

        metadata = load_from_json_file(metadata_file)

        win32api.SetFileAttributes(
            str(metadata_file.parent), win32con.FILE_ATTRIBUTE_HIDDEN
        )
        win32api.SetFileAttributes(str(metadata_file), win32con.FILE_ATTRIBUTE_HIDDEN)

    elif sys_platform.startswith("linux"):
        metadata = load_from_json_file(metadata_file)

    _check_key_device_metadata(metadata)  # Raises if troubles
    return metadata


def _check_key_device_metadata(metadata: dict):
    if not (
        isinstance(metadata, dict) and metadata.get("user") and metadata.get("device_uid")
    ):  # Lightweight checkup for now
        raise ValueError("Abnormal key device metadata: %s" % str(metadata))


def _list_available_key_devices_win32():
    import pywintypes  # Import which also helps win32api to load
    import win32api
    import wmi

    key_device_list = []
    for drive in wmi.WMI().Win32_DiskDrive():
        pnp_dev_id = drive.PNPDeviceID.split("\\")

        if pnp_dev_id[0] != "USBSTOR":
            continue

        for partition in drive.associators("Win32_DiskDriveToDiskPartition"):
            for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):

                device_path = logical_disk.Caption + "\\"

                key_device = {}

                try:
                    # This returns (volname, volsernum, maxfilenamlen, sysflags, filesystemtype) on success
                    key_device["label"] = win32api.GetVolumeInformation(device_path)[0]
                except pywintypes.error as exc:
                    # Happens e.g. if filesystem is unknown or missing
                    logging.warning("Skipping faulty device %s: %r", device_path, exc)
                    continue

                key_device["drive_type"] = pnp_dev_id[0]  # type like 'USBSTOR'
                key_device["path"] = device_path  # E.g. 'E:\\'
                assert drive.Size, drive.Size
                key_device["size"] = int(partition.Size)  # In bytes
                key_device["format"] = logical_disk.FileSystem.lower()  # E.g 'fat32'
                key_device["is_initialized"] = is_key_device_initialized(
                    key_device
                )  # E.g True

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

    return key_device_list


def _get_metadata_file_path(key_device: dict):
    return Path(key_device["path"]).joinpath(".key_storage", ".metadata.json")


def _common_key_device_initialization(hidden_file: Path, user: str):
    assert isinstance(user, str) and user, repr(user)
    hidden_folder = hidden_file.parent
    if not Path(hidden_folder).exists():
        Path(hidden_file.parent).mkdir()
    # E.g {'device_uid': device_uid('0e7ee05d-07ad-75bc-c1f9-05db3e0680ca'), 'user': 'John Doe'}
    metadata = {"device_uid": generate_uuid0(), "user": user}
    dump_to_json_file(hidden_file, metadata)
    return metadata


def _initialize_key_device_win32(key_device: dict, user: str):

    import win32api
    import win32.lib.win32con as win32con

    metadata_file = _get_metadata_file_path(key_device)
    metadata = _common_key_device_initialization(metadata_file, user)

    win32api.SetFileAttributes(str(metadata_file.parent), win32con.FILE_ATTRIBUTE_HIDDEN)  # FIXME - leak of abstraction regarding metadata_file_path
    win32api.SetFileAttributes(str(metadata_file), win32con.FILE_ATTRIBUTE_HIDDEN)

    return metadata


def _initialize_key_device_linux(key_device: dict, user: str):
    metadata_file = _get_metadata_file_path(key_device)
    metadata = _common_key_device_initialization(metadata_file, user)
    return metadata
