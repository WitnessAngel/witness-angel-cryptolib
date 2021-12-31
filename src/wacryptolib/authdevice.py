import logging
from sys import platform as sys_platform
from pathlib import Path
from pathlib import PurePath
from typing import Optional

from wacryptolib.authenticator import is_authenticator_initialized, initialize_authenticator, load_authenticator_metadata

logger = logging.getLogger(__name__)

# FIXME regroup all metadata and is_initialized in single "metadata" field??

# FIXME change "format" here, bad wording!!!!
def list_available_authdevices():
    """
    Generate a list of dictionaries representing mounted partitions of USB keys.

    :return: (list) Dictionaries having at least these fields: path, label, format, size, is_initialized, and metadata
    
        - "path" (str):  mount point on the filesystem.
        - "label" (str): possibly empty, label of the partition
        - "format" (str): lowercase character string for filesystem type, like "ext2", "fat32" ...
        - "size" (int): filesystem size in bytes
        - "is_initialized" (bool): if the device has been initialized with metadata
        - "metadata" (dict): None if device is not initialized, else dict with at least "authenticator_owner" (str) and "authenticator_uid" (UUID) attributes.

    The linux environment has an additional field which is 'partition' (str) e.g. "/dev/sda1".
    """

    if sys_platform == "win32":
        authdevices = _list_available_authdevices_win32()
    else:  # Linux, MacOS etc.
        authdevices = _list_available_authdevices_linux()

    for authdevice in authdevices:
        metadata = None
        if authdevice["is_initialized"]:
            metadata = load_authdevice_metadata(authdevice)  # FIXME - might crash concurrently here??
        authdevice["metadata"] = metadata

    return authdevices


# FIXME - actually unused?
def initialize_authdevice(authdevice: dict, authdevice_owner: str, extra_metadata: Optional[dict] = None):
    """
    Initialize a specific USB key, by creating an internal structure with key device metadata.

    The device must not be already initialized.

    :param authdevice: (dict) Mounted partition of USB key.
    :param user: (str) User name to store in device.

    On success, updates 'authdevice' to mark it as initialized, and to contain device metadata.
    """
    assert not authdevice["is_initialized"]  # Will be doubled with actual check of filesystem

    authenticator_dir = get_authenticator_dir_for_authdevice(authdevice)

    metadata = initialize_authenticator(
        authenticator_dir=authenticator_dir, authenticator_owner=authdevice_owner, extra_metadata=extra_metadata
    )

    authdevice["is_initialized"] = True
    authdevice["metadata"] = metadata


# FIXME - actually unused?
def is_authdevice_initialized(authdevice: dict):
    """
    Check if a key device seems initialized (by ignoring, of course, its "is_initialized" field).

    Doesn't actually load the device metadata.
    Dooesn't modify `authdevice` dict content.

    :param authdevice: (dict) Key device information.

    :return: (bool) True if and only if the key device is initialized.
    """
    authenticator_dir = get_authenticator_dir_for_authdevice(authdevice)
    return is_authenticator_initialized(authenticator_dir)


# FIXME - actually unused?
def load_authdevice_metadata(authdevice: dict) -> dict:
    """
    Return the device metadata stored in the given mountpoint, after checking that it contains at least mandatory
    (user and authenticator_uid) fields.

    Raises `ValueError` or json decoding exceptions if device appears initialized, but has corrupted metadata.
    """
    authenticator_dir = get_authenticator_dir_for_authdevice(authdevice)
    return load_authenticator_metadata(authenticator_dir)


def _list_available_authdevices_win32():
    import pywintypes  # Import which also helps win32api to load
    import win32api
    import wmi

    authdevice_list = []
    for drive in wmi.WMI().Win32_DiskDrive():
        pnp_dev_id = drive.PNPDeviceID.split("\\")

        if pnp_dev_id[0] != "USBSTOR":
            continue

        for partition in drive.associators("Win32_DiskDriveToDiskPartition"):
            for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):

                device_path = logical_disk.Caption + "\\"

                authdevice = {}

                try:
                    # This returns (volname, volsernum, maxfilenamlen, sysflags, filesystemtype) on success
                    authdevice["label"] = win32api.GetVolumeInformation(device_path)[0]
                except pywintypes.error as exc:
                    # Happens e.g. if filesystem is unknown or missing
                    logging.warning("Skipping faulty device %s: %r", device_path, exc)
                    continue

                authdevice["drive_type"] = pnp_dev_id[0]  # type like 'USBSTOR'
                authdevice["path"] = device_path  # E.g. 'E:\\'
                assert drive.Size, drive.Size
                authdevice["size"] = int(partition.Size)  # In bytes
                authdevice["format"] = logical_disk.FileSystem.lower()  # E.g 'fat32'
                authdevice["is_initialized"] = is_authdevice_initialized(
                    authdevice
                )  # E.g True

                authdevice_list.append(authdevice)

    return authdevice_list


def _list_available_authdevices_linux():
    import pyudev
    import psutil

    context = pyudev.Context()
    authdevice_list = []
    removable_devices = [
        device
        for device in context.list_devices(subsystem="block", DEVTYPE="disk")
        if device.attributes.asstring("removable") == "1"
    ]
    logger.debug("Removable pyudev devices found: %s", str(removable_devices))

    removable_devices_partitions = [
        device.device_node
        for removable_device in removable_devices
        for device in context.list_devices(subsystem="block", DEVTYPE="partition", parent=removable_device)
    ]
    logger.debug("Removable pyudev partitions found: %s", str(removable_devices_partitions))

    all_existing_partitions = psutil.disk_partitions()
    logger.debug("All mounted psutil partitions found: %s", str(all_existing_partitions))

    for p in all_existing_partitions:

        if p.device not in removable_devices_partitions:
            #logger.warning("REJECTED %s", p)
            continue
        #logger.warning("FOUND USB %s", p)

        authdevice = {}
        authdevice["drive_type"] = "USBSTOR"
        authdevice["label"] = str(PurePath(p.mountpoint).name)  # E.g: 'UBUNTU 20_0'
        authdevice["path"] = p.mountpoint  # E.g: '/media/akram/UBUNTU 20_0',
        authdevice["size"] = psutil.disk_usage(authdevice["path"]).total  # E.g: 30986469376
        authdevice["format"] = p.fstype  # E.g: 'vfat'
        authdevice["partition"] = p.device  # E.g: '/dev/sda1'
        authdevice["is_initialized"] = is_authdevice_initialized(
            authdevice
        )  # E.g False
        authdevice_list.append(authdevice)

    return authdevice_list


# FIXME introduce an AuthenticationDevice class to normalize and lazify this API instead of the dict?

def get_authenticator_dir_for_authdevice(authdevice: dict):
    return Path(authdevice["path"]).joinpath(".authenticator")

