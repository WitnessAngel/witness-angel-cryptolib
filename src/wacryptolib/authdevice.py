import logging
from pathlib import Path
from pathlib import PurePath

from sys import platform as sys_platform

logger = logging.getLogger(__name__)


def _get_authenticator_dir_for_authdevice(authdevice: dict):
    return Path(authdevice["path"]).joinpath(".authenticator")


# FIXME change "format" here, bad wording!!!!
def list_available_authdevices() -> list:
    """
    Generate a list of dictionaries representing mounted partitions of USB keys.

    :return: list of dicts having at least these fields:
    
        - "drive_type" (str): device type like "USBSTOR"
        - "path" (str):  mount point of device on the filesystem.
        - "label" (str): possibly empty, label of the partition
        - "format" (str): lowercase character string for filesystem type, like "ext2", "fat32" ...
        - "size" (int): filesystem size in bytes
        - "partition" (str): Path to the Linux partition e.g. "/dev/sda1" (remains None on WIndows)
        - "authenticator_path" (str): Theoretical absolute path to the authenticator (might not exist yet)

    """

    if sys_platform == "win32":
        authdevices = _list_available_authdevices_win32()
    else:  # Linux, MacOS etc.
        authdevices = _list_available_authdevices_linux()

    for authdevice in authdevices:
        authdevice["authenticator_path"] = _get_authenticator_dir_for_authdevice(authdevice)

    return authdevices


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
                authdevice["partition"] = None
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

    removable_device_partitions = [
        device.device_node
        for removable_device in removable_devices
        for device in context.list_devices(subsystem="block", DEVTYPE="partition", parent=removable_device)
    ]
    logger.debug("Removable pyudev partitions found: %s", str(removable_device_partitions))

    all_existing_partitions = psutil.disk_partitions()
    logger.debug("All mounted psutil partitions found: %s", str(all_existing_partitions))

    for p in all_existing_partitions:

        if p.device not in removable_device_partitions:
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
        authdevice_list.append(authdevice)

    return authdevice_list


