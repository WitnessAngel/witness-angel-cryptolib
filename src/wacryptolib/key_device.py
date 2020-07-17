from sys import platform as sys_platform
from pathlib import Path
from pathlib import PurePath
from wacryptolib.utilities import dump_to_json_file
from wacryptolib.utilities import generate_uuid0


def list_available_key_devices() -> list:  # FIXME use the same docstring format as others of this repository (1 line + 1 block)
    """Returns a list of dictionaries representing mounted partitions of USB keys.

    Returned dictionaries have at least these fields:

    - "path" (string): mount point on the file system.  # TODO later, switch to Path
    - "label" (string): partition label (possibly empty)
    - "format" (lowercase string): filesystem such as "ext2", "fat32"...
    - "size" (int): total filesystem size in bytes

    * Also, this function must check if each USB is initialized by the metadata included in ".key_storage / .metadata.json" through the search for this file.
    If the USB device is not initialized, we call the initialize_key_device() function
    """  # FIXME - this function must NOT initialise keys! Just return their data
    if sys_platform == "win32":  # All Windows versions
        return _list_available_key_devices_win32()
    else:  # We assume a POSIX compatible OS
        return _list_available_key_devices_linux()


def _list_available_key_devices_win32():

    # Windows-specific imports
    import win32api
    import wmi

    usb_dev_list = []
    for drive in wmi.WMI().Win32_DiskDrive():
        pnp_dev_id = drive.PNPDeviceID.split("\\")

        if (
            pnp_dev_id[0] != "USBSTOR"
        ):  # For "USB key"   # FIXME use negative conditional
            continue

        usb_dev = {}  # FIXME wrong init location, must be more inside loops
        usb_dev["drive_type"] = pnp_dev_id[0]  # type like 'USBSTOR'
        for partition in drive.associators("Win32_DiskDriveToDiskPartition"):
            for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                if drive.Size is None:  # FIXME when does it happen?
                    continue

                logical_address = logical_disk.Caption

                usb_dev["path"] = logical_address  # E.g. 'E:'

                usb_dev["label"] = str(   # FIXME str() needed ??
                    win32api.GetVolumeInformation(logical_disk.Caption + "\\")[0]
                )  # Can be ""
                usb_dev["size"] = int(partition.Size)  # In bytes
                # Format like :'FAT32'  # FIXME wrong
                usb_dev["format"] = str(logical_disk.FileSystem).lower()  # FIXME str() needed ??
                # check if there is a directory ".key_storage" in the key storage

                # TODO add is_initialized field

                if not Path(  # FIXME this must be a separate _is_key_device_initialized(key_device) function
                    usb_dev["path"] + "\.key_storage\.metadata.json"
                ).exists():

                    _initialize_key_device_win32(usb_dev, "akram")
                else:
                    print(
                        "Information device in: '"
                        + usb_dev["path"]
                        + "' -device is already initialized"
                    )
                usb_dev_list.append(usb_dev)

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
        # print("All removable partitions: {}".format(", ".join(partitions)))  # FIXME remove scaffolding lines
        # print("Mounted removable partitions:")
        for p in psutil.disk_partitions():
            # check is device is mounted
            if p.device in partitions:
                key_device = {}
                # print("  {}: {}".format(p.device, p.mountpoint))
                key_device["drive_type"] = "USBSTOR"
                #'label': 'UBUNTU 20_0'
                key_device["label"] = str(PurePath(p.mountpoint).name)
                #'path': '/media/akram/UBUNTU 20_0',
                key_device["path"] = p.mountpoint
                #'size': 30986469376
                key_device["size"] = psutil.disk_usage("/media/akram/UBUNTU 20_0").total
                #'format': 'vfat'
                key_device["format"] = p.fstype
                # partition': '/dev/sda1'
                key_device["partition"] = p.device
                # The path like : 'E:'
                if not Path(
                    key_device["path"] + "/.key_storage/.metadata.json"
                ).exists():
                    _initialize_key_device_linux(key_device, "John Doe")
                else:
                    print(
                        "Information device in: "
                        + key_device["path"]
                        + " -device is already initialized"
                    )
                usb_dev_list.append(key_device)

            else:
                pass
        return usb_dev_list


def initialize_key_device(  # FIXME - rename all usb_dev to "key_device" EVERYWHERE
    key_device: dict, user: str
):
    """
    TODO
    """
    if sys_platform == "win32":  # All Windows versions
        return _initialize_key_device_win32(key_device=key_device, user=user)
    else:  # We assume a POSIX compatible OS
        return _initialize_key_device_linux(key_device=key_device, user=user)


def _initialize_key_device_win32(usb_dev: dict, user: str):
    """
    for Windows OS
    Creates a HIDDEN (if possible, eg. at least on fat32/ntfs) ".key_storage/" folder in partition represented by "key_device",
    and .metadata.json file inside, which contains fields "uuid" (autogenerated uuid thanks to wacryptolib function) and "user" as passed as argument.
    
    A RuntimError is raised if key_device was already initialized.
    * The argument "user" and "uuid" are the metadata that will be included in the detected USB (will be inserted in the list that will be included in the .starage_key / .metadata.json file.
    * "Uuid" is returned by a predefined function in the wacryptolib library: generate_uuid0
    """
    import pywintypes
    import win32api
    import win32.lib.win32con as win32con

    assert isinstance(user, str) and user, repr(user)

    # TODO: if already initialized (use common function), raise RuntimeError

    try:
        if Path(usb_dev["path"]).exists() and (usb_dev["path"] != ""):
            hidden_folder = usb_dev["path"] + "\.key_storage"
            hidden_file = hidden_folder + "\.metadata.json"  # TEMP: Tells if device is initialized

            if not Path(hidden_folder).exists():
                Path(hidden_folder).mkdir()
            Path(hidden_file).touch()  # FIXME wrong

            metadata = {}
            # create like : {'uuid': UUID('0e7ee05d-07ad-75bc-c1f9-05db3e0680ca'), 'user': 'John Doe'}
            metadata["uuid"] = generate_uuid0()
            try:
                if user == "":  # FIXME - Now redundant with assert
                    raise RuntimeError("user name not defined")
                else:
                    metadata["user"] = user
            except RuntimeError as err:
                print(err.args)

            dump_to_json_file(hidden_file, metadata)
            win32api.SetFileAttributes(hidden_folder, win32con.FILE_ATTRIBUTE_HIDDEN)
            win32api.SetFileAttributes(hidden_file, win32con.FILE_ATTRIBUTE_HIDDEN)
            print(
                "Information device in: "
                + usb_dev["path"]
                + " - metadata installed in device "
            )
        else:
            raise RuntimeError("'" + usb_dev["path"] + " : This path doesn't exist")
    except RuntimeError as erreur_path:
        print(erreur_path.args)


def _initialize_key_device_linux(key_device: dict, user: str):
    """
    for Linux OS   #DUPLICATED docstring
    Creates a HIDDEN (if possible, eg. at least on fat32/ntfs) ".key_storage/" folder in partition represented by "key_device",
    and .metadata.json file inside, which contains fields "uuid" (autogenerated uuid thanks to wacryptolib function) and "user" as passed as argument.
    
    A RuntimError is raised if key_device was already initialized.
    * The argument "user" and "uuid" are the metadata that will be included in the detected USB (will be inserted in the list that will be included in the .starage_key / .metadata.json file.
    * "Uuid" is returned by a predefined function in the wacryptolib library: generate_uuid0
    """
    if Path(key_device["path"]).exists() and (key_device["path"] != ""):
        hidden_folder = key_device["path"] + "/.key_storage"
        hidden_file = hidden_folder + "/.metadata.json"
        if not Path(hidden_folder).exists():
            Path(hidden_folder).mkdir()
            Path(hidden_file).touch()
        else:
            Path(hidden_file).touch()

        metadata = {}
        # create uuid like : {'uuid': UUID('0e7ee05d-07ad-75bc-c1f9-05db3e0680ca'), 'user': 'John Doe'}
        metadata["uuid"] = generate_uuid0()
        # generate_uuid0()
        metadata["user"] = user
        dump_to_json_file(hidden_file, metadata)
        print(
            "Information device in: "
            + key_device["path"]
            + " - metadata installed in device "
        )
    else:
        print(
            "'" + key_device["path"] + ", : This path doesn't exist"
        )  # FIXME don't use print() to report errors, but exceptions
