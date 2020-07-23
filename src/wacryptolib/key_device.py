from sys import platform as sys_platform
from pathlib import Path
from pathlib import PurePath
from wacryptolib.utilities import dump_to_json_file, load_from_json_file
from wacryptolib.utilities import generate_uuid0


def list_available_key_devices(): 

    import psutil
    usb_dev_list = [] 
    if sys_platform.startswith('linux'):
        # linux
        check='rw,nosuid,nodev,'#start with 'rw,nosuid'
        """E.g :
            'opts':'rw,nosuid,nodev,relatime,uid=1000,
        gid=1000,fmask=0022,dmask=0022,codepage=437,
        iocharset=iso8859-1,shortname=mixed,showexec,utf8,flush,
        errors=remount-ro'
        """
    elif sys_platform == "darwin":
        # MAC OS X
        check='rw,nosuid,local,ignore-ownership'
        #E.g :'opts': 'rw,nosuid,local,ignore-ownership'

    elif sys_platform == "win32":
        # Windows
        #E.g :'opts': 'rw,removable'
        check='rw,removable'
    else: 
        raise RuntimeError("'" + sys_platform + " OS not spported")
    """
    If all parameter is False, disk_partitions(all=False)tries to distinguish 
    and return physical devices only (e.g. hard disks, cd-rom drives, USB keys) 
    and ignore all others (e.g. pseudo, memory, duplicate, inaccessible filesystems)
    """
    for p in psutil.disk_partitions(all=False):
            if p.opts.startswith(check):
                key_device = {}
                key_device["opts"] = p.opts
                key_device["drive_type"] = "USBSTOR"
                key_device["label"] = str(
                    PurePath(p.mountpoint).name
                )  # E.g: 'UBUNTU 20_0'
                key_device["path"] = p.mountpoint  # E.g: '/media/akram/UBUNTU 20_0',
                key_device["size"] = psutil.disk_usage(
                    key_device["path"]
                ).total  # E.g: 30986469376
                key_device["format"] = p.fstype.lower()  # E.g: 'vfat'
                key_device["partition"] = p.device  # E.g: '/dev/sda1'
                key_device["is_initialized"] = _is_key_device_initialized(key_device)  # E.g 'False'
                key_device["mountpoint"] = p.mountpoint
                usb_dev_list.append(key_device)
    return usb_dev_list

def _is_key_device_initialized(key_device: dict):
    """
    Check if a key device is initialized.
    
    key_device ( dict ) -mounted partitions of USB keys.
    
    :return: ( bool ) : If 'True', the key device is initialized. Otherwise, it is not initialized."""
    if sys_platform == "win32":  # All Windows versions
        return _is_key_device_initialized_win32(key_device)
    else:  # darwin and linux
        return _is_key_device_initialized_posix(key_device)
    
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

def _is_key_device_initialized_posix(key_device: dict):
    
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


def initialize_key_device(key_device: dict, user: str):
    """
    key_device ( dict ) - mounted partitions of USB keys.
    
    user ( str )        - user name."""

    if sys_platform == "win32":  # All Windows versions
        return _initialize_key_device_win32(key_device=key_device, user=user)
    else:  # We assume a POSIX compatible OS
        return _initialize_key_device_posix(key_device=key_device, user=user)
    
def _initialize_key_device_win32(key_device: dict, user: str):
    import pywintypes
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


def _initialize_key_device_posix(key_device: dict, user: str):

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
        
