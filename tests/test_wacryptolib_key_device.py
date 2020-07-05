import win32com.client
import win32file
from win32com.client import gencache
import win32api
import wmi
import win32con
from pathlib import Path
from wacryptolib.key_device import list_available_key_devices
from wacryptolib.key_device import initialize_key_device

def test_list_available_key_devices():
    usb_dev_list=[{'Drive_type': 'USBSTOR', 'path': 'I:', 'label': 'TOSHIBA', 'size': 31000166400, 'format': 'FAT32'}]
    for usb_dev in usb_dev_list:
    	assert  Path(usb_dev['path']).exists ,"This path doesn't exist"
    	assert usb_dev['label'].isalnum(), " label is not alphanumeric"
    	assert usb_dev['size'] >= 0 ,"must be greater or equal to zero" 
    	
    
    
   


def test_initialize_key_device():
    
    key_device = {'Drive_type': 'USBSTOR', 'path': 'I:', 'label': 'TOSHIBA', 'size': 31000166400, 'format': 'FAT32'}
    initialize_key_device(key_device, "Michel Dupont")
                            


