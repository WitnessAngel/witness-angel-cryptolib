from pathlib import Path
from uuid import UUID

from _test_mockups import get_fake_authdevice
from wacryptolib.authdevice import list_available_authdevices
from wacryptolib.authenticator import _get_keystore_metadata_file_path


def test_list_available_authdevices():  # FIXME add mockups to simulate real USB key?

    authdevices_list = list_available_authdevices()
    assert isinstance(authdevices_list, list)

    for authdevice in authdevices_list:  # Only works if REAL usb key is plugged!

        print(">> USB key detected:", authdevice)

        assert len(authdevice) == 7  # Same format on all platforms

        assert isinstance(authdevice, dict) or isinstance(authdevice, None)

        assert isinstance(authdevice["drive_type"], str)  # UNDOCUMENTED FIELD
        assert authdevice["drive_type"] == "USBSTOR"

        assert isinstance(authdevice["path"], str)
        assert Path(authdevice["path"]).exists()

        assert isinstance(authdevice["label"], str)  # Might be empty

        assert isinstance(authdevice["format"], str)
        assert authdevice["format"]

        assert isinstance(authdevice["size"], int)
        assert authdevice["size"] > 0

        assert isinstance(authdevice["partition"], (type(None), str))

        assert Path(authdevice["authenticator_path"]).parent == Path(authdevice["path"])
