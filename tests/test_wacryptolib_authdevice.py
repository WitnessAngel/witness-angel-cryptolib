from pathlib import Path

from wacryptolib.authdevice import list_available_authdevices


def test_list_available_authdevices():  # FIXME add mockups to simulate real USB key?

    authdevices_list = list_available_authdevices()
    assert isinstance(authdevices_list, list)

    for authdevice in authdevices_list:  # Only works if REAL USB KEY is plugged!

        print(">> USB key detected:", authdevice)

        assert len(authdevice) == 6  # Same format on all platforms

        assert isinstance(authdevice, dict)

        assert isinstance(authdevice["device_type"], str)
        assert authdevice["device_type"] == "USBSTOR"

        assert isinstance(authdevice["partition_mountpoint"], str)
        assert Path(authdevice["partition_mountpoint"]).exists()

        assert isinstance(authdevice["partition_label"], str)  # Might be empty

        assert isinstance(authdevice["filesystem_format"], str)
        assert authdevice["filesystem_format"]

        assert isinstance(authdevice["filesystem_size"], int)
        assert authdevice["filesystem_size"] > 0

        assert Path(authdevice["authenticator_dir"]).parent == Path(authdevice["partition_mountpoint"])
