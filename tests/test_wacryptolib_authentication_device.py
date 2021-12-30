from pathlib import Path
from uuid import UUID

from _test_mockups import get_fake_authdevice
from wacryptolib.authdevice import (
    list_available_authdevices,
    is_authdevice_initialized,
    get_authenticator_dir_for_authdevice,
)
from wacryptolib.authdevice import initialize_authdevice, load_authdevice_metadata
from wacryptolib.utilities import get_metadata_file_path


def test_list_available_authdevices():  # FIXME add mockups to simulate real USB key?

    authdevices_list = list_available_authdevices()
    assert isinstance(authdevices_list, list)

    for authdevice in authdevices_list:
        print(">> USB key detected:", authdevice)
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

        assert isinstance(authdevice["is_initialized"], bool)

        if authdevice["metadata"]:
            assert isinstance(authdevice["metadata"]["user"], str)  # Might be empty
            assert isinstance(authdevice["metadata"]["device_uid"], (type(None), UUID))  # Might be empty


def test_authdevice_initialization_and_checkers(tmp_path):

    authdevice = get_fake_authdevice(tmp_path)
    authdevice_original = authdevice.copy()

    assert not is_authdevice_initialized(authdevice)
    initialize_authdevice(authdevice, user="Michél Dûpont")
    assert is_authdevice_initialized(authdevice)

    # UNCHANGED fields
    assert authdevice["drive_type"] == "USBSTOR"
    assert authdevice["path"] == tmp_path
    assert authdevice["label"] == "TOSHIBA"
    assert authdevice["size"] == 31000166400
    assert authdevice["format"] == "fat32"

    # UPDATED fields
    assert authdevice["is_initialized"] == True
    assert len(authdevice["metadata"]) == 2
    assert authdevice["metadata"]["user"] == "Michél Dûpont"
    assert isinstance(authdevice["metadata"]["device_uid"], UUID)

    # REAL metadata file content
    metadata = load_authdevice_metadata(authdevice)
    assert len(metadata) == 2
    assert metadata["user"] == "Michél Dûpont"
    assert isinstance(metadata["device_uid"], UUID)

    # We ensure the code doesn't do any weird shortcut
    authdevice["is_initialized"] = False
    authdevice["metadata"] = None  # Revert to original
    assert authdevice == authdevice_original
    metadata = load_authdevice_metadata(authdevice)
    assert authdevice == authdevice_original  # Untouched
    assert metadata["user"] == "Michél Dûpont"
    assert isinstance(metadata["device_uid"], UUID)

    assert is_authdevice_initialized(authdevice)
    metadata_file_path = get_metadata_file_path(get_authenticator_dir_for_authdevice(authdevice))
    metadata_file_path.unlink()
    assert not is_authdevice_initialized(authdevice)
    metadata_file_path.write_text("ZJSJS")
    assert is_authdevice_initialized(authdevice)  # No checkup of json file here!

    # Test extra metadata

    metadata_file_path.unlink()
    assert not is_authdevice_initialized(authdevice)
    initialize_authdevice(
        authdevice, user="Johnny", extra_metadata=dict(passphrase_hint="big passphrâse \n aboùt bïrds")
    )
    assert is_authdevice_initialized(authdevice)

    metadata = load_authdevice_metadata(authdevice)
    assert len(metadata) == 3
    assert metadata["user"] == "Johnny"
    assert isinstance(metadata["device_uid"], UUID)
    assert metadata["passphrase_hint"] == "big passphrâse \n aboùt bïrds"
