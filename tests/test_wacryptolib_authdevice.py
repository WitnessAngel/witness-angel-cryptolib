from pathlib import Path
from uuid import UUID

from _test_mockups import get_fake_authdevice
from wacryptolib.authdevice import (
    list_available_authdevices,
    _is_authdevice_initialized,
    _get_authenticator_dir_for_authdevice,
)
from wacryptolib.authdevice import _initialize_authdevice, _load_authdevice_metadata
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


def _____test_authdevice_initialization_and_checkers(tmp_path):

    authdevice = get_fake_authdevice(tmp_path)
    authdevice_original = authdevice.copy()

    assert not is_authdevice_initialized(authdevice)
    initialize_authdevice(authdevice, authdevice_owner="Michél Dûpont")
    assert is_authdevice_initialized(authdevice)

    # UNCHANGED fields
    assert authdevice["drive_type"] == "USBSTOR"
    assert authdevice["path"] == tmp_path
    assert authdevice["label"] == "TOSHIBA"
    assert authdevice["size"] == 31000166400
    assert authdevice["format"] == "fat32"

    # UPDATED fields
    assert authdevice["is_initialized"] == True
    assert len(authdevice["metadata"]) == 4
    assert authdevice["metadata"]["keystore_type"] == "authenticator"
    assert authdevice["metadata"]["keystore_owner"] == "Michél Dûpont"
    assert isinstance(authdevice["metadata"]["keystore_uid"], UUID)
    assert authdevice["metadata"]["keystore_format"] == 'keystore_1.0'

    # REAL metadata file content
    metadata = load_authdevice_metadata(authdevice)
    assert len(metadata) == 4
    assert authdevice["metadata"]["keystore_type"] == "authenticator"
    assert metadata["keystore_owner"] == "Michél Dûpont"
    assert isinstance(metadata["keystore_uid"], UUID)
    assert metadata["keystore_format"] == 'keystore_1.0'

    # We ensure the code doesn't do any weird shortcut
    authdevice["is_initialized"] = False
    authdevice["metadata"] = None  # Revert to original
    assert authdevice == authdevice_original
    metadata = load_authdevice_metadata(authdevice)
    assert authdevice == authdevice_original  # Untouched
    assert metadata["keystore_type"] == "authenticator"
    assert metadata["keystore_owner"] == "Michél Dûpont"
    assert isinstance(metadata["keystore_uid"], UUID)
    assert metadata["keystore_format"] == 'keystore_1.0'

    assert is_authdevice_initialized(authdevice)
    metadata_file_path = _get_keystore_metadata_file_path(get_authenticator_dir_for_authdevice(authdevice))
    metadata_file_path.unlink()
    assert not is_authdevice_initialized(authdevice)
    metadata_file_path.write_text("ZJSJS")
    assert is_authdevice_initialized(authdevice)  # No checkup of json file here!

    # Test extra metadata

    metadata_file_path.unlink()
    assert not is_authdevice_initialized(authdevice)
    initialize_authdevice(
        authdevice, authdevice_owner="Johnny", extra_metadata=dict(keystore_passphrase_hint="big passphrâse \n aboùt bïrds")
    )
    assert is_authdevice_initialized(authdevice)

    metadata = load_authdevice_metadata(authdevice)
    assert len(metadata) == 5
    assert metadata["keystore_type"] == "authenticator"
    assert metadata["keystore_owner"] == "Johnny"
    assert isinstance(metadata["keystore_uid"], UUID)
    assert metadata["keystore_format"] == 'keystore_1.0'
    assert metadata["keystore_passphrase_hint"] == "big passphrâse \n aboùt bïrds"
