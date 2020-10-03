from uuid import UUID

from wacryptolib.container import ContainerStorage


class FakeTestContainerStorage(ContainerStorage):
    """Fake class which bypasses encryption and forces filename unicity regardless of datetime, to speed up tests..."""

    increment = 0

    def enqueue_file_for_encryption(self, filename_base, data, **kwargs):
        super().enqueue_file_for_encryption(filename_base + (".%03d" % self.increment), data, **kwargs)
        self.increment += 1

    def _encrypt_data_into_container(self, data, **kwargs):
        return dict(a=33, data_ciphertext=data)

    def _decrypt_data_from_container(self, container, **kwargs):
        return container["data_ciphertext"]


class WildcardUuid(object):
    """Dummy UUID wildcard to compare data trees containing any UUID"""

    def __eq__(self, other):
        return isinstance(other, UUID)


def get_fake_authentication_device(device_path):
    """Return a dict representing a fak authentication device."""
    authentication_device = {
        "drive_type": "USBSTOR",
        "path": device_path,
        "label": "TOSHIBA",
        "size": 31000166400,
        "format": "fat32",
        "is_initialized": False,
        "metadata": None,
    }
    return authentication_device
