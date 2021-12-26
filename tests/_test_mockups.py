import random
from uuid import UUID

from wacryptolib.cryptainer import CryptainerStorage, dump_cryptainer_to_filesystem


class FakeTestCryptainerStorage(CryptainerStorage):
    """Fake class which bypasses encryption and forces filename unicity regardless of datetime, to speed up tests..."""

    increment = 0

    def enqueue_file_for_encryption(self, filename_base, data, **kwargs):
        super().enqueue_file_for_encryption(filename_base + (".%03d" % self.increment), data, **kwargs)
        self.increment += 1

    def _use_streaming_encryption_for_conf(self, cryptoconf):
        return self._offload_data_ciphertext  # Do NOT dig cryptoconf here, it might be all wrong

    def _encrypt_data_and_dump_cryptainer_to_filesystem(self, data, cryptainer_filepath, metadata, keychain_uid, cryptoconf):
        cryptainer = self._encrypt_data_into_cryptainer(
            data, metadata=metadata, keychain_uid=keychain_uid, cryptoconf=cryptoconf
        )
        dump_cryptainer_to_filesystem(
            cryptainer_filepath, cryptainer=cryptainer, offload_data_ciphertext=True
        )

    def _encrypt_data_into_cryptainer(self, data, **kwargs):
        return dict(a=33, data_ciphertext=data)

    def _decrypt_data_from_cryptainer(self, cryptainer, **kwargs):
        return cryptainer["data_ciphertext"]


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


def random_bool():
    return random.choice((True, False))
