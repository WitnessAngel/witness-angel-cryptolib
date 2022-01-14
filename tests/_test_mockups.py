import random
from uuid import UUID

from wacryptolib.cryptainer import CryptainerStorage, dump_cryptainer_to_filesystem, PAYLOAD_CIPHERTEXT_LOCATIONS


class FakeTestCryptainerStorage(CryptainerStorage):
    """Fake class which bypasses encryption and forces filename unicity regardless of datetime, to speed up tests..."""

    increment = 0

    def enqueue_file_for_encryption(self, filename_base, payload, **kwargs):
        super().enqueue_file_for_encryption(filename_base + (".%03d" % self.increment), payload, **kwargs)
        self.increment += 1

    def _use_streaming_encryption_for_cryptoconf(self, cryptoconf):
        return self._offload_payload_ciphertext  # Do NOT dig cryptoconf here, it might be all wrong

    def _encrypt_payload_and_stream_cryptainer_to_filesystem(
        self, payload, cryptainer_filepath, cryptainer_metadata, keychain_uid, cryptoconf
    ):
        cryptainer = self._encrypt_payload_into_cryptainer(
            payload, cryptainer_metadata=cryptainer_metadata, keychain_uid=keychain_uid, cryptoconf=cryptoconf
        )
        dump_cryptainer_to_filesystem(cryptainer_filepath, cryptainer=cryptainer, offload_payload_ciphertext=True)

    def _encrypt_payload_into_cryptainer(self, payload, **kwargs):
        return dict(
            a=33,
            payload_ciphertext_struct=dict(
                ciphertext_location=PAYLOAD_CIPHERTEXT_LOCATIONS.INLINE, ciphertext_value=payload
            ),
        )

    def _decrypt_payload_from_cryptainer(self, cryptainer, **kwargs):
        return cryptainer["payload_ciphertext_struct"]["ciphertext_value"]


class WildcardUuid:
    """Dummy UUID wildcard to compare data trees containing any UUID"""

    def __eq__(self, other):
        return isinstance(other, UUID)


def get_fake_authdevice(device_path):
    """Return a dict representing a fak authentication device."""
    authdevice = {
        "device_type": "USBSTOR",
        "partition_mountpoint": device_path,
        "partition_label": "TOSHIBA",
        "filesystem_size": 31000166400,
        "filesystem_format": "fat32",
        "authenticator_dir": device_path / ".myauthenticator",
    }
    return authdevice


def random_bool():
    return random.choice((True, False))
