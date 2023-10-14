import random
import secrets
import sys
from uuid import UUID

from wacryptolib.cryptainer import CryptainerStorage, dump_cryptainer_to_filesystem, PAYLOAD_CIPHERTEXT_LOCATIONS
from wacryptolib.keystore import KEYSTORE_FORMAT, FilesystemKeystorePool
from wacryptolib.utilities import generate_uuid0


def get_longrun_command_line(marker):
    longrun_command_line = [
        sys.executable,
        "-u",  # UNBUFFERED OUTPUT STREAMS
        "-c",
        # We use "or" to chain the two print() expressions, it's not a bug!
        "import time, sys ;\nfor i in range(600): print('This is some test data output [%s]!') or print('Some stderr logging here [%s]!', file=sys.stderr) or time.sleep(0.33)" % (marker, marker),
    ]
    return longrun_command_line


# No need for UNBUFFERED here, termination of programs seems to trigger a flush of streams
oneshot_command_line = [sys.executable, "-c", "print('This is some test data output and then I quit immediately!')"]


class FakeTestCryptainerStorage(CryptainerStorage):
    """Fake class which bypasses encryption and forces filename unicity regardless of datetime, to speed up tests..."""

    increment = 0

    def enqueue_file_for_encryption(self, filename_base, payload, **kwargs):
        super().enqueue_file_for_encryption(filename_base + (".%03d" % self.increment), payload, **kwargs)
        self.increment += 1

    def _use_streaming_encryption_for_cryptoconf(self, cryptoconf):
        return self._offload_payload_ciphertext  # Do NOT dig cryptoconf here, it might be all wrong

    def _encrypt_payload_and_stream_cryptainer_to_filesystem(
        self, payload, cryptainer_filepath, cryptainer_metadata, cryptoconf
    ):
        cryptainer = self._encrypt_payload_into_cryptainer(  # No streaming pipeline in this FAKE class!
            payload,
            cryptainer_metadata=cryptainer_metadata,
            cryptoconf=cryptoconf,
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
        return cryptainer["payload_ciphertext_struct"]["ciphertext_value"], []


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


def generate_keystore_pool(tmp_path):
    keystore_uid = generate_uuid0()
    keychain_uid = generate_uuid0()
    key_algo = "RSA_OAEP"
    keystore_secret = secrets.token_urlsafe(64)

    keystore_tree = {
        "keystore_type": "authenticator",
        "keystore_format": KEYSTORE_FORMAT,
        "keystore_owner": "Jacques",
        "keystore_uid": keystore_uid,
        "keystore_secret": keystore_secret,
        "keypairs": [{"keychain_uid": keychain_uid, "key_algo": key_algo, "public_key": b"555", "private_key": b"okj"}],
    }
    authdevice_path = tmp_path / "device"
    authdevice_path.mkdir()

    for _ in range(2):  # Import is idempotent
        keystore_pool = FilesystemKeystorePool(authdevice_path)
        keystore_pool.import_foreign_keystore_from_keystore_tree(keystore_tree)

    return keystore_pool
