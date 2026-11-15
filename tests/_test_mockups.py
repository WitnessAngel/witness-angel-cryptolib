# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import random
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import pytest
import secrets
import sys
from uuid import UUID

from wacryptolib.cryptainer import CryptainerStorage, dump_cryptainer_to_filesystem, PAYLOAD_CIPHERTEXT_LOCATIONS
import wacryptolib.keystore as keystore_module
from wacryptolib.keystore import KEYSTORE_FORMAT, FilesystemKeystore, FilesystemKeystorePool, ReadonlyFilesystemKeystore
from wacryptolib.utilities import generate_uuid0


def get_longrun_command_line(marker):
    longrun_command_line = [
        sys.executable,
        "-u",  # UNBUFFERED OUTPUT STREAMS
        "-c",
        # We use "or" to chain the two print() expressions, it's not a bug!
        "import time, sys ;\nfor i in range(600): print('This is some test data output [%s]!') or print('Some stderr logging here [%s]!', file=sys.stderr) or time.sleep(0.33)"
        % (marker, marker),
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


def is_fallback_backend():
    from wacryptolib import _crypto_backend

    return _crypto_backend.BACKEND_NAME == "fallback"


def skip_if_fallback_backend(feature):
    if is_fallback_backend():
        pytest.skip("%s requires native pycryptodome, unavailable in fallback backend" % feature)


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


def write_legacy_uppercase_algo_keystore(keys_dir, keypairs, free_keypairs=None):
    """
    Fill a directory like earlier releases did, with legacy uppercase algo names in key file names and in
    `free_keys/<ALGO>/` subdirectories.

    :param keypairs: iterable of (keychain_uid, key_algo, keypair dict as returned by generate_keypair())
    :param free_keypairs: iterable of (key_algo, keypair dict)
    """
    keys_dir = Path(keys_dir)
    for keychain_uid, key_algo, keypair in keypairs:
        (keys_dir / ("%s_%s_public_key.pem" % (keychain_uid, key_algo.upper()))).write_bytes(keypair["public_key"])
        (keys_dir / ("%s_%s_private_key.pem" % (keychain_uid, key_algo.upper()))).write_bytes(keypair["private_key"])
    for index, (key_algo, keypair) in enumerate(free_keypairs or ()):
        subdir = keys_dir / "free_keys" / key_algo.upper()
        subdir.mkdir(parents=True, exist_ok=True)
        (subdir / ("%d_public_key.pem" % (1000 + index))).write_bytes(keypair["public_key"])
        (subdir / ("%d_private_key.pem" % (1000 + index))).write_bytes(keypair["private_key"])


@contextmanager
def emulate_case_sensitive_filesystem():
    """
    Make the LOOKUPS of Path.stat()/exists()/is_dir() case-sensitive, to emulate Linux on Windows/macOS:
    a path is only found if its last component is spelled exactly as in its parent directory.

    Writes are NOT emulated: on a case-insensitive filesystem, creating a file or directory whose name only differs
    in case from an existing one still opens or collides with the existing one (e.g. mkdir() raises FileExistsError).
    So distinct files under both spellings can't be created here, use a case-sensitive filesystem or mock the stats.
    """
    path_class = type(Path())
    orig_stat, orig_exists, orig_is_dir = path_class.stat, path_class.exists, path_class.is_dir

    def _exact_name_present(path):
        try:
            return path.name in os.listdir(path.parent)
        except (FileNotFoundError, NotADirectoryError):
            return False

    def stat(self, *args, **kwargs):
        result = orig_stat(self, *args, **kwargs)  # Raises FileNotFoundError on its own if not found at all
        if not _exact_name_present(self):
            raise FileNotFoundError(2, "No such file or directory (emulated case-sensitive filesystem)", str(self))
        return result

    def exists(self, *args, **kwargs):
        return orig_exists(self, *args, **kwargs) and _exact_name_present(self)

    def is_dir(self, *args, **kwargs):
        return orig_is_dir(self, *args, **kwargs) and _exact_name_present(self)

    with mock.patch.object(path_class, "stat", stat), mock.patch.object(
        path_class, "exists", exists
    ), mock.patch.object(path_class, "is_dir", is_dir):
        yield


def is_case_insensitive_filesystem(directory: Path) -> bool:
    """Probe whether a (writable) directory lives on a case-insensitive filesystem."""
    probe = Path(directory) / "case_probe_file"
    probe.write_bytes(b"")
    try:
        return Path(directory, "CASE_PROBE_FILE").exists()
    finally:
        probe.unlink()


@contextmanager
def emulate_case_insensitive_filesystem(directory: Path):
    """
    Make the key files of filesystem keystores behave as on a case-insensitive (but case-preserving) filesystem,
    like NTFS, APFS or FAT: any spelling of an existing key file name designates this file, while a new file keeps
    the spelling it's created with. Does nothing if `directory` already lives on a case-insensitive filesystem.

    Only key file lookups, reads and writes are emulated, not free keys subdirectories nor other Path methods.
    """
    if is_case_insensitive_filesystem(directory):
        yield
        return

    def _get_actual_path(path):
        path = Path(path)
        try:
            names = os.listdir(path.parent)
        except (FileNotFoundError, NotADirectoryError):
            return path
        matches = [name for name in names if name.lower() == path.name.lower()]
        return path.with_name(matches[0]) if matches else path

    original_stat_if_existing = keystore_module._stat_if_existing
    original_read_from_storage_file = ReadonlyFilesystemKeystore._read_from_storage_file
    original_write_to_storage_file = FilesystemKeystore._write_to_storage_file

    def stat_if_existing(path):
        return original_stat_if_existing(_get_actual_path(path))

    def read_from_storage_file(self, filepath):
        return original_read_from_storage_file(self, _get_actual_path(filepath))

    def write_to_storage_file(self, filepath, data):
        return original_write_to_storage_file(self, filepath=_get_actual_path(filepath), data=data)

    with mock.patch.object(keystore_module, "_stat_if_existing", stat_if_existing), mock.patch.object(
        ReadonlyFilesystemKeystore, "_read_from_storage_file", read_from_storage_file
    ), mock.patch.object(FilesystemKeystore, "_write_to_storage_file", write_to_storage_file):
        yield
