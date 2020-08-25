import os
import random
from pathlib import Path
from uuid import UUID

import pytest

from wacryptolib.key_generation import SUPPORTED_ASYMMETRIC_KEY_TYPES
from wacryptolib.key_storage import (
    FilesystemKeyStorage,
    DummyKeyStorage,
    KeyStorageBase,
)
from wacryptolib.scaffolding import (
    check_key_storage_free_keys_concurrency,
    check_key_storage_basic_get_set_api,
    check_key_storage_free_keys_api,
)
from wacryptolib.key_generation import generate_asymmetric_keypair
from wacryptolib.utilities import generate_uuid0

def test_key_storage_basic_get_set_api(tmp_path):

    with pytest.raises(TypeError, match="Can't instantiate abstract class"):
        KeyStorageBase()

    dummy_key_storage = DummyKeyStorage()
    filesystem_key_storage = FilesystemKeyStorage(keys_dir=str(tmp_path))

    filesystem_key_storage_test_locals = None
    for key_storage in (dummy_key_storage, filesystem_key_storage):
        res = check_key_storage_basic_get_set_api(key_storage=key_storage)
        if isinstance(key_storage, FilesystemKeyStorage):
            filesystem_key_storage_test_locals = res

    # Specific tests for filesystem storage

    keychain_uid = filesystem_key_storage_test_locals["keychain_uid"]

    is_public = random.choice([True, False])
    basename = filesystem_key_storage._get_filename(
        keychain_uid, key_type="abxz", is_public=is_public
    )
    with open(os.path.join(str(tmp_path), basename), "rb") as f:
        key_data = f.read()
        assert key_data == (
            b"public_data" if is_public else b"private_data"
        )  # IMPORTANT no exchange of keys in files!


def test_key_storage_free_keys_api(tmp_path):

    dummy_key_storage = DummyKeyStorage()
    filesystem_key_storage = FilesystemKeyStorage(keys_dir=str(tmp_path))

    for key_storage in (dummy_key_storage, filesystem_key_storage):
        check_key_storage_free_keys_api(key_storage)


def test_key_storage_free_keys_concurrency(tmp_path):

    dummy_key_storage = DummyKeyStorage()
    filesystem_key_storage = FilesystemKeyStorage(keys_dir=str(tmp_path))

    for key_storage in (dummy_key_storage, filesystem_key_storage):
        check_key_storage_free_keys_concurrency(key_storage)


def test_key_storage_list_keys(tmp_path: Path):
    """
    FIXME it's abnormal to have only one call to list_keys() here

    A normal test is :
    - try list_keys on an empty key storage
    - add some keys
    - test list_keys() and the count+format of dicts (using a local _check_key() utility for example)
    - remove 1 private key file
    - retest list_keys(), checking private_key_present value especially (reuse _check_key())
    - destroy all public key files
    - check that list_keys() returns empty list
    """

    def _check_key_dict_format(key):
        print(">> public key detected:", key)

        assert isinstance(key["keychain_uid"], UUID)
        assert key["key_type"] in SUPPORTED_ASYMMETRIC_KEY_TYPES
        assert isinstance(key["private_key_present"], bool)

    key_storage = FilesystemKeyStorage(tmp_path)
    assert key_storage.list_keys() == []

    # CASE 1 : only one key in storage

    key_type = random.choice(SUPPORTED_ASYMMETRIC_KEY_TYPES)
    key_pair = generate_asymmetric_keypair(
                    key_type=key_type,
                    passphrase="abc".encode(),
                )
    keychain_uid = generate_uuid0()
    key_storage.set_keys(
        keychain_uid=keychain_uid,
        key_type=key_type,
        public_key=key_pair["public_key"],
        private_key=key_pair["private_key"],
    )

    keys_list = key_storage.list_keys()
    assert isinstance(keys_list, list)
    assert len(keys_list) == 1

    single_key = keys_list[0]
    _check_key_dict_format(single_key)
    assert single_key["keychain_uid"] == keychain_uid
    assert single_key["key_type"] == key_type
    assert single_key["private_key_present"]

    # CASE 2 : multiple public keys, with or without private keys

    for i in range(3):
        _key_type = random.choice(SUPPORTED_ASYMMETRIC_KEY_TYPES)
        _key_pair = generate_asymmetric_keypair(
                        key_type=key_type,
                        passphrase="xzf".encode(),
                    )
        key_storage.set_keys(
            keychain_uid=generate_uuid0(),
            key_type=_key_type,
            public_key=_key_pair["public_key"],
            private_key=_key_pair["private_key"],
        )

    for bad_filename in (
        "0e896f1d-a4d0-67d6-7286-056f1ec342e8_RSA_OAEP_public_key.dot",
        "0e896f1d-a4d0-67d6-7286-056f1ec342e8_RSA_OAEP_publicX_key.pem",
        "a4d0-67d6-7286-056f1ec342e8_RSA_OAEP_public_key.pem"):
        Path(tmp_path.joinpath(bad_filename)).touch()  # These will be ignored thanks to Regex

    keys_list = key_storage.list_keys()
    assert isinstance(keys_list, list)
    assert len(keys_list) == 4

    for some_key in keys_list:
        _check_key_dict_format(some_key)
        assert single_key["private_key_present"]  # ALWAYS for now

    for filepath in tmp_path.glob("*" + FilesystemKeyStorage._private_key_suffix):
        filepath.unlink()

    keys_list = key_storage.list_keys()
    assert isinstance(keys_list, list)
    assert len(keys_list) == 4

    for some_key in keys_list:
        _check_key_dict_format(some_key)
        assert not some_key["private_key_present"]  # Private keys were deleted

    # CASE 3 : keys all deleted

    for filepath in tmp_path.glob("*.pem"):
        filepath.unlink()

    assert key_storage.list_keys() == []
