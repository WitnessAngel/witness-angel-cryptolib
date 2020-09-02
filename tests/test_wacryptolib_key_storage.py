import os
import random
from pathlib import Path
from uuid import UUID

import pytest

from wacryptolib.escrow import generate_asymmetric_keypair_for_storage
from wacryptolib.exceptions import KeyStorageDoesNotExist
from wacryptolib.key_generation import SUPPORTED_ASYMMETRIC_KEY_TYPES
from wacryptolib.key_storage import (
    FilesystemKeyStorage,
    DummyKeyStorage,
    KeyStorageBase, FilesystemKeyStoragePool,
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

    def _check_key_dict_format(key):
        print(">> public key detected:", key)

        assert isinstance(key["keychain_uid"], UUID)
        assert key["key_type"] in SUPPORTED_ASYMMETRIC_KEY_TYPES
        assert isinstance(key["private_key_present"], bool)

    key_storage = FilesystemKeyStorage(tmp_path)
    assert key_storage.list_keys() == []

    # CASE 1 : only one key in storage

    key_type = random.choice(SUPPORTED_ASYMMETRIC_KEY_TYPES)

    keychain_uid = generate_uuid0()
    generate_asymmetric_keypair_for_storage(
            key_type=key_type, key_storage=key_storage, keychain_uid=keychain_uid)

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
        generate_asymmetric_keypair_for_storage(key_type=_key_type, key_storage=key_storage,
                                                passphrase="xzf".encode())

    for bad_filename in (
        "0e896f1d-a4d0-67d6-7286-056f1ec342e8_RSA_OAEP_public_key.dot",
        "0e896f1d-a4d0-67d6-7286-056f1ec342e8_RSA_OAEP_publicX_key.pem",
        "a4d0-67d6-7286-056f1ec342e8_RSA_OAEP_public_key.pem",
        "WRONGPREFIX_public_key.pem"):
        tmp_path.joinpath(bad_filename).touch()  # These will be ignored thanks to Regex

    keys_list = key_storage.list_keys()
    assert isinstance(keys_list, list)
    assert len(keys_list) == 4
    assert keys_list == sorted(keys_list, key=lambda x: (x["keychain_uid"], x["key_type"]))  # Well sorted

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


def test_key_storage_pool(tmp_path: Path):

    pool = FilesystemKeyStoragePool(tmp_path)

    local_key_storage = pool.get_local_key_storage()
    assert isinstance(local_key_storage, FilesystemKeyStorage)
    assert not local_key_storage.list_keys()

    keypair = generate_asymmetric_keypair_for_storage(
            key_type="RSA_OAEP", key_storage=local_key_storage, passphrase="xzf".encode())

    assert len(local_key_storage.list_keys()) == 1

    assert pool.list_imported_key_storage_uids() == []

    imported_key_storage_uid = generate_uuid0()
    mirror_path = tmp_path.joinpath(pool.IMPORTED_STORAGES_DIRNAME, pool.IMPORTED_STORAGE_PREFIX + str(imported_key_storage_uid))
    mirror_path.mkdir(parents=True, exist_ok=False)

    imported_key_storage_uid2 = generate_uuid0()
    mirror_path2 = tmp_path.joinpath(pool.IMPORTED_STORAGES_DIRNAME, pool.IMPORTED_STORAGE_PREFIX + str(imported_key_storage_uid2))
    mirror_path2.mkdir(parents=True, exist_ok=False)

    assert pool.list_imported_key_storage_uids() == sorted([imported_key_storage_uid, imported_key_storage_uid2])

    with pytest.raises(KeyStorageDoesNotExist, match="not found"):
        pool.get_imported_key_storage(generate_uuid0())

    imported_key_storage = pool.get_imported_key_storage(imported_key_storage_uid)
    assert isinstance(imported_key_storage, FilesystemKeyStorage)
    assert not imported_key_storage.list_keys()

    imported_key_storage.set_keys(
        keychain_uid=generate_uuid0(),
        key_type="RSA_OAEP",
        public_key=keypair["public_key"],
        private_key=keypair["private_key"],
    )

    assert len(local_key_storage.list_keys()) == 1  # Unchanged
    assert len(imported_key_storage.list_keys()) == 1

    imported_key_storage2 = pool.get_imported_key_storage(imported_key_storage_uid2)
    assert isinstance(imported_key_storage2, FilesystemKeyStorage)
    assert not imported_key_storage2.list_keys()
