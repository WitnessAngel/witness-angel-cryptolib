import os
import random
import shutil
from pathlib import Path
from uuid import UUID

import pytest

from _test_mockups import get_fake_authentication_device
from wacryptolib.authentication_device import _get_key_storage_folder_path, initialize_authentication_device
from wacryptolib.escrow import generate_asymmetric_keypair_for_storage
from wacryptolib.exceptions import KeyStorageDoesNotExist, KeyStorageAlreadyExists
from wacryptolib.key_generation import SUPPORTED_ASYMMETRIC_KEY_TYPES
from wacryptolib.key_storage import FilesystemKeyStorage, DummyKeyStorage, KeyStorageBase, FilesystemKeyStoragePool
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
    basename = filesystem_key_storage._get_filename(keychain_uid, key_type="abxz", is_public=is_public)
    with open(os.path.join(str(tmp_path), basename), "rb") as f:
        key_data = f.read()
        assert key_data == (b"public_data" if is_public else b"private_data")  # IMPORTANT no exchange of keys in files!


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


def test_key_storage_list_keypair_identifiers(tmp_path: Path):
    def _check_key_dict_format(key):
        print(">> public key detected:", key)

        assert isinstance(key["keychain_uid"], UUID)
        assert key["key_type"] in SUPPORTED_ASYMMETRIC_KEY_TYPES
        assert isinstance(key["private_key_present"], bool)

    key_storage = FilesystemKeyStorage(tmp_path)
    assert key_storage.list_keypair_identifiers() == []

    # CASE 1 : only one key in storage

    key_type = random.choice(SUPPORTED_ASYMMETRIC_KEY_TYPES)

    keychain_uid = generate_uuid0()
    generate_asymmetric_keypair_for_storage(key_type=key_type, key_storage=key_storage, keychain_uid=keychain_uid)

    keys_list = key_storage.list_keypair_identifiers()
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
        generate_asymmetric_keypair_for_storage(key_type=_key_type, key_storage=key_storage, passphrase="xzf".encode())

    for bad_filename in (
        "0e896f1d-a4d0-67d6-7286-056f1ec342e8_RSA_OAEP_public_key.dot",
        "0e896f1d-a4d0-67d6-7286-056f1ec342e8_RSA_OAEP_publicX_key.pem",
        "a4d0-67d6-7286-056f1ec342e8_RSA_OAEP_public_key.pem",
        "WRONGPREFIX_public_key.pem",
    ):
        tmp_path.joinpath(bad_filename).touch()  # These will be ignored thanks to Regex

    keys_list = key_storage.list_keypair_identifiers()
    assert isinstance(keys_list, list)
    assert len(keys_list) == 4
    assert keys_list == sorted(keys_list, key=lambda x: (x["keychain_uid"], x["key_type"]))  # Well sorted

    for some_key in keys_list:
        _check_key_dict_format(some_key)
        assert single_key["private_key_present"]  # ALWAYS for now

    for filepath in tmp_path.glob("*" + FilesystemKeyStorage._private_key_suffix):
        filepath.unlink()

    keys_list = key_storage.list_keypair_identifiers()
    assert isinstance(keys_list, list)
    assert len(keys_list) == 4

    for some_key in keys_list:
        _check_key_dict_format(some_key)
        assert not some_key["private_key_present"]  # Private keys were deleted

    # CASE 3 : keys all deleted

    for filepath in tmp_path.glob("*.pem"):
        filepath.unlink()

    assert key_storage.list_keypair_identifiers() == []


def test_key_storage_pool_basics(tmp_path: Path):

    pool = FilesystemKeyStoragePool(tmp_path)

    local_key_storage = pool.get_local_key_storage()
    assert isinstance(local_key_storage, FilesystemKeyStorage)
    assert not local_key_storage.list_keypair_identifiers()

    keypair = generate_asymmetric_keypair_for_storage(
        key_type="RSA_OAEP", key_storage=local_key_storage, passphrase="xzf".encode()
    )

    assert len(local_key_storage.list_keypair_identifiers()) == 1

    assert pool.list_imported_key_storage_uids() == []

    imported_key_storage_uid = generate_uuid0()
    mirror_path = tmp_path.joinpath(
        pool.IMPORTED_STORAGES_DIRNAME, pool.IMPORTED_STORAGE_PREFIX + str(imported_key_storage_uid)
    )
    mirror_path.mkdir(parents=True, exist_ok=False)

    imported_key_storage_uid2 = generate_uuid0()
    mirror_path2 = tmp_path.joinpath(
        pool.IMPORTED_STORAGES_DIRNAME, pool.IMPORTED_STORAGE_PREFIX + str(imported_key_storage_uid2)
    )
    mirror_path2.mkdir(parents=True, exist_ok=False)

    assert pool.list_imported_key_storage_uids() == sorted([imported_key_storage_uid, imported_key_storage_uid2])

    with pytest.raises(KeyStorageDoesNotExist, match="not found"):
        pool.get_imported_key_storage(generate_uuid0())

    imported_key_storage = pool.get_imported_key_storage(imported_key_storage_uid)
    assert isinstance(imported_key_storage, FilesystemKeyStorage)
    assert not imported_key_storage.list_keypair_identifiers()

    imported_key_storage.set_keys(
        keychain_uid=generate_uuid0(),
        key_type="RSA_OAEP",
        public_key=keypair["public_key"],
        private_key=keypair["private_key"],
    )

    assert len(local_key_storage.list_keypair_identifiers()) == 1  # Unchanged
    assert len(imported_key_storage.list_keypair_identifiers()) == 1

    imported_key_storage2 = pool.get_imported_key_storage(imported_key_storage_uid2)
    assert isinstance(imported_key_storage2, FilesystemKeyStorage)
    assert not imported_key_storage2.list_keypair_identifiers()


def test_key_storage_import_key_storage_from_folder(tmp_path: Path):

    pool_path = tmp_path / "pool"
    pool_path.mkdir()
    pool = FilesystemKeyStoragePool(pool_path)
    assert pool.list_imported_key_storage_uids() == []
    assert pool.list_imported_key_storage_metadata() == {}

    authentication_device_path = tmp_path / "device"
    authentication_device_path.mkdir()
    authentication_device = get_fake_authentication_device(authentication_device_path)
    initialize_authentication_device(authentication_device, user="Jean-Jâcques")

    keychain_uid = generate_uuid0()
    key_type = "RSA_OAEP"

    remote_key_storage_path = _get_key_storage_folder_path(authentication_device)
    remote_key_storage = FilesystemKeyStorage(remote_key_storage_path)
    remote_key_storage.set_keys(keychain_uid=keychain_uid, key_type=key_type, public_key=b"555", private_key=b"okj")

    # Still untouched of course
    assert pool.list_imported_key_storage_uids() == []
    assert pool.list_imported_key_storage_metadata() == {}

    pool.import_key_storage_from_folder(remote_key_storage_path)

    (key_storage_uid,) = pool.list_imported_key_storage_uids()
    metadata_mapper = pool.list_imported_key_storage_metadata()
    assert tuple(metadata_mapper) == (key_storage_uid,)

    metadata = metadata_mapper[key_storage_uid]
    assert metadata["device_uid"] == key_storage_uid
    assert metadata["user"] == "Jean-Jâcques"

    with pytest.raises(KeyStorageAlreadyExists, match=str(key_storage_uid)):
        pool.import_key_storage_from_folder(remote_key_storage_path)

    shutil.rmtree(authentication_device_path)  # Not important anymore

    assert pool.list_imported_key_storage_uids() == [key_storage_uid]
    metadata_mapper2 = pool.list_imported_key_storage_metadata()
    assert metadata_mapper2 == metadata_mapper

    key_storage = pool.get_imported_key_storage(key_storage_uid)
    assert key_storage.list_keypair_identifiers() == [
        dict(keychain_uid=keychain_uid, key_type=key_type, private_key_present=True)
    ]
    assert key_storage.get_public_key(keychain_uid=keychain_uid, key_type=key_type) == b"555"
    assert key_storage.get_private_key(keychain_uid=keychain_uid, key_type=key_type) == b"okj"
