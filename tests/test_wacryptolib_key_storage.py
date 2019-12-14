import os
import random

import pytest

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


def test_key_storages_free_keys_concurrency(tmp_path):

    dummy_key_storage = DummyKeyStorage()
    filesystem_key_storage = FilesystemKeyStorage(keys_dir=str(tmp_path))

    for key_storage in (dummy_key_storage, filesystem_key_storage):
        check_key_storage_free_keys_concurrency(key_storage)
