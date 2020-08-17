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


@pytest.mark.parametrize(
    "key_type", ['DSA_DSS', 'ECC_DSS', 'RSA_OAEP', 'RSA_PSS']
)
def test_list_keys(tmp_path,key_type):

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
  
    from wacryptolib.key_generation import generate_asymmetric_keypair
    from wacryptolib.utilities import generate_uuid0
    key_pair = generate_asymmetric_keypair(
                    key_type=key_type,
                    passphrase="abc".encode(),
                )  
            
    key_pairs_dir=str(tmp_path)            
    object_FilesystemKeyStorage = FilesystemKeyStorage(key_pairs_dir)

    object_FilesystemKeyStorage.set_keys(
        keychain_uid=generate_uuid0(),
        key_type=key_type,
        public_key=key_pair["public_key"],
        private_key=key_pair["private_key"],
    )

    public_key_list=object_FilesystemKeyStorage.list_keys()
    
    assert isinstance(public_key_list, list)

    assert public_key_list, "No public key detected during test"

    for public_key in public_key_list:
        print(">> public key detected:", public_key)
        assert isinstance(public_key, dict) or isinstance(public_key, None)

        assert isinstance(public_key["keychain_uid"], str)
        
        assert (public_key["private_key_present"] == True) or (
            public_key["private_key_present"] == False  # We almost never do "== True/false" in Python
        )
        
        assert public_key["key_type"] in ('DSA_DSS', 'ECC_DSS', 'RSA_OAEP', 'RSA_PSS')

       
