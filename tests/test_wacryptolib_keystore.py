import os
import random
import shutil
import time
from pathlib import Path
from uuid import UUID

import pytest

from _test_mockups import get_fake_authdevice, random_bool
from wacryptolib.authenticator import initialize_authenticator
from wacryptolib.exceptions import KeystoreDoesNotExist, KeystoreAlreadyExists
from wacryptolib.keygen import SUPPORTED_ASYMMETRIC_KEY_ALGOS
from wacryptolib.keystore import (
    FilesystemKeystore,
    DummyKeystore,
    KeystoreBase,
    FilesystemKeystorePool,
    generate_free_keypair_for_least_provisioned_key_algo,
    get_free_keypair_generator_worker,
    generate_keypair_for_storage,
    ReadonlyFilesystemKeystore,
)
from wacryptolib.scaffolding import (
    check_keystore_free_keys_concurrency,
    check_keystore_basic_get_set_api,
    check_keystore_free_keys_api,
)
from wacryptolib.utilities import generate_uuid0


def test_keystore_basic_get_set_api(tmp_path):

    with pytest.raises(TypeError, match="Can't instantiate abstract class"):
        KeystoreBase()

    dummy_keystore = DummyKeystore()
    filesystem_keystore = FilesystemKeystore(keys_dir=tmp_path)
    readonly_filesystem_keystore = ReadonlyFilesystemKeystore(keys_dir=tmp_path)

    filesystem_keystore_test_locals = None
    for keystore, readonly_keystore in [(dummy_keystore, None), (filesystem_keystore, readonly_filesystem_keystore)]:
        res = check_keystore_basic_get_set_api(keystore=keystore, readonly_keystore=readonly_keystore)
        if isinstance(keystore, FilesystemKeystore):
            filesystem_keystore_test_locals = res

    # Specific tests for filesystem storage

    keychain_uid = filesystem_keystore_test_locals["keychain_uid"]

    is_public = random_bool()
    basename = filesystem_keystore._get_filename(keychain_uid, key_algo="abxz", is_public=is_public)
    with open(os.path.join(str(tmp_path), basename), "rb") as f:
        key_data = f.read()
        assert key_data == (b"public_data" if is_public else b"private_data")  # IMPORTANT no exchange of keys in files!


def test_keystore_free_keys_api(tmp_path):

    dummy_keystore = DummyKeystore()
    filesystem_keystore = FilesystemKeystore(keys_dir=tmp_path)
    assert not filesystem_keystore._free_keys_dir.exists()

    for keystore in (dummy_keystore, filesystem_keystore):
        check_keystore_free_keys_api(keystore)

    assert filesystem_keystore._free_keys_dir.exists()


def test_readonly_keystore_limitations(tmp_path):
    """For now we just test that the base ReadonlyFilesystemKeystore class doesn't have dangerous fields."""

    normal_keystore = FilesystemKeystore(keys_dir=tmp_path)
    readonly_keystore = ReadonlyFilesystemKeystore(keys_dir=tmp_path)

    forbidden_fields = [
        "set_keys",
        "get_free_keypairs_count",
        "add_free_keypair",
        "attach_free_keypair_to_uuid",
        "_write_to_storage_file",
    ]

    for forbidden_field in forbidden_fields:
        assert hasattr(normal_keystore, forbidden_field)
        assert not hasattr(readonly_keystore, forbidden_field)


def test_keystore_free_keys_concurrency(tmp_path):

    dummy_keystore = DummyKeystore()
    filesystem_keystore = FilesystemKeystore(keys_dir=tmp_path)

    for keystore in (dummy_keystore, filesystem_keystore):
        check_keystore_free_keys_concurrency(keystore)


def test_filesystem_keystore_list_keypair_identifiers(tmp_path: Path):
    def _check_key_dict_format(key):
        print(">> public key detected:", key)

        assert isinstance(key["keychain_uid"], UUID)
        assert key["key_algo"] in SUPPORTED_ASYMMETRIC_KEY_ALGOS
        assert isinstance(key["private_key_present"], bool)

    keystore = FilesystemKeystore(tmp_path)
    assert keystore.list_keypair_identifiers() == []

    # CASE 1 : only one key in storage

    key_algo = random.choice(SUPPORTED_ASYMMETRIC_KEY_ALGOS)

    keychain_uid = generate_uuid0()
    generate_keypair_for_storage(key_algo=key_algo, keystore=keystore, keychain_uid=keychain_uid)

    keys_list = keystore.list_keypair_identifiers()
    assert isinstance(keys_list, list)
    assert len(keys_list) == 1

    single_key = keys_list[0]
    _check_key_dict_format(single_key)
    assert single_key["keychain_uid"] == keychain_uid
    assert single_key["key_algo"] == key_algo
    assert single_key["private_key_present"]

    # CASE 2 : multiple public keys, with or without private keys

    for i in range(3):
        _key_algo = random.choice(SUPPORTED_ASYMMETRIC_KEY_ALGOS)
        generate_keypair_for_storage(key_algo=_key_algo, keystore=keystore, passphrase="xzf".encode())

    for bad_filename in (
        "0e896f1d-a4d0-67d6-7286-056f1ec342e8_RSA_OAEP_public_key.dot",
        "0e896f1d-a4d0-67d6-7286-056f1ec342e8_RSA_OAEP_publicX_key.pem",
        "a4d0-67d6-7286-056f1ec342e8_RSA_OAEP_public_key.pem",
        "WRONGPREFIX_public_key.pem",
    ):
        tmp_path.joinpath(bad_filename).touch()  # These will be ignored thanks to Regex

    keys_list = keystore.list_keypair_identifiers()
    assert isinstance(keys_list, list)
    assert len(keys_list) == 4
    assert keys_list == sorted(keys_list, key=lambda x: (x["keychain_uid"], x["key_algo"]))  # Well sorted

    for some_key in keys_list:
        _check_key_dict_format(some_key)
        assert single_key["private_key_present"]  # ALWAYS for now

    for filepath in tmp_path.glob("*" + FilesystemKeystore._private_key_suffix):
        filepath.unlink()

    keys_list = keystore.list_keypair_identifiers()
    assert isinstance(keys_list, list)
    assert len(keys_list) == 4

    for some_key in keys_list:
        _check_key_dict_format(some_key)
        assert not some_key["private_key_present"]  # Private keys were deleted

    # CASE 3 : keys all deleted

    for filepath in tmp_path.glob("*.pem"):
        filepath.unlink()

    assert keystore.list_keypair_identifiers() == []


def test_keystore_pool_basics(tmp_path: Path):

    pool = FilesystemKeystorePool(tmp_path)

    local_keystore = pool.get_local_keyfactory()
    assert isinstance(local_keystore, FilesystemKeystore)
    assert not local_keystore.list_keypair_identifiers()

    keypair = generate_keypair_for_storage(key_algo="RSA_OAEP", keystore=local_keystore, passphrase="xzf".encode())

    assert len(local_keystore.list_keypair_identifiers()) == 1

    assert pool.list_imported_keystore_uids() == []

    imported_keystore_uid = generate_uuid0()
    mirror_path = tmp_path.joinpath(
        pool.IMPORTED_KEYSTORES_DIRNAME, pool.IMPORTED_KEYSTORE_PREFIX + str(imported_keystore_uid)
    )
    mirror_path.mkdir(parents=True, exist_ok=False)

    imported_keystore_uid2 = generate_uuid0()
    mirror_path2 = tmp_path.joinpath(
        pool.IMPORTED_KEYSTORES_DIRNAME, pool.IMPORTED_KEYSTORE_PREFIX + str(imported_keystore_uid2)
    )
    mirror_path2.mkdir(parents=True, exist_ok=False)

    assert pool.list_imported_keystore_uids() == sorted([imported_keystore_uid, imported_keystore_uid2])

    with pytest.raises(KeystoreDoesNotExist, match="not found"):
        pool.get_imported_keystore(generate_uuid0())

    imported_keystore = pool.get_imported_keystore(imported_keystore_uid)
    assert isinstance(imported_keystore, FilesystemKeystore)
    assert not imported_keystore.list_keypair_identifiers()

    imported_keystore.set_keys(
        keychain_uid=generate_uuid0(),
        key_algo="RSA_OAEP",
        public_key=keypair["public_key"],
        private_key=keypair["private_key"],
    )

    assert len(local_keystore.list_keypair_identifiers()) == 1  # Unchanged
    assert len(imported_keystore.list_keypair_identifiers()) == 1

    imported_keystore2 = pool.get_imported_keystore(imported_keystore_uid2)
    assert isinstance(imported_keystore2, FilesystemKeystore)
    assert not imported_keystore2.list_keypair_identifiers()


def test_keystore_import_keystore_from_filesystem(tmp_path: Path):

    pool_path = tmp_path / "pool"
    pool_path.mkdir()
    pool = FilesystemKeystorePool(pool_path)
    assert pool.list_imported_keystore_uids() == []
    assert pool.get_imported_keystore_metadata() == {}

    authdevice_path = tmp_path / "device"
    authdevice_path.mkdir()
    authdevice = get_fake_authdevice(authdevice_path)
    remote_keystore_dir = authdevice["authenticator_dir"]
    initialize_authenticator(remote_keystore_dir, keystore_owner="Jean-Jâcques", keystore_passphrase_hint="my-hint")

    keychain_uid = generate_uuid0()
    key_algo = "RSA_OAEP"

    remote_keystore = FilesystemKeystore(remote_keystore_dir)
    remote_keystore.set_keys(keychain_uid=keychain_uid, key_algo=key_algo, public_key=b"555", private_key=b"okj")

    # Still untouched of course
    assert pool.list_imported_keystore_uids() == []
    assert pool.get_imported_keystore_metadata() == {}

    pool.import_keystore_from_filesystem(remote_keystore_dir)

    (keystore_uid,) = pool.list_imported_keystore_uids()
    metadata_mapper = pool.get_imported_keystore_metadata()
    assert tuple(metadata_mapper) == (keystore_uid,)

    metadata = metadata_mapper[keystore_uid]
    assert metadata["keystore_uid"] == keystore_uid
    assert metadata["keystore_owner"] == "Jean-Jâcques"

    with pytest.raises(KeystoreAlreadyExists, match=str(keystore_uid)):
        pool.import_keystore_from_filesystem(remote_keystore_dir)

    shutil.rmtree(authdevice_path)  # Not important anymore

    assert pool.list_imported_keystore_uids() == [keystore_uid]
    metadata_mapper2 = pool.get_imported_keystore_metadata()
    assert metadata_mapper2 == metadata_mapper

    keystore = pool.get_imported_keystore(keystore_uid)
    assert keystore.list_keypair_identifiers() == [
        dict(keychain_uid=keychain_uid, key_algo=key_algo, private_key_present=True)
    ]
    assert keystore.get_public_key(keychain_uid=keychain_uid, key_algo=key_algo) == b"555"
    assert keystore.get_private_key(keychain_uid=keychain_uid, key_algo=key_algo) == b"okj"


def test_generate_free_keypair_for_least_provisioned_key_algo():

    generated_keys_count = 0

    def keygen_func(key_algo, serialize):
        nonlocal generated_keys_count
        generated_keys_count += 1
        return dict(private_key=b"someprivatekey", public_key=b"somepublickey")

    # Check the fallback on "all types of keys" for key_algos parameter

    keystore = DummyKeystore()

    for _ in range(4):
        res = generate_free_keypair_for_least_provisioned_key_algo(
            keystore=keystore,
            max_free_keys_per_algo=10,
            keygen_func=keygen_func,
            # no key_algos parameter provided
        )
        assert res

    assert keystore.get_free_keypairs_count("DSA_DSS") == 1
    assert keystore.get_free_keypairs_count("ECC_DSS") == 1
    assert keystore.get_free_keypairs_count("RSA_OAEP") == 1
    assert keystore.get_free_keypairs_count("RSA_PSS") == 1
    assert generated_keys_count == 4

    # Now test with a restricted set of key types

    keystore = DummyKeystore()
    restricted_key_algos = ["DSA_DSS", "ECC_DSS", "RSA_OAEP"]
    generated_keys_count = 0

    for _ in range(7):
        res = generate_free_keypair_for_least_provisioned_key_algo(
            keystore=keystore, max_free_keys_per_algo=10, keygen_func=keygen_func, key_algos=restricted_key_algos
        )
        assert res

    assert keystore.get_free_keypairs_count("DSA_DSS") == 3
    assert keystore.get_free_keypairs_count("ECC_DSS") == 2
    assert keystore.get_free_keypairs_count("RSA_OAEP") == 2
    assert generated_keys_count == 7

    for _ in range(23):
        res = generate_free_keypair_for_least_provisioned_key_algo(
            keystore=keystore, max_free_keys_per_algo=10, keygen_func=keygen_func, key_algos=restricted_key_algos
        )
        assert res

    assert keystore.get_free_keypairs_count("DSA_DSS") == 10
    assert keystore.get_free_keypairs_count("ECC_DSS") == 10
    assert keystore.get_free_keypairs_count("RSA_OAEP") == 10
    assert generated_keys_count == 30

    res = generate_free_keypair_for_least_provisioned_key_algo(
        keystore=keystore, max_free_keys_per_algo=10, keygen_func=keygen_func, key_algos=restricted_key_algos
    )
    assert not res
    assert generated_keys_count == 30  # Unchanged

    for _ in range(7):
        generate_free_keypair_for_least_provisioned_key_algo(
            keystore=keystore, max_free_keys_per_algo=15, keygen_func=keygen_func, key_algos=["RSA_OAEP", "DSA_DSS"]
        )

    assert keystore.get_free_keypairs_count("DSA_DSS") == 14  # First in sorting order
    assert keystore.get_free_keypairs_count("ECC_DSS") == 10
    assert keystore.get_free_keypairs_count("RSA_OAEP") == 13
    assert generated_keys_count == 37

    res = generate_free_keypair_for_least_provisioned_key_algo(
        keystore=keystore, max_free_keys_per_algo=20, keygen_func=keygen_func, key_algos=restricted_key_algos
    )
    assert res
    assert keystore.get_free_keypairs_count("DSA_DSS") == 14
    assert keystore.get_free_keypairs_count("ECC_DSS") == 11
    assert keystore.get_free_keypairs_count("RSA_OAEP") == 13
    assert generated_keys_count == 38

    res = generate_free_keypair_for_least_provisioned_key_algo(
        keystore=keystore, max_free_keys_per_algo=5, keygen_func=keygen_func, key_algos=restricted_key_algos
    )
    assert not res
    assert generated_keys_count == 38


def test_get_free_keypair_generator_worker():

    generated_keys_count = 0

    keystore = DummyKeystore()

    def keygen_func(key_algo, serialize):
        nonlocal generated_keys_count
        generated_keys_count += 1
        time.sleep(0.01)
        return dict(private_key=b"someprivatekey2", public_key=b"somepublickey2")

    worker = get_free_keypair_generator_worker(
        keystore=keystore, max_free_keys_per_algo=30, sleep_on_overflow_s=0.5, keygen_func=keygen_func
    )

    try:
        worker.start()
        time.sleep(0.5)
        worker.stop()
        worker.join()

        assert 10 < generated_keys_count < 50, generated_keys_count  # Not enough time to generate all

        worker.start()
        time.sleep(6)
        worker.stop()
        worker.join()

        assert (
            generated_keys_count == 120  # 4 key types for now
        ), generated_keys_count  # All keys had the time to be generated

        print("NEW START")
        start = time.time()
        worker.start()
        time.sleep(0.01)
        worker.stop()
        print("NEW STOP")
        worker.join()
        print("NEW JOINED")
        end = time.time()
        assert (end - start) > 0.4  # sleep-on-overflow occurred

    finally:
        if worker.is_running:
            worker.stop()
