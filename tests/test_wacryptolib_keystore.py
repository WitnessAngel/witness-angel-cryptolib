# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import posixpath
import random
import secrets
import stat
import time
from contextlib import nullcontext
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock
from unittest.mock import ANY
from uuid import UUID

import pytest

from _test_mockups import (
    emulate_case_sensitive_filesystem,
    get_fake_authdevice,
    is_case_insensitive_filesystem,
    is_fallback_backend,
    random_bool,
    skip_if_fallback_backend,
    write_legacy_uppercase_algo_keystore,
)
from wacryptolib.authenticator import initialize_authenticator
from wacryptolib.exceptions import (
    KeystoreDoesNotExist,
    SchemaValidationError,
    ValidationError,
    KeyAlreadyExists,
    KeyDoesNotExist,
    KeystoreMetadataDoesNotExist,
    OperationNotSupported,
)
from wacryptolib.keygen import SUPPORTED_ASYMMETRIC_KEY_ALGOS, generate_keypair
import wacryptolib.keystore as keystore_module
from wacryptolib.keystore import (
    FilesystemKeystore,
    InMemoryKeystore,
    KeystoreBase,
    FilesystemKeystorePool,
    generate_free_keypair_for_least_provisioned_key_algo,
    get_free_keypair_generator_worker,
    DEFAULT_FREE_KEYPAIR_ALGOS,
    generate_keypair_for_storage,
    ReadonlyFilesystemKeystore,
    KEYSTORE_FORMAT,
    InMemoryKeystorePool,
    _get_keystore_metadata_file_path,
)
from wacryptolib.operations import check_authenticator
from wacryptolib.scaffolding import (
    check_keystore_free_keys_concurrency,
    check_keystore_basic_get_set_api,
    check_keystore_free_keys_api,
)
from wacryptolib.utilities import generate_uuid0, get_utc_now_date, dump_to_json_file


def test_keystore_basic_get_set_api(tmp_path):
    tmp_path1 = tmp_path / "subdir1"
    tmp_path1.mkdir()
    tmp_path2 = tmp_path / "subdir2"
    tmp_path2.mkdir()

    with pytest.raises(TypeError, match="Can't instantiate abstract class"):
        KeystoreBase()

    dummy_keystore = InMemoryKeystore()
    filesystem_keystore = FilesystemKeystore(keys_dir=tmp_path1)
    readonly_filesystem_keystore = ReadonlyFilesystemKeystore(keys_dir=tmp_path1)

    class IntolerantKeystore(FilesystemKeystore):
        """Some keystores might be unable to list keypairs, e.g. servers with big databases"""

        def list_keypair_identifiers(self, *args, **kwargs) -> list:
            raise OperationNotSupported

    intolerant_keystore = IntolerantKeystore(keys_dir=tmp_path2)

    filesystem_keystore_test_locals = None
    for keystore, readonly_keystore in [
        (dummy_keystore, None),
        (intolerant_keystore, None),
        (filesystem_keystore, readonly_filesystem_keystore),
    ]:
        res = check_keystore_basic_get_set_api(keystore=keystore, readonly_keystore=readonly_keystore)
        if keystore.__class__ == FilesystemKeystore:
            filesystem_keystore_test_locals = res

    # Specific tests for filesystem storage

    keychain_uid = filesystem_keystore_test_locals["keychain_uid"]

    is_public = random_bool()
    key_filename = "%s_abxz_%s_key.pem" % (keychain_uid, "public" if is_public else "private")  # Lowercase algo
    filepath = filesystem_keystore._keys_dir / key_filename
    with open(filepath, "rb") as f:
        key_data = f.read()
        assert key_data == (b"public_data" if is_public else b"private_data")  # IMPORTANT no exchange of keys in files!


def test_keystore_free_keys_api(tmp_path):
    dummy_keystore = InMemoryKeystore()
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
        "set_keypair",
        "set_public_key",
        "set_private_key",
        "get_free_keypairs_count",
        "add_free_keypair",
        "attach_free_keypair_to_uuid",
        "_write_to_storage_file",
    ]

    for forbidden_field in forbidden_fields:
        assert hasattr(normal_keystore, forbidden_field)
        assert not hasattr(readonly_keystore, forbidden_field)


def test_keystore_free_keys_concurrency(tmp_path):
    dummy_keystore = InMemoryKeystore()
    filesystem_keystore = FilesystemKeystore(keys_dir=tmp_path)

    for keystore in (dummy_keystore, filesystem_keystore):
        check_keystore_free_keys_concurrency(keystore)


def test_filesystem_keystore_list_keypair_identifiers(tmp_path: Path):
    def _check_key_dict_format(key):
        print(">> public key detected:", key)

        assert isinstance(key["keychain_uid"], UUID)
        assert key["key_algo"] in SUPPORTED_ASYMMETRIC_KEY_ALGOS
        assert isinstance(key["private_key_present"], bool)

    key_algos = SUPPORTED_ASYMMETRIC_KEY_ALGOS
    if is_fallback_backend():  # Post-quantum keys are only implemented by pycryptodome
        key_algos = [key_algo for key_algo in key_algos if not key_algo.startswith("ML_")]

    keystore = FilesystemKeystore(tmp_path)
    assert keystore.list_keypair_identifiers() == []

    # CASE 1 : only one key in storage

    key_algo = random.choice(key_algos)

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
        _key_algo = random.choice(key_algos)
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


def test_in_memory_keystore_pool_corner_cases():
    keystore_uid = generate_uuid0()

    pool = InMemoryKeystorePool()

    assert pool.get_local_keyfactory()
    with pytest.raises(KeystoreDoesNotExist):
        pool.get_foreign_keystore(keystore_uid)

    assert pool.list_foreign_keystore_uids() == []


def test_filesystem_keystore_pool_basics(tmp_path: Path):
    pool = FilesystemKeystorePool(tmp_path)

    assert pool.get_all_foreign_keystore_metadata() == {}

    local_keystore = pool.get_local_keyfactory()
    assert isinstance(local_keystore, FilesystemKeystore)
    assert not local_keystore.list_keypair_identifiers()

    keypair = generate_keypair_for_storage(key_algo="RSA_OAEP", keystore=local_keystore, passphrase="xzf".encode())

    assert len(local_keystore.list_keypair_identifiers()) == 1

    assert pool.list_foreign_keystore_uids() == []

    foreign_keystore_uid = generate_uuid0()
    mirror_path = tmp_path.joinpath(
        pool.FOREIGN_KEYSTORES_DIRNAME, pool.FOREIGN_KEYSTORE_PREFIX + str(foreign_keystore_uid)
    )
    mirror_path.mkdir(parents=True, exist_ok=False)

    foreign_keystore_uid2 = generate_uuid0()
    mirror_path2 = tmp_path.joinpath(
        pool.FOREIGN_KEYSTORES_DIRNAME, pool.FOREIGN_KEYSTORE_PREFIX + str(foreign_keystore_uid2)
    )
    mirror_path2.mkdir(parents=True, exist_ok=False)

    assert pool.list_foreign_keystore_uids() == sorted([foreign_keystore_uid, foreign_keystore_uid2])

    with pytest.raises(KeystoreMetadataDoesNotExist):
        pool.get_all_foreign_keystore_metadata()
    with pytest.raises(KeystoreMetadataDoesNotExist):  # Error raised immediately
        pool.get_foreign_keystore_metadata(foreign_keystore_uid)

    with pytest.raises(KeystoreDoesNotExist, match="not found"):
        pool.get_foreign_keystore(generate_uuid0())

    foreign_keystore = pool.get_foreign_keystore(foreign_keystore_uid)
    assert isinstance(foreign_keystore, ReadonlyFilesystemKeystore)
    assert not isinstance(foreign_keystore, FilesystemKeystore)  # NOT writable

    foreign_keystore = pool.get_foreign_keystore(foreign_keystore_uid, writable=True)
    assert isinstance(foreign_keystore, ReadonlyFilesystemKeystore)
    assert isinstance(foreign_keystore, FilesystemKeystore)  # Writable

    assert not foreign_keystore.list_keypair_identifiers()

    foreign_keystore.set_keypair(
        keychain_uid=generate_uuid0(),
        key_algo="RSA_OAEP",
        public_key=keypair["public_key"],
        private_key=keypair["private_key"],
    )

    assert len(local_keystore.list_keypair_identifiers()) == 1  # Unchanged
    assert len(foreign_keystore.list_keypair_identifiers()) == 1

    foreign_keystore2 = pool.get_foreign_keystore(foreign_keystore_uid2)
    assert isinstance(foreign_keystore2, ReadonlyFilesystemKeystore)
    assert not isinstance(foreign_keystore2, FilesystemKeystore)
    assert not foreign_keystore2.list_keypair_identifiers()


def test_keystore_export_from_keystore_tree(tmp_path: Path):
    authdevice_path = tmp_path / "device1"
    authdevice_path.mkdir()
    authdevice = get_fake_authdevice(authdevice_path)

    remote_keystore_dir = authdevice["authenticator_dir"]

    metadata = initialize_authenticator(
        remote_keystore_dir, keystore_owner="Jean-Jâcques", keystore_passphrase_hint="my-hint"
    )

    extra_fields_schema = {"keystore_creation_datetime": ANY}
    use_legacy_format = random_bool()
    if use_legacy_format:
        del metadata["keystore_creation_datetime"]
        metadata_file = _get_keystore_metadata_file_path(authdevice["authenticator_dir"])
        dump_to_json_file(metadata_file, metadata)
        extra_fields_schema = {}

    remote_keystore = FilesystemKeystore(remote_keystore_dir)

    keychain_uid = generate_uuid0()
    key_algo = "RSA_OAEP"

    remote_keystore.set_keypair(keychain_uid=keychain_uid, key_algo=key_algo, public_key=b"555", private_key=b"okj")

    keystore_tree = remote_keystore.export_to_keystore_tree(include_private_keys=True)
    assert keystore_tree == {
        "keypairs": [
            {"key_algo": "RSA_OAEP", "keychain_uid": keychain_uid, "private_key": b"okj", "public_key": b"555"}
        ],
        "keystore_format": "keystore_1.0",
        "keystore_owner": "Jean-Jâcques",
        "keystore_passphrase_hint": "my-hint",
        "keystore_secret": ANY,
        "keystore_type": "authenticator",
        "keystore_uid": ANY,
        **extra_fields_schema,
    }
    if "keystore_creation_datetime" in extra_fields_schema:
        assert isinstance(keystore_tree["keystore_creation_datetime"], datetime)

    keystore_tree = remote_keystore.export_to_keystore_tree(include_private_keys=False)
    assert keystore_tree == {
        "keypairs": [{"key_algo": "RSA_OAEP", "keychain_uid": keychain_uid, "private_key": None, "public_key": b"555"}],
        "keystore_format": "keystore_1.0",
        "keystore_owner": "Jean-Jâcques",
        "keystore_passphrase_hint": "my-hint",
        "keystore_secret": ANY,
        "keystore_type": "authenticator",
        "keystore_uid": ANY,
        **extra_fields_schema,
    }
    if "keystore_creation_datetime" in extra_fields_schema:
        assert isinstance(keystore_tree["keystore_creation_datetime"], datetime)

    with pytest.raises(SchemaValidationError):
        # FIXME - set_keypair() should actually validate data too
        remote_keystore.set_keypair(
            keychain_uid=keychain_uid, key_algo="bad_algo", public_key=b"555", private_key=b"okj"
        )
        remote_keystore.export_to_keystore_tree()  # Raises because of bad_algo

    # Create uninitialized keystore (no metadata file) and try to export it
    authdevice_path = tmp_path / "device2"
    authdevice_path.mkdir()
    authdevice = get_fake_authdevice(authdevice_path)
    remote_keystore_dir = authdevice["authenticator_dir"]
    remote_keystore_dir.mkdir()
    remote_keystore = FilesystemKeystore(remote_keystore_dir)
    with pytest.raises(KeystoreDoesNotExist):
        remote_keystore.export_to_keystore_tree()


def test_keystore_tree_export_with_lowercase_key_algo(tmp_path: Path):
    initialize_authenticator(tmp_path, keystore_owner="Owner", keystore_passphrase_hint="hint")
    keystore = FilesystemKeystore(tmp_path)
    keystore.set_keypair(  # Lowercase algo names are normalized, so they don't break exports
        keychain_uid=generate_uuid0(), key_algo="rsa_oaep", public_key=b"pub", private_key=b"priv"
    )
    keystore_tree = keystore.export_to_keystore_tree()
    assert [keypair["key_algo"] for keypair in keystore_tree["keypairs"]] == ["RSA_OAEP"]


def test_keystore_set_keypair_assertion_does_not_leak_keys(tmp_path: Path):
    keystore = FilesystemKeystore(tmp_path)
    with pytest.raises(AssertionError) as exc_info:
        keystore.set_keypair(
            keychain_uid=generate_uuid0(), key_algo="RSA_OAEP", public_key=b"", private_key=b"SECRETPRIVATEKEY"
        )
    assert b"SECRETPRIVATEKEY" not in str(exc_info.value).encode()


def test_keystore_tree_export_and_import_with_all_asymmetric_key_algos(tmp_path: Path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    initialize_authenticator(source_dir, keystore_owner="Owner", keystore_passphrase_hint="hint")
    source_keystore = FilesystemKeystore(source_dir)

    keychain_uid = generate_uuid0()
    for key_algo in SUPPORTED_ASYMMETRIC_KEY_ALGOS:  # Including signature-only algos like ML_DSA_65
        source_keystore.set_keypair(  # Lowercase algo names are normalized, so they don't break exports
            keychain_uid=keychain_uid, key_algo=key_algo.lower(), public_key=b"pub", private_key=b"priv"
        )

    keystore_tree = source_keystore.export_to_keystore_tree()
    assert sorted(keypair["key_algo"] for keypair in keystore_tree["keypairs"]) == sorted(SUPPORTED_ASYMMETRIC_KEY_ALGOS)

    target_dir = tmp_path / "target"
    target_dir.mkdir()
    target_keystore = FilesystemKeystore(target_dir)
    assert not target_keystore.import_from_keystore_tree(keystore_tree)  # Created, not updated
    for key_algo in SUPPORTED_ASYMMETRIC_KEY_ALGOS:
        assert target_keystore.get_private_key(keychain_uid=keychain_uid, key_algo=key_algo) == b"priv"


def test_keystore_import_from_keystore_tree(tmp_path: Path):
    authdevice_path = tmp_path / "device"
    authdevice_path.mkdir()
    filesystem_keystore = FilesystemKeystore(authdevice_path)

    keystore_uid = generate_uuid0()
    keychain_uid = generate_uuid0()
    keychain_uid_bis = generate_uuid0()
    key_algo = "RSA_OAEP"
    keystore_secret = secrets.token_urlsafe(64)

    keypairs1 = [{"keychain_uid": keychain_uid, "key_algo": key_algo, "public_key": b"555", "private_key": None}]
    keypairs2 = [
        {"keychain_uid": keychain_uid, "key_algo": key_algo, "public_key": b"8888", "private_key": b"okj"},
        {"keychain_uid": keychain_uid_bis, "key_algo": key_algo, "public_key": b"23", "private_key": b"3234"},
    ]

    keystore_tree = {
        # These are MANDATORY FIELDS
        "keystore_type": "authenticator",
        "keystore_format": KEYSTORE_FORMAT,
        "keystore_owner": "Jacques",
        "keystore_uid": keystore_uid,
        "keypairs": keypairs1,
    }

    use_keystore_secret = random_bool()
    if use_keystore_secret:
        keystore_tree["keystore_secret"] = keystore_secret

    use_keystore_creation_datetime = random_bool()
    if use_keystore_creation_datetime:
        keystore_tree["keystore_creation_datetime"] = get_utc_now_date()

    use_keystore_passphrase_hint = random_bool()
    if use_keystore_passphrase_hint:
        keystore_tree["keystore_passphrase_hint"] = secrets.token_urlsafe(20)

    keystore_tree_metadata = keystore_tree.copy()
    del keystore_tree_metadata["keypairs"]

    # Initial import

    updated = filesystem_keystore.import_from_keystore_tree(keystore_tree)
    assert not updated

    metadata = filesystem_keystore.get_keystore_metadata()

    def _check_loaded_metadata_coherence(loaded_metadata):
        # Quick checks
        assert loaded_metadata["keystore_uid"] == keystore_uid
        assert loaded_metadata["keystore_owner"] == "Jacques"

        assert len(loaded_metadata) == len(keystore_tree_metadata)

        for key, value in keystore_tree_metadata.items():
            if key == "keystore_creation_datetime":
                # Special case: precision trouble because Bson only goes down to milliseconds
                assert (value - loaded_metadata[key]) <= timedelta(milliseconds=1)
            else:
                assert loaded_metadata[key] == value

    _check_loaded_metadata_coherence(metadata)

    assert filesystem_keystore.list_keypair_identifiers() == [
        dict(keychain_uid=keychain_uid, key_algo=key_algo, private_key_present=False)
    ]
    assert filesystem_keystore.get_public_key(keychain_uid=keychain_uid, key_algo=key_algo) == b"555"
    with pytest.raises(KeyDoesNotExist):
        filesystem_keystore.get_private_key(keychain_uid=keychain_uid, key_algo=key_algo)

    # Update import

    for i in range(2):  # IDEMPOTENT
        keystore_tree["keystore_owner"] += "_corrupted"  # Corrupted, but not taken into account on update!

        keystore_tree["keypairs"] = keypairs2
        updated = filesystem_keystore.import_from_keystore_tree(keystore_tree)
        assert updated

        metadata = filesystem_keystore.get_keystore_metadata()
        _check_loaded_metadata_coherence(metadata)

        expected_keypair_identifiers = [
            dict(keychain_uid=keychain_uid, key_algo=key_algo, private_key_present=True),
            dict(keychain_uid=keychain_uid_bis, key_algo=key_algo, private_key_present=True),
        ]
        expected_keypair_identifiers.sort(key=lambda x: (x["keychain_uid"], x["key_algo"]))
        assert filesystem_keystore.list_keypair_identifiers() == expected_keypair_identifiers
        assert filesystem_keystore.get_public_key(keychain_uid=keychain_uid, key_algo=key_algo) == b"555"  # NOT changed
        assert filesystem_keystore.get_private_key(keychain_uid=keychain_uid, key_algo=key_algo) == b"okj"  # Added

    # Mismatch of keystore_uid
    keystore_tree["keystore_uid"] = generate_uuid0()
    with pytest.raises(ValidationError, match="Mismatch"):
        filesystem_keystore.import_from_keystore_tree(keystore_tree)

    # Corrupt the keystore_tree with extra key
    keystore_tree["keystore_stuff"] = 33
    with pytest.raises(SchemaValidationError):
        filesystem_keystore.import_from_keystore_tree(keystore_tree)
    del keystore_tree["keystore_stuff"]

    # Corrupt the keystore_tree with bad content
    keystore_tree["keystore_owner"] = 2242
    with pytest.raises(SchemaValidationError):
        filesystem_keystore.import_from_keystore_tree(keystore_tree)
    keystore_tree["keystore_owner"] = "Jacques"

    # Corrupt the keystore_tree with missing key
    del keystore_tree["keystore_owner"]
    with pytest.raises(SchemaValidationError):
        filesystem_keystore.import_from_keystore_tree(keystore_tree)


def test_keystorepool_export_and_import_foreign_keystore_to_keystore_tree(tmp_path: Path):
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

    for idx in range(2):  # Import is idempotent
        keystore_pool = FilesystemKeystorePool(authdevice_path)
        updated = keystore_pool.import_foreign_keystore_from_keystore_tree(keystore_tree)
        assert updated == bool(idx)  # Second import is an update

        metadata = keystore_pool.get_foreign_keystore_metadata(keystore_uid)

        # We test this utility along the way
        all_metadata = keystore_pool.get_all_foreign_keystore_metadata()
        assert all_metadata == {metadata["keystore_uid"]: metadata}  # Only a single entry here

        keystore_tree = keystore_pool.export_foreign_keystore_to_keystore_tree(
            metadata["keystore_uid"], include_private_keys=True
        )

        foreign_keystore = keystore_pool.get_foreign_keystore(keystore_uid)

        assert foreign_keystore.list_keypair_identifiers() == [
            dict(keychain_uid=keychain_uid, key_algo=key_algo, private_key_present=True)
        ]
        assert (
            foreign_keystore.get_public_key(keychain_uid=keychain_uid, key_algo=key_algo)
            == keystore_tree["keypairs"][0]["public_key"]
        )
        assert (
            foreign_keystore.get_private_key(keychain_uid=keychain_uid, key_algo=key_algo)
            == keystore_tree["keypairs"][0]["private_key"]
        )


def _build_minimal_keystore_tree(keystore_uid, keystore_secret, public_keys_by_keychain_uid: dict):
    return {
        "keystore_type": "authenticator",
        "keystore_format": KEYSTORE_FORMAT,
        "keystore_owner": "Jacques",
        "keystore_uid": keystore_uid,
        "keystore_secret": keystore_secret,
        "keypairs": [
            {"keychain_uid": keychain_uid, "key_algo": "RSA_OAEP", "public_key": public_key, "private_key": b"okj"}
            for keychain_uid, public_key in public_keys_by_keychain_uid.items()
        ],
    }


PLATFORM_IGNORES_CASE = os.path.normcase("A") == "a"  # Like Windows, which compares file names case-insensitively


def _import_minimal_foreign_keystore(keystore_pool, public_keys_by_keychain_uid: dict, keystore_uid=None):
    keystore_uid = keystore_uid or generate_uuid0()
    keystore_pool.import_foreign_keystore_from_keystore_tree(
        _build_minimal_keystore_tree(keystore_uid, "secret-%s" % keystore_uid, public_keys_by_keychain_uid)
    )
    return keystore_uid


def test_keystorepool_foreign_keystore_dir_in_uppercase(tmp_path: Path):
    keychain_uid, new_keychain_uid = generate_uuid0(), generate_uuid0()
    keystore_pool = FilesystemKeystorePool(tmp_path)
    keystore_uid = _import_minimal_foreign_keystore(keystore_pool, {keychain_uid: b"555"})
    foreign_keystores_dir = tmp_path / keystore_pool.FOREIGN_KEYSTORES_DIRNAME
    canonical_dirname = "keystore_%s" % keystore_uid
    assert os.listdir(foreign_keystores_dir) == [canonical_dirname]  # New directories are lowercase

    uppercase_dirname = canonical_dirname.upper()  # Like a keystore copied by hand or by FAT tools
    (foreign_keystores_dir / canonical_dirname).rename(foreign_keystores_dir / uppercase_dirname)

    with mock.patch.object(keystore_module, "logger") as logger_mock:
        keystore_uids = keystore_pool.list_foreign_keystore_uids()
    assert not logger_mock.warning.called

    if not PLATFORM_IGNORES_CASE:
        assert keystore_uids == []  # Not a foreign keystore name on this platform
        return

    assert keystore_uids == [keystore_uid]
    assert keystore_pool.get_foreign_keystore_metadata(keystore_uid)["keystore_uid"] == keystore_uid
    foreign_keystore = keystore_pool.get_foreign_keystore(keystore_uid)
    assert foreign_keystore.get_public_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == b"555"

    # Importing again completes the existing directory, without creating another one
    _import_minimal_foreign_keystore(
        keystore_pool, {keychain_uid: b"555", new_keychain_uid: b"666"}, keystore_uid=keystore_uid
    )
    foreign_keystore = keystore_pool.get_foreign_keystore(keystore_uid)
    assert foreign_keystore.get_public_key(keychain_uid=new_keychain_uid, key_algo="RSA_OAEP") == b"666"
    assert os.listdir(foreign_keystores_dir) == [uppercase_dirname]  # Not renamed


def test_keystorepool_foreign_keystore_dir_with_uppercase_uuid(tmp_path: Path):
    keychain_uid = generate_uuid0()
    keystore_pool = FilesystemKeystorePool(tmp_path)
    keystore_uid = _import_minimal_foreign_keystore(keystore_pool, {keychain_uid: b"555"})
    foreign_keystores_dir = tmp_path / keystore_pool.FOREIGN_KEYSTORES_DIRNAME
    uppercase_uuid_dirname = "keystore_%s" % str(keystore_uid).upper()
    (foreign_keystores_dir / ("keystore_%s" % keystore_uid)).rename(foreign_keystores_dir / uppercase_uuid_dirname)

    with mock.patch.object(keystore_module, "logger") as logger_mock:
        keystore_uids = keystore_pool.list_foreign_keystore_uids()

    if PLATFORM_IGNORES_CASE:
        assert keystore_uids == [keystore_uid]
        assert not logger_mock.warning.called
        foreign_keystore = keystore_pool.get_foreign_keystore(keystore_uid)
        assert foreign_keystore.get_public_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == b"555"
    else:
        assert keystore_uids == []  # It couldn't be opened at its canonical path
        assert uppercase_uuid_dirname in str(logger_mock.warning.call_args_list)
    assert os.listdir(foreign_keystores_dir) == [uppercase_uuid_dirname]  # Not renamed


def test_keystorepool_unparsable_foreign_keystore_dirs(tmp_path: Path):
    keystore_pool = FilesystemKeystorePool(tmp_path)
    keystore_uid = _import_minimal_foreign_keystore(keystore_pool, {generate_uuid0(): b"555"})
    foreign_keystores_dir = tmp_path / keystore_pool.FOREIGN_KEYSTORES_DIRNAME
    abnormal_dirnames = ["keystore_backup", "keystore_%s" % generate_uuid0().hex]  # The latter has no dashes
    for dirname in abnormal_dirnames + ["temp_import_dir"]:
        (foreign_keystores_dir / dirname).mkdir()

    with mock.patch.object(keystore_module, "logger") as logger_mock:
        assert keystore_pool.list_foreign_keystore_uids() == [keystore_uid]
    warnings = str(logger_mock.warning.call_args_list)
    for dirname in abnormal_dirnames:
        assert dirname in warnings
    assert "temp_import_dir" not in warnings  # Not a foreign keystore


def test_generate_free_keypair_for_least_provisioned_key_algo():
    generated_keys_count = 0

    def keygen_func(key_algo, serialize):
        nonlocal generated_keys_count
        generated_keys_count += 1
        return dict(private_key=b"someprivatekey", public_key=b"somepublickey")

    # Check the fallback on "all classical types of keys" for key_algos parameter

    assert "RSA_OAEP" in DEFAULT_FREE_KEYPAIR_ALGOS
    assert isinstance(DEFAULT_FREE_KEYPAIR_ALGOS, tuple)  # Not mutable by accident
    assert "ML_KEM_768" not in DEFAULT_FREE_KEYPAIR_ALGOS  # Post-quantum keypairs are opt-in
    assert "ML_DSA_65" not in DEFAULT_FREE_KEYPAIR_ALGOS

    keystore = InMemoryKeystore()

    for _ in range(len(DEFAULT_FREE_KEYPAIR_ALGOS)):
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
    for opt_in_key_algo in ("ECIES_X25519", "ML_KEM_768", "ML_DSA_65"):  # New key algos are opt-in
        assert keystore.get_free_keypairs_count(opt_in_key_algo) == 0
    assert generated_keys_count == 4

    keystore = InMemoryKeystore()
    generate_free_keypair_for_least_provisioned_key_algo(
        keystore=keystore, max_free_keys_per_algo=1, keygen_func=keygen_func, key_algos=["rsa_oaep"]
    )
    assert keystore.get_free_keypairs_count("RSA_OAEP") == 1  # Algo names are normalized to uppercase

    # Now test with a restricted set of key types

    keystore = InMemoryKeystore()
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

    keystore = InMemoryKeystore()

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
            generated_keys_count == 120  # 4 default key types
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


def test_filesystem_keystore_lists_post_quantum_keypairs(tmp_path: Path):
    skip_if_fallback_backend("ML-KEM/ML-DSA")
    # Key algo names with digits (ML_KEM_768, ML_DSA_65) must be accepted by the filename regex
    keystore = FilesystemKeystore(tmp_path)
    keychain_uid_1 = generate_uuid0()
    keychain_uid_2 = generate_uuid0()
    generate_keypair_for_storage(key_algo="ML_KEM_768", keystore=keystore, keychain_uid=keychain_uid_1)
    generate_keypair_for_storage(key_algo="ML_DSA_65", keystore=keystore, keychain_uid=keychain_uid_2, passphrase=b"xyz")
    tmp_path.joinpath("%s_ml_dsa_65_private_key.pem" % keychain_uid_2).unlink()  # Only public key remains

    keys_list = keystore.list_keypair_identifiers()
    assert keys_list == sorted(
        [
            dict(keychain_uid=keychain_uid_1, key_algo="ML_KEM_768", private_key_present=True),
            dict(keychain_uid=keychain_uid_2, key_algo="ML_DSA_65", private_key_present=False),
        ],
        key=lambda x: (x["keychain_uid"], x["key_algo"]),
    )


# --- Lowercase on-disk algo names, with fallback on legacy uppercase algo names of earlier releases ---


def _generate_pem_keypair(key_algo):
    return generate_keypair(key_algo=key_algo, serialize=True)


def test_filesystem_keystore_writes_lowercase_names(tmp_path: Path):
    keystore = FilesystemKeystore(tmp_path)
    keychain_uid = generate_uuid0()
    keypair = _generate_pem_keypair("RSA_OAEP")
    keystore.set_keypair(keychain_uid=keychain_uid, key_algo="RSA_OAEP", **keypair)

    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "%s_rsa_oaep_private_key.pem" % keychain_uid,
        "%s_rsa_oaep_public_key.pem" % keychain_uid,
    ]
    assert keystore.get_public_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == keypair["public_key"]

    keystore.add_free_keypair(key_algo="RSA_OAEP", **keypair)
    assert [p.name for p in (tmp_path / "free_keys").iterdir()] == ["rsa_oaep"]


def test_filesystem_keystore_legacy_uppercase_algo_keys_are_found(tmp_path: Path):
    keychain_uid = generate_uuid0()
    keypair = _generate_pem_keypair("RSA_OAEP")
    write_legacy_uppercase_algo_keystore(tmp_path, [(keychain_uid, "RSA_OAEP", keypair)])
    names_before = sorted(p.name for p in tmp_path.iterdir())

    with emulate_case_sensitive_filesystem(), mock.patch.object(keystore_module, "logger") as logger_mock:
        keystore = FilesystemKeystore(tmp_path)
        assert keystore.get_public_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == keypair["public_key"]
        assert keystore.get_private_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == keypair["private_key"]
        assert keystore.get_public_key(keychain_uid=keychain_uid, key_algo="rsa_oaep") == keypair["public_key"]
        assert keystore.list_keypair_identifiers() == [
            dict(keychain_uid=keychain_uid, key_algo="RSA_OAEP", private_key_present=True)
        ]

        readonly_keystore = ReadonlyFilesystemKeystore(tmp_path)
        assert readonly_keystore.get_public_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == keypair["public_key"]

        # Setting over an existing legacy keypair must not create a lowercase twin
        with pytest.raises(KeyAlreadyExists):
            keystore.set_keypair(keychain_uid=keychain_uid, key_algo="RSA_OAEP", **_generate_pem_keypair("RSA_OAEP"))

    assert not logger_mock.warning.called and not logger_mock.error.called  # The fallback is silent
    assert sorted(p.name for p in tmp_path.iterdir()) == names_before  # No file created/renamed/deleted


def test_filesystem_keystore_lowercase_key_files_take_precedence(tmp_path: Path):
    keychain_uid = generate_uuid0()
    keystore = FilesystemKeystore(tmp_path)
    keystore.set_keypair(keychain_uid=keychain_uid, key_algo="RSA_OAEP", public_key=b"pub", private_key=b"priv")
    lowercase_names = ["%s_rsa_oaep_%s_key.pem" % (keychain_uid, kind) for kind in ("public", "private")]
    legacy_names = ["%s_RSA_OAEP_%s_key.pem" % (keychain_uid, kind) for kind in ("public", "private")]

    # Make legacy uppercase twins seem to exist as distinct files, like on a case-sensitive filesystem
    original_stat_if_existing = keystore_module._stat_if_existing
    original_list_key_filenames = ReadonlyFilesystemKeystore._list_key_filenames

    def fake_stat_if_existing(path):
        if path.name in legacy_names:  # Exact comparison, whereas Windows paths compare case-insensitively
            fake_inode = 10**12 + legacy_names.index(path.name)
            return os.stat_result((stat.S_IFREG | 0o644, fake_inode, 1234, 1, 0, 0, 1, 0, 0, 0))
        return original_stat_if_existing(path)

    def fake_list_key_filenames(self):
        return original_list_key_filenames(self) + legacy_names

    with mock.patch.object(keystore_module, "_stat_if_existing", fake_stat_if_existing), mock.patch.object(
        ReadonlyFilesystemKeystore, "_list_key_filenames", fake_list_key_filenames
    ), mock.patch.object(keystore_module, "logger") as logger_mock:
        for is_public, lowercase_name in zip((True, False), lowercase_names):
            existing_filepath = keystore._get_existing_key_filepath(keychain_uid, "RSA_OAEP", is_public=is_public)
            assert existing_filepath.name == lowercase_name
        assert keystore.get_public_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == b"pub"
        assert keystore.get_private_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == b"priv"
        assert keystore.list_keypair_identifiers() == [
            dict(keychain_uid=keychain_uid, key_algo="RSA_OAEP", private_key_present=True)
        ]
    assert not logger_mock.warning.called and not logger_mock.error.called


def test_filesystem_keystore_lowercase_key_files_take_precedence_with_real_files(tmp_path: Path):
    if is_case_insensitive_filesystem(tmp_path):
        pytest.skip("Distinct files differing only in case can't coexist on a case-insensitive filesystem")
    keychain_uid = generate_uuid0()
    for kind in ("public", "private"):
        (tmp_path / ("%s_rsa_oaep_%s_key.pem" % (keychain_uid, kind))).write_bytes(b"new_" + kind.encode())
        (tmp_path / ("%s_RSA_OAEP_%s_key.pem" % (keychain_uid, kind))).write_bytes(b"old_" + kind.encode())
    lowercase_private_key_name = "%s_rsa_oaep_private_key.pem" % keychain_uid
    names_before = sorted(p.name for p in tmp_path.iterdir())

    keystore = FilesystemKeystore(tmp_path)
    with mock.patch.object(keystore_module, "logger") as logger_mock:
        assert keystore.get_public_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == b"new_public"
        assert keystore.get_private_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == b"new_private"
        assert keystore.list_keypair_identifiers() == [
            dict(keychain_uid=keychain_uid, key_algo="RSA_OAEP", private_key_present=True)
        ]
        with pytest.raises(KeyAlreadyExists):
            keystore.set_keypair(keychain_uid=keychain_uid, key_algo="RSA_OAEP", public_key=b"x", private_key=b"y")

        # Each key file falls back on its own, so the halves of a keypair may have different spellings
        (tmp_path / lowercase_private_key_name).unlink()
        assert keystore.get_public_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == b"new_public"
        assert keystore.get_private_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == b"old_private"
        assert keystore.list_keypair_identifiers()[0]["private_key_present"]
    assert not logger_mock.warning.called and not logger_mock.error.called
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        name for name in names_before if name != lowercase_private_key_name
    ]


@pytest.mark.parametrize("emulate_case_sensitivity", [False, True])
def test_filesystem_keystore_set_private_key_next_to_legacy_public_key(tmp_path: Path, emulate_case_sensitivity):
    keychain_uid = generate_uuid0()
    keypair = _generate_pem_keypair("RSA_OAEP")
    legacy_public_key_name = "%s_RSA_OAEP_public_key.pem" % keychain_uid
    (tmp_path / legacy_public_key_name).write_bytes(keypair["public_key"])

    with emulate_case_sensitive_filesystem() if emulate_case_sensitivity else nullcontext():
        keystore = FilesystemKeystore(tmp_path)
        assert not keystore.list_keypair_identifiers()[0]["private_key_present"]
        keystore.set_private_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP", private_key=keypair["private_key"])
        assert keystore.get_public_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == keypair["public_key"]
        assert keystore.get_private_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == keypair["private_key"]
        assert keystore.list_keypair_identifiers() == [
            dict(keychain_uid=keychain_uid, key_algo="RSA_OAEP", private_key_present=True)
        ]

    # New key files are always lowercase, so this keypair is split across spellings, each half being found on its own
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(
        ["%s_rsa_oaep_private_key.pem" % keychain_uid, legacy_public_key_name]
    )


def test_filesystem_keystore_import_private_keys_next_to_legacy_public_keys(tmp_path: Path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    initialize_authenticator(source_dir, keystore_owner="owner", keystore_passphrase_hint="hint")
    keychain_uids = [generate_uuid0(), generate_uuid0()]
    keypairs = [_generate_pem_keypair("RSA_OAEP") for _ in keychain_uids]
    write_legacy_uppercase_algo_keystore(source_dir, [(uid, "RSA_OAEP", kp) for uid, kp in zip(keychain_uids, keypairs)])
    with emulate_case_sensitive_filesystem():
        keystore_tree = ReadonlyFilesystemKeystore(source_dir).export_to_keystore_tree(include_private_keys=True)

    # An earlier import, with public keys only, by a release writing uppercase names
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    for keychain_uid in keychain_uids:
        public_key_name = "%s_RSA_OAEP_public_key.pem" % keychain_uid
        (target_dir / public_key_name).write_bytes((source_dir / public_key_name).read_bytes())

    with emulate_case_sensitive_filesystem():
        target_keystore = FilesystemKeystore(target_dir)
        target_keystore.import_from_keystore_tree(keystore_tree)
        for keychain_uid, keypair in zip(keychain_uids, keypairs):
            assert target_keystore.get_public_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == keypair["public_key"]
            assert (
                target_keystore.get_private_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == keypair["private_key"]
            )

    assert sorted(p.name for p in target_dir.glob("*.pem")) == sorted(
        name
        for keychain_uid in keychain_uids
        for name in ("%s_RSA_OAEP_public_key.pem" % keychain_uid, "%s_rsa_oaep_private_key.pem" % keychain_uid)
    )


def test_filesystem_keystore_listing_skips_non_canonical_uuid_file_names(tmp_path: Path):
    keychain_uid = generate_uuid0()
    non_canonical_public_key_name = "%s_rsa_oaep_public_key.pem" % keychain_uid.hex  # UUID without dashes
    for kind in ("public", "private"):
        (tmp_path / ("%s_rsa_oaep_%s_key.pem" % (keychain_uid.hex, kind))).write_bytes(b"data")

    keystore = FilesystemKeystore(tmp_path)
    with mock.patch.object(keystore_module, "logger") as logger_mock:
        assert keystore.list_keypair_identifiers() == []  # They couldn't be fetched
    assert non_canonical_public_key_name in str(logger_mock.warning.call_args)

    # With the canonical public key present too, only it is listed, whatever the listing order
    keystore.set_public_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP", public_key=b"pub")
    for key_filenames in (sorted(os.listdir(tmp_path)), sorted(os.listdir(tmp_path), reverse=True)):
        with mock.patch.object(ReadonlyFilesystemKeystore, "_list_key_filenames", return_value=key_filenames):
            assert keystore.list_keypair_identifiers() == [
                dict(keychain_uid=keychain_uid, key_algo="RSA_OAEP", private_key_present=False)
            ]


def test_filesystem_keystore_algo_names_without_letters(tmp_path: Path):
    keychain_uid = generate_uuid0()
    keystore = FilesystemKeystore(tmp_path)
    with pytest.raises(KeyDoesNotExist):
        keystore.get_public_key(keychain_uid=keychain_uid, key_algo="123")

    keystore.set_keypair(keychain_uid=keychain_uid, key_algo="123", public_key=b"pub", private_key=b"priv")
    assert keystore.get_public_key(keychain_uid=keychain_uid, key_algo="123") == b"pub"
    assert keystore.get_private_key(keychain_uid=keychain_uid, key_algo="123") == b"priv"

    other_keychain_uid = generate_uuid0()
    (tmp_path / ("%s___public_key.pem" % other_keychain_uid)).write_bytes(b"stray")  # Algo name "_"
    assert keystore.list_keypair_identifiers() == sorted(
        [
            dict(keychain_uid=keychain_uid, key_algo="123", private_key_present=True),
            dict(keychain_uid=other_keychain_uid, key_algo="_", private_key_present=False),
        ],
        key=lambda x: (x["keychain_uid"], x["key_algo"]),
    )

    keystore.add_free_keypair(key_algo="123", public_key=b"pub", private_key=b"priv")
    assert keystore.get_free_keypairs_count("123") == 1  # Not counted twice


@pytest.mark.parametrize("key_algo", ["RSA?OAEP", "RSA\0OAEP", "../RSA_OAEP", "RSA/OAEP", "", "A" * 65])
def test_filesystem_keystore_unstorable_algo_names(tmp_path: Path, key_algo):
    keychain_uid = generate_uuid0()
    keystore = FilesystemKeystore(tmp_path)
    names_before = sorted(os.listdir(tmp_path))

    with pytest.raises(KeyDoesNotExist):
        keystore.get_public_key(keychain_uid=keychain_uid, key_algo=key_algo)
    with pytest.raises(KeyDoesNotExist):
        keystore.get_private_key(keychain_uid=keychain_uid, key_algo=key_algo)
    assert keystore.get_free_keypairs_count(key_algo) == 0
    with pytest.raises(KeyDoesNotExist):
        keystore.attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_algo=key_algo)
    with pytest.raises(ValidationError, match="can't be stored"):
        keystore.set_keypair(keychain_uid=keychain_uid, key_algo=key_algo, public_key=b"pub", private_key=b"priv")
    with pytest.raises(ValidationError, match="can't be stored"):
        keystore.set_public_key(keychain_uid=keychain_uid, key_algo=key_algo, public_key=b"pub")
    with pytest.raises(ValidationError, match="can't be stored"):
        keystore.add_free_keypair(key_algo=key_algo, public_key=b"pub", private_key=b"priv")

    assert sorted(os.listdir(tmp_path)) == names_before  # No file nor free keys directory created


@pytest.mark.parametrize(
    "uid_spelling, disk_algo_name, listed_when_ignoring_case",
    [
        ("uppercase", "rsa_oaep", True),
        ("lowercase", "Rsa_Oaep", True),  # Mixed-case algo name
        ("hex", "rsa_oaep", False),  # Keychain uid without dashes
    ],
)
def test_filesystem_keystore_listing_of_key_names_in_other_letter_cases(
    tmp_path: Path, uid_spelling, disk_algo_name, listed_when_ignoring_case
):
    keychain_uid = generate_uuid0()
    uid_str = dict(uppercase=str(keychain_uid).upper(), lowercase=str(keychain_uid), hex=keychain_uid.hex)[uid_spelling]
    public_key_name = "%s_%s_public_key.pem" % (uid_str, disk_algo_name)
    for kind in ("public", "private"):
        (tmp_path / ("%s_%s_%s_key.pem" % (uid_str, disk_algo_name, kind))).write_bytes(b"data-" + kind.encode())
    keystore = FilesystemKeystore(tmp_path)

    # Names are compared like the platform does, so other platforms are emulated on Windows
    normcase_functions = [os.path.normcase] + ([posixpath.normcase] if PLATFORM_IGNORES_CASE else [])
    for normcase in normcase_functions:
        with mock.patch.object(os.path, "normcase", normcase), mock.patch.object(keystore_module, "logger") as logger_mock:
            keypair_identifiers = keystore.list_keypair_identifiers()

        if listed_when_ignoring_case and normcase("A") == "a":
            assert keypair_identifiers == [
                dict(keychain_uid=keychain_uid, key_algo="RSA_OAEP", private_key_present=True)
            ]
            assert not logger_mock.warning.called
            # The filesystem ignores letter case too, so the getters find these files
            assert keystore.get_public_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP") == b"data-public"
        else:
            assert keypair_identifiers == []  # They couldn't be fetched
            assert public_key_name in str(logger_mock.warning.call_args_list)


def test_filesystem_keystore_legacy_uppercase_algo_free_keypairs(tmp_path: Path):
    free_keypairs = [("RSA_OAEP", _generate_pem_keypair("RSA_OAEP")) for _ in range(2)]
    write_legacy_uppercase_algo_keystore(tmp_path, [], free_keypairs=free_keypairs)

    with emulate_case_sensitive_filesystem():
        keystore = FilesystemKeystore(tmp_path)
        assert keystore.get_free_keypairs_count("RSA_OAEP") == 2

        for _ in range(2):
            keystore.attach_free_keypair_to_uuid(keychain_uid=generate_uuid0(), key_algo="RSA_OAEP")
        assert keystore.get_free_keypairs_count("RSA_OAEP") == 0
        with pytest.raises(KeyDoesNotExist):
            keystore.attach_free_keypair_to_uuid(keychain_uid=generate_uuid0(), key_algo="RSA_OAEP")

    key_names = [p.name for p in tmp_path.iterdir() if p.is_file()]
    assert len(key_names) == 4
    assert all("_rsa_oaep_" in name for name in key_names), key_names


def test_filesystem_keystore_free_keypairs_count_sums_both_spellings(tmp_path: Path):
    (tmp_path / "free_keys").mkdir()
    (tmp_path / "free_keys" / "rsa_oaep").mkdir()
    (tmp_path / "free_keys" / "rsa_oaep" / "1_private_key.pem").write_bytes(b"a")
    keystore = FilesystemKeystore(tmp_path)
    try:
        (tmp_path / "free_keys" / "RSA_OAEP").mkdir()
    except FileExistsError:
        pytest.skip("Case-insensitive filesystem")
    (tmp_path / "free_keys" / "RSA_OAEP" / "2_private_key.pem").write_bytes(b"b")
    assert keystore.get_free_keypairs_count("RSA_OAEP") == 2


def test_filesystem_keystore_mixed_layout_listing_check_and_export(tmp_path: Path):
    authenticator_dir = tmp_path / "authenticator"
    authenticator_dir.mkdir()
    initialize_authenticator(authenticator_dir, keystore_owner="owner", keystore_passphrase_hint="hint")

    uppercase_uid, lowercase_uid = generate_uuid0(), generate_uuid0()
    uppercase_keypair = generate_keypair(key_algo="RSA_OAEP", serialize=True, passphrase=b"pass")
    lowercase_keypair = generate_keypair(key_algo="ECC_DSS", serialize=True, passphrase=b"pass")
    write_legacy_uppercase_algo_keystore(authenticator_dir, [(uppercase_uid, "RSA_OAEP", uppercase_keypair)])

    with emulate_case_sensitive_filesystem():
        keystore = FilesystemKeystore(authenticator_dir)
        keystore.set_keypair(keychain_uid=lowercase_uid, key_algo="ECC_DSS", **lowercase_keypair)

        identifiers = keystore.list_keypair_identifiers()
        assert sorted((str(i["keychain_uid"]), i["key_algo"], i["private_key_present"]) for i in identifiers) == sorted(
            [(str(uppercase_uid), "RSA_OAEP", True), (str(lowercase_uid), "ECC_DSS", True)]
        )
        for identifier in identifiers:  # Every listed identifier is fetchable
            keystore.get_public_key(keychain_uid=identifier["keychain_uid"], key_algo=identifier["key_algo"])

        check_authenticator(authenticator_dir, keystore_passphrase=b"pass")  # Doesn't raise

        keystore_tree = ReadonlyFilesystemKeystore(authenticator_dir).export_to_keystore_tree()
        assert {(k["keychain_uid"], k["key_algo"]) for k in keystore_tree["keypairs"]} == {
            (uppercase_uid, "RSA_OAEP"),
            (lowercase_uid, "ECC_DSS"),
        }

    # Re-import into a fresh keystore: lowercase-named files
    fresh_dir = tmp_path / "fresh"
    fresh_dir.mkdir()
    FilesystemKeystore(fresh_dir).import_from_keystore_tree(keystore_tree)
    key_files = [p.name for p in fresh_dir.glob("*.pem")]
    assert len(key_files) == 4
    assert all(name == name.lower() for name in key_files), key_files
