# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import copy
from unittest import mock

import pytest

from test_wacryptolib_cli import _get_cli_base_args_for_folder_isolation, _get_cli_runner
from test_wacryptolib_cryptainer import SIMPLE_CRYPTOCONF
from wacryptolib.cli import wacryptolib_cli as cli
from wacryptolib.cryptainer import (
    ValidatedCryptoconf,
    ValidatedCryptainer,
    ensure_validated_cryptoconf,
    ensure_validated_cryptainer,
    check_cryptainer_sanity,
    CryptainerStorage,
    encrypt_payload_into_cryptainer,
    decrypt_payload_from_cryptainer,
    gather_decryptable_symkeys,
    OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER,
)
from wacryptolib.cryptainer import _validation
from wacryptolib.exceptions import SchemaValidationError
from wacryptolib.keystore import InMemoryKeystorePool
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes, dump_to_json_file


@pytest.fixture
def validation_counter():
    """Counts the python-schema validations of cryptoconfs and cryptainers (and not e.g. of operation reports)"""
    real_function = _validation._validate_data_tree
    counts = {"cryptoconf": 0, "cryptainer": 0}

    def _counting_function(data_tree, validation_schema):
        if validation_schema is _validation.CRYPTOCONF_SCHEMA_PYTHON:
            counts["cryptoconf"] += 1
        elif validation_schema is _validation.CRYPTAINER_SCHEMA_PYTHON:
            counts["cryptainer"] += 1
        return real_function(data_tree=data_tree, validation_schema=validation_schema)

    with mock.patch.object(_validation, "_validate_data_tree", side_effect=_counting_function):
        yield counts


def test_tokens_are_dropped_by_copies_and_serialization():
    cryptoconf = ensure_validated_cryptoconf(SIMPLE_CRYPTOCONF)
    cryptainer = ValidatedCryptainer(encrypt_payload_into_cryptainer(b"abc", cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_metadata=None))

    for token in (cryptoconf, cryptainer):
        assert type(copy.deepcopy(token)) is dict
        assert type(token.copy()) is dict
        assert type(copy.copy(token)) is dict
        assert type(load_from_json_bytes(dump_to_json_bytes(token))) is dict

    assert ValidatedCryptoconf() == {} and ValidatedCryptainer().inline_payload_checked is False  # Python-schema needs it
    assert type(copy.deepcopy(cryptoconf["payload_cipher_layers"])) is list


def test_ensure_validated_cryptoconf_is_idempotent_and_snapshots(validation_counter):
    cryptoconf = copy.deepcopy(SIMPLE_CRYPTOCONF)
    token = ensure_validated_cryptoconf(cryptoconf)
    assert validation_counter == {"cryptoconf": 1, "cryptainer": 0}
    assert isinstance(token, ValidatedCryptoconf) and token == SIMPLE_CRYPTOCONF

    assert ensure_validated_cryptoconf(token) is token
    assert validation_counter["cryptoconf"] == 1  # Not validated again

    cryptoconf["payload_cipher_layers"] = []  # Later mutation of the original must not alter the token
    assert token == SIMPLE_CRYPTOCONF

    with pytest.raises(SchemaValidationError):
        ensure_validated_cryptoconf(cryptoconf)


def test_ensure_validated_cryptainer_strictness(validation_counter):
    cryptainer = copy.deepcopy(encrypt_payload_into_cryptainer(b"abc", cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_metadata=None))
    assert validation_counter["cryptainer"] == 0  # Trusted output of encryption

    strict_token = ensure_validated_cryptainer(cryptainer)
    assert strict_token.inline_payload_checked and validation_counter["cryptainer"] == 1
    assert ensure_validated_cryptainer(strict_token) is strict_token
    assert ensure_validated_cryptainer(strict_token, require_inline_payload=False) is strict_token
    assert validation_counter["cryptainer"] == 1  # Strict satisfies lenient

    offloaded_cryptainer = copy.deepcopy(cryptainer)
    offloaded_cryptainer["payload_ciphertext_struct"] = OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER
    lenient_token = ensure_validated_cryptainer(offloaded_cryptainer, require_inline_payload=False)
    assert not lenient_token.inline_payload_checked and validation_counter["cryptainer"] == 2
    assert ensure_validated_cryptainer(lenient_token, require_inline_payload=False) is lenient_token
    assert validation_counter["cryptainer"] == 2

    with pytest.raises(SchemaValidationError, match="must be inline"):  # Lenient does not satisfy strict
        ensure_validated_cryptainer(lenient_token)
    with pytest.raises(SchemaValidationError, match="must be inline"):
        decrypt_payload_from_cryptainer(lenient_token)
    assert validation_counter["cryptainer"] == 2  # Strict re-validation fails before reaching the schema


def test_encrypt_then_decrypt_in_memory_validates_once(validation_counter):
    keystore_pool = InMemoryKeystorePool()
    cryptainer = encrypt_payload_into_cryptainer(
        b"abc", cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_metadata=None, keystore_pool=keystore_pool
    )
    assert validation_counter == {"cryptoconf": 1, "cryptainer": 0}
    assert isinstance(cryptainer, ValidatedCryptainer) and cryptainer.inline_payload_checked
    check_cryptainer_sanity(cryptainer)  # Output really is a valid strict cryptainer
    validation_counter["cryptainer"] = 0

    payload, report = decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)
    assert payload == b"abc"
    gather_decryptable_symkeys([("mine", cryptainer)])
    assert validation_counter == {"cryptoconf": 1, "cryptainer": 0}

    # A reloaded cryptainer is untagged, so it is validated again
    reloaded_cryptainer = load_from_json_bytes(dump_to_json_bytes(cryptainer))
    decrypt_payload_from_cryptainer(reloaded_cryptainer, keystore_pool=keystore_pool)
    assert validation_counter["cryptainer"] == 1


def test_invalid_cryptainer_metadata_is_refused():
    with pytest.raises(SchemaValidationError, match="metadata"):
        encrypt_payload_into_cryptainer(b"abc", cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_metadata="notadict")


def test_cryptainer_metadata_is_not_aliased_by_cryptainer_token(monkeypatch):
    monkeypatch.setenv(_validation.DEBUG_TOKEN_DIGEST_ENV_VAR, "1")
    cryptainer_metadata = {"a": 1}
    cryptainer = encrypt_payload_into_cryptainer(b"abc", cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_metadata=cryptainer_metadata)
    cryptainer_metadata["a"] = 2  # Caller reuses its dict, the token is untouched
    assert decrypt_payload_from_cryptainer(cryptainer)[0] == b"abc"
    assert cryptainer["cryptainer_metadata"] == {"a": 1}


def test_storage_validates_default_cryptoconf_once(tmp_path, validation_counter):
    storage = CryptainerStorage(default_cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_dir=tmp_path)
    assert validation_counter["cryptoconf"] == 1
    for idx in range(3):
        storage.encrypt_file("file%d.dat" % idx, b"stuffs", cryptainer_metadata=None)
        storage.enqueue_file_for_encryption("queued%d.dat" % idx, b"stuffs", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert validation_counter["cryptoconf"] == 1

    # Early failures, instead of errors swallowed by worker threads
    with pytest.raises(SchemaValidationError):
        CryptainerStorage(default_cryptoconf={"whatever": True}, cryptainer_dir=tmp_path)
    assert CryptainerStorage(default_cryptoconf={}, cryptainer_dir=tmp_path)._default_cryptoconf is None  # No default
    with pytest.raises(SchemaValidationError):
        storage.enqueue_file_for_encryption("bad.dat", b"stuffs", cryptainer_metadata=None, cryptoconf={"a": 1})

    # Later edits of the original dict don't affect the storage
    cryptoconf = copy.deepcopy(SIMPLE_CRYPTOCONF)
    storage = CryptainerStorage(default_cryptoconf=cryptoconf, cryptainer_dir=tmp_path)
    cryptoconf["payload_cipher_layers"] = []
    storage.encrypt_file("edited.dat", b"stuffs", cryptainer_metadata=None)


def test_gather_decryptable_symkeys_names_faulty_cryptainer_and_trusts_strict_tokens(validation_counter):
    cryptainer = encrypt_payload_into_cryptainer(b"abc", cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_metadata=None)
    gather_decryptable_symkeys([("mine", cryptainer)])
    assert validation_counter["cryptainer"] == 0

    with pytest.raises(SchemaValidationError, match="Invalid cryptainer broken.crypt"):
        gather_decryptable_symkeys([("broken.crypt", {"cryptainer_format": "x"})])


def test_cli_encrypt_validates_cryptoconf_once(tmp_path, validation_counter):
    base_args, keystore_pool_path, cryptainer_storage = _get_cli_base_args_for_folder_isolation(tmp_path)
    runner = _get_cli_runner()

    with runner.isolated_filesystem():
        with open("data.txt", "w") as f:
            f.write("hello")
        dump_to_json_file("conf.json", SIMPLE_CRYPTOCONF)
        with open("badconf.json", "wb") as f:
            f.write(dump_to_json_bytes({"payload_cipher_layers": []}))

        result = runner.invoke(cli, base_args + ["encrypt", "data.txt", "-c", "conf.json"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert validation_counter["cryptoconf"] == 1

        result = runner.invoke(cli, base_args + ["encrypt", "data.txt", "-c", "badconf.json"])
        assert result.exit_code != 0
        assert isinstance(result.exception, SchemaValidationError)


def test_debug_digest_detects_mutations_of_tokens(monkeypatch):
    monkeypatch.setenv(_validation.DEBUG_TOKEN_DIGEST_ENV_VAR, "1")
    token = ensure_validated_cryptoconf(SIMPLE_CRYPTOCONF)
    assert ensure_validated_cryptoconf(token) is token  # Unchanged tree is fine
    token["payload_cipher_layers"][0]["payload_cipher_algo"] = "AES_CBC" if (
        token["payload_cipher_layers"][0]["payload_cipher_algo"] != "AES_CBC") else "AES_EAX"
    with pytest.raises(AssertionError, match="mutated"):
        ensure_validated_cryptoconf(token)

    cryptainer = encrypt_payload_into_cryptainer(b"abc", cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_metadata=None)
    cryptainer["payload_ciphertext_struct"]["ciphertext_value"] += b"x"  # Bytes are hashed too
    with pytest.raises(AssertionError, match="mutated"):
        decrypt_payload_from_cryptainer(cryptainer)

    monkeypatch.delenv(_validation.DEBUG_TOKEN_DIGEST_ENV_VAR)
    token = ensure_validated_cryptoconf(SIMPLE_CRYPTOCONF)
    assert token._debug_digest is None  # Nothing computed when the guard is off
    token["keychain_uid"] = None
    assert ensure_validated_cryptoconf(token) is token  # Not noticed, by design
