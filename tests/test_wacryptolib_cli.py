# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import copy
import io
import json
import os
import pathlib
import random
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest import mock
from uuid import UUID

import click
import pytest
from click.testing import CliRunner

import wacryptolib
from _test_mockups import oneshot_command_line, random_bool, get_longrun_command_line
from test_wacryptolib_cryptainer import SIMPLE_CRYPTOCONF
from wacryptolib.authenticator import initialize_authenticator
from wacryptolib.cli import wacryptolib_cli as cli, _short_format_datetime, _ensure_paths_not_existing
from wacryptolib.cryptainer import (
    LOCAL_KEYFACTORY_TRUSTEE_MARKER,
    CryptainerStorage,
    check_cryptoconf_sanity,
)
from wacryptolib import operations
from wacryptolib.exceptions import KeystoreDoesNotExist, ValidationError
from wacryptolib.keygen import generate_keypair
from wacryptolib.keystore import FilesystemKeystore, generate_keypair_for_storage, _get_keystore_metadata_file_path
from wacryptolib.utilities import (
    dump_to_json_file,
    get_utc_now_date,
    load_from_json_str,
    load_from_json_bytes,
    convert_to_extjson,
    DocumentFormat,
    convert_document_tree_to_bytes,
    dump_to_cbor_bytes,
    load_from_cbor_bytes,
    load_from_document_file,
)

FAKE_GATEWAY_URL = "https://gateway.example.com/jsonrpc/"  # Never contacted: JSON-RPC calls are mocked
FAKE_GATEWAY_KEYSTORE_UID = "0f0c0988-80c1-9362-11c1-b06909a3a53c"  # Authenticator of ¤aaa, served by the mock
FAKE_GATEWAY_KEYCHAIN_UID = UUID("0f0c0989-1111-a226-c471-99cbb2d203c3")


def _build_fake_gateway_get_public_authenticator():
    """Return a replacement for the remote `get_public_authenticator()` method, avoiding any network access."""
    public_authenticator = dict(
        keystore_owner="¤aaa",
        keystore_uid=UUID(FAKE_GATEWAY_KEYSTORE_UID),
        keystore_creation_datetime=get_utc_now_date(),
        public_keys=[
            dict(
                keychain_uid=FAKE_GATEWAY_KEYCHAIN_UID,
                key_algo="RSA_OAEP",
                key_value=generate_keypair(key_algo="RSA_OAEP", serialize=True)["public_key"],
            )
        ],
    )

    def get_public_authenticator(self, keystore_uid):
        if keystore_uid != public_authenticator["keystore_uid"]:
            raise KeystoreDoesNotExist("Keystore %s does not exist in database" % keystore_uid)
        return copy.deepcopy(public_authenticator)

    return get_public_authenticator

# For when runner.invoke() is not sufficient
FLIGHTBOX_CLI_INVOCATION_ARGS = [sys.executable, "-m", "wacryptolib"]


def _get_cli_runner():
    return CliRunner()


def _get_cli_base_args_for_folder_isolation(tmp_path):
    keystore_pool_path = tmp_path / "keystore-pool"
    keystore_pool_path.mkdir()

    cryptainer_storage = tmp_path / "cryptainer-storage"
    cryptainer_storage.mkdir()

    base_args = ["-k", str(keystore_pool_path), "-c", str(cryptainer_storage)]

    return base_args, keystore_pool_path, cryptainer_storage


def test_cli_help_texts():
    runner = _get_cli_runner()

    result = runner.invoke(cli, ["-h"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "Usage:" in result.stdout

    result = runner.invoke(cli, ["encrypt", "-h"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "into a secure container" in result.stdout

    result = runner.invoke(cli, ["cryptoconf", "-h"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "validate" in result.stdout

    result = runner.invoke(cli, ["foreign-keystore", "-h"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "list" in result.stdout

    result = runner.invoke(cli, ["cryptainer", "-h"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "summarize" in result.stdout


def _iter_cli_commands(command, path=()):
    yield path, command
    for name, subcommand in getattr(command, "commands", {}).items():
        yield from _iter_cli_commands(subcommand, path + (name,))


def test_cli_has_no_ambiguous_f_short_option():
    commands = list(_iter_cli_commands(cli))
    assert len(commands) > 20, commands  # Sanity check of the tree walking, chained subcommands included

    force_command_paths = set()
    for path, command in commands:
        for param in command.params:
            assert "-f" not in param.opts + param.secondary_opts, (path, param.name)
            if param.name == "force":
                assert param.opts == ["--force"] and not param.secondary_opts, (path, param.opts)
                force_command_paths.add(path)
    assert force_command_paths == {
        ("encrypt",),
        ("cryptainer", "decrypt"),
        ("cryptoconf", "generate-simple"),
        ("convert-format",),
    }


def test_cli_format_option_is_long_only(tmp_path):
    base_args, keystore_pool_path, cryptainer_storage = _get_cli_base_args_for_folder_isolation(tmp_path)
    runner = _get_cli_runner()

    result = runner.invoke(cli, base_args + ["cryptainer", "list", "-f", "json"])
    assert result.exit_code == 2
    assert "No such option" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainer", "list", "--format", "json"])
    assert result.exit_code == 0, result.stderr
    assert load_from_json_str(result.stdout) == []


def test_ensure_paths_not_existing(tmp_path):
    existing_file = tmp_path / "existing.txt"
    existing_file.write_text("hello")
    missing_file = tmp_path / "missing.txt"

    for force in (False, True):
        _ensure_paths_not_existing([missing_file, "-", pathlib.Path("-")], force=force)  # No error

        with pytest.raises(click.UsageError, match="is a directory"):
            _ensure_paths_not_existing([missing_file, tmp_path], force=force)

    _ensure_paths_not_existing([existing_file], force=True)
    with pytest.raises(click.UsageError, match=r"existing\.txt' already exists, use --force"):
        _ensure_paths_not_existing([missing_file, existing_file], force=False)
    assert existing_file.read_text() == "hello"

    dangling_symlink = tmp_path / "dangling_symlink"
    try:
        dangling_symlink.symlink_to(tmp_path / "nonexistent_target")
    except OSError:  # E.g. missing privileges on Windows
        pass
    else:
        _ensure_paths_not_existing([dangling_symlink], force=True)
        with pytest.raises(click.UsageError, match="already exists"):
            _ensure_paths_not_existing([dangling_symlink], force=False)


def test_cli_authenticator_management(tmp_path):
    authenticator_path = tmp_path / "myauthenticator"
    authenticator_subpath = authenticator_path / "mysubauthenticator"
    passphrase = "somepassphrase"

    runner = _get_cli_runner()

    result = runner.invoke(
        cli, ["authenticator", "create", str(tmp_path), "--owner", "Donald", "--passphrase-hint", "somehint"]
    )
    assert result.exit_code == 2
    assert "Target directory" in result.stderr
    assert "must not exist yet" in result.stderr

    result = runner.invoke(
        cli,
        ["authenticator", "create", str(authenticator_subpath), "--owner", "Donald", "--passphrase-hint", "somehint"],
    )
    assert result.exit_code == 2
    assert "Parent directory" in result.stderr
    assert "must already exist" in result.stderr

    result = runner.invoke(
        cli,
        [
            "authenticator",
            "create",
            str(authenticator_path),
            "--owner",
            "Donald",
            "--passphrase-hint",
            "somehint",
            "--keypair-count",
            "0",
        ],
    )
    assert result.exit_code == 2
    assert "At least 1 keypair must be created" in result.stderr

    result = runner.invoke(cli, ["authenticator", "delete", str(tmp_path)])
    assert result.exit_code == 1
    assert "not an initialized authenticator" in result.stderr

    booleans = [True, False]
    random.shuffle(booleans)

    for use_env_var_for_passphrase in booleans:
        assert not authenticator_path.exists()

        if use_env_var_for_passphrase:
            env = dict(WA_PASSPHRASE=passphrase, **os.environ)  # E.g. for PYTHONPATH etc.
            input = None
        else:
            env = None
            input = passphrase

        result = runner.invoke(
            cli,
            [
                "authenticator",
                "create",
                str(authenticator_path),
                "--owner",
                "Donald",
                "--passphrase-hint",
                "somehint",
                "--keypair-count",
                "1",
            ],
            env=env,
            input=input,
        )  # Passphrase needed, else this freezes
        assert result.exit_code == 0
        assert authenticator_path.is_dir()

        result = runner.invoke(cli, ["authenticator", "validate", str(authenticator_path)], env=env, input=input)
        assert result.exit_code == 0
        assert "no integrity errors found" in result.stderr

        result = runner.invoke(cli, ["authenticator", "view", str(authenticator_path), "--format", "json"])
        assert result.exit_code == 0
        authenticator_data = load_from_json_str(result.stdout)  # Test loading of output
        assert len(authenticator_data) == 5
        assert authenticator_data["keystore_uid"]
        assert authenticator_data["keystore_owner"] == "Donald"
        assert authenticator_data["keystore_passphrase_hint"] == "somehint"
        assert authenticator_data["keystore_creation_datetime"] <= get_utc_now_date()
        assert len(authenticator_data["keypair_identifiers"]) == 1
        keypair = authenticator_data["keypair_identifiers"][0]
        assert set(keypair) == set(["keychain_uid", "key_algo", "private_key_present"])
        assert isinstance(keypair["keychain_uid"], UUID), keypair
        assert keypair["key_algo"] == "RSA_OAEP"

        result = runner.invoke(cli, ["authenticator", "view", str(authenticator_path)])  # PLAIN format
        assert str(authenticator_data["keystore_uid"]) in result.stdout
        assert "Donald" in result.stdout
        assert "somehint" in result.stdout
        assert _short_format_datetime(authenticator_data["keystore_creation_datetime"]) in result.stdout
        assert keypair["key_algo"] in result.stdout
        assert str(keypair["keychain_uid"]) in result.stdout

        result = runner.invoke(cli, ["authenticator", "delete", str(authenticator_path)])
        assert result.exit_code == 0
        assert not authenticator_path.exists()


def test_cli_authenticator_validation_errors(tmp_path):
    authenticator_path = tmp_path / "myauthenticator"
    runner = _get_cli_runner()
    passphrase = "my pâssphraze"

    result = runner.invoke(
        cli,
        [
            "authenticator",
            "create",
            str(authenticator_path),
            "--owner",
            "Donald",
            "--passphrase-hint",
            "somehint",
            "--keypair-count",
            "1",
        ],
        input=passphrase,
    )  # Passphrase needed, else this freezes
    assert result.exit_code == 0
    assert authenticator_path.is_dir()

    def do_validate(pwd):
        return runner.invoke(cli, ["authenticator", "validate", str(authenticator_path)], input=pwd)

    result = do_validate(passphrase)
    assert result.exit_code == 0
    assert "Keypair count: 1" in result.stdout  # Prevent regression on this count

    result = do_validate("badpassphrase")
    assert result.exit_code == 1
    assert "Undecodable private keys" in result.stdout

    private_key_path = next(authenticator_path.glob("*_private_key.pem"))
    private_key_path.unlink()
    result = do_validate(passphrase)
    assert result.exit_code == 1
    assert "Missing private keys" in result.stdout

    for public_key in authenticator_path.glob("*_public_key.pem"):
        public_key.unlink()
    result = do_validate(passphrase)
    assert result.exit_code == 1
    assert "No keypairs found" in result.stdout

    metadata_file = _get_keystore_metadata_file_path(authenticator_path)
    metadata_file.unlink()
    result = do_validate(passphrase)
    assert result.exit_code == 1
    assert "Authenticator metadata couldn't be loaded" in result.stdout


def test_cli_encryption_and_decryption_via_pipe(tmp_path):  # UNFINISHED
    base_args, keystore_pool_path, cryptainer_storage = _get_cli_base_args_for_folder_isolation(tmp_path)
    runner = _get_cli_runner()  # Only used for isolated dir, here...

    with runner.isolated_filesystem() as tempdir, ThreadPoolExecutor(max_workers=1) as executor:
        print("TEMPORARY TEST DIRECTORY:", tempdir)

        # Test specific CLI constraints when using STDIN PIPE
        feeder = subprocess.Popen(oneshot_command_line, stdout=subprocess.PIPE)
        _encryption_args = ["encrypt", "-"] + (["--bundle"] if random_bool() else [])
        consumer_process_completed = subprocess.run(
            FLIGHTBOX_CLI_INVOCATION_ARGS + base_args + _encryption_args, stdin=feeder.stdout, stderr=subprocess.PIPE
        )
        assert consumer_process_completed.returncode == 2, consumer_process_completed.stderr
        assert b"Ouput basename must be provided when input file is STDIN" in consumer_process_completed.stderr

        for idx in range(2):  # Test both bundled (so all-at-once) and unbundled (so streamable) encryptions
            must_bundle = bool(idx)

            # First we test NORMAL execution of a short encryption pipeline

            feeder = subprocess.Popen(oneshot_command_line, stdout=subprocess.PIPE)
            _encryption_args = ["encrypt", "-", "-o", "my_piped_oneshot_cryptainer%d.crypt" % idx] + (
                ["--bundle"] if must_bundle else []
            )
            consumer_process_completed = subprocess.run(
                FLIGHTBOX_CLI_INVOCATION_ARGS + base_args + _encryption_args,
                stdin=feeder.stdout,
                stderr=subprocess.PIPE,
            )
            assert consumer_process_completed.returncode == 0, consumer_process_completed.stderr
            assert b"successfully encrypted" in consumer_process_completed.stderr
            assert cryptainer_storage.joinpath("my_piped_oneshot_cryptainer%d.crypt.json" % idx).is_file()
            assert (
                cryptainer_storage.joinpath("my_piped_oneshot_cryptainer%d.crypt.json.payload" % idx).is_file()
                != must_bundle
            )

            _decryption_args = ["cryptainer", "decrypt", "my_piped_oneshot_cryptainer%d.crypt.json" % idx]
            consumer_process_completed = subprocess.run(
                FLIGHTBOX_CLI_INVOCATION_ARGS + base_args + _decryption_args, stderr=subprocess.PIPE
            )
            assert consumer_process_completed.returncode == 0, consumer_process_completed.stderr
            assert b"successfully finished" in consumer_process_completed.stderr
            result_file = pathlib.Path("./my_piped_oneshot_cryptainer%d" % idx)
            assert result_file.is_file()
            result_data = result_file.read_bytes()
            assert (
                result_data.strip() == b"This is some test data output and then I quit immediately!"
            )  # Beware of newlines

            # Then we test ABNORMAL execution of a long, INTERRUPTED, encryption pipeline

            feeder = subprocess.Popen(
                get_longrun_command_line("encryption_and_decryption_via_pipe"), stdout=subprocess.PIPE
            )

            def _interrupt_feeder_soon():
                time.sleep(6)  # Let it some time to launch and output things
                feeder.kill()  # Brutal termination

            executor.submit(_interrupt_feeder_soon)

            _encryption_args = ["encrypt", "-", "-o", "my_piped_longrun_cryptainer%d.crypt" % idx] + (
                ["--bundle"] if must_bundle else []
            )
            consumer_process_completed = subprocess.run(
                FLIGHTBOX_CLI_INVOCATION_ARGS + base_args + _encryption_args,
                stdin=feeder.stdout,
                stderr=subprocess.PIPE,
            )
            assert consumer_process_completed.returncode == 0, consumer_process_completed.stderr
            assert b"successfully encrypted" in consumer_process_completed.stderr
            assert cryptainer_storage.joinpath("my_piped_longrun_cryptainer%d.crypt.json" % idx).is_file()
            assert (
                cryptainer_storage.joinpath("my_piped_longrun_cryptainer%d.crypt.json.payload" % idx).is_file()
                != must_bundle
            )

            _decryption_args = ["cryptainer", "decrypt", "my_piped_longrun_cryptainer%d.crypt.json" % idx]
            consumer_process_completed = subprocess.run(
                FLIGHTBOX_CLI_INVOCATION_ARGS + base_args + _decryption_args, stderr=subprocess.PIPE
            )
            print("STDERR FROM DECRYPTION:")
            print(consumer_process_completed.stderr.decode("utf8", "ignore"))
            assert consumer_process_completed.returncode == 0
            assert b"successfully finished" in consumer_process_completed.stderr
            result_file = pathlib.Path("./my_piped_longrun_cryptainer%d" % idx)
            assert result_file.is_file()
            result_data = result_file.read_bytes()
            result_data = result_data.splitlines()
            assert len(result_data) > 6, result_data
            assert set(result_data) == {
                b"This is some test data output [encryption_and_decryption_via_pipe]!"
            }  # No TRUNCATED line!


def test_cli_encryption_and_decryption_with_default_cryptoconf(tmp_path):
    base_args, keystore_pool_path, cryptainer_storage = _get_cli_base_args_for_folder_isolation(tmp_path)

    runner = _get_cli_runner()

    data_file = "test_file.txt"
    data_sample = "Héllô\nguÿs"

    with runner.isolated_filesystem() as tempdir:
        print("TEMPORARY TEST DIRECTORY:", tempdir)

        with open(data_file, "w") as output_file:
            output_file.write(data_sample)

        result = runner.invoke(cli, base_args + ["encrypt", data_file, "--bundle"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "successfully encrypted" in result.stderr
        assert cryptainer_storage.joinpath(data_file + ".crypt.json").is_file()
        assert not cryptainer_storage.joinpath(data_file + ".crypt.json.payload").is_file()  # NOT OFFLOADED in this case

        result = runner.invoke(cli, base_args + ["encrypt", data_file, "-o", "stuff.dat"], catch_exceptions=False)
        print("TEST-STDERR1:", result.stderr)
        assert result.exit_code == 0
        assert "successfully encrypted" in result.stderr
        assert not os.path.exists("./stuff.dat")  # This is NOT a full target filepath
        assert cryptainer_storage.joinpath("stuff.dat.crypt.json").is_file()
        assert cryptainer_storage.joinpath("stuff.dat.crypt.json.payload").is_file()  # OFFLOADED in this case

        result = runner.invoke(
            cli, base_args + ["encrypt", data_file, "-o", "folder/stuff.dat"], catch_exceptions=False
        )
        print("TEST-STDERR2:", result.stderr)
        assert result.exit_code == 2
        assert "basename must not contain path separators" in result.stderr

        with open(cryptainer_storage.joinpath("stuff.dat.crypt.json"), "r") as input_file:
            data = input_file.read()
            assert "AES_CBC" in data
            assert "CHACHA20_POLY1305" not in data  # Not in default cryptoconf

        os.remove(data_file)  # CLEANUP of original data file
        assert not os.path.exists(data_file)
        assert not cryptainer_storage.joinpath(
            data_file
        ).is_file()  # This will be the default output file for decryption

        result = runner.invoke(
            cli, base_args + ["cryptainer", "decrypt", data_file + ".crypt.json"], catch_exceptions=False
        )
        assert result.exit_code == 0
        assert os.path.exists(data_file)  # Created in CWD
        assert not cryptainer_storage.joinpath(data_file).is_file()  # Not created in CRYPTAINER STORAGE itself

        # Simulate weird suffix for cryptainer file (would cause problems with cryptainer listing, though)
        cryptainer_storage.joinpath("stuff.dat.crypt.json").rename(cryptainer_storage.joinpath("stuff.dat.fb"))
        cryptainer_storage.joinpath("stuff.dat.crypt.json.payload").rename(
            cryptainer_storage.joinpath("stuff.dat.fb.payload")
        )

        assert not os.path.exists("./stuff.dat.decrypted")
        result = runner.invoke(cli, base_args + ["cryptainer", "decrypt", "stuff.dat.fb"], catch_exceptions=False)
        assert result.exit_code == 0
        assert os.path.exists(
            "./stuff.dat.fb.decrypted"
        )  # Automatic extension, when no ".crypt" suffix in cryptainer name

        assert not os.path.exists("stuffs.txt")
        result = runner.invoke(
            cli, base_args + ["cryptainer", "decrypt", "stuff.dat.fb", "-o", "stuffs.txt"], catch_exceptions=False
        )
        assert result.exit_code == 0
        assert os.path.exists("stuffs.txt")

        for result_file in (data_file, "./stuff.dat.fb.decrypted", "stuffs.txt"):
            with open(result_file, "r") as input_file:
                data = input_file.read()
                assert data == data_sample

        empty_keystore_path = tmp_path.joinpath("subdir")
        empty_keystore_path.mkdir()
        result = runner.invoke(
            cli,
            [
                "-k",
                empty_keystore_path,
                "-c",
                str(cryptainer_storage),
                "cryptainer",
                "decrypt",
                "stuff.dat.fb",
                "-o",
                "mystuffs.txt",
            ],
        )
        assert result.exit_code == 1  # Decryption failed because keypair was regenerated
        assert "Decryption report:" in result.stderr
        assert "Content could not be decrypted" in str(result.exc_info[1])
        assert not os.path.exists("mystuffs.txt")


def test_cli_encryption_and_summarize_with_custom_cryptoconf(tmp_path):
    base_args, keystore_pool_path, cryptainer_storage = _get_cli_base_args_for_folder_isolation(tmp_path)

    runner = _get_cli_runner()

    data_file = "test_file.txt"
    data_sample = "Héllô\nguÿs"
    cryptoconf_file = "mycryptoconf.json"

    with runner.isolated_filesystem() as tempdir:
        print("TEMPORARY TEST DIRECTORY:", tempdir)

        with open(data_file, "w") as f:
            f.write(data_sample)

        with open(cryptoconf_file, "wb") as f:
            f.write(b"badcontent")

        result = runner.invoke(
            cli,
            base_args + ["cryptoconf", "summarize", cryptoconf_file],
        )
        assert result.exit_code == 1  # Wrong JSON content

        result = runner.invoke(
            cli,
            base_args + ["encrypt", data_file, "-o", "specialconf.crypt", "-c", cryptoconf_file],
        )
        assert result.exit_code == 1
        assert not os.path.exists("specialconf.crypt")

        simple_cryptoconf_tree = dict(
            payload_cipher_layers=[
                dict(
                    payload_cipher_algo="CHACHA20_POLY1305",
                    key_cipher_layers=[
                        dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                    ],
                    payload_ciphertext_signatures=[],
                )
            ]
        )
        check_cryptoconf_sanity(simple_cryptoconf_tree)

        dump_to_json_file(cryptoconf_file, simple_cryptoconf_tree)
        assert os.path.exists(cryptoconf_file)

        result = runner.invoke(cli, base_args + ["cryptoconf", "summarize", cryptoconf_file], catch_exceptions=False)
        assert result.exit_code == 0
        assert b"CHACHA20_POLY1305" in result.stdout_bytes
        assert b"RSA_OAEP" in result.stdout_bytes

        result = runner.invoke(
            cli,
            base_args + ["encrypt", data_file, "-o", "specialconf.crypt", "-c", cryptoconf_file],
            catch_exceptions=False,
        )
        print(">>>>>>", result.stderr)
        assert result.exit_code == 0
        assert cryptainer_storage.joinpath("specialconf.crypt.json").is_file()  # Premature suffix stripped
        assert not cryptainer_storage.joinpath("specialconf.crypt").exists()
        assert not cryptainer_storage.joinpath("specialconf.crypt.crypt.json").exists()

        data = cryptainer_storage.joinpath("specialconf.crypt.json").read_text()
        assert "CHACHA20_POLY1305" in data

        result = runner.invoke(
            cli,
            base_args + ["cryptainer", "summarize", "specialconf.crypt.json"],  # Works on CRYPTAINERS too
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert b"CHACHA20_POLY1305" in result.stdout_bytes
        assert b"RSA_OAEP" in result.stdout_bytes

        result = runner.invoke(
            cli,
            base_args + ["cryptainer", "decrypt", "specialconf.crypt.json", "-o", "specialconf.crypt.decrypted"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert os.path.exists("specialconf.crypt.decrypted")

        with open("specialconf.crypt.decrypted", "r") as input_file:
            data = input_file.read()
            assert data == data_sample


def test_cli_cryptoconf_generate_simple():
    runner = _get_cli_runner()

    def _load_and_validate_cryptoconf(_result):
        assert result.exit_code == 0, [_result.stdout, _result.stderr]
        _cryptoconf_str = _result.stdout.strip()
        _cryptoconf = load_from_json_str(_cryptoconf_str)
        check_cryptoconf_sanity(
            _cryptoconf
        )  # This is ALREADY supposed to happen in cryptoconf generation command of CLI
        return _cryptoconf

    # Simplest configuration
    command = """cryptoconf generate-simple add-payload-cipher-layer --sym-cipher-algo aes_cbc add-key-cipher-layer
              --asym-cipher-algo RSA_OAEP --trustee-type authenticator --keystore-uid 0f2ee6c1-d91e-7593-1310-7036dc9b782e""".split()
    result = runner.invoke(cli, command)
    cryptoconf = _load_and_validate_cryptoconf(result)
    assert cryptoconf == {
        "payload_cipher_layers": [
            {
                "key_cipher_layers": [
                    {
                        "key_cipher_algo": "RSA_OAEP",
                        "key_cipher_trustee": {
                            "keystore_uid": UUID("0f2ee6c1-d91e-7593-1310-7036dc9b782e"),
                            "trustee_type": "authenticator",
                        },
                    }
                ],
                "payload_cipher_algo": "AES_CBC",
                "payload_ciphertext_signatures": [],
            }
        ]
    }

    # Simple configuration with hybrid key encryption
    command = """cryptoconf generate-simple --keychain-uid 123e4567-e89b-12d3-a456-426614174000 
                    add-payload-cipher-layer --sym-cipher-algo chacha20_poly1305 
                    add-key-cipher-layer 
                    --asym-cipher-algo RSA_OAEP --trustee-type local_keyfactory 
                    --sym-cipher-algo aes_eax --keychain-uid 6a3c8ac8-c26b-45fa-8810-6dd3157b97fa""".split()
    result = runner.invoke(cli, command)
    cryptoconf = _load_and_validate_cryptoconf(result)
    assert cryptoconf == {
        "keychain_uid": UUID("123e4567-e89b-12d3-a456-426614174000"),
        "payload_cipher_layers": [
            {
                "key_cipher_layers": [
                    {
                        "key_cipher_algo": "AES_EAX",
                        "key_cipher_layers": [
                            {
                                "key_cipher_algo": "RSA_OAEP",
                                "key_cipher_trustee": {"trustee_type": "local_keyfactory"},
                                "keychain_uid": UUID("6a3c8ac8-c26b-45fa-8810-6dd3157b97fa"),
                            }
                        ],
                    }
                ],
                "payload_cipher_algo": "CHACHA20_POLY1305",
                "payload_ciphertext_signatures": [],
            }
        ],
    }

    # Medium configuration with a shared secret
    command = """cryptoconf generate-simple add-payload-cipher-layer --sym-cipher-algo aes_eax 
        add-key-shared-secret --threshold 1 
            add-key-shard --asym-cipher-algo RSA_OAEP --trustee-type authenticator 
                          --keystore-uid 0f2ee6c1-d91e-7593-1310-7036dc9b782e  --sym-cipher-algo aes_eax
            add-key-shard --asym-cipher-algo RSA_OAEP --trustee-type authenticator 
                          --keystore-uid af2ee6c1-d91e-7593-1310-7036dc9b782a --keychain-uid 6a3c8ac8-c26b-45fa-8810-6dd3157b97fd
        add-key-cipher-layer --asym-cipher-algo RSA_OAEP --trustee-type authenticator --keystore-uid 0f2ee6c1-d91e-7593-1310-7036dc9b783b """.split()
    result = runner.invoke(cli, command)
    cryptoconf = _load_and_validate_cryptoconf(result)
    # pprint(cryptoconf)
    assert cryptoconf == {
        "payload_cipher_layers": [
            {
                "key_cipher_layers": [
                    {
                        "key_cipher_algo": "[SHARED_SECRET]",
                        "key_shared_secret_shards": [
                            {
                                "key_cipher_layers": [
                                    {
                                        "key_cipher_algo": "AES_EAX",
                                        "key_cipher_layers": [
                                            {
                                                "key_cipher_algo": "RSA_OAEP",
                                                "key_cipher_trustee": {
                                                    "keystore_uid": UUID("0f2ee6c1-d91e-7593-1310-7036dc9b782e"),
                                                    "trustee_type": "authenticator",
                                                },
                                            }
                                        ],
                                    }
                                ]
                            },
                            {
                                "key_cipher_layers": [
                                    {
                                        "key_cipher_algo": "RSA_OAEP",
                                        "key_cipher_trustee": {
                                            "keystore_uid": UUID("af2ee6c1-d91e-7593-1310-7036dc9b782a"),
                                            "trustee_type": "authenticator",
                                        },
                                        "keychain_uid": UUID("6a3c8ac8-c26b-45fa-8810-6dd3157b97fd"),
                                    }
                                ]
                            },
                        ],
                        "key_shared_secret_threshold": 1,
                    },
                    {
                        "key_cipher_algo": "RSA_OAEP",
                        "key_cipher_trustee": {
                            "keystore_uid": UUID("0f2ee6c1-d91e-7593-1310-7036dc9b783b"),
                            "trustee_type": "authenticator",
                        },
                    },
                ],
                "payload_cipher_algo": "AES_EAX",
                "payload_ciphertext_signatures": [],
            }
        ]
    }

    # Output to a file instead of STDOUT
    with runner.isolated_filesystem():
        command = """cryptoconf generate-simple -o myconf.json add-payload-cipher-layer --sym-cipher-algo aes_cbc
                  add-key-cipher-layer --asym-cipher-algo RSA_OAEP --trustee-type local_keyfactory""".split()
        result = runner.invoke(cli, command)
        assert result.exit_code == 0, [result.stdout, result.stderr]
        assert not result.stdout.strip()
        with open("myconf.json") as f:
            cryptoconf = load_from_json_str(f.read())
        assert cryptoconf == {
            "payload_cipher_layers": [
                {
                    "key_cipher_layers": [
                        {"key_cipher_algo": "RSA_OAEP", "key_cipher_trustee": {"trustee_type": "local_keyfactory"}}
                    ],
                    "payload_cipher_algo": "AES_CBC",
                    "payload_ciphertext_signatures": [],
                }
            ]
        }

    wrong_commands = [
        # Missing payload encryption
        "cryptoconf generate-simple".split(),
        # Missing key encryption
        "cryptoconf generate-simple add-payload-cipher-layer --sym-cipher-algo aes_cbc".split(),
        # Missing keystore-uid fro authenticator trustee
        "cryptoconf generate-simple add-payload-cipher-layer --sym-cipher-algo chacha20_poly1305 "
        "add-key-cipher-layer --asym-cipher-algo RSA_OAEP --trustee-type authenticator ".split(),
        # Authenticators only have RSA_OAEP keys
        "cryptoconf generate-simple add-payload-cipher-layer --sym-cipher-algo aes_cbc "
        "add-key-cipher-layer --asym-cipher-algo ECIES_X25519 --trustee-type authenticator "
        "--keystore-uid 0f2ee6c1-d91e-7593-1310-7036dc9b782e".split(),
        # Wrong threshold too small
        "cryptoconf generate-simple add-payload-cipher-layer --sym-cipher-algo aes_cbc add-key-shared-secret --threshold 0 "
        "add-key-shard --asym-cipher-algo RSA_OAEP --trustee-type local_keyfactory".split(),
        # Wrong threshold too big
        "cryptoconf generate-simple add-payload-cipher-layer --sym-cipher-algo aes_cbc add-key-shared-secret --threshold 2 "
        "add-key-shard --asym-cipher-algo RSA_OAEP --trustee-type local_keyfactory".split(),
        # Wrong place for 'add-key-shard'
        "cryptoconf generate-simple add-payload-cipher-layer --sym-cipher-algo aes_cbc add-key-shard "
        "--asym-cipher-algo RSA_OAEP --trustee-type authenticator --keystore-uid 0f2ee6c1-d91e-7593-1310-7036dc9b782e  --sym-cipher-algo aes_eax".split(),
        # Wrong place for 'add-key-shard' again
        "cryptoconf generate-simple add-payload-cipher-layer --sym-cipher-algo aes_cbc add-key-shared-secret --threshold 1 "
        "add-key-shard --asym-cipher-algo RSA_OAEP --trustee-type authenticator --keystore-uid 0f2ee6c1-d91e-7593-1310-7036dc9b782e add-payload-cipher-layer "
        "--sym-cipher-algo aes_eax add-key-shard --asym-cipher-algo RSA_OAEP --trustee-type local_keyfactory",
    ]
    for wrong_command in wrong_commands:
        result = runner.invoke(cli, wrong_command)
        assert result.exit_code != 0, (result.exit_code, result.output)  # UsageError, not crash

    result = runner.invoke(cli, wrong_commands[3])  # Readable error, not a schema dump
    assert "Authenticator trustee only has RSA_OAEP keys for now" in result.output, result.output


def test_cli_cryptoconf_generate_simple_output_file(tmp_path):
    runner = _get_cli_runner()
    layers = """add-payload-cipher-layer --sym-cipher-algo aes_cbc
                add-key-cipher-layer --asym-cipher-algo RSA_OAEP --trustee-type local_keyfactory""".split()

    # Long option name, and the generated file is a valid cryptoconf
    output_file = tmp_path / "long.json"
    result = runner.invoke(cli, ["cryptoconf", "generate-simple", "--output-file", str(output_file)] + layers)
    assert result.exit_code == 0, [result.stdout, result.stderr]
    assert not result.stdout.strip()
    result = runner.invoke(cli, ["cryptoconf", "validate", str(output_file)])
    assert result.exit_code == 0, [result.stdout, result.stderr]

    # "-" explicitly means STDOUT, same content as the file
    result = runner.invoke(cli, ["cryptoconf", "generate-simple", "-o", "-"] + layers)
    assert result.exit_code == 0, [result.stdout, result.stderr]
    assert load_from_json_str(result.stdout) == load_from_json_str(output_file.read_text())

    # An invalid cryptoconf produces an error and no output file content
    wrong_output_file = tmp_path / "wrong.json"
    result = runner.invoke(cli, ["cryptoconf", "generate-simple", "-o", str(wrong_output_file)])
    assert result.exit_code != 0
    assert not wrong_output_file.exists() or not wrong_output_file.read_text()


def test_cli_cryptoconf_validate(tmp_path):
    cryptoconf_file = tmp_path / "good_cryptoconf.json"
    wrong_cryptoconf_file = tmp_path / "wrong_cryptoconf.json"

    simple_cryptoconf_tree = dict(
        payload_cipher_layers=[
            dict(
                payload_cipher_algo="CHACHA20_POLY1305",
                key_cipher_layers=[
                    dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                ],
                payload_ciphertext_signatures=[],
            )
        ]
    )
    check_cryptoconf_sanity(simple_cryptoconf_tree)
    dump_to_json_file(cryptoconf_file, simple_cryptoconf_tree)

    dump_to_json_file(wrong_cryptoconf_file, {})

    runner = _get_cli_runner()

    result = runner.invoke(cli, ["cryptoconf", "validate", "unexistingfile"])
    assert result.exit_code == 2
    assert "No such file or directory" in result.stderr

    result = runner.invoke(cli, ["cryptoconf", "validate", str(wrong_cryptoconf_file)])
    assert result.exit_code == 2
    assert "is invalid" in result.stderr
    assert "payload_cipher_layers" in result.stderr

    result = runner.invoke(cli, ["cryptoconf", "validate", str(cryptoconf_file)], catch_exceptions=False)
    assert result.exit_code == 0
    assert "is valid" in result.stderr


def test_cli_subprocess_invocation():
    src_dir = str(pathlib.Path(wacryptolib.__file__).resolve().parents[1])

    env = os.environ.copy()
    env["PYTHONPATH"] = env.get("PYTHONPATH", "") + os.pathsep + src_dir

    proc = subprocess.Popen(
        FLIGHTBOX_CLI_INVOCATION_ARGS + ["-h"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate(timeout=15)
    assert b"Options:" in stdout
    assert b"Commands:" in stdout
    assert b"CLI is using temp APP DIR PARENT" in stderr
    assert proc.returncode == 0


def test_cli_foreign_keystore_management(tmp_path):
    with mock.patch(
        "wacryptolib.jsonrpc_client.JsonRpcProxy.get_public_authenticator",
        new=_build_fake_gateway_get_public_authenticator(),
        create=True,
    ):
        _check_cli_foreign_keystore_management(tmp_path)


def _check_cli_foreign_keystore_management(tmp_path):
    base_args, keystore_pool_path, cryptainer_storage = _get_cli_base_args_for_folder_isolation(tmp_path)

    authenticator_path = tmp_path / "authenticator"
    authenticator_path.mkdir()

    wrong_uuid_str = "676ff51f-1439-48d9-94f9-a6011357fd11"

    runner = _get_cli_runner()

    result = runner.invoke(
        cli, ["-v", "DEBUG", "foreign-keystore", "list"], catch_exceptions=False
    )  # No forced keystore pool here
    assert result.exit_code == 0
    assert "No keystore-pool directory provided, defaulting " in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystore", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "No foreign keystores found" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystore", "import"])  # Must specify usb/gateway/...
    assert result.exit_code == 2
    assert "No source selected" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystore", "import", "--from-usb"], catch_exceptions=False)
    assert result.exit_code == 0
    assert (
        "0 new authenticators imported, 0 updated, 0 skipped because corrupted" in result.stderr
    )  # DO NOT keep USB key in PC for now when running unit-tests, else this fails!

    result = runner.invoke(
        cli, base_args + ["foreign-keystore", "import", "--from-usb", "--include-private-keys"], catch_exceptions=False
    )
    assert result.exit_code == 0
    assert "0 new authenticators imported, 0 updated, 0 skipped because corrupted" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystore", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "No foreign keystores found" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystore", "import", "--from-gateway", FAKE_GATEWAY_KEYSTORE_UID])
    assert result.exit_code == 2  # click.UsageError
    assert "No web gateway URL specified" in result.stderr

    result = runner.invoke(
        cli,
        base_args
        + [
            "--gateway-url",
            FAKE_GATEWAY_URL,  # Here --include-private-keys has no effect
            "foreign-keystore",
            "import",
            "--include-private-keys",
            "--from-gateway",
            FAKE_GATEWAY_KEYSTORE_UID,
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "Authenticator 0f0c0988-80c1-9362-11c1-b06909a3a53c (owner: ¤aaa) imported" in result.stderr

    result = runner.invoke(
        cli,
        base_args
        + [
            "--gateway-url",
            FAKE_GATEWAY_URL,
            "foreign-keystore",
            "import",
            "--from-gateway",
            FAKE_GATEWAY_KEYSTORE_UID,
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "Authenticator 0f0c0988-80c1-9362-11c1-b06909a3a53c (owner: ¤aaa) updated" in result.stderr

    result = runner.invoke(
        cli,
        base_args
        + [
            "--gateway-url",
            FAKE_GATEWAY_URL,
            "foreign-keystore",
            "import",
            "--from-gateway",
            "676ff51f-1439-48d9-94f9-xxx",
        ],
    )
    assert result.exit_code == 2
    assert "not a valid UUID." in result.stderr

    result = runner.invoke(
        cli,
        base_args + ["--gateway-url", FAKE_GATEWAY_URL, "foreign-keystore", "import", "--from-gateway", wrong_uuid_str],
    )
    assert result.exit_code == 1  # Other exception raised
    assert "does not exist in database" in str(result.exc_info[1])

    result = runner.invoke(cli, base_args + ["foreign-keystore", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert " 0f0c0988-80c1-9362-11c1-b06909a3a53c " in result.stdout  # Table is displayed
    assert " ¤aaa " in result.stdout

    result = runner.invoke(
        cli, base_args + ["foreign-keystore", "view", FAKE_GATEWAY_KEYSTORE_UID], catch_exceptions=False
    )
    assert result.exit_code == 0
    assert " 0f0c0988-80c1-9362-11c1-b06909a3a53c " in result.stdout  # Table is displayed
    assert " ¤aaa " in result.stdout
    assert " RSA_OAEP 0f0c0989-1111-a226-c471-99cbb2d203c3 " in result.stdout  # Keypairs are listed

    result = runner.invoke(cli, base_args + ["foreign-keystore", "view", wrong_uuid_str])
    assert result.exit_code == 2
    assert "not found" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystore", "import", "--from-gateway", FAKE_GATEWAY_KEYSTORE_UID])
    assert result.exit_code == 2
    assert "No web gateway URL specified" in result.stderr

    result = runner.invoke(
        cli, base_args + ["foreign-keystore", "delete", FAKE_GATEWAY_KEYSTORE_UID], catch_exceptions=False
    )
    assert result.exit_code == 0
    assert "successfully deleted" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystore", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "No foreign keystores found" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystore", "list", "--format", "json"], catch_exceptions=False)
    assert result.exit_code == 0
    assert result.stdout == "[]\n"

    result = runner.invoke(cli, base_args + ["foreign-keystore", "import", "--from-path", authenticator_path])
    assert result.exit_code == 1
    assert "keystore_metadata.json does not exist" in str(result.exc_info[1])

    keystore_metadata = initialize_authenticator(
        authenticator_path, keystore_owner="myuserxyz", keystore_passphrase_hint="somestuffs"
    )
    new_keystore_uid = keystore_metadata["keystore_uid"]
    filesystem_keystore = FilesystemKeystore(authenticator_path)
    keypairs_count = random.randint(1, 3)

    for i in range(keypairs_count):
        generate_keypair_for_storage(key_algo="RSA_OAEP", keystore=filesystem_keystore, passphrase=None)

    result = runner.invoke(
        cli, base_args + ["foreign-keystore", "import", "--from-path", authenticator_path], catch_exceptions=False
    )
    assert result.exit_code == 0
    assert "imported" in result.stderr
    assert "updated" not in result.stderr
    assert "without private keys" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystore", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert str(new_keystore_uid) in result.stdout
    assert " 0 " in result.stdout  # Private keys
    assert (" %d " % keypairs_count) in result.stdout  # Public keys

    result = runner.invoke(cli, base_args + ["foreign-keystore", "list", "--format", "json"], catch_exceptions=False)
    assert result.exit_code == 0
    assert str(new_keystore_uid) not in result.stdout  # Output uses ExtendedJson encoding
    # RELAXED format uses plain integers instead of {"$numberInt": "N"}
    assert (': %d' % keypairs_count) in result.stdout  # Plain integer in RELAXED format
    data_tree = load_from_json_str(result.stdout)  # Test loading of output
    assert isinstance(data_tree, list)
    assert len(data_tree) == 1
    assert data_tree[0]["keystore_owner"] == "myuserxyz"

    result = runner.invoke(
        cli,
        base_args + ["foreign-keystore", "import", "--include-private-keys", "--from-path", authenticator_path],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "imported" not in result.stderr
    assert "updated" in result.stderr
    assert "with private keys" in result.stderr

    result = runner.invoke(
        cli, base_args + ["foreign-keystore", "list", "--format", "plain"], catch_exceptions=False
    )  # Plain format is the default anyway
    assert result.exit_code == 0
    assert str(new_keystore_uid) in result.stdout
    assert " 0 " not in result.stdout
    assert result.stdout.count(" %d " % keypairs_count) == 2  # Public keys AND private keys

    result = runner.invoke(cli, base_args + ["foreign-keystore", "delete", wrong_uuid_str])
    assert result.exit_code == 2
    assert "Failed deletion" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystore", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert str(new_keystore_uid) in result.stdout
    assert " myuserxyz " in result.stdout

    result = runner.invoke(
        cli, base_args + ["foreign-keystore", "delete", str(new_keystore_uid)], catch_exceptions=False
    )
    assert result.exit_code == 0
    assert "successfully deleted" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystore", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "No foreign keystores found" in result.stderr


def test_cli_cryptainer_storage_list_delete_and_purge(tmp_path):
    cryptainer_storage_path = tmp_path

    cryptainer_storage = CryptainerStorage(cryptainer_storage_path, default_cryptoconf=SIMPLE_CRYPTOCONF)
    cryptainer_storage_bundled = CryptainerStorage(
        cryptainer_storage_path, default_cryptoconf=SIMPLE_CRYPTOCONF, offload_payload_ciphertext=False
    )

    base_args = ["--cryptainer-storage", str(cryptainer_storage_path)]

    runner = _get_cli_runner()

    result = runner.invoke(
        cli, ["-v", "DEBUG", "cryptainer", "list"], catch_exceptions=False
    )  # No forced cryptainer storage here
    assert result.exit_code == 0
    assert "No cryptainer-storage directory provided, defaulting" in result.stderr

    result = runner.invoke(
        cli, base_args + ["cryptainer", "list", "--format", "plain"], catch_exceptions=False
    )  # Default format
    assert result.exit_code == 0
    assert "No cryptainers found" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainer", "list", "--format", "json"], catch_exceptions=False)
    assert result.exit_code == 0
    assert result.stdout == "[]\n"

    result = runner.invoke(cli, base_args + ["cryptainer", "delete", "badname.crypt"])
    assert result.exit_code == 2
    assert "Invalid cryptainer name" in result.stderr

    cryptainer_storage.enqueue_file_for_encryption("myfilename", payload=b"xyz", cryptainer_metadata=None)
    cryptainer_storage.wait_for_idle_state()

    result = runner.invoke(cli, base_args + ["cryptainer", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "myfilename.crypt.json" in result.stdout

    result = runner.invoke(cli, base_args + ["cryptainer", "delete", "myfilename.crypt.json"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "successfully deleted" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainer", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "No cryptainers found" in result.stderr

    recent_date_str = (get_utc_now_date() - timedelta(days=100)).strftime("%Y%m%d")
    first_cryptainer_name_base = "%s_152428_rtsp_camera_cryptainer.mp4" % recent_date_str
    cryptainer_storage.enqueue_file_for_encryption(first_cryptainer_name_base, payload=b"xyz", cryptainer_metadata=None)
    cryptainer_storage.enqueue_file_for_encryption(
        "20420221_152428_rtsp_camera_cryptainer.mp4", payload=b"xyz" * 1024**2, cryptainer_metadata=None
    )
    cryptainer_storage_bundled.enqueue_file_for_encryption(
        "20430221_152428_rtsp_camera_cryptainer.mp4", payload=b"xyz", cryptainer_metadata=None
    )

    cryptainer_storage.wait_for_idle_state()
    cryptainer_storage_bundled.wait_for_idle_state()

    result = runner.invoke(cli, base_args + ["cryptainer", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert " 20420221_152428_rtsp_camera_cryptainer.mp4.crypt.json " in result.stdout
    assert " X " in result.stdout  # For "is offloaded" column

    result = runner.invoke(cli, base_args + ["cryptainer", "list", "--format", "json"], catch_exceptions=False)
    assert result.exit_code == 0
    assert '"20420221_152428_rtsp_camera_cryptainer.mp4.crypt.json"' in result.stdout
    data_tree = load_from_json_str(result.stdout)  # Test loading of output
    assert isinstance(data_tree, list)
    assert len(data_tree) == 3
    assert data_tree[0]["name"] == first_cryptainer_name_base + ".crypt.json"

    result = runner.invoke(cli, base_args + ["cryptainer", "purge"])  # Missing purge parameters
    assert result.exit_code == 2
    assert "no criterion was provided" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainer", "purge", "--max-age", "101"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "Cryptainers successfully deleted: 0" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainer", "purge", "--max-age", "99"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "Cryptainers successfully deleted: 1" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainer", "purge", "--max-quota", "4"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "Cryptainers successfully deleted: 0" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainer", "purge", "--max-quota", "3"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "Cryptainers successfully deleted: 1" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainer", "purge", "--max-count", "1"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "Cryptainers successfully deleted: 0" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainer", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert " 20430221_152428_rtsp_camera_cryptainer.mp4.crypt.json " in result.stdout

    result = runner.invoke(cli, base_args + ["cryptainer", "purge", "--max-count", "0"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "Cryptainers successfully deleted: 1" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainer", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "No cryptainers found" in result.stderr


def test_cli_cryptainer_validate(tmp_path):
    cryptainer_storage_path = tmp_path

    (cryptainer_storage_path / "badcryptainer.crypt").write_bytes(b"{}")

    cryptainer_storage = CryptainerStorage(cryptainer_storage_path, default_cryptoconf=SIMPLE_CRYPTOCONF)
    cryptainer_storage.encrypt_file("goodfile", payload=b"ABCD", cryptainer_metadata=None)
    assert tmp_path.joinpath("goodfile.crypt.json").is_file()

    runner = _get_cli_runner()

    base_args = ["--cryptainer-storage", str(cryptainer_storage_path)]

    result = runner.invoke(cli, base_args + ["cryptainer", "validate", "unexistingfile"])
    assert result.exit_code == 1  # Raised by wacryptolib code and not Click
    assert "No such file or directory" in str(result.exc_info[1])

    result = runner.invoke(cli, base_args + ["cryptainer", "validate", "goodfile.crypt.json"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "is valid" in result.stderr

    result = runner.invoke(
        cli, base_args + ["cryptainer", "validate", "goodfile.crypt.json.payload"]
    )  # Exists but is not a proper cryptainer!
    assert result.exit_code == 1
    assert "is invalid" not in result.stderr
    # Unhandled exception for now: random ciphertext is neither Extended JSON nor WA-CBOR, and depending on its first
    # byte, it gives a DocumentFormatError, a WaCborDecodingError, or a JSON parsing error (e.g. UnicodeDecodeError)
    assert isinstance(result.exc_info[1], ValueError), result.exc_info

    result = runner.invoke(cli, base_args + ["cryptainer", "validate", "badcryptainer.crypt"])
    assert result.exit_code == 2
    assert "is invalid" in result.stderr


def test_cli_default_app_root_creation():
    std_env = os.environ.copy()
    del std_env["_WA_RANDOMIZE_CLI_APP_DIR"]

    proc = subprocess.run(FLIGHTBOX_CLI_INVOCATION_ARGS + ["-h"], env=std_env)
    assert proc.returncode == 0

    assert os.path.exists(os.path.expanduser("~/.witnessangel/"))  # Auto-created on launch


def _encrypt_sample_file_for_overwrite_tests(runner, base_args, data_file, data_sample, extra_args=()):
    with open(data_file, "wb") as f:
        f.write(data_sample)
    result = runner.invoke(cli, base_args + ["encrypt", data_file] + list(extra_args), catch_exceptions=False)
    assert result.exit_code == 0, result.stderr
    return result


def test_cli_decrypt_refuses_overwriting_existing_files(tmp_path):
    base_args, keystore_pool_path, cryptainer_storage = _get_cli_base_args_for_folder_isolation(tmp_path)
    runner = _get_cli_runner()
    data_file = "video.mp4"
    data_sample = "original média content".encode("utf8")

    with runner.isolated_filesystem():
        _encrypt_sample_file_for_overwrite_tests(runner, base_args, data_file, data_sample)
        cryptainer_name = data_file + ".crypt.json"

        # Decrypting next to the original file, with the default output name, is refused before any decryption
        pathlib.Path(data_file).write_bytes(b"precious original")
        with mock.patch("wacryptolib.cli.decrypt_payload_from_cryptainer") as decryption_mock:
            result = runner.invoke(cli, base_args + ["cryptainer", "decrypt", cryptainer_name])
            assert result.exit_code == 2, result.stderr
            assert "video.mp4' already exists, use --force to overwrite it" in result.stderr
            decryption_mock.assert_not_called()
        assert pathlib.Path(data_file).read_bytes() == b"precious original"

        # Same for an explicit existing output file
        pathlib.Path("out.bin").write_bytes(b"other precious content")
        result = runner.invoke(cli, base_args + ["cryptainer", "decrypt", cryptainer_name, "-o", "out.bin"])
        assert result.exit_code == 2, result.stderr
        assert "out.bin' already exists, use --force" in result.stderr
        assert pathlib.Path("out.bin").read_bytes() == b"other precious content"

        # The removed "-f" short option is not an alias of --force
        result = runner.invoke(cli, base_args + ["cryptainer", "decrypt", cryptainer_name, "-o", "out.bin", "-f"])
        assert result.exit_code == 2, result.stderr
        assert "No such option" in result.stderr
        assert pathlib.Path("out.bin").read_bytes() == b"other precious content"

        # Forced decryption overwrites existing files
        for extra_args, target_file in [([], data_file), (["-o", "out.bin"], "out.bin")]:
            result = runner.invoke(
                cli,
                base_args + ["cryptainer", "decrypt", cryptainer_name, "--force"] + extra_args,
                catch_exceptions=False,
            )
            assert result.exit_code == 0, result.stderr
            assert pathlib.Path(target_file).read_bytes() == data_sample

        # Directories are refused, even with --force
        pathlib.Path("some_dir").mkdir()
        for extra_args in ([], ["--force"]):
            result = runner.invoke(
                cli, base_args + ["cryptainer", "decrypt", cryptainer_name, "-o", "some_dir"] + extra_args
            )
            assert result.exit_code == 2, result.stderr
            assert "some_dir" in result.stderr
            assert "is a directory" in result.stderr
            assert not any(pathlib.Path("some_dir").iterdir())

        # A new output file is written as before, and STDOUT is never blocked
        result = runner.invoke(
            cli, base_args + ["cryptainer", "decrypt", cryptainer_name, "-o", "new.bin"], catch_exceptions=False
        )
        assert result.exit_code == 0, result.stderr
        assert pathlib.Path("new.bin").read_bytes() == data_sample

        result = runner.invoke(
            cli, base_args + ["cryptainer", "decrypt", cryptainer_name, "-o", "-"], catch_exceptions=False
        )
        assert result.exit_code == 0, result.stderr
        assert data_sample in result.stdout_bytes
        assert not os.path.exists("-")

        # If the target file appears after the early check, exclusive creation still refuses to overwrite it
        def _decrypt_and_create_target(*args, **kwargs):
            pathlib.Path("late.bin").write_bytes(b"late content")
            return data_sample, None

        with mock.patch("wacryptolib.cli.decrypt_payload_from_cryptainer", side_effect=_decrypt_and_create_target):
            result = runner.invoke(cli, base_args + ["cryptainer", "decrypt", cryptainer_name, "-o", "late.bin"])
        assert result.exit_code == 1, result.stderr
        assert "late.bin" in result.stderr
        assert pathlib.Path("late.bin").read_bytes() == b"late content"


def test_cli_encrypt_refuses_overwriting_existing_cryptainers(tmp_path):
    base_args, keystore_pool_path, cryptainer_storage = _get_cli_base_args_for_folder_isolation(tmp_path)
    runner = _get_cli_runner()
    data_file = "report.txt"

    with runner.isolated_filesystem():
        _encrypt_sample_file_for_overwrite_tests(runner, base_args, data_file, b"first content", ["-o", "report"])
        cryptainer_file = cryptainer_storage / "report.crypt.json"
        payload_file = cryptainer_storage / "report.crypt.json.payload"
        assert cryptainer_file.is_file() and payload_file.is_file()
        original_contents = (cryptainer_file.read_bytes(), payload_file.read_bytes())

        pathlib.Path(data_file).write_bytes(b"second content")

        # Re-encrypting with the same basename is refused before any encryption, both files staying untouched
        for extra_args in ([], ["--bundle"]):
            with mock.patch("wacryptolib.cli.CryptainerStorage.encrypt_file") as encryption_mock:
                result = runner.invoke(cli, base_args + ["encrypt", data_file, "-o", "report.crypt"] + extra_args)
                assert result.exit_code == 2, result.stderr
                assert "report.crypt.json' already exists, use --force to overwrite it" in result.stderr
                encryption_mock.assert_not_called()
            assert (cryptainer_file.read_bytes(), payload_file.read_bytes()) == original_contents

        # STDIN is not consumed when encryption is refused

        class _UnclosableBytesIO(io.BytesIO):
            def close(self):
                pass  # CliRunner closes its input stream, but we want to inspect it afterwards

        stdin_stream = _UnclosableBytesIO(b"piped content")
        result = runner.invoke(cli, base_args + ["encrypt", "-", "-o", "report"], input=stdin_stream)
        assert result.exit_code == 2, result.stderr
        assert stdin_stream.tell() == 0

        # A lone leftover offloaded payload file blocks encryption too, bundled or not
        cryptainer_file.unlink()
        for extra_args in ([], ["--bundle"]):
            result = runner.invoke(cli, base_args + ["encrypt", data_file, "-o", "report"] + extra_args)
            assert result.exit_code == 2, result.stderr
            assert "report.crypt.json.payload' already exists" in result.stderr
            assert not cryptainer_file.exists()

        # A directory in the way is refused even with --force
        cryptainer_storage.joinpath("dirred.crypt.json").mkdir()
        result = runner.invoke(cli, base_args + ["encrypt", data_file, "-o", "dirred", "--force"])
        assert result.exit_code == 2, result.stderr
        assert "is a directory" in result.stderr

        # Forced encryption overwrites the stored cryptainer, which then decrypts to the new content
        cryptainer_file.write_bytes(original_contents[0])
        result = runner.invoke(
            cli, base_args + ["encrypt", data_file, "-o", "report", "--force"], catch_exceptions=False
        )
        assert result.exit_code == 0, result.stderr
        assert cryptainer_file.read_bytes() != original_contents[0]
        result = runner.invoke(
            cli, base_args + ["cryptainer", "decrypt", "report.crypt.json", "-o", "decrypted.txt"], catch_exceptions=False
        )
        assert result.exit_code == 0, result.stderr
        assert pathlib.Path("decrypted.txt").read_bytes() == b"second content"


def test_cli_cryptoconf_generate_simple_refuses_overwriting_existing_file(tmp_path):
    runner = _get_cli_runner()
    layers = """add-payload-cipher-layer --sym-cipher-algo aes_cbc
                add-key-cipher-layer --asym-cipher-algo RSA_OAEP --trustee-type local_keyfactory""".split()

    output_file = tmp_path / "conf.json"
    output_file.write_text("my precious cryptoconf")

    result = runner.invoke(cli, ["cryptoconf", "generate-simple", "-o", str(output_file)] + layers)
    assert result.exit_code == 2, result.stderr
    assert "conf.json' already exists, use --force to overwrite it" in result.stderr
    assert output_file.read_text() == "my precious cryptoconf"

    result = runner.invoke(cli, ["cryptoconf", "generate-simple", "--force", "-o", str(output_file)] + layers)
    assert result.exit_code == 0, result.stderr
    check_cryptoconf_sanity(load_from_json_str(output_file.read_text()))

    for extra_args in ([], ["--force"]):
        result = runner.invoke(cli, ["cryptoconf", "generate-simple", "-o", str(tmp_path)] + extra_args + layers)
        assert result.exit_code == 2, result.stderr
        assert "is a directory" in result.stderr

    result = runner.invoke(cli, ["cryptoconf", "generate-simple"] + layers)  # STDOUT is never blocked
    assert result.exit_code == 0, result.stderr
    check_cryptoconf_sanity(load_from_json_str(result.stdout))


def test_cli_authenticator_create_refuses_existing_paths(tmp_path):
    runner = _get_cli_runner()
    no_passphrase_env = {"WA_PASSPHRASE": None}  # Any passphrase prompt would then abort with exit code 1
    base_args = ["authenticator", "create", "--owner", "Donald", "--passphrase-hint", "somehint"]

    existing_dir = tmp_path / "existing_dir"
    existing_dir.mkdir()
    existing_dir.joinpath("content.txt").write_text("content")
    existing_file = tmp_path / "existing_file"
    existing_file.write_text("file content")

    result = runner.invoke(cli, base_args + [str(existing_dir)], env=no_passphrase_env)
    assert result.exit_code == 2, result.stderr
    assert "must not exist yet" in result.stderr
    assert "passphrase" not in result.stderr.lower()
    assert [p.name for p in existing_dir.iterdir()] == ["content.txt"]

    result = runner.invoke(cli, base_args + [str(existing_file)], env=no_passphrase_env)
    assert result.exit_code == 2, result.stderr
    assert "already exists and is not a directory, remove it first" in result.stderr
    assert "existing_file" in result.stderr
    assert "passphrase" not in result.stderr.lower()
    assert result.exc_info[0] is SystemExit  # No traceback
    assert existing_file.read_text() == "file content"

    # No overwriting option exists for directories
    result = runner.invoke(cli, base_args + [str(existing_dir), "--force"], env=no_passphrase_env)
    assert result.exit_code == 2, result.stderr
    assert "No such option: --force" in result.stderr
    result = runner.invoke(cli, ["authenticator", "create", "--help"])
    assert "--force" not in result.stdout

    # Library callers get a ValidationError too
    with pytest.raises(ValidationError, match="already exists and is not a directory"):
        operations.create_authenticator(
            existing_file,
            keypair_count=1,
            keystore_owner="Donald",
            keystore_passphrase_hint="somehint",
            keystore_passphrase="somepassphrase",
        )
    assert existing_file.read_text() == "file content"


_GENERATE_SIMPLE_LAYERS = """add-payload-cipher-layer --sym-cipher-algo aes_cbc
    add-key-cipher-layer --asym-cipher-algo RSA_OAEP --trustee-type local_keyfactory""".split()


def _get_document_file_format(path):
    """Detect the format of a document file from its content only."""
    first_byte = pathlib.Path(path).read_bytes()[:1]
    assert first_byte, path
    if first_byte in (b"{", b"["):
        return DocumentFormat.JSON
    assert 0x80 <= first_byte[0] <= 0xBF, (path, first_byte)
    return DocumentFormat.CBOR


def _list_filenames(directory="."):
    return sorted(os.listdir(directory))  # Actual names, whatever the case sensitivity of the filesystem


def test_cli_encrypt_with_file_format(tmp_path):
    base_args, keystore_pool_path, cryptainer_storage = _get_cli_base_args_for_folder_isolation(tmp_path)
    runner = _get_cli_runner()

    with runner.isolated_filesystem():
        pathlib.Path("video.mp4").write_bytes(b"some video content")

        # Encrypt default
        result = runner.invoke(cli, base_args + ["encrypt", "video.mp4"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert _list_filenames(cryptainer_storage) == ["video.mp4.crypt.json", "video.mp4.crypt.json.payload"]
        assert _get_document_file_format(cryptainer_storage / "video.mp4.crypt.json") == DocumentFormat.JSON

        # Encrypt to CBOR, offloaded or bundled, the warning naming the sibling of another format
        result = runner.invoke(cli, base_args + ["encrypt", "video.mp4", "--format", "cbor"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert "existing cryptainer video.mp4.crypt.json," in result.stderr
        result = runner.invoke(
            cli, base_args + ["encrypt", "video.mp4", "-o", "bundled", "--format", "CBOR", "--bundle"]
        )
        assert result.exit_code == 0, result.stderr
        assert _list_filenames(cryptainer_storage) == [
            "bundled.crypt.cbor",
            "video.mp4.crypt.cbor",
            "video.mp4.crypt.cbor.payload",
            "video.mp4.crypt.json",
            "video.mp4.crypt.json.payload",
        ]
        for name in ("bundled.crypt.cbor", "video.mp4.crypt.cbor"):
            assert _get_document_file_format(cryptainer_storage / name) == DocumentFormat.CBOR

        # Decrypt default output name, for every suffix
        os.remove("video.mp4")
        result = runner.invoke(cli, base_args + ["cryptainer", "decrypt", "video.mp4.crypt.cbor"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert pathlib.Path("video.mp4").read_bytes() == b"some video content"
        result = runner.invoke(cli, base_args + ["cryptainer", "decrypt", "bundled.crypt.cbor"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert pathlib.Path("bundled").read_bytes() == b"some video content"

        result = runner.invoke(cli, base_args + ["cryptainer", "list", "--format", "json"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert sorted(entry["name"] for entry in load_from_json_str(result.stdout)) == [
            "bundled.crypt.cbor",
            "video.mp4.crypt.cbor",
            "video.mp4.crypt.json",
        ]

        # Unknown file format
        result = runner.invoke(cli, base_args + ["encrypt", "video.mp4", "-o", "other", "--format", "yaml"])
        assert result.exit_code == 2, result.stderr
        assert "Invalid value for '--format'" in result.stderr
        assert not any(name.startswith("other") for name in _list_filenames(cryptainer_storage))


def test_cli_encrypt_overwrite_checks_per_file_format(tmp_path):
    base_args, keystore_pool_path, cryptainer_storage = _get_cli_base_args_for_folder_isolation(tmp_path)
    runner = _get_cli_runner()

    with runner.isolated_filesystem():
        pathlib.Path("report.txt").write_bytes(b"new content")

        # Encrypting over an existing CBOR cryptainer is refused
        cryptainer_storage.joinpath("report.crypt.cbor").write_bytes(b"existing cbor cryptainer")
        result = runner.invoke(cli, base_args + ["encrypt", "report.txt", "-o", "report", "--format", "cbor"])
        assert result.exit_code == 2, result.stderr
        assert "report.crypt.cbor' already exists, use --force to overwrite it" in result.stderr
        assert cryptainer_storage.joinpath("report.crypt.cbor").read_bytes() == b"existing cbor cryptainer"
        assert _list_filenames(cryptainer_storage) == ["report.crypt.cbor"]

        # A leftover CBOR payload blocks CBOR encryption, bundled or not
        cryptainer_storage.joinpath("report.crypt.cbor").unlink()
        cryptainer_storage.joinpath("report.crypt.cbor.payload").write_bytes(b"leftover")
        for extra_args in ([], ["--bundle"]):
            result = runner.invoke(
                cli, base_args + ["encrypt", "report.txt", "-o", "report", "--format", "cbor"] + extra_args
            )
            assert result.exit_code == 2, result.stderr
            assert "report.crypt.cbor.payload' already exists" in result.stderr
            assert _list_filenames(cryptainer_storage) == ["report.crypt.cbor.payload"]
        cryptainer_storage.joinpath("report.crypt.cbor.payload").unlink()

        # A cryptainer in another format does not block encryption
        pathlib.Path("old.txt").write_bytes(b"old content")
        result = runner.invoke(cli, base_args + ["encrypt", "old.txt", "-o", "report"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        for suffix in ("", ".payload"):  # Renamed as a legacy cryptainer
            cryptainer_storage.joinpath("report.crypt.json" + suffix).rename(
                cryptainer_storage.joinpath("report.crypt" + suffix)
            )
        legacy_contents = {
            name: cryptainer_storage.joinpath(name).read_bytes() for name in ("report.crypt", "report.crypt.payload")
        }
        result = runner.invoke(cli, base_args + ["encrypt", "report.txt", "-o", "report"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert "existing cryptainer report.crypt," in result.stderr  # Warning
        assert _list_filenames(cryptainer_storage) == [
            "report.crypt",
            "report.crypt.json",
            "report.crypt.json.payload",
            "report.crypt.payload",
        ]
        for name, content in legacy_contents.items():
            assert cryptainer_storage.joinpath(name).read_bytes() == content

        for cryptainer_name, expected_content in [("report.crypt", b"old content"), ("report.crypt.json", b"new content")]:
            result = runner.invoke(
                cli,
                base_args + ["cryptainer", "decrypt", cryptainer_name, "-o", "-"],
                catch_exceptions=False,
            )
            assert result.exit_code == 0, result.stderr
            assert expected_content in result.stdout_bytes


def test_cli_encrypt_strips_premature_cryptainer_suffixes(tmp_path):
    base_args, keystore_pool_path, cryptainer_storage = _get_cli_base_args_for_folder_isolation(tmp_path)
    runner = _get_cli_runner()

    with runner.isolated_filesystem():
        pathlib.Path("video.mp4").write_bytes(b"clip content")

        for output_basename, extra_args, expected_name in [
            ("clip.crypt.json", ["--format", "cbor"], "clip.crypt.cbor"),  # Premature suffix stripped
            ("Clip.CRYPT", [], "Clip.crypt.json"),  # Premature suffix in another letter case
            ("Other.Crypt.Cbor", [], "Other.crypt.json"),
            ("legacy.crypt", ["--format", "cbor"], "legacy.crypt.cbor"),
            ("report.JSON", [], "report.json.crypt.json"),  # Not a cryptainer suffix, but a normalized extension
            ("temp.crypt.json~", [], "temp.crypt.json~.crypt.json"),  # Temporary names end with no cryptainer suffix
        ]:
            result = runner.invoke(
                cli, base_args + ["encrypt", "video.mp4", "-o", output_basename, "--bundle"] + extra_args
            )
            assert result.exit_code == 0, (output_basename, result.stderr)
            assert expected_name in _list_filenames(cryptainer_storage), (output_basename, _list_filenames(cryptainer_storage))

        assert _list_filenames(cryptainer_storage) == sorted(
            [
                "Clip.crypt.json",
                "Other.crypt.json",
                "clip.crypt.cbor",
                "legacy.crypt.cbor",
                "report.json.crypt.json",
                "temp.crypt.json~.crypt.json",
            ]
        )

        # Decrypt default output names: suffix stripped in any letter case, ".decrypted" added to temporary names
        shutil.copyfile(cryptainer_storage / "Clip.crypt.json", cryptainer_storage / "Upper.CRYPT.JSON")
        shutil.copyfile(cryptainer_storage / "Clip.crypt.json", cryptainer_storage / "unfinished.crypt.json~")
        for cryptainer_name, expected_output_name in [
            ("Upper.CRYPT.JSON", "Upper"),
            ("unfinished.crypt.json~", "unfinished.crypt.json~.decrypted"),
            ("report.json.crypt.json", "report.json"),
        ]:
            result = runner.invoke(
                cli, base_args + ["cryptainer", "decrypt", cryptainer_name], catch_exceptions=False
            )
            assert result.exit_code == 0, result.stderr
            assert pathlib.Path(expected_output_name).read_bytes() == b"clip content"
        assert _list_filenames() == ["Upper", "report.json", "unfinished.crypt.json~.decrypted", "video.mp4"]


def _write_cryptoconf_files(tmp_path):
    json_cryptoconf_path = tmp_path / "conf.json"
    dump_to_json_file(json_cryptoconf_path, SIMPLE_CRYPTOCONF)
    cbor_cryptoconf_path = tmp_path / "conf.cbor"
    cbor_cryptoconf_path.write_bytes(dump_to_cbor_bytes(SIMPLE_CRYPTOCONF))
    return json_cryptoconf_path, cbor_cryptoconf_path


def test_cli_cryptoconf_readers_accept_both_file_formats(tmp_path):
    base_args, keystore_pool_path, cryptainer_storage = _get_cli_base_args_for_folder_isolation(tmp_path)
    runner = _get_cli_runner()
    json_cryptoconf_path, cbor_cryptoconf_path = _write_cryptoconf_files(tmp_path)

    # Recognized by name, else by content, and from STDIN
    no_extension_path = tmp_path / "01_simple.cryptoconf"
    no_extension_path.write_bytes(cbor_cryptoconf_path.read_bytes())
    upper_extension_path = tmp_path / "UPPER.JSON"  # Opened as typed
    upper_extension_path.write_bytes(json_cryptoconf_path.read_bytes())

    for cryptoconf_path in (json_cryptoconf_path, cbor_cryptoconf_path, no_extension_path, upper_extension_path):
        result = runner.invoke(cli, ["cryptoconf", "validate", str(cryptoconf_path)], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert "is valid" in result.stderr

        result = runner.invoke(cli, ["cryptoconf", "summarize", str(cryptoconf_path)], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert "AES_CBC" in result.stdout

    for cryptoconf_path in (json_cryptoconf_path, cbor_cryptoconf_path):
        cryptoconf_bytes = cryptoconf_path.read_bytes()
        result = runner.invoke(cli, ["cryptoconf", "validate", "-"], input=cryptoconf_bytes, catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        result = runner.invoke(cli, ["cryptoconf", "summarize", "-"], input=cryptoconf_bytes, catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert "AES_CBC" in result.stdout

    data_file = tmp_path / "data.txt"
    data_file.write_bytes(b"some data")
    for cryptoconf_path in (json_cryptoconf_path, cbor_cryptoconf_path):
        output_basename = "data_" + cryptoconf_path.suffix[1:]
        result = runner.invoke(
            cli,
            base_args + ["encrypt", str(data_file), "-o", output_basename, "-c", str(cryptoconf_path)],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.stderr
        assert cryptainer_storage.joinpath(output_basename + ".crypt.json").is_file()

    # CBOR cryptoconf piped to STDIN, for encryption too
    result = runner.invoke(
        cli,
        base_args + ["encrypt", str(data_file), "-o", "data_stdin", "-c", "-"],
        input=cbor_cryptoconf_path.read_bytes(),
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.stderr
    assert cryptainer_storage.joinpath("data_stdin.crypt.json").is_file()

    # Mislabeled file refused, naming the file and both formats
    mislabeled_path = tmp_path / "mislabeled.json"
    mislabeled_path.write_bytes(cbor_cryptoconf_path.read_bytes())
    for command in (["cryptoconf", "validate"], ["cryptoconf", "summarize"]):
        result = runner.invoke(cli, command + [str(mislabeled_path)])
        assert result.exit_code == 2, result.stderr
        assert "mislabeled.json" in result.stderr
        assert "should be Extended JSON from its name, but its content looks like WA-CBOR" in result.stderr
    result = runner.invoke(cli, base_args + ["encrypt", str(data_file), "-o", "data_bad", "-c", str(mislabeled_path)])
    assert result.exit_code == 2, result.stderr
    assert "mislabeled.json" in result.stderr
    assert not any(name.startswith("data_bad") for name in _list_filenames(cryptainer_storage))


def test_cli_cryptoconf_generate_simple_with_file_format(tmp_path):
    runner = _get_cli_runner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        for output_name, extra_args, created_name, expected_format in [
            ("conf.cbor", [], "conf.cbor", DocumentFormat.CBOR),  # Cryptoconf format from extension
            ("conf2.CBOR", [], "conf2.cbor", DocumentFormat.CBOR),  # Cryptoconf extension in another letter case
            ("conf3.Json", [], "conf3.json", DocumentFormat.JSON),
            ("conf4.json", ["--format", "json"], "conf4.json", DocumentFormat.JSON),
            ("conf5.txt", [], "conf5.txt", DocumentFormat.JSON),  # Any other name, in Extended JSON by default
            ("conf6.txt", ["--format", "cbor"], "conf6.txt", DocumentFormat.CBOR),
            ("conf7.TXT", ["--format", "CBOR"], "conf7.TXT", DocumentFormat.CBOR),
        ]:
            result = runner.invoke(
                cli, ["cryptoconf", "generate-simple", "-o", output_name] + extra_args + _GENERATE_SIMPLE_LAYERS
            )
            assert result.exit_code == 0, (output_name, result.stderr)
            assert created_name in _list_filenames(), (output_name, _list_filenames())
            assert _get_document_file_format(created_name) == expected_format
            cryptoconf = load_from_document_file(created_name, format=expected_format)
            check_cryptoconf_sanity(cryptoconf)
            assert cryptoconf["payload_cipher_layers"][0]["payload_cipher_algo"] == "AES_CBC"
        assert _list_filenames() == [
            "conf.cbor",
            "conf2.cbor",
            "conf3.json",
            "conf4.json",
            "conf5.txt",
            "conf6.txt",
            "conf7.TXT",
        ]

        # Contradicting format
        for output_name, extra_args in [("bad.cbor", ["--format", "json"]), ("bad.JSON", ["--format", "cbor"])]:
            result = runner.invoke(
                cli, ["cryptoconf", "generate-simple", "-o", output_name] + extra_args + _GENERATE_SIMPLE_LAYERS
            )
            assert result.exit_code == 2, result.stderr
            assert "contradicts the extension of output file" in result.stderr
        assert not any(name.lower().startswith("bad") for name in _list_filenames())

        # Overwrite protection applies to the normalized name, and --force replaces the file
        pathlib.Path("conf.cbor").write_bytes(b"precious")
        result = runner.invoke(cli, ["cryptoconf", "generate-simple", "-o", "conf.CBOR"] + _GENERATE_SIMPLE_LAYERS)
        assert result.exit_code == 2, result.stderr
        assert "conf.cbor' already exists, use --force" in result.stderr
        assert pathlib.Path("conf.cbor").read_bytes() == b"precious"
        result = runner.invoke(
            cli, ["cryptoconf", "generate-simple", "-o", "conf.CBOR", "--force"] + _GENERATE_SIMPLE_LAYERS
        )
        assert result.exit_code == 0, result.stderr
        assert _get_document_file_format("conf.cbor") == DocumentFormat.CBOR
        assert "conf.CBOR" not in _list_filenames()

    # Raw CBOR bytes, or JSON text, to STDOUT
    result = runner.invoke(cli, ["cryptoconf", "generate-simple", "--format", "cbor"] + _GENERATE_SIMPLE_LAYERS)
    assert result.exit_code == 0, result.stderr
    check_cryptoconf_sanity(load_from_cbor_bytes(result.stdout_bytes))
    result = runner.invoke(cli, ["cryptoconf", "generate-simple"] + _GENERATE_SIMPLE_LAYERS)
    assert result.exit_code == 0, result.stderr
    check_cryptoconf_sanity(load_from_json_str(result.stdout))

    # No -f short option
    result = runner.invoke(cli, ["cryptoconf", "generate-simple", "-f", "cbor"] + _GENERATE_SIMPLE_LAYERS)
    assert result.exit_code == 2, result.stderr
    assert "No such option" in result.stderr


def _invoke_convert_format(runner, args, **kwargs):
    return runner.invoke(cli, ["convert-format"] + args, **kwargs)


def test_cli_convert_format_of_simple_documents(tmp_path):
    runner = _get_cli_runner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        dump_to_json_file("conf.json", SIMPLE_CRYPTOCONF)
        original_json_bytes = pathlib.Path("conf.json").read_bytes()

        # Cryptoconf to CBOR
        result = _invoke_convert_format(runner, ["conf.json", "-o", "other.cbor"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert pathlib.Path("conf.json").read_bytes() == original_json_bytes
        assert pathlib.Path("other.cbor").read_bytes() == dump_to_cbor_bytes(load_from_json_bytes(original_json_bytes))

        # Back to JSON, with a derived name
        os.remove("conf.json")
        pathlib.Path("other.cbor").rename("conf.cbor")
        result = _invoke_convert_format(runner, ["conf.cbor"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert pathlib.Path("conf.json").read_bytes() == original_json_bytes
        assert _list_filenames() == ["conf.cbor", "conf.json"]

        # Unknown target extension
        for target in ("conf.yaml", "conf.crypt", "conf"):
            result = _invoke_convert_format(runner, ["conf.json", "-o", target])
            assert result.exit_code == 2, result.stderr
            assert "must have a .json or .cbor extension" in result.stderr
        assert _list_filenames() == ["conf.cbor", "conf.json"]

        # Target extension in another letter case
        result = _invoke_convert_format(runner, ["conf.json", "-o", "OTHER.CBOR"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert _list_filenames() == ["OTHER.cbor", "conf.cbor", "conf.json"]
        assert pathlib.Path("OTHER.cbor").read_bytes() == pathlib.Path("conf.cbor").read_bytes()

        # Source extension in another letter case, read as typed
        pathlib.Path("Report.JSON").write_bytes(original_json_bytes)
        result = _invoke_convert_format(runner, ["Report.JSON"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert "Report.cbor" in _list_filenames()
        assert pathlib.Path("Report.cbor").read_bytes() == pathlib.Path("conf.cbor").read_bytes()

        # Corpus-style name
        pathlib.Path("01_simple.cryptoconf").write_bytes(original_json_bytes)
        result = _invoke_convert_format(runner, ["01_simple.cryptoconf"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert pathlib.Path("01_simple.cryptoconf.cbor").read_bytes() == pathlib.Path("conf.cbor").read_bytes()

        # Existing target refused
        before = _list_filenames()
        pathlib.Path("conf.cbor").write_bytes(b"precious")
        result = _invoke_convert_format(runner, ["conf.json"])
        assert result.exit_code == 2, result.stderr
        assert "conf.cbor' already exists, use --force to overwrite it" in result.stderr
        assert pathlib.Path("conf.cbor").read_bytes() == b"precious"

        # Forced overwrite
        result = _invoke_convert_format(runner, ["conf.json", "--force"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert pathlib.Path("conf.cbor").read_bytes() == pathlib.Path("OTHER.cbor").read_bytes()
        assert _list_filenames() == before  # No temporary file left

        # Target is the source
        for args in (["conf.json", "-o", "conf.json", "--force"], ["conf.cbor", "-o", "conf.cbor"]):
            result = _invoke_convert_format(runner, args)
            assert result.exit_code == 2, result.stderr
            assert "is the same file as" in result.stderr
        assert pathlib.Path("conf.json").read_bytes() == original_json_bytes

        # Letter case of the target: the filesystem decides whether it is the source
        pathlib.Path("upper.JSON").write_bytes(original_json_bytes)
        case_insensitive_filesystem = os.path.exists("upper.json")
        result = _invoke_convert_format(runner, ["upper.JSON", "-o", "upper.json", "--force"])
        if case_insensitive_filesystem:
            assert result.exit_code == 2, result.stderr
            assert "is the same file as" in result.stderr
            assert "upper.JSON" in _list_filenames()
        else:
            assert result.exit_code == 0, result.stderr
            assert {"upper.JSON", "upper.json"} <= set(_list_filenames())
        assert pathlib.Path("upper.JSON").read_bytes() == original_json_bytes

        # No -f short option
        before = _list_filenames()
        result = _invoke_convert_format(runner, ["conf.json", "-f"])
        assert result.exit_code == 2, result.stderr
        assert "No such option" in result.stderr
        assert _list_filenames() == before


def test_cli_convert_format_failures_leave_no_output(tmp_path):
    runner = _get_cli_runner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        # Unsupported value
        pathlib.Path("nan.json").write_text('{"value": {"$numberDecimal": "NaN"}}')
        result = _invoke_convert_format(runner, ["nan.json"])
        assert result.exit_code == 1, result.stderr
        assert "NaN" in result.stderr
        assert _list_filenames() == ["nan.json"]

        # Same for a same-format conversion, since conversions reject values that a format can't carry faithfully
        result = _invoke_convert_format(runner, ["nan.json", "-o", "nan2.json"])
        assert result.exit_code == 1, result.stderr
        assert _list_filenames() == ["nan.json"]

        # Malformed and mislabeled sources
        pathlib.Path("malformed.json").write_text('{"value": ')
        pathlib.Path("mislabeled.json").write_bytes(dump_to_cbor_bytes({"a": 1}))
        pathlib.Path("malformed.cbor").write_bytes(b"\xa1\x61")
        pathlib.Path("garbage.dat").write_bytes(b"garbage")
        for source in ("malformed.json", "mislabeled.json", "malformed.cbor", "garbage.dat"):
            result = _invoke_convert_format(runner, [source])
            assert result.exit_code == 1, (source, result.stderr)
            assert source in result.stderr
        assert "should be Extended JSON from its name, but its content looks like WA-CBOR" in _invoke_convert_format(
            runner, ["mislabeled.json"]
        ).stderr
        assert _list_filenames() == ["garbage.dat", "malformed.cbor", "malformed.json", "mislabeled.json", "nan.json"]

        # A target appearing after the early check is not clobbered without --force
        dump_to_json_file("conf.json", SIMPLE_CRYPTOCONF)

        def _convert_and_create_target(*args, **kwargs):
            pathlib.Path("conf.cbor").write_bytes(b"late content")
            return convert_document_tree_to_bytes(*args, **kwargs)

        with mock.patch("wacryptolib.cli.convert_document_tree_to_bytes", side_effect=_convert_and_create_target):
            result = _invoke_convert_format(runner, ["conf.json"])
        assert result.exit_code == 2, result.stderr
        assert "conf.cbor' already exists" in result.stderr
        assert pathlib.Path("conf.cbor").read_bytes() == b"late content"

        # A failed forced conversion leaves the previous target intact, and no temporary file
        before = _list_filenames()
        with mock.patch("wacryptolib.cli.os.replace", side_effect=OSError("disk full")):
            result = _invoke_convert_format(runner, ["conf.json", "--force"])
        assert result.exit_code == 1, result.stderr
        assert "disk full" in result.stderr
        assert pathlib.Path("conf.cbor").read_bytes() == b"late content"
        assert _list_filenames() == before


def test_cli_convert_format_of_cryptainers(tmp_path):
    base_args, keystore_pool_path, cryptainer_storage = _get_cli_base_args_for_folder_isolation(tmp_path)
    runner = _get_cli_runner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        pathlib.Path("x").write_bytes(b"secret content")
        result = runner.invoke(cli, base_args + ["encrypt", "x"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        result = runner.invoke(cli, base_args + ["encrypt", "x", "-o", "inline", "--bundle"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        os.chdir(cryptainer_storage)
        source_contents = {name: pathlib.Path(name).read_bytes() for name in _list_filenames()}
        assert sorted(source_contents) == ["inline.crypt.json", "x.crypt.json", "x.crypt.json.payload"]

        def _check_sources_unchanged():
            for name, content in source_contents.items():
                assert pathlib.Path(name).read_bytes() == content

        def _check_decryption(cryptainer_name):
            result = runner.invoke(
                cli, base_args + ["cryptainer", "decrypt", cryptainer_name, "-o", "-"], catch_exceptions=False
            )
            assert result.exit_code == 0, result.stderr
            assert b"secret content" in result.stdout_bytes

        # Offloaded cryptainer converted, its payload copied
        result = _invoke_convert_format(runner, ["x.crypt.json"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert _list_filenames() == [
            "inline.crypt.json",
            "x.crypt.cbor",
            "x.crypt.cbor.payload",
            "x.crypt.json",
            "x.crypt.json.payload",
        ]
        assert pathlib.Path("x.crypt.cbor.payload").read_bytes() == source_contents["x.crypt.json.payload"]
        assert _get_document_file_format("x.crypt.cbor") == DocumentFormat.CBOR
        _check_sources_unchanged()
        _check_decryption("x.crypt.cbor")

        # Inline cryptainer converted, without payload
        result = _invoke_convert_format(runner, ["inline.crypt.json"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert "inline.crypt.cbor" in _list_filenames()
        assert "inline.crypt.cbor.payload" not in _list_filenames()
        _check_decryption("inline.crypt.cbor")

        # Existing target payload refused
        os.remove("x.crypt.cbor")
        pathlib.Path("x.crypt.cbor.payload").write_bytes(b"precious payload")
        result = _invoke_convert_format(runner, ["x.crypt.json"])
        assert result.exit_code == 2, result.stderr
        assert "x.crypt.cbor.payload' already exists" in result.stderr
        assert not os.path.exists("x.crypt.cbor")
        assert pathlib.Path("x.crypt.cbor.payload").read_bytes() == b"precious payload"

        # Forced conversion overwrites both target files
        pathlib.Path("x.crypt.cbor").write_bytes(b"precious cryptainer")
        result = _invoke_convert_format(runner, ["x.crypt.json", "--force"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert pathlib.Path("x.crypt.cbor.payload").read_bytes() == source_contents["x.crypt.json.payload"]
        _check_decryption("x.crypt.cbor")

        # Legacy cryptainer, in CANONICAL Extended JSON, normalized to RELAXED Extended JSON
        cryptainer = load_from_json_bytes(source_contents["x.crypt.json"])
        pathlib.Path("old.crypt").write_text(json.dumps(convert_to_extjson(cryptainer, canonical=True)))
        shutil.copyfile("x.crypt.json.payload", "old.crypt.payload")
        assert pathlib.Path("old.crypt").read_bytes() != source_contents["x.crypt.json"]
        result = _invoke_convert_format(runner, ["old.crypt", "-o", "old.crypt.json"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert pathlib.Path("old.crypt.json").read_bytes() == source_contents["x.crypt.json"]
        assert pathlib.Path("old.crypt.json.payload").read_bytes() == source_contents["x.crypt.json.payload"]

        # Legacy cryptainer with a derived name
        result = _invoke_convert_format(runner, ["old.crypt"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert {"old.crypt.cbor", "old.crypt.cbor.payload"} <= set(_list_filenames())
        _check_decryption("old.crypt.cbor")

        # Suffix in another letter case
        shutil.copyfile("x.crypt.json", "Upper.CRYPT.JSON")
        shutil.copyfile("x.crypt.json.payload", "Upper.CRYPT.JSON.payload")
        result = _invoke_convert_format(runner, ["Upper.CRYPT.JSON"], catch_exceptions=False)
        assert result.exit_code == 0, result.stderr
        assert {"Upper.crypt.cbor", "Upper.crypt.cbor.payload"} <= set(_list_filenames())
        _check_decryption("Upper.crypt.cbor")

        # Missing source payload
        before = _list_filenames()
        shutil.copyfile("x.crypt.json", "orphan.crypt.json")
        result = _invoke_convert_format(runner, ["orphan.crypt.json"])
        assert result.exit_code == 1, result.stderr
        assert "orphan.crypt.json.payload" in result.stderr
        assert _list_filenames() == sorted(before + ["orphan.crypt.json"])

        # A target payload which is the source itself is refused
        before = _list_filenames()
        shutil.copyfile("x.crypt.json", "weird.cbor.payload")  # Extended JSON detected from its content
        shutil.copyfile("x.crypt.json.payload", "weird.cbor.payload.payload")
        result = _invoke_convert_format(runner, ["weird.cbor.payload", "-o", "weird.cbor", "--force"])
        assert result.exit_code == 2, result.stderr
        assert "is the same file as" in result.stderr
        assert pathlib.Path("weird.cbor.payload").read_bytes() == source_contents["x.crypt.json"]
        assert _list_filenames() == sorted(before + ["weird.cbor.payload", "weird.cbor.payload.payload"])
