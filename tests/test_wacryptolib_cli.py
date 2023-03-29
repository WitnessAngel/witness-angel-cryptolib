import os
import pathlib
import random
import subprocess
from datetime import timedelta
from unittest import mock

import sys

from click.testing import CliRunner

import wacryptolib
from test_wacryptolib_cryptainer import SIMPLE_CRYPTOCONF
from wacryptolib.authenticator import initialize_authenticator
from wacryptolib.cli import wacryptolib_cli as cli
from wacryptolib.cryptainer import LOCAL_KEYFACTORY_TRUSTEE_MARKER, CryptainerStorage
from wacryptolib.keystore import FilesystemKeystore, generate_keypair_for_storage
from wacryptolib.utilities import dump_to_json_file, get_utc_now_date, load_from_json_str
from _test_mockups import generate_keystore_pool


REAL_GATEWAY_URL = "https://api.witnessangel.com/gateway/jsonrpc/"  # Real gateway used by some tests
REAL_GATEWAY_KEYSTORE_UID = "0f0c0988-80c1-9362-11c1-b06909a3a53c"  # Authenticator of ¤aaa, must exist in real prod


def _get_cli_runner():
    return CliRunner(mix_stderr=False)


def test_cli_help_texts():
    runner = _get_cli_runner()

    result = runner.invoke(cli, ["-h"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "Usage:" in result.stdout

    result = runner.invoke(cli, ["encrypt", "-h"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "into a secure cryptainer" in result.stdout

    result = runner.invoke(cli, ["decrypt", "-h"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "original media file" in result.stdout

    result = runner.invoke(cli, ["foreign-keystores", "-h"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "foreign-keystores" in result.stdout


def test_cli_encryption_decryption_and_summary(tmp_path):
    runner = _get_cli_runner()

    data_file = "test_file.txt"
    data_sample = "Héllô\nguÿs"
    cryptoconf_file = "mycryptoconf.json"

    for idx, base_args in enumerate([[], ["-k", tmp_path]]):  # Store keys into cwd or into specific folder

        with runner.isolated_filesystem() as tempdir:

            print("TEMPORARY TEST DIRECTORY:", tempdir)

            with open(data_file, "w") as output_file:
                output_file.write(data_sample)

            result = runner.invoke(cli, base_args + ["encrypt", "-i", "test_file.txt"], catch_exceptions=False)
            assert result.exit_code == 0
            assert os.path.exists(data_file + ".crypt")

            result = runner.invoke(
                cli, base_args + ["encrypt", "-i", "test_file.txt", "-o", "stuff.dat"], catch_exceptions=False
            )
            assert result.exit_code == 0
            assert os.path.exists("stuff.dat")

            with open("stuff.dat", "r") as input_file:
                data = input_file.read()
                assert "CHACHA20_POLY1305" not in data  # Not in default cryptoconf

            os.remove(data_file)  # CLEANUP
            assert not os.path.exists(data_file)

            result = runner.invoke(cli, base_args + ["decrypt", "-i", data_file + ".crypt"], catch_exceptions=False)
            assert result.exit_code == 0
            assert os.path.exists(data_file)

            result = runner.invoke(cli, base_args + ["decrypt", "-i", "stuff.dat"], catch_exceptions=False)
            assert result.exit_code == 0
            assert os.path.exists("stuff.dat.medium")

            result = runner.invoke(
                cli, base_args + ["decrypt", "-i", "stuff.dat", "-o", "stuffs.txt"], catch_exceptions=False
            )
            assert result.exit_code == 0
            assert os.path.exists("stuffs.txt")

            for result_file in (data_file, "stuff.dat.medium", "stuffs.txt"):
                with open(result_file, "r") as input_file:
                    data = input_file.read()
                    assert data == data_sample

            empty_storage = tmp_path.joinpath("subdir_%s" % idx)
            empty_storage.mkdir()
            result = runner.invoke(
                cli, ["-k", empty_storage, "decrypt", "-i", "stuff.dat", "-o", "stuffs.txt"], catch_exceptions=True
            )
            assert result.exit_code == 1  # Decryption failed because keypair was regenerated

            # CUSTOM cryptoconf !

            with open(cryptoconf_file, "wb") as f:
                f.write(b"badcontent")

            result = runner.invoke(
                cli, base_args + ["summarize", "-i", cryptoconf_file], catch_exceptions=True  # Wrong JSON content
            )
            assert result.exit_code == 1

            result = runner.invoke(
                cli,
                base_args + ["encrypt", "-i", "test_file.txt", "-o", "specialconf.crypt", "-c", cryptoconf_file],
                catch_exceptions=True,
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
                        payload_signatures=[],
                    )
                ]
            )
            dump_to_json_file(cryptoconf_file, simple_cryptoconf_tree)

            result = runner.invoke(cli, base_args + ["summarize", "-i", cryptoconf_file], catch_exceptions=False)
            assert result.exit_code == 0
            assert b"CHACHA20_POLY1305" in result.stdout_bytes
            assert b"RSA_OAEP" in result.stdout_bytes

            result = runner.invoke(
                cli,
                base_args + ["encrypt", "-i", "test_file.txt", "-o", "specialconf.crypt", "-c", cryptoconf_file],
                catch_exceptions=False,
            )
            assert result.exit_code == 0
            assert os.path.exists("specialconf.crypt")

            with open("specialconf.crypt", "r") as input_file:
                data = input_file.read()
                assert "CHACHA20_POLY1305" in data

            result = runner.invoke(
                cli,
                base_args + ["summarize", "-i", "specialconf.crypt"],  # Works on CRYPTAINERS too
                catch_exceptions=False,
            )
            assert result.exit_code == 0
            assert b"CHACHA20_POLY1305" in result.stdout_bytes
            assert b"RSA_OAEP" in result.stdout_bytes

            result = runner.invoke(
                cli,
                base_args + ["decrypt", "-i", "specialconf.crypt", "-o", "specialconf.crypt.decrypted"],
                catch_exceptions=False,
            )
            assert result.exit_code == 0
            assert os.path.exists("specialconf.crypt.decrypted")

            with open("specialconf.crypt.decrypted", "r") as input_file:
                data = input_file.read()
                assert data == data_sample


def test_cli_subprocess_invocation():
    src_dir = str(pathlib.Path(wacryptolib.__file__).resolve().parents[1])

    env = os.environ.copy()
    env["PYTHONPATH"] = env.get("PYTHONPATH", "") + os.pathsep + src_dir

    proc = subprocess.Popen(
        [sys.executable, "-m", "wacryptolib", "-h"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate(timeout=15)
    assert b"Options:" in stdout
    assert b"Commands:" in stdout
    assert not stderr or b"debugger" in stderr  # For when pydev debugger connects to process...
    assert proc.returncode == 0


def test_cli_foreign_keystore_management(tmp_path):
    keystore_pool_path = tmp_path / "keystore-pool"
    keystore_pool_path.mkdir()

    authenticator_path = tmp_path / "authenticator"
    authenticator_path.mkdir()

    base_args = ["--keystore-pool", str(keystore_pool_path)]

    wrong_uuid_str = "676ff51f-1439-48d9-94f9-a6011357fd11"

    runner = _get_cli_runner()

    result = runner.invoke(cli, ["-v", "DEBUG", "foreign-keystores", "list"])  # No forced keystore pool here
    assert result.exit_code == 0
    assert "No keystore-pool directory provided, defaulting " in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list"])
    assert result.exit_code == 0
    assert "No foreign keystores found" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystores", "import", "--from-usb"])
    assert result.exit_code == 0
    assert "0 new authenticators imported, 0 updated, 0 skipped because corrupted" in result.stderr   # DO NOT keep USB key in PC for now!

    result = runner.invoke(cli, base_args + ["foreign-keystores", "import", "--from-usb", "--include-private-keys"])
    assert result.exit_code == 0
    assert "0 new authenticators imported, 0 updated, 0 skipped because corrupted" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list"])
    assert result.exit_code == 0
    assert "No foreign keystores found" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystores", "import", "--from-gateway", REAL_GATEWAY_KEYSTORE_UID])
    assert result.exit_code == 2  # click.UsageError
    assert "No web gateway URL specified" in result.stderr

    result = runner.invoke(cli, base_args + ["--gateway-url", REAL_GATEWAY_URL,  # Here --include-private-keys has no effect
                                             "foreign-keystores", "import", "--include-private-keys", "--from-gateway", REAL_GATEWAY_KEYSTORE_UID])
    assert result.exit_code == 0
    assert "Authenticator 0f0c0988-80c1-9362-11c1-b06909a3a53c (owner: ¤aaa) imported" in result.stderr

    result = runner.invoke(cli, base_args + ["--gateway-url", REAL_GATEWAY_URL,
                                             "foreign-keystores", "import", "--from-gateway", REAL_GATEWAY_KEYSTORE_UID])
    assert result.exit_code == 0
    assert "Authenticator 0f0c0988-80c1-9362-11c1-b06909a3a53c (owner: ¤aaa) updated" in result.stderr

    result = runner.invoke(cli, base_args + ["--gateway-url", REAL_GATEWAY_URL,
                                             "foreign-keystores", "import", "--from-gateway", "676ff51f-1439-48d9-94f9-xxx"])
    assert result.exit_code == 2
    assert "not a valid UUID." in result.stderr

    result = runner.invoke(cli, base_args + ["--gateway-url", REAL_GATEWAY_URL,
                                             "foreign-keystores", "import", "--from-gateway", wrong_uuid_str])
    assert result.exit_code == 1  # Other exception raised
    assert "does not exist in database" in str(result.exc_info[1])

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list"])
    assert result.exit_code == 0
    assert " 0f0c0988-80c1-9362-11c1-b06909a3a53c " in result.stdout  # Table is displayed
    assert " ¤aaa " in result.stdout

    result = runner.invoke(cli, base_args + ["foreign-keystores", "import", "--from-gateway", REAL_GATEWAY_KEYSTORE_UID])
    assert result.exit_code == 2
    assert "No web gateway URL specified" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystores", "delete", REAL_GATEWAY_KEYSTORE_UID])
    assert result.exit_code == 0
    assert "successfully deleted" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list"])
    assert result.exit_code == 0
    assert "No foreign keystores found" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list", "--format", "json"])
    assert result.exit_code == 0
    assert result.stdout == "[]\n"

    result = runner.invoke(cli, base_args + ["foreign-keystores", "import", "--from-path", authenticator_path])
    assert result.exit_code == 1
    assert "keystore_metadata.json does not exist" in str(result.exc_info[1])

    keystore_metadata = initialize_authenticator(authenticator_path, keystore_owner="myuserxyz", keystore_passphrase_hint="somestuffs")
    new_keystore_uid = keystore_metadata["keystore_uid"]
    filesystem_keystore = FilesystemKeystore(authenticator_path)
    keypairs_count = random.randint(1, 3)

    for i in range(keypairs_count):
        generate_keypair_for_storage(
            key_algo="RSA_OAEP", keystore=filesystem_keystore, passphrase=None
        )

    result = runner.invoke(cli, base_args + ["foreign-keystores", "import", "--from-path", authenticator_path])
    assert result.exit_code == 0
    assert "imported" in result.stderr
    assert "updated" not in result.stderr
    assert "without private keys" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list"])
    assert result.exit_code == 0
    assert str(new_keystore_uid) in result.stdout
    assert " 0 " in result.stdout  # Private keys
    assert (" %d " % keypairs_count) in result.stdout  # Public keys

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list", "--format", "json"])
    assert result.exit_code == 0
    assert str(new_keystore_uid) not in result.stdout  # Output uses ExtendedJson encoding
    assert ('"$numberInt": "%d"' % keypairs_count) in result.stdout
    data_tree = load_from_json_str(result.stdout)  # Test loading of output
    assert isinstance(data_tree, list)
    assert len(data_tree) == 1
    assert data_tree[0]["keystore_owner"] == "myuserxyz"

    result = runner.invoke(cli, base_args + ["foreign-keystores", "import", "--include-private-keys", "--from-path", authenticator_path])
    assert result.exit_code == 0
    assert "imported" not in result.stderr
    assert "updated" in result.stderr
    assert "with private keys" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list", "--format", "plain"])  # Plain format is the default anyway
    assert result.exit_code == 0
    assert str(new_keystore_uid) in result.stdout
    assert " 0 " not in result.stdout
    assert result.stdout.count(" %d " % keypairs_count) == 2   # Public keys AND private keys

    result = runner.invoke(cli, base_args + ["foreign-keystores", "delete", wrong_uuid_str])
    assert result.exit_code == 2
    assert "Failed deletion" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list"])
    assert result.exit_code == 0
    assert str(new_keystore_uid) in result.stdout
    assert " myuserxyz " in result.stdout

    result = runner.invoke(cli, base_args + ["foreign-keystores", "delete", str(new_keystore_uid)])
    assert result.exit_code == 0
    assert "successfully deleted" in result.stderr

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list"])
    assert result.exit_code == 0
    assert "No foreign keystores found" in result.stderr


def test_cli_cryptainer_management(tmp_path):
    cryptainer_storage_path = tmp_path

    cryptainer_storage = CryptainerStorage(cryptainer_storage_path, default_cryptoconf=SIMPLE_CRYPTOCONF)

    base_args = ["--cryptainer-storage", str(cryptainer_storage_path)]

    runner = _get_cli_runner()

    result = runner.invoke(cli, ["-v", "DEBUG", "cryptainers", "list"])  # No forced cryptainer storage here
    assert result.exit_code == 0
    assert "No cryptainer-storage directory provided, defaulting" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainers", "list", "--format", "plain"])  # Default format
    assert result.exit_code == 0
    assert "No cryptainers found" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainers", "list", "--format", "json"])
    assert result.exit_code == 0
    assert result.stdout == "[]\n"

    result = runner.invoke(cli, base_args + ["cryptainers", "delete", "badname.crypt"])
    assert result.exit_code == 2
    assert "Invalid cryptainer name" in result.stderr

    cryptainer_storage.enqueue_file_for_encryption("myfilename", payload=b"xyz", cryptainer_metadata=None)
    cryptainer_storage.wait_for_idle_state()

    result = runner.invoke(cli, base_args + ["cryptainers", "list"])
    assert result.exit_code == 0
    assert "myfilename.crypt" in result.stdout

    result = runner.invoke(cli, base_args + ["cryptainers", "delete", "myfilename.crypt"])
    assert result.exit_code == 0
    assert "successfully deleted" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainers", "list"])
    assert result.exit_code == 0
    assert "No cryptainers found" in result.stderr

    recent_date_str = (get_utc_now_date() - timedelta(days=100)).strftime("%Y%m%d")
    first_cryptainer_name_base = "%s_152428_rtsp_camera_cryptainer.mp4" % recent_date_str
    cryptainer_storage.enqueue_file_for_encryption(first_cryptainer_name_base, payload=b"xyz", cryptainer_metadata=None)
    cryptainer_storage.enqueue_file_for_encryption("20420221_152428_rtsp_camera_cryptainer.mp4", payload=b"xyz"*1024**2, cryptainer_metadata=None)
    cryptainer_storage.enqueue_file_for_encryption("20430221_152428_rtsp_camera_cryptainer.mp4", payload=b"xyz", cryptainer_metadata=None)
    cryptainer_storage.wait_for_idle_state()

    result = runner.invoke(cli, base_args + ["cryptainers", "list"])
    assert result.exit_code == 0
    assert " 20420221_152428_rtsp_camera_cryptainer.mp4.crypt " in result.stdout

    result = runner.invoke(cli, base_args + ["cryptainers", "list", "--format", "json"])
    assert result.exit_code == 0
    assert '"20420221_152428_rtsp_camera_cryptainer.mp4.crypt"' in result.stdout
    data_tree = load_from_json_str(result.stdout)  # Test loading of output
    assert isinstance(data_tree, list)
    assert len(data_tree) == 3
    assert data_tree[0]["name"] == first_cryptainer_name_base + ".crypt"

    result = runner.invoke(cli, base_args + ["cryptainers", "purge", "--max-age", "101"])
    assert result.exit_code == 0
    assert "Cryptainers successfully deleted: 0" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainers", "purge", "--max-age", "99"])
    assert result.exit_code == 0
    assert "Cryptainers successfully deleted: 1" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainers", "purge", "--max-quota", "4"])
    assert result.exit_code == 0
    assert "Cryptainers successfully deleted: 0" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainers", "purge", "--max-quota", "3"])
    assert result.exit_code == 0
    assert "Cryptainers successfully deleted: 1" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainers", "purge", "--max-count", "1"])
    assert result.exit_code == 0
    assert "Cryptainers successfully deleted: 0" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainers", "list"])
    assert result.exit_code == 0
    assert " 20430221_152428_rtsp_camera_cryptainer.mp4.crypt " in result.stdout

    result = runner.invoke(cli, base_args + ["cryptainers", "purge", "--max-count", "0"])
    assert result.exit_code == 0
    assert "Cryptainers successfully deleted: 1" in result.stderr

    result = runner.invoke(cli, base_args + ["cryptainers", "list"])
    assert result.exit_code == 0
    assert "No cryptainers found" in result.stderr

