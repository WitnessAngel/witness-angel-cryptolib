import os
import pathlib
import subprocess
import sys

from click.testing import CliRunner

import wacryptolib
from wacryptolib.authenticator import initialize_authenticator
from wacryptolib.cli import wacryptolib_cli as cli
from wacryptolib.cryptainer import LOCAL_KEYFACTORY_TRUSTEE_MARKER
from wacryptolib.utilities import dump_to_json_file
from _test_mockups import generate_keystore_pool


REAL_GATEWAY_URL = "https://api.witnessangel.com/gateway/jsonrpc/"  # Real gateway used by some tests
REAL_GATEWAY_KEYSTORE_UID = "0f0c0988-80c1-9362-11c1-b06909a3a53c"  # Authenticator of ¤aaa, must exist in real prod


def test_cli_help_texts():
    runner = CliRunner()

    result = runner.invoke(cli, ["-h"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "Usage:" in result.output

    result = runner.invoke(cli, ["encrypt", "-h"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "into a secure cryptainer" in result.output

    result = runner.invoke(cli, ["decrypt", "-h"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "original media file" in result.output

    result = runner.invoke(cli, ["foreign-keystores", "-h"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "foreign-keystores" in result.output


def test_cli_encryption_decryption_and_summary(tmp_path):
    runner = CliRunner()

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

    runner = CliRunner()

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list"])
    assert result.exit_code == 0
    assert "No foreign keystores found" in result.output

    result = runner.invoke(cli, base_args + ["foreign-keystores", "import", "--from-usb"])
    assert result.exit_code == 0
    assert "0 new authenticators imported, 0 updated, 0 skipped because corrupted" in result.output   # DO NOT keep USB key in PC here!

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list"])
    assert result.exit_code == 0
    assert "No foreign keystores found" in result.output

    result = runner.invoke(cli, base_args + ["foreign-keystores", "import", "--from-gateway", REAL_GATEWAY_KEYSTORE_UID])
    assert result.exit_code == 2  # click.UsageError
    assert "No web gateway URL specified" in result.output

    result = runner.invoke(cli, base_args + ["--gateway-url", REAL_GATEWAY_URL,
                                             "foreign-keystores", "import", "--from-gateway", REAL_GATEWAY_KEYSTORE_UID])
    assert result.exit_code == 0
    assert "Authenticator 0f0c0988-80c1-9362-11c1-b06909a3a53c (owner: ¤aaa) imported" in result.output

    result = runner.invoke(cli, base_args + ["--gateway-url", REAL_GATEWAY_URL,
                                             "foreign-keystores", "import", "--from-gateway", "676ff51f-1439-48d9-94f9-xxx"])
    assert result.exit_code == 2
    assert "not a valid UUID." in result.output

    result = runner.invoke(cli, base_args + ["--gateway-url", REAL_GATEWAY_URL,
                                             "foreign-keystores", "import", "--from-gateway", wrong_uuid_str])
    assert result.exit_code == 1  # Other exception raised
    assert "does not exist in database" in str(result.exc_info[1])

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list"])
    assert result.exit_code == 0
    assert " 0f0c0988-80c1-9362-11c1-b06909a3a53c " in result.output
    assert " ¤aaa " in result.output

    result = runner.invoke(cli, base_args + ["foreign-keystores", "import", "--from-gateway", REAL_GATEWAY_KEYSTORE_UID])
    assert result.exit_code == 2
    assert "No web gateway URL specified" in result.output

    result = runner.invoke(cli, base_args + ["foreign-keystores", "delete", REAL_GATEWAY_KEYSTORE_UID])
    assert result.exit_code == 0
    assert "successfully deleted" in result.output

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list"])
    assert result.exit_code == 0
    assert "No foreign keystores found" in result.output

    result = runner.invoke(cli, base_args + ["foreign-keystores", "import", "--from-path", authenticator_path])
    assert result.exit_code == 1
    assert "keystore_metadata.json does not exist" in str(result.exc_info[1])

    keystore_metadata = initialize_authenticator(authenticator_path, keystore_owner="myuserxyz", keystore_passphrase_hint="somestuffs")
    new_keystore_uid = keystore_metadata["keystore_uid"]

    result = runner.invoke(cli, base_args + ["foreign-keystores", "import", "--from-path", authenticator_path])
    assert result.exit_code == 0
    assert "imported" in result.output
    assert "without private keys" in result.output

    result = runner.invoke(cli, base_args + ["foreign-keystores", "delete", wrong_uuid_str])
    assert result.exit_code == 2
    assert "Failed deletion" in result.output

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list"])
    assert result.exit_code == 0
    assert str(new_keystore_uid) in result.output
    assert " myuserxyz " in result.output

    result = runner.invoke(cli, base_args + ["foreign-keystores", "delete", str(new_keystore_uid)])
    assert result.exit_code == 0
    assert "successfully deleted" in result.output

    result = runner.invoke(cli, base_args + ["foreign-keystores", "list"])
    assert result.exit_code == 0
    assert "No foreign keystores found" in result.output


def test_cli_list_foreign_keystores_yolo(tmp_path, capsys):
    #runner = CliRunner()

    keystore_pool = generate_keystore_pool(tmp_path)
    foreign_keystores = keystore_pool.list_foreign_keystore_uids()
    #breakpoint()
    try:
        result = cli.main(prog_name="python -m wacryptolib", args=["-k", str(tmp_path), "foreign-keystores", "list"], standalone_mode=False)
    except SystemExit as e:
        captured = capsys.readouterr()
        print(e)

    #result = runner.invoke(cli, ["-k", str(tmp_path), "foreign-keystores", "list"], catch_exceptions=False)
    #breakpoint()
    assert result.exit_code == 0
    assert result.output == foreign_keystores
