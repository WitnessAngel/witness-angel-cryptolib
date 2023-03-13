import os
import pathlib
import subprocess
import sys

from click.testing import CliRunner

import wacryptolib
from wacryptolib.__main__ import wacryptolib_cli as cli
from wacryptolib.cryptainer import LOCAL_KEYFACTORY_TRUSTEE_MARKER
from wacryptolib.utilities import dump_to_json_file
from _test_mockups import generate_keystore_pool


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


def test_cli_list_foreign_keystores_not_found():
    runner = CliRunner()

    result = runner.invoke(cli, ["foreign-keystores", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "No foreign keystores found" in result.output


def test_cli_list_foreign_keystores_yolo(tmp_path, capsys):
    #runner = CliRunner()

    keystore_pool = generate_keystore_pool(tmp_path)
    foreign_keystores = keystore_pool.list_foreign_keystore_uids()
    breakpoint()
    try:
        result = cli.main(prog_name="python -m wacryptolib", args=["-k", str(tmp_path), "foreign-keystores", "list"], standalone_mode=False)
    except SystemExit as e:
        captured = capsys.readouterr()
        print(e)

    #result = runner.invoke(cli, ["-k", str(tmp_path), "foreign-keystores", "list"], catch_exceptions=False)
    breakpoint()
    assert result.exit_code == 0
    assert result.output == foreign_keystores
