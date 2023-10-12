import os
import pathlib
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pprint import pprint
from uuid import UUID

from click.testing import CliRunner

import wacryptolib
from _test_mockups import oneshot_command_line, random_bool, get_longrun_command_line
from test_wacryptolib_cryptainer import SIMPLE_CRYPTOCONF
from wacryptolib.authenticator import initialize_authenticator
from wacryptolib.cli import wacryptolib_cli as cli, _short_format_datetime
from wacryptolib.cryptainer import LOCAL_KEYFACTORY_TRUSTEE_MARKER, CryptainerStorage, check_cryptoconf_sanity
from wacryptolib.keystore import FilesystemKeystore, generate_keypair_for_storage, _get_keystore_metadata_file_path
from wacryptolib.utilities import dump_to_json_file, get_utc_now_date, load_from_json_str

REAL_GATEWAY_URL = "https://api.witnessangel.com/gateway/jsonrpc/"  # Real gateway used by some tests
REAL_GATEWAY_KEYSTORE_UID = "0f0c0988-80c1-9362-11c1-b06909a3a53c"  # Authenticator of ¤aaa, must exist in real prod

# For when runner.invoke() is not sufficient
FLIGHTBOX_CLI_INVOCATION_ARGS = [sys.executable, "-m", "wacryptolib"]


def _get_cli_runner():
    return CliRunner(mix_stderr=False)


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


def test_cli_authenticator_management(tmp_path):

    authenticator_path = tmp_path / "myauthenticator"
    authenticator_subpath = authenticator_path / "mysubauthenticator"
    passphrase = "somepassphrase"

    runner = _get_cli_runner()

    result = runner.invoke(cli, ["authenticator", "create", str(tmp_path), "--owner", "Donald", "--passphrase-hint", "somehint"])
    assert result.exit_code == 2
    assert "Target directory" in result.stderr
    assert "must not exist yet" in result.stderr

    result = runner.invoke(cli, ["authenticator", "create", str(authenticator_subpath), "--owner", "Donald", "--passphrase-hint", "somehint"])
    assert result.exit_code == 2
    assert "Parent directory" in result.stderr
    assert "must already exist" in result.stderr

    result = runner.invoke(cli, ["authenticator", "create", str(authenticator_path), "--owner", "Donald", "--passphrase-hint", "somehint", "--keypair-count", "0"])
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
            env = dict(WA_PASSPHRASE=passphrase)
            input = None
        else:
            env = None
            input = passphrase

        result = runner.invoke(cli, ["authenticator", "create", str(authenticator_path), "--owner", "Donald", "--passphrase-hint", "somehint", "--keypair-count", "1"],
                               env=env, input=input)  # Passphrase needed, else this freezes
        assert result.exit_code == 0
        assert authenticator_path.is_dir()

        result = runner.invoke(cli, ["authenticator", "validate", str(authenticator_path)],
                               env=env, input=input)
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

    result = runner.invoke(cli, ["authenticator", "create", str(authenticator_path), "--owner", "Donald",
                                 "--passphrase-hint", "somehint", "--keypair-count", "1"],
                           input=passphrase)  # Passphrase needed, else this freezes
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
        consumer_process_completed = subprocess.run(FLIGHTBOX_CLI_INVOCATION_ARGS + base_args + _encryption_args,
                                  stdin=feeder.stdout, stderr=subprocess.PIPE)
        assert consumer_process_completed.returncode == 2, consumer_process_completed.stderr
        assert b"Ouput basename must be provided when input file is STDIN" in consumer_process_completed.stderr

        for idx in range(2):  # Test both bundled (so all-at-once) and unbundled (so streamable) encryptions
            must_bundle = bool(idx)

            # First we test NORMAL execution of a short encryption pipeline
    
            feeder = subprocess.Popen(oneshot_command_line, stdout=subprocess.PIPE)
            _encryption_args = ["encrypt", "-", "-o", "my_piped_oneshot_cryptainer%d.crypt" % idx] + (["--bundle"] if must_bundle else [])
            consumer_process_completed = subprocess.run(FLIGHTBOX_CLI_INVOCATION_ARGS + base_args + _encryption_args,
                                      stdin=feeder.stdout, stderr=subprocess.PIPE)
            assert consumer_process_completed.returncode == 0, consumer_process_completed.stderr
            assert b"successfully finished" in consumer_process_completed.stderr
            assert cryptainer_storage.joinpath("my_piped_oneshot_cryptainer%d.crypt" % idx).is_file()
            assert cryptainer_storage.joinpath("my_piped_oneshot_cryptainer%d.crypt.payload" % idx).is_file() != must_bundle
    
            _decryption_args = ["cryptainer", "decrypt", "my_piped_oneshot_cryptainer%d.crypt" % idx]
            consumer_process_completed = subprocess.run(FLIGHTBOX_CLI_INVOCATION_ARGS + base_args + _decryption_args, stderr=subprocess.PIPE)
            assert consumer_process_completed.returncode == 0, consumer_process_completed.stderr
            assert b"successfully finished" in consumer_process_completed.stderr
            result_file = pathlib.Path("./my_piped_oneshot_cryptainer%d" % idx)
            assert result_file.is_file()
            result_data = result_file.read_bytes()
            assert result_data.strip() == b"This is some test data output and then I quit immediately!"  # Beware of newlines

            # Then we test ABNORMAL execution of a long, INTERRUPTED, encryption pipeline

            feeder = subprocess.Popen(get_longrun_command_line("encryption_and_decryption_via_pipe"), stdout=subprocess.PIPE)

            def _interrupt_feeder_soon():
                time.sleep(6)  # Let it some time to launch and output things
                feeder.kill()  # Brutal termination
            executor.submit(_interrupt_feeder_soon)

            _encryption_args = ["encrypt", "-", "-o", "my_piped_longrun_cryptainer%d.crypt" % idx] + (["--bundle"] if must_bundle else [])
            consumer_process_completed = subprocess.run(FLIGHTBOX_CLI_INVOCATION_ARGS + base_args + _encryption_args,
                                      stdin=feeder.stdout, stderr=subprocess.PIPE)
            assert consumer_process_completed.returncode == 0, consumer_process_completed.stderr
            assert b"successfully finished" in consumer_process_completed.stderr
            assert cryptainer_storage.joinpath("my_piped_longrun_cryptainer%d.crypt" % idx).is_file()
            assert cryptainer_storage.joinpath("my_piped_longrun_cryptainer%d.crypt.payload" % idx).is_file() != must_bundle

            _decryption_args = ["cryptainer", "decrypt", "my_piped_longrun_cryptainer%d.crypt" % idx]
            consumer_process_completed = subprocess.run(FLIGHTBOX_CLI_INVOCATION_ARGS + base_args + _decryption_args, stderr=subprocess.PIPE)
            print("STDERR FROM DECRYPTION:")
            print(consumer_process_completed.stderr.decode("utf8", "ignore"))
            assert consumer_process_completed.returncode == 0
            assert b"successfully finished" in consumer_process_completed.stderr
            result_file = pathlib.Path("./my_piped_longrun_cryptainer%d" % idx)
            assert result_file.is_file()
            result_data = result_file.read_bytes()
            result_data = result_data.splitlines()
            assert len(result_data) > 6, result_data
            assert set(result_data) == {b"This is some test data output [encryption_and_decryption_via_pipe]!"}  # No TRUNCATED line!


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
        assert "successfully finished" in result.stderr
        assert cryptainer_storage.joinpath(data_file + ".crypt").is_file()
        assert not cryptainer_storage.joinpath(data_file + ".crypt.payload").is_file()  # NOT OFFLOADED in this case

        result = runner.invoke(cli, base_args + ["encrypt", data_file, "-o", "stuff.dat"], catch_exceptions=False)
        print("TEST-STDERR1:", result.stderr)
        assert result.exit_code == 0
        assert "successfully finished" in result.stderr
        assert not os.path.exists("./stuff.dat")  # This is NOT a full target filepath
        assert cryptainer_storage.joinpath("stuff.dat.crypt").is_file()
        assert cryptainer_storage.joinpath("stuff.dat.crypt.payload").is_file()  # OFFLOADED in this case

        result = runner.invoke(cli, base_args + ["encrypt", data_file, "-o", "folder/stuff.dat"], catch_exceptions=False)
        print("TEST-STDERR2:", result.stderr)
        assert result.exit_code == 2
        assert "basename must not contain path separators" in result.stderr

        with open(cryptainer_storage.joinpath("stuff.dat.crypt"), "r") as input_file:
            data = input_file.read()
            assert "AES_CBC" in data
            assert "CHACHA20_POLY1305" not in data  # Not in default cryptoconf

        os.remove(data_file)  # CLEANUP of original data file
        assert not os.path.exists(data_file)
        assert not cryptainer_storage.joinpath(
            data_file
        ).is_file()  # This will be the default output file for decryption

        result = runner.invoke(
            cli, base_args + ["cryptainer", "decrypt", data_file + ".crypt"], catch_exceptions=False
        )
        assert result.exit_code == 0
        assert os.path.exists(data_file)  # Created in CWD
        assert not cryptainer_storage.joinpath(data_file).is_file()  # Not created in CRYPTAINER STORAGE itself

        # Simulate weird suffix for cryptainer file (would cause problems with cryptainer listing, though)
        cryptainer_storage.joinpath("stuff.dat.crypt").rename(cryptainer_storage.joinpath("stuff.dat.fb"))
        cryptainer_storage.joinpath("stuff.dat.crypt.payload").rename(
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
                    payload_signatures=[],
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
        assert cryptainer_storage.joinpath("specialconf.crypt").is_file()  # No double suffix

        data = cryptainer_storage.joinpath("specialconf.crypt").read_text()
        assert "CHACHA20_POLY1305" in data

        result = runner.invoke(
            cli,
            base_args + ["cryptainer", "summarize", "specialconf.crypt"],  # Works on CRYPTAINERS too
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert b"CHACHA20_POLY1305" in result.stdout_bytes
        assert b"RSA_OAEP" in result.stdout_bytes

        result = runner.invoke(
            cli,
            base_args + ["cryptainer", "decrypt", "specialconf.crypt", "-o", "specialconf.crypt.decrypted"],
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
        check_cryptoconf_sanity(_cryptoconf)  # This is ALREADY supposed to happen in cryptoconf generation command of CLI
        return _cryptoconf

    # Simplest configuration
    command = """cryptoconf generate-simple add-payload-cipher-layer --sym-cipher-algo aes_cbc add-key-cipher-layer
              --asym-cipher-algo RSA_OAEP --trustee-type authenticator --keystore-uid 0f2ee6c1-d91e-7593-1310-7036dc9b782e""".split()
    result = runner.invoke(cli, command)
    cryptoconf = _load_and_validate_cryptoconf(result)
    assert cryptoconf == {
        'payload_cipher_layers': [{'key_cipher_layers': [{'key_cipher_algo': 'RSA_OAEP',
                               'key_cipher_trustee': {'keystore_uid': UUID('0f2ee6c1-d91e-7593-1310-7036dc9b782e'),
                                                      'trustee_type': 'authenticator'}}],
        'payload_cipher_algo': 'AES_CBC',
        'payload_signatures': []}]}

    # Simple configuration with hybrid key encryption
    command = """cryptoconf generate-simple --keychain-uid 123e4567-e89b-12d3-a456-426614174000 
                    add-payload-cipher-layer --sym-cipher-algo chacha20_poly1305 
                    add-key-cipher-layer 
                    --asym-cipher-algo RSA_OAEP --trustee-type local_keyfactory 
                    --sym-cipher-algo aes_eax --keychain-uid 6a3c8ac8-c26b-45fa-8810-6dd3157b97fa""".split()
    result = runner.invoke(cli, command)
    cryptoconf = _load_and_validate_cryptoconf(result)
    assert cryptoconf == {
        'keychain_uid': UUID("123e4567-e89b-12d3-a456-426614174000"),
        'payload_cipher_layers': [{'key_cipher_layers': [{'key_cipher_algo': 'AES_EAX',
                               'key_cipher_layers': [{'key_cipher_algo': 'RSA_OAEP',
                                                      'key_cipher_trustee': {'trustee_type': 'local_keyfactory'},
                                                      'keychain_uid': UUID("6a3c8ac8-c26b-45fa-8810-6dd3157b97fa")}]}],
        'payload_cipher_algo': 'CHACHA20_POLY1305',
        'payload_signatures': []}]}

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
    #pprint(cryptoconf)
    assert cryptoconf == {
        'payload_cipher_layers': [{'key_cipher_layers': [{'key_cipher_algo': '[SHARED_SECRET]',
                               'key_shared_secret_shards': [{'key_cipher_layers': [{'key_cipher_algo': 'AES_EAX',
                                                                                    'key_cipher_layers': [{'key_cipher_algo': 'RSA_OAEP',
                                                                                                           'key_cipher_trustee': {'keystore_uid': UUID('0f2ee6c1-d91e-7593-1310-7036dc9b782e'),
                                                                                                                                  'trustee_type': 'authenticator'}}]}]},
                                                            {'key_cipher_layers': [{'key_cipher_algo': 'RSA_OAEP',
                                                                                    'key_cipher_trustee': {'keystore_uid': UUID('af2ee6c1-d91e-7593-1310-7036dc9b782a'),
                                                                                                           'trustee_type': 'authenticator'},
                                                                                    'keychain_uid': UUID("6a3c8ac8-c26b-45fa-8810-6dd3157b97fd")}]}],
                               'key_shared_secret_threshold': 1},
                              {'key_cipher_algo': 'RSA_OAEP',
                               'key_cipher_trustee': {'keystore_uid': UUID('0f2ee6c1-d91e-7593-1310-7036dc9b783b'),
                                                      'trustee_type': 'authenticator'}}],
        'payload_cipher_algo': 'AES_EAX',
        'payload_signatures': []}]}

    # Missing payload encryption
    result = runner.invoke(cli, "cryptoconf generate-simple".split(),)
    assert result.exit_code == 0
    assert "Usage:" in result.stdout  # For some reason this displays help without raising an error...

    wrong_commands = [
        # Missing key encryption
        "cryptoconf generate-simple add-payload-cipher-layer --sym-cipher-algo aes_cbc".split(),

        # Missing keystore-uid fro authenticator trustee
        "cryptoconf generate-simple add-payload-cipher-layer --sym-cipher-algo chacha20_poly1305 "
        "add-key-cipher-layer --asym-cipher-algo RSA_OAEP --trustee-type authenticator ".split(),

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
        "--sym-cipher-algo aes_eax add-key-shard --asym-cipher-algo RSA_OAEP --trustee-type local_keyfactory"
    ]
    for wrong_command in wrong_commands:
        result = runner.invoke(cli, wrong_command)
        assert result.exit_code != 0, (result.exit_code, result.stdout)  # UsageError, not crash


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
                payload_signatures=[],
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

    result = runner.invoke(
        cli, base_args + ["foreign-keystore", "import", "--from-gateway", REAL_GATEWAY_KEYSTORE_UID]
    )
    assert result.exit_code == 2  # click.UsageError
    assert "No web gateway URL specified" in result.stderr

    result = runner.invoke(
        cli,
        base_args
        + [
            "--gateway-url",
            REAL_GATEWAY_URL,  # Here --include-private-keys has no effect
            "foreign-keystore",
            "import",
            "--include-private-keys",
            "--from-gateway",
            REAL_GATEWAY_KEYSTORE_UID,
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
            REAL_GATEWAY_URL,
            "foreign-keystore",
            "import",
            "--from-gateway",
            REAL_GATEWAY_KEYSTORE_UID,
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
            REAL_GATEWAY_URL,
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
        base_args
        + ["--gateway-url", REAL_GATEWAY_URL, "foreign-keystore", "import", "--from-gateway", wrong_uuid_str],
    )
    assert result.exit_code == 1  # Other exception raised
    assert "does not exist in database" in str(result.exc_info[1])

    result = runner.invoke(cli, base_args + ["foreign-keystore", "list"], catch_exceptions=False)
    assert result.exit_code == 0
    assert " 0f0c0988-80c1-9362-11c1-b06909a3a53c " in result.stdout  # Table is displayed
    assert " ¤aaa " in result.stdout

    result = runner.invoke(
        cli, base_args + ["foreign-keystore", "import", "--from-gateway", REAL_GATEWAY_KEYSTORE_UID]
    )
    assert result.exit_code == 2
    assert "No web gateway URL specified" in result.stderr

    result = runner.invoke(
        cli, base_args + ["foreign-keystore", "delete", REAL_GATEWAY_KEYSTORE_UID], catch_exceptions=False
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
    assert ('"$numberInt": "%d"' % keypairs_count) in result.stdout
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
    assert "myfilename.crypt" in result.stdout

    result = runner.invoke(cli, base_args + ["cryptainer", "delete", "myfilename.crypt"], catch_exceptions=False)
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
    assert " 20420221_152428_rtsp_camera_cryptainer.mp4.crypt " in result.stdout
    assert " X " in result.stdout  # For "is offloaded" column

    result = runner.invoke(cli, base_args + ["cryptainer", "list", "--format", "json"], catch_exceptions=False)
    assert result.exit_code == 0
    assert '"20420221_152428_rtsp_camera_cryptainer.mp4.crypt"' in result.stdout
    data_tree = load_from_json_str(result.stdout)  # Test loading of output
    assert isinstance(data_tree, list)
    assert len(data_tree) == 3
    assert data_tree[0]["name"] == first_cryptainer_name_base + ".crypt"

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
    assert " 20430221_152428_rtsp_camera_cryptainer.mp4.crypt " in result.stdout

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
    assert tmp_path.joinpath("goodfile.crypt").is_file()

    runner = _get_cli_runner()

    base_args = ["--cryptainer-storage", str(cryptainer_storage_path)]

    result = runner.invoke(cli, base_args + ["cryptainer", "validate", "unexistingfile"])
    assert result.exit_code == 1  # Raised by wacryptolib code and not Click
    assert "No such file or directory" in str(result.exc_info[1])

    result = runner.invoke(cli, base_args + ["cryptainer", "validate", "goodfile.crypt"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "is valid" in result.stderr

    result = runner.invoke(
        cli, base_args + ["cryptainer", "validate", "goodfile.crypt.payload"]
    )  # Exists but is not a proper cryptainer!
    assert result.exit_code == 1
    assert "is invalid" not in result.stderr
    assert "can't decode" in str(result.exc_info[1])  # Unhandled exception for now

    result = runner.invoke(cli, base_args + ["cryptainer", "validate", "badcryptainer.crypt"])
    assert result.exit_code == 2
    assert "is invalid" in result.stderr


def test_cli_default_app_root_creation():
    std_env = os.environ.copy()
    del std_env["_WA_RANDOMIZE_CLI_APP_DIR"]

    proc = subprocess.run(FLIGHTBOX_CLI_INVOCATION_ARGS + ["-h"], env=std_env)
    assert proc.returncode == 0

    assert os.path.exists(os.path.expanduser("~/.witnessangel/"))  # Auto-created on launch

