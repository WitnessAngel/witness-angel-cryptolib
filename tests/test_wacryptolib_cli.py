import os

from click.testing import CliRunner

from wacryptolib.__main__ import cli


def test_cli_help_texts():
    runner = CliRunner()

    result = runner.invoke(cli, ["-h"])
    assert result.exit_code == 0
    assert "Usage:" in result.output

    result = runner.invoke(cli, ["encrypt", "-h"])
    assert result.exit_code == 0
    assert "into a secure container" in result.output

    result = runner.invoke(cli, ["decrypt", "-h"])
    assert result.exit_code == 0
    assert "original media file" in result.output


def test_cli_encryption_and_decryption():
    runner = CliRunner()

    data_file = "test_file.txt"
    data_sample = "Héllô\nguÿs"

    with runner.isolated_filesystem() as tempdir:

        print("TEMPORARY TEST DIRECTORY:", tempdir)

        with open(data_file, "w") as output_file:
            output_file.write(data_sample)

        result = runner.invoke(cli, ["encrypt", "-i", "test_file.txt"])
        assert result.exit_code == 0
        assert os.path.exists(data_file + ".crypt")

        result = runner.invoke(
            cli, ["encrypt", "-i", "test_file.txt", "-o", "stuff.dat"]
        )
        assert result.exit_code == 0
        assert os.path.exists("stuff.dat")

        os.remove(data_file)  # CLEANUP
        assert not os.path.exists(data_file)

        result = runner.invoke(cli, ["decrypt", "-i", data_file + ".crypt"])
        assert result.exit_code == 0
        assert os.path.exists(data_file)

        result = runner.invoke(cli, ["decrypt", "-i", "stuff.dat"])
        assert result.exit_code == 0
        assert os.path.exists("stuff.dat.medium")

        result = runner.invoke(cli, ["decrypt", "-i", "stuff.dat", "-o", "stuffs.txt"])
        assert result.exit_code == 0
        assert os.path.exists("stuffs.txt")

        for result_file in (data_file, "stuff.dat.medium", "stuffs.txt"):
            with open(result_file, "r") as input_file:
                data = input_file.read()
                assert data == data_sample
