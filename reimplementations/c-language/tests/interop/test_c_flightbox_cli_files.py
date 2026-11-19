# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Output file handling of the C CLI: --force replaces existing outputs only once the new ones are complete (an
existing recording is never lost on failure, a replaced payload file being put back when its cryptainer cannot be
replaced), files created by a failed run are deleted, outputs that are one of the input files are refused (whatever
the spelling of their path), files of any name are reachable, stdin is usable once, and chunk sizes are strict
decimal numbers.

Encryption failures after the outputs are created are provoked with a directory as input file, which opens but
cannot be read on POSIX systems.
"""

import importlib.util
import os
import stat

import pytest

from c_flightbox_interop_support import C_UNIT_TESTS_DIR

CRYPTAINER_SUFFIXES = {"json": ".crypt.json", "cbor": ".crypt.cbor"}
PROFILE_FILENAME = "profile.cbor"
INPUT_FILENAME = "input.bin"


def _get_valid_profile_bytes():
    spec = importlib.util.spec_from_file_location(
        "generate_device_profile_samples", C_UNIT_TESTS_DIR / "generate_device_profile_samples.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (sample,) = [
        sample for sample in module.collect_device_profile_samples() if sample["name"] == "minimal_rsa_authenticator"
    ]
    return sample["data"]


VALID_PROFILE_BYTES = _get_valid_profile_bytes()


def _prepare(work_dir, input_bytes=b"first recording " * 100):
    (work_dir / PROFILE_FILENAME).write_bytes(VALID_PROFILE_BYTES)
    (work_dir / INPUT_FILENAME).write_bytes(input_bytes)


def _list_files(work_dir):
    return sorted(path.name for path in work_dir.iterdir())


def _get_output_names(basename, document_format):
    cryptainer_name = basename + CRYPTAINER_SUFFIXES[document_format]
    return cryptainer_name, cryptainer_name + ".payload"


def _encrypt(c_build, document_format, work_dir, *extra_arguments, input_name=INPUT_FILENAME):
    return c_build.run_cli(
        input_name, "-p", PROFILE_FILENAME, "--format", document_format, "-o", "out", *extra_arguments, cwd=work_dir
    )


@pytest.mark.skipif(os.name == "nt", reason="A directory cannot be opened as a file on Windows")
def test_failed_forced_run_keeps_existing_outputs(c_build, document_format, tmp_path):
    _prepare(tmp_path)
    cryptainer_name, payload_name = _get_output_names("out", document_format)
    process = _encrypt(c_build, document_format, tmp_path)
    assert process.returncode == 0, process.stderr
    old_cryptainer = (tmp_path / cryptainer_name).read_bytes()
    old_payload = (tmp_path / payload_name).read_bytes()
    files_before = _list_files(tmp_path)

    (tmp_path / "unreadable").mkdir()
    for extra_arguments in [("--force",), ("--force", "--bundle")]:
        process = _encrypt(c_build, document_format, tmp_path, *extra_arguments, input_name="unreadable")
        stderr = process.stderr.decode(errors="replace")
        assert process.returncode == 1 and "cannot read the input file" in stderr, stderr
        assert (tmp_path / cryptainer_name).read_bytes() == old_cryptainer
        assert (tmp_path / payload_name).read_bytes() == old_payload
        assert _list_files(tmp_path) == sorted(files_before + ["unreadable"])  # No temporary file left


@pytest.mark.skipif(os.name == "nt", reason="A directory cannot be opened as a file on Windows")
def test_failed_run_deletes_created_outputs(c_build, document_format, tmp_path):
    _prepare(tmp_path)
    (tmp_path / "unreadable").mkdir()
    files_before = _list_files(tmp_path)
    for extra_arguments in [(), ("--bundle",)]:
        process = _encrypt(c_build, document_format, tmp_path, *extra_arguments, input_name="unreadable")
        assert process.returncode == 1, process.stderr
        assert _list_files(tmp_path) == files_before


def test_successful_forced_run_replaces_outputs(c_build, document_format, tmp_path):
    _prepare(tmp_path)
    cryptainer_name, payload_name = _get_output_names("out", document_format)
    assert _encrypt(c_build, document_format, tmp_path).returncode == 0
    old_payload = (tmp_path / payload_name).read_bytes()

    process = _encrypt(c_build, document_format, tmp_path)  # Without --force: refused, nothing changed
    assert process.returncode == 1 and b"already exists" in process.stderr, process.stderr
    assert (tmp_path / payload_name).read_bytes() == old_payload

    (tmp_path / INPUT_FILENAME).write_bytes(b"second recording, longer " * 300)
    process = _encrypt(c_build, document_format, tmp_path, "--force")
    assert process.returncode == 0, process.stderr
    assert process.stdout.decode().split() == [cryptainer_name, payload_name]
    new_payload = (tmp_path / payload_name).read_bytes()
    assert new_payload != old_payload and len(new_payload) > len(old_payload)
    assert _list_files(tmp_path) == sorted([INPUT_FILENAME, PROFILE_FILENAME, cryptainer_name, payload_name])


def _prepare_previous_outputs(c_build, document_format, work_dir):
    """Outputs of a first run, then another input: (cryptainer name, payload name, their bytes, the files)."""
    _prepare(work_dir)
    cryptainer_name, payload_name = _get_output_names("out", document_format)
    process = _encrypt(c_build, document_format, work_dir)
    assert process.returncode == 0, process.stderr
    (work_dir / INPUT_FILENAME).write_bytes(b"second recording, longer " * 300)
    old_cryptainer = (work_dir / cryptainer_name).read_bytes()
    old_payload = (work_dir / payload_name).read_bytes()
    return cryptainer_name, payload_name, old_cryptainer, old_payload, _list_files(work_dir)


def test_forced_run_unable_to_replace_cryptainer_restores_payload(c_build, document_format, tmp_path):
    """The cryptainer is replaced after its payload: when it cannot be, the previous payload file is back."""
    cryptainer_name, payload_name, _old_cryptainer, old_payload, files_before = _prepare_previous_outputs(
        c_build, document_format, tmp_path
    )
    # A file cannot be renamed over a directory, on any system
    os.remove(tmp_path / cryptainer_name)
    (tmp_path / cryptainer_name).mkdir()
    (tmp_path / cryptainer_name / "kept").write_bytes(b"kept")

    process = _encrypt(c_build, document_format, tmp_path, "--force")
    assert process.returncode == 1 and b"cannot replace " + cryptainer_name.encode() in process.stderr, process.stderr
    assert process.stdout == b""
    assert (tmp_path / payload_name).read_bytes() == old_payload
    assert _list_files(tmp_path / cryptainer_name) == ["kept"]
    assert _list_files(tmp_path) == files_before  # Neither temporary nor backup file left

    # Without a previous payload file, the new one does not stay next to what is not its cryptainer
    os.remove(tmp_path / payload_name)
    process = _encrypt(c_build, document_format, tmp_path, "--force")
    assert process.returncode == 1 and b"cannot replace " + cryptainer_name.encode() in process.stderr, process.stderr
    assert _list_files(tmp_path) == sorted(set(files_before) - {payload_name})


@pytest.mark.skipif(os.name != "nt", reason="Open files and read-only files can be replaced on POSIX systems")
@pytest.mark.parametrize("locked_output", ["cryptainer", "payload"])
@pytest.mark.parametrize("lock", ["open", "read-only"])
def test_forced_run_keeps_previous_outputs_locked_on_windows(c_build, document_format, tmp_path, locked_output, lock):
    cryptainer_name, payload_name, old_cryptainer, old_payload, files_before = _prepare_previous_outputs(
        c_build, document_format, tmp_path
    )
    locked_path = tmp_path / (cryptainer_name if locked_output == "cryptainer" else payload_name)
    if lock == "open":
        with open(locked_path, "rb"):  # Not shared for deletion: the file can be neither renamed nor replaced
            process = _encrypt(c_build, document_format, tmp_path, "--force")
    else:
        os.chmod(locked_path, stat.S_IREAD)
        process = _encrypt(c_build, document_format, tmp_path, "--force")
        os.chmod(locked_path, stat.S_IREAD | stat.S_IWRITE)
    assert process.returncode == 1 and b"cannot replace " + locked_path.name.encode() in process.stderr, process.stderr
    assert (tmp_path / cryptainer_name).read_bytes() == old_cryptainer
    assert (tmp_path / payload_name).read_bytes() == old_payload
    assert _list_files(tmp_path) == files_before

    process = _encrypt(c_build, document_format, tmp_path, "--force")  # Replaceable once unlocked
    assert process.returncode == 0, process.stderr
    assert (tmp_path / cryptainer_name).read_bytes() != old_cryptainer
    assert len((tmp_path / payload_name).read_bytes()) > len(old_payload)
    assert _list_files(tmp_path) == files_before


def test_outputs_being_inputs_refused(c_build, document_format, tmp_path):
    cryptainer_name, payload_name = _get_output_names("out", document_format)
    _prepare(tmp_path)
    original_input = (tmp_path / INPUT_FILENAME).read_bytes()

    # The payload file is the input file, given with another spelling, or through a hard link
    os.rename(tmp_path / INPUT_FILENAME, tmp_path / payload_name)
    for input_name in [payload_name, "./" + payload_name]:
        process = _encrypt(c_build, document_format, tmp_path, "--force", input_name=input_name)
        assert process.returncode == 1 and b"is the input file" in process.stderr, process.stderr
        assert (tmp_path / payload_name).read_bytes() == original_input
    os.link(tmp_path / payload_name, tmp_path / "linked_input.bin")
    process = _encrypt(c_build, document_format, tmp_path, "--force", input_name="linked_input.bin")
    assert process.returncode == 1 and b"is the input file" in process.stderr, process.stderr
    assert (tmp_path / payload_name).read_bytes() == original_input

    # The cryptainer file is the profile, or the metadata file
    os.rename(tmp_path / payload_name, tmp_path / INPUT_FILENAME)
    os.rename(tmp_path / PROFILE_FILENAME, tmp_path / cryptainer_name)
    process = c_build.run_cli(
        INPUT_FILENAME, "-p", cryptainer_name, "--format", document_format, "-o", "out", "--force", cwd=tmp_path
    )
    assert process.returncode == 1 and b"is the profile" in process.stderr, process.stderr
    assert (tmp_path / cryptainer_name).read_bytes() == VALID_PROFILE_BYTES
    (tmp_path / PROFILE_FILENAME).write_bytes(VALID_PROFILE_BYTES)
    process = c_build.run_cli(
        INPUT_FILENAME, "-p", PROFILE_FILENAME, "-m", cryptainer_name, "--format", document_format, "--bundle",
        "-o", "out", "--force", cwd=tmp_path,
    )
    assert process.returncode == 1 and b"is the metadata file" in process.stderr, process.stderr
    assert (tmp_path / cryptainer_name).read_bytes() == VALID_PROFILE_BYTES
    assert _list_files(tmp_path) == sorted([INPUT_FILENAME, PROFILE_FILENAME, cryptainer_name, "linked_input.bin"])


def test_non_ascii_paths(c_build, document_format, tmp_path):
    """Every file is reachable under names outside ASCII, and outside the ANSI code page of Windows."""
    directory_name = "répertoire 日本"
    input_name = directory_name + "/enregistrement 日本 Ж.bin"
    profile_name = directory_name + "/profil é日.cbor"
    metadata_name = directory_name + "/métadonnées 本.cbor"
    cryptainer_name, payload_name = _get_output_names(directory_name + "/sortie 日本 è", document_format)
    try:
        (tmp_path / directory_name).mkdir()
        (tmp_path / input_name).write_bytes(b"first recording " * 100)
    except (OSError, UnicodeError):
        pytest.skip("File system without such names")
    (tmp_path / profile_name).write_bytes(VALID_PROFILE_BYTES)
    (tmp_path / metadata_name).write_bytes(bytes.fromhex("a1616101"))  # {"a": 1}
    arguments = [input_name, "-p", profile_name, "-m", metadata_name, "--format", document_format]
    arguments += ["-o", cryptainer_name[: -len(CRYPTAINER_SUFFIXES[document_format])]]

    process = c_build.run_cli(*arguments, cwd=tmp_path)
    assert process.returncode == 0, process.stderr
    assert process.stdout.decode("utf-8").splitlines() == [cryptainer_name, payload_name]
    old_payload = (tmp_path / payload_name).read_bytes()
    assert (tmp_path / cryptainer_name).is_file() and old_payload

    process = c_build.run_cli(*arguments, cwd=tmp_path)  # Existing outputs are seen
    assert process.returncode == 1 and b"already exists" in process.stderr, process.stderr
    process = c_build.run_cli(payload_name, *arguments[1:], "--force", cwd=tmp_path)  # An output is the input
    assert process.returncode == 1 and b"is the input file" in process.stderr, process.stderr
    assert (tmp_path / payload_name).read_bytes() == old_payload

    (tmp_path / input_name).write_bytes(b"second recording, longer " * 300)
    process = c_build.run_cli(*arguments, "--force", cwd=tmp_path)  # And replaced
    assert process.returncode == 0, process.stderr
    assert len((tmp_path / payload_name).read_bytes()) > len(old_payload)
    assert _list_files(tmp_path / directory_name) == sorted(
        name.split("/")[1] for name in [input_name, profile_name, metadata_name, cryptainer_name, payload_name]
    )


def test_stdin_usable_once(c_build, tmp_path):
    _prepare(tmp_path)
    for arguments in [("-", "-p", "-", "-o", "out"), (INPUT_FILENAME, "-p", "-", "-m", "-")]:
        process = c_build.run_cli(*arguments, cwd=tmp_path, input_bytes=VALID_PROFILE_BYTES)
        assert process.returncode == 2 and b"stdin ('-') can only be one" in process.stderr, process.stderr
    assert _list_files(tmp_path) == sorted([INPUT_FILENAME, PROFILE_FILENAME])
    # A profile from stdin
    process = c_build.run_cli(INPUT_FILENAME, "-p", "-", "--bundle", cwd=tmp_path, input_bytes=VALID_PROFILE_BYTES)
    assert process.returncode == 0, process.stderr


@pytest.mark.parametrize("chunk_size", ["-1", "+5", " 5", "5 ", "0", "0x10", "", "1073741825", "99999999999999999999999"])
def test_invalid_chunk_sizes(c_build, chunk_size, tmp_path):
    _prepare(tmp_path)
    process = c_build.run_cli(INPUT_FILENAME, "-p", PROFILE_FILENAME, "--chunk-size", chunk_size, cwd=tmp_path)
    assert process.returncode == 2 and b"invalid chunk size" in process.stderr, process.stderr
    assert _list_files(tmp_path) == sorted([INPUT_FILENAME, PROFILE_FILENAME])


@pytest.mark.parametrize("chunk_size", ["1", "007", "65536"])
def test_valid_chunk_sizes(c_build, chunk_size, tmp_path):
    _prepare(tmp_path, input_bytes=b"x" * 3000)
    process = c_build.run_cli(
        INPUT_FILENAME, "-p", PROFILE_FILENAME, "--chunk-size", chunk_size, "--bundle", cwd=tmp_path
    )
    assert process.returncode == 0, process.stderr
