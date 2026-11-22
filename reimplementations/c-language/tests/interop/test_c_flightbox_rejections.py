# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Rejections by the C CLI (task 9.6): each case gives an expected status and error location, a non-zero exit code,
and no output file.

Device profiles are the samples of the profile loading unit tests (generate_device_profile_samples.py, built with
the device profile test helpers): signature confs, missing keys, missing root keychain uid, bad thresholds, too many shards, both
signature alias keys, output fields in the cryptoconf, excessive key cipher nesting, mutated profiles, every
valid corpus cryptoconf without a root keychain uid (2022 generations), and every invalid corpus cryptoconf (WA-CBOR ones spliced into a profile, Extended JSON ones through the raw converter). The
valid samples are encrypted successfully, as a counterpart. Metadata cases cover floats, datetimes, out-of-range
integers, keyword maps, excessive depth and non-map documents.
"""

import importlib.util
import re

import pytest

from c_flightbox_interop_support import (
    COMPATIBILITY_ROOT,
    C_UNIT_TESTS_DIR,
    get_valid_corpus_cryptoconfs,
    has_signatures,
    load_corpus_cryptoconf,
    profile_helpers,
)

CRYPTAINER_SUFFIXES = {"json": ".crypt.json", "cbor": ".crypt.cbor"}
INPUT_FILENAME = "input.bin"
PROFILE_FILENAME = "profile.cbor"
METADATA_FILENAME = "metadata.cbor"
ERROR_LINE_PATTERN = re.compile(r"^Error: (?P<context>[^:]+): .+ \[(?P<status>WA_STATUS_[A-Z_]+)\](?: at (?P<location>\S+))?$")


def _load_sample_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_device_profile_samples", C_UNIT_TESTS_DIR / "generate_device_profile_samples.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DEVICE_PROFILE_SAMPLES = _load_sample_generator().collect_device_profile_samples()
REJECTED_SAMPLES = [sample for sample in DEVICE_PROFILE_SAMPLES if sample["status"] != "WA_STATUS_OK"]
VALID_SAMPLES = [sample for sample in DEVICE_PROFILE_SAMPLES if sample["status"] == "WA_STATUS_OK"]

# Locations of the invalid Extended JSON corpus cryptoconfs (only their status is checked by the unit tests)
PAYLOAD_0 = "cryptoconf.payload_cipher_layers[0]"
KEY_LAYER_0 = PAYLOAD_0 + ".key_cipher_layers[0]"
INVALID_CORPUS_LOCATIONS = {
    "invalid_corpus_asymmetric_payload_cipher_algo": PAYLOAD_0 + ".payload_cipher_algo",
    "invalid_corpus_no_key_cipher_layer": PAYLOAD_0 + ".key_cipher_layers",
    "invalid_corpus_no_payload_cipher_layer": "cryptoconf.payload_cipher_layers",
    "invalid_corpus_shared_secret_threshold_above_shard_count": KEY_LAYER_0 + ".key_shared_secret_threshold",
    "invalid_corpus_shared_secret_threshold_zero": KEY_LAYER_0 + ".key_shared_secret_threshold",
    "invalid_corpus_unknown_payload_cipher_algo": PAYLOAD_0 + ".payload_cipher_algo",
    "invalid_corpus_unknown_trustee_type": KEY_LAYER_0 + ".key_cipher_trustee.trustee_type",
}


def test_samples_cover_the_specified_rejections():
    names = {sample["name"] for sample in REJECTED_SAMPLES}
    for required_name in (
        "ciphertext_signature",
        "plaintext_signature",
        "missing_public_key",
        "missing_root_keychain_uid",
        "threshold_zero",
        "threshold_above_shard_count",
        "shard_count_31",
        "shard_count_31_nested",
        "both_signature_list_keys",
        "layer_key_ciphertext_format",
        "key_cipher_nesting_9_levels",
        "duplicate_layer_key",
        "root_keychain_uid_as_text",
    ):
        assert any(name.startswith(required_name) for name in names), required_name
    invalid_corpus_files = sorted(COMPATIBILITY_ROOT.glob("cryptoconfs/*/invalid/*.cryptoconf*"))
    invalid_corpus_files = [path for path in invalid_corpus_files if not path.name.endswith(".json")]
    assert len(invalid_corpus_files) == 12
    for path in invalid_corpus_files:
        prefix = "spliced_invalid_corpus_" if path.suffix == ".cbor" else "invalid_corpus_"
        assert prefix + path.name.split(".")[0] in names, path
    assert set(INVALID_CORPUS_LOCATIONS) == {name for name in names if name.startswith("invalid_corpus_")}


def _run_cli(c_build, document_format, work_dir, profile_bytes, metadata_bytes=None):
    """Run the CLI over a small input; return (process, files of work_dir other than its inputs)."""
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / INPUT_FILENAME).write_bytes(b"payload " * 600)
    (work_dir / PROFILE_FILENAME).write_bytes(profile_bytes)
    arguments = [INPUT_FILENAME, "-p", PROFILE_FILENAME, "--format", document_format]
    if metadata_bytes is not None:
        (work_dir / METADATA_FILENAME).write_bytes(metadata_bytes)
        arguments += ["-m", METADATA_FILENAME]
    process = c_build.run_cli(*arguments, cwd=work_dir)
    outputs = sorted(
        path.name
        for path in work_dir.iterdir()
        if path.name not in (INPUT_FILENAME, PROFILE_FILENAME, METADATA_FILENAME)
    )
    return process, outputs


def check_rejection(process, outputs, expected_context, expected_statuses, expected_location):
    """A non-zero exit, one error line with the expected context, status and location ("" for none), no output."""
    stderr = process.stderr.decode("utf8", errors="replace")
    assert process.returncode != 0, stderr
    assert outputs == [], (outputs, stderr)
    assert process.stdout == b"", process.stdout
    error_lines = stderr.splitlines()
    assert len(error_lines) == 1, stderr
    match = ERROR_LINE_PATTERN.match(error_lines[0])
    assert match, stderr
    assert match.group("context") == expected_context, stderr
    assert match.group("status") in expected_statuses, stderr
    assert (match.group("location") or "") == expected_location, stderr


def _get_document_format(c_build, index):
    return c_build.document_formats[index % len(c_build.document_formats)]


@pytest.mark.parametrize("sample", REJECTED_SAMPLES, ids=lambda sample: sample["name"])
def test_rejected_device_profiles(c_build, sample, tmp_path):
    expected_statuses = {sample["status"]} | ({sample["alternative_status"]} if sample["alternative_status"] else set())
    expected_location = sample["location"]
    if expected_location is None:
        expected_location = INVALID_CORPUS_LOCATIONS[sample["name"]]
    process, outputs = _run_cli(
        c_build, _get_document_format(c_build, REJECTED_SAMPLES.index(sample)), tmp_path, sample["data"]
    )
    check_rejection(process, outputs, "invalid device profile", expected_statuses, expected_location)


@pytest.mark.parametrize("sample", VALID_SAMPLES, ids=lambda sample: sample["name"])
def test_valid_device_profiles(c_build, document_format, sample, tmp_path):
    """The counterpart of the rejections: valid samples give a cryptainer and its payload file."""
    process, outputs = _run_cli(c_build, document_format, tmp_path, sample["data"])
    assert process.returncode == 0, process.stderr
    cryptainer_name = INPUT_FILENAME + CRYPTAINER_SUFFIXES[document_format]
    assert outputs == sorted([cryptainer_name, cryptainer_name + ".payload"])


# METADATA #


def _nested_maps(level_count):
    """Nested maps {"a": {"a": ... {}}} of level_count levels."""
    value = {}
    for _ in range(level_count - 1):
        value = {"a": value}
    return value


def _metadata_cases():
    """(name, metadata CBOR bytes, expected error context, expected statuses); None context: accepted."""
    encode = profile_helpers.encode_cbor_item
    unsupported = {"WA_STATUS_UNSUPPORTED_TYPE"}
    cases = [
        ("float_16", encode({"k": profile_helpers.Float(1.5, 16)}), "invalid metadata", unsupported),
        ("float_32", encode({"k": profile_helpers.Float(1.5, 32)}), "invalid metadata", unsupported),
        ("float_64", encode({"k": [profile_helpers.Float(1.5, 64)]}), "invalid metadata", unsupported),
        (
            "datetime_tag_0",
            encode({"k": profile_helpers.Tagged(0, "2026-01-01T00:00:00Z")}),
            "invalid metadata",
            unsupported,
        ),
        # Tag 1 (epoch datetime) is invalid WA-CBOR
        ("datetime_tag_1", encode({"k": profile_helpers.Tagged(1, 1767225600)}), "invalid metadata", {"WA_STATUS_DECODING_ERROR"}),
        ("integer_above_int64", encode({"k": 2**63}), "invalid metadata", unsupported),
        ("bignum_tag_2", encode({"k": profile_helpers.Tagged(2, b"\x01")}), "invalid metadata", unsupported),
        # Keyword maps are invalid WA-CBOR, at any depth
        ("keyword_map", encode({"$uuid": "0123"}), "invalid metadata", {"WA_STATUS_DECODING_ERROR"}),
        ("nested_keyword_map", encode({"inner": [{"$date": 0}]}), "invalid metadata", {"WA_STATUS_DECODING_ERROR"}),
        # Metadata sits at depth 2 of cryptainers: 63 levels pass, 64 are refused by the encryptor, 65 by the decoder
        ("depth_63", encode(_nested_maps(63)), None, None),
        ("depth_64", encode(_nested_maps(64)), "cryptainer creation failed", {"WA_STATUS_NESTING_TOO_DEEP"}),
        ("depth_65", encode(_nested_maps(65)), "invalid metadata", {"WA_STATUS_NESTING_TOO_DEEP"}),
        ("array", encode([1, 2]), "cryptainer creation failed", {"WA_STATUS_INVALID_PROFILE"}),
        ("text", encode("metadata"), "invalid metadata", {"WA_STATUS_DECODING_ERROR"}),
        ("truncated", encode({"k": "value"})[:-1], "invalid metadata", {"WA_STATUS_DECODING_ERROR"}),
    ]
    return cases


METADATA_CASES = _metadata_cases()


@pytest.mark.parametrize(
    ("metadata_bytes", "expected_context", "expected_statuses"),
    [case[1:] for case in METADATA_CASES],
    ids=[case[0] for case in METADATA_CASES],
)
def test_metadata(c_build, document_format, metadata_bytes, expected_context, expected_statuses, tmp_path):
    profile_bytes = next(sample["data"] for sample in VALID_SAMPLES if sample["name"] == "minimal_rsa_authenticator")
    process, outputs = _run_cli(c_build, document_format, tmp_path, profile_bytes, metadata_bytes)
    if expected_context is None:
        assert process.returncode == 0, process.stderr
        assert len(outputs) == 2, outputs
    else:
        check_rejection(process, outputs, expected_context, expected_statuses, "")


ROOTLESS_CORPUS_CRYPTOCONFS = [
    (name, relative_path)
    for name, relative_path in get_valid_corpus_cryptoconfs()
    if not load_corpus_cryptoconf(relative_path)[0].get("keychain_uid")
]


def test_rootless_corpus_cryptoconfs_are_found():
    assert len(ROOTLESS_CORPUS_CRYPTOCONFS) == 9


@pytest.mark.parametrize("name, relative_path", ROOTLESS_CORPUS_CRYPTOCONFS, ids=[name for name, _ in ROOTLESS_CORPUS_CRYPTOCONFS])
def test_rootless_corpus_cryptoconfs(c_build, name, relative_path, tmp_path):
    """Valid corpus cryptoconfs without a root keychain uid (wacryptolib then draws one per cryptainer, which a
    device can't hold keys for) are rejected, in a raw profile without key entries, legacy "payload_signatures" key
    included. Signed ones are stripped of their signatures first, since signatures are rejected before (as other
    samples check)."""
    cryptoconf = load_corpus_cryptoconf(relative_path)[0]
    if has_signatures(cryptoconf):
        cryptoconf = profile_helpers.strip_signatures(cryptoconf)
    profile_bytes = profile_helpers.encode_cbor_item(
        profile_helpers.build_raw_device_profile(cryptoconf, add_root_keychain_uid=False, add_public_keys=False)
    )
    document_format = _get_document_format(c_build, ROOTLESS_CORPUS_CRYPTOCONFS.index((name, relative_path)))
    process, outputs = _run_cli(c_build, document_format, tmp_path, profile_bytes)
    check_rejection(process, outputs, "invalid device profile", {"WA_STATUS_INVALID_PROFILE"}, "cryptoconf.keychain_uid")
