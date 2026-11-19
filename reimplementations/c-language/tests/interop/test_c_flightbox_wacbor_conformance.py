# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
WA-CBOR conformance of the C decoder and writers (task 9.2, design D8):
- the test vectors of section 10 of the WA-CBOR specification, classified as accepted, unsupported or invalid;
- accepted deterministic vectors re-encoded to exactly `cbor_hex`, and written as exactly `extjson`;
- the invalid WA-CBOR documents of the corpus, spliced into a device profile, rejected;
- a differential test: every input the C decoder accepts loads with load_from_cbor_bytes() to the same tree.
"""

import importlib.util
import json
import random
import re
import uuid

import pytest

from c_flightbox_interop_support import (
    COMPATIBILITY_ROOT,
    C_UNIT_TESTS_DIR,
    MAXIMUM_INLINE_BYTES_ARGUMENTS_LENGTH,
    REPOSITORY_ROOT,
    CBuild,
    profile_helpers,
)

SPECIFICATION_PATH = REPOSITORY_ROOT / "docs" / "specifications" / "wa_cbor_document_format.md"

UNSUPPORTED_OR_INVALID_STATUSES = {"WA_STATUS_UNSUPPORTED_TYPE", "WA_STATUS_DECODING_ERROR"}


def _load_vector_classification():
    """The classification of the C unit tests' vector generator (which fails on unclassified vectors)."""
    spec = importlib.util.spec_from_file_location(
        "generate_wacbor_specification_vectors", C_UNIT_TESTS_DIR / "generate_wacbor_specification_vectors.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CLASSIFICATION = _load_vector_classification()


def _load_specification_vectors():
    """Parsed like wacryptolib's own test of the vectors does."""
    specification_text = SPECIFICATION_PATH.read_text(encoding="utf-8")
    match = re.search(r"^```json wa-cbor-test-vectors\n(.*?)^```", specification_text, re.MULTILINE | re.DOTALL)
    assert match, "No test vector block found in the WA-CBOR specification"
    return json.loads(match.group(1))


SPECIFICATION_VECTORS = _load_specification_vectors()


def _get_expected_statuses(vector_name, is_valid):
    if is_valid:
        if vector_name in CLASSIFICATION.ACCEPTED_VALID_VECTORS:
            return {"WA_STATUS_OK"}
        assert vector_name in CLASSIFICATION.UNSUPPORTED_VALID_VECTORS, "Unclassified valid vector %r" % vector_name
        return {"WA_STATUS_UNSUPPORTED_TYPE"}
    if vector_name in CLASSIFICATION.DECODING_ERROR_INVALID_VECTORS:
        return {"WA_STATUS_DECODING_ERROR"}
    if vector_name in CLASSIFICATION.EITHER_STATUS_INVALID_VECTORS:
        return UNSUPPORTED_OR_INVALID_STATUSES
    assert vector_name in CLASSIFICATION.NESTING_TOO_DEEP_INVALID_VECTORS, "Unclassified invalid vector %r" % vector_name
    return {"WA_STATUS_NESTING_TOO_DEEP"}


def _check_accepted_output(c_build, output, cbor_bytes):
    """The trees printed by the C writers equal what wacryptolib loads from the same bytes."""
    from wacryptolib.utilities import load_from_cbor_bytes, load_from_json_bytes

    expected_tree = load_from_cbor_bytes(cbor_bytes)
    if "cbor" in c_build.document_formats:
        assert load_from_cbor_bytes(bytes.fromhex(output["cbor"])) == expected_tree
    if "json" in c_build.document_formats:
        assert load_from_json_bytes(bytes.fromhex(output["json"])) == expected_tree
    return expected_tree


WINDOWS_COMMAND_LINE_LIMIT = 32767  # Characters, for the whole command line (CreateProcess)


@pytest.mark.parametrize("length", [1000, 8 * 1024, 8 * 1024 + 1, 16 * 1024, 60000])
def test_bytes_arguments_of_any_length_reach_the_driver(c_build, length):
    """Bytes go through the command line or through a file, depending on their length: whole in both cases (16 KiB
    in hex is the limit of a Windows command line by itself)."""
    from wacryptolib.utilities import dump_to_cbor_bytes

    data_length = length - 9  # Map head, key, byte string head
    tree = {"data": bytes(range(256)) * (data_length // 256) + bytes(data_length % 256)}
    cbor_bytes = dump_to_cbor_bytes(tree)
    assert len(cbor_bytes) == length
    output = c_build.run_driver("cbor-decode", cbor_bytes)
    assert output["status"] == "WA_STATUS_OK", output
    assert _check_accepted_output(c_build, output, cbor_bytes) == tree


def test_bytes_arguments_fit_the_command_line(tmp_path):
    """The inline budget is for a whole command, whose line stays far below the limit of Windows."""
    budget = MAXIMUM_INLINE_BYTES_ARGUMENTS_LENGTH
    arguments = ["subcommand", bytes(budget // 2), "text", bytes(budget // 2), bytes(1), b"", tmp_path, bytes(budget)]
    command_arguments = CBuild.get_driver_command_arguments(arguments, tmp_path)
    assert command_arguments[:4] == ["subcommand", "00" * (budget // 2), "text", "00" * (budget // 2)]
    assert command_arguments[4:7] == ["@" + str(tmp_path / "argument_4.bin"), "", str(tmp_path)]  # Budget spent
    assert command_arguments[7] == "@" + str(tmp_path / "argument_7.bin")
    assert (tmp_path / "argument_4.bin").read_bytes() == bytes(1)
    assert (tmp_path / "argument_7.bin").read_bytes() == bytes(budget)
    assert 2 * budget <= (WINDOWS_COMMAND_LINE_LIMIT + 1) // 2  # Hex characters: as much left for the rest


@pytest.mark.parametrize("vector", SPECIFICATION_VECTORS["valid"], ids=lambda vector: vector["name"])
def test_valid_specification_vectors(c_build, vector):
    output = c_build.run_driver("cbor-decode", vector["cbor_hex"])
    assert output["status"] in _get_expected_statuses(vector["name"], is_valid=True), output
    if output["status"] != "WA_STATUS_OK":
        assert set(output) == {"status"}
        return
    _check_accepted_output(c_build, output, bytes.fromhex(vector["cbor_hex"]))
    if vector["deterministic"]:
        if "cbor" in c_build.document_formats:
            assert output["cbor"] == vector["cbor_hex"]
        if "json" in c_build.document_formats:
            assert bytes.fromhex(output["json"]).decode("ascii") == vector["extjson"]


@pytest.mark.parametrize("vector", SPECIFICATION_VECTORS["invalid"], ids=lambda vector: vector["name"])
def test_invalid_specification_vectors(c_build, vector):
    output = c_build.run_driver("cbor-decode", vector["cbor_hex"])
    assert output["status"] in _get_expected_statuses(vector["name"], is_valid=False), output
    assert set(output) == {"status"}


def test_every_specification_vector_is_classified():
    names = {vector["name"] for vector in SPECIFICATION_VECTORS["valid"] + SPECIFICATION_VECTORS["invalid"]}
    classified_names = (
        CLASSIFICATION.ACCEPTED_VALID_VECTORS
        | CLASSIFICATION.UNSUPPORTED_VALID_VECTORS
        | CLASSIFICATION.DECODING_ERROR_INVALID_VECTORS
        | CLASSIFICATION.EITHER_STATUS_INVALID_VECTORS
        | CLASSIFICATION.NESTING_TOO_DEEP_INVALID_VECTORS
    )
    assert names == classified_names, names ^ classified_names


def _get_base_device_profile():
    """A small valid device profile, as a tree (built without validation, from a corpus cryptoconf)."""
    from wacryptolib.utilities import load_from_cbor_bytes

    cryptoconf = load_from_cbor_bytes(
        (COMPATIBILITY_ROOT / "cryptoconfs" / "2026_cbor_pairs" / "01_single_layer.cryptoconf.cbor").read_bytes()
    )
    return profile_helpers.build_raw_device_profile(cryptoconf)


INVALID_CORPUS_DOCUMENTS = sorted((COMPATIBILITY_ROOT / "cryptoconfs" / "2026_cbor_pairs" / "invalid").glob("*.cryptoconf.cbor"))


@pytest.mark.parametrize("document_path", INVALID_CORPUS_DOCUMENTS, ids=lambda path: path.name)
def test_invalid_corpus_documents_rejected_through_the_splicer(c_build, document_path, tmp_path):
    from wacryptolib.utilities import WaCborError, load_from_cbor_bytes

    document_bytes = document_path.read_bytes()
    with pytest.raises(WaCborError):
        load_from_cbor_bytes(document_bytes)  # Invalid for wacryptolib too

    output = c_build.run_driver("cbor-decode", document_bytes)
    assert output["status"] in UNSUPPORTED_OR_INVALID_STATUSES, output

    profile_path = tmp_path / "spliced_profile.cbor"
    profile_path.write_bytes(profile_helpers.splice_cryptoconf_item(_get_base_device_profile(), document_bytes))
    output = c_build.run_driver("load-profile", profile_path)
    assert output["status"] in UNSUPPORTED_OR_INVALID_STATUSES, output


def _iter_differential_inputs():
    """Specification vectors, helper mutations of a valid device profile, and seeded random corruptions of it."""
    for vector in SPECIFICATION_VECTORS["valid"] + SPECIFICATION_VECTORS["invalid"]:
        yield "vector:" + vector["name"], bytes.fromhex(vector["cbor_hex"])

    base_profile = _get_base_device_profile()
    base_bytes = profile_helpers.dump_device_profile(base_profile)
    yield "base_profile", base_bytes
    cryptoconf_path = ("cryptoconf",)
    layer_path = ("cryptoconf", "payload_cipher_layers", 0)
    mutations = {
        "uuid_to_text": lambda: profile_helpers.mutate_uuid_to_text(base_profile, ("cryptoconf", "keychain_uid")),
        "added_key": lambda: profile_helpers.mutate_add_key(base_profile, layer_path),
        "removed_key": lambda: profile_helpers.mutate_remove_key(base_profile, layer_path, "payload_cipher_algo"),
        "duplicate_key": lambda: profile_helpers.mutate_duplicate_key(base_profile, cryptoconf_path, "keychain_uid"),
        "keyword_map": lambda: profile_helpers.mutate_keyword_map(base_profile, layer_path + ("payload_cipher_algo",)),
        "indefinite_length": lambda: profile_helpers.mutate_indefinite_length(base_profile, cryptoconf_path),
        "indefinite_text": lambda: profile_helpers.mutate_indefinite_length(
            base_profile, layer_path + ("payload_cipher_algo",), chunks=["AES_", "CBC"]
        ),
        "float": lambda: profile_helpers.mutate_float(base_profile, layer_path + ("payload_cipher_algo",)),
        "half_float": lambda: profile_helpers.mutate_float(base_profile, layer_path + ("payload_cipher_algo",), 1.5, 16),
        "datetime_tag": lambda: profile_helpers.mutate_tag(
            base_profile, layer_path + ("payload_cipher_algo",), 0, "2026-01-02T03:04:05Z"
        ),
        "unknown_tag": lambda: profile_helpers.mutate_tag(base_profile, layer_path + ("payload_cipher_algo",), 258),
        "self_described": lambda: profile_helpers.mutate_self_described(base_profile),
        "integer_value": lambda: profile_helpers.mutate_value(base_profile, layer_path + ("payload_cipher_algo",), -(2**63)),
        "uuid_value": lambda: profile_helpers.mutate_value(
            base_profile, layer_path + ("payload_cipher_algo",), uuid.UUID(int=1)
        ),
    }
    for name, mutate in mutations.items():
        yield "mutation:" + name, mutate()

    randomizer = random.Random(20261117)
    for index in range(300):
        corrupted = bytearray(base_bytes)
        kind = index % 4
        if kind == 0:  # Truncation
            corrupted = corrupted[: randomizer.randrange(len(corrupted))]
        elif kind == 1:  # Byte replacement
            for _ in range(randomizer.randint(1, 3)):
                corrupted[randomizer.randrange(len(corrupted))] = randomizer.randrange(256)
        elif kind == 2:  # Bit flip
            position = randomizer.randrange(len(corrupted))
            corrupted[position] ^= 1 << randomizer.randrange(8)
        else:  # Inserted or deleted byte
            position = randomizer.randrange(len(corrupted))
            if randomizer.random() < 0.5:
                corrupted.insert(position, randomizer.randrange(256))
            else:
                del corrupted[position]
        yield "corruption:%d" % index, bytes(corrupted)


def test_differential_acceptance(c_build):
    """Whatever the C decoder accepts, wacryptolib loads to the same tree (never the other way round: the
    sub-profile is narrower)."""
    from wacryptolib.utilities import WaCborError, load_from_cbor_bytes

    accepted_count = 0
    rejected_count = 0
    for name, cbor_bytes in _iter_differential_inputs():
        output = c_build.run_driver("cbor-decode", cbor_bytes)
        if output["status"] == "WA_STATUS_OK":
            accepted_count += 1
            try:
                _check_accepted_output(c_build, output, cbor_bytes)
            except WaCborError as exc:
                pytest.fail("Input %s accepted by the C decoder, rejected by wacryptolib: %s" % (name, exc))
        else:
            rejected_count += 1
            assert output["status"] in UNSUPPORTED_OR_INVALID_STATUSES | {"WA_STATUS_NESTING_TOO_DEEP"}, (name, output)
            if output["status"] == "WA_STATUS_DECODING_ERROR":  # Not WA-CBOR: wacryptolib rejects it too
                with pytest.raises(WaCborError):
                    load_from_cbor_bytes(cbor_bytes)
    # Both outcomes are exercised
    assert accepted_count > 10 and rejected_count > 100, (accepted_count, rejected_count)
