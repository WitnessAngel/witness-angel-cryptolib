# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Tests of the flightbox device profile export script (scripts/flightbox/export_device_profile.py), and self-checks
of the device profile test helpers of the C reimplementation (reimplementations/c-language/tests/interop/).
"""

import copy
import re
import sys
import uuid
from pathlib import Path

import cbor2
import pytest

from wacryptolib.cryptainer import check_cryptoconf_sanity
from wacryptolib.utilities import dump_to_cbor_bytes, load_from_cbor_bytes, load_from_document_file

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "reimplementations" / "c-language" / "tests" / "interop"))

import device_profile_test_helpers as helpers  # noqa: E402

CRYPTOCONFS_DIR = REPOSITORY_ROOT / "compatibility" / "cryptoconfs"
KEYSTORES_DIR = REPOSITORY_ROOT / "compatibility" / "keystores"
DEVICE_PROFILE_SPECIFICATION_PATH = (
    REPOSITORY_ROOT / "docs" / "flightbox_specifications" / "flightbox_device_profile_specification.md"
)

CLASSIC_POOL = KEYSTORES_DIR / "2026_current" / "classic_pool"
CBOR_PAIRS_POOL = KEYSTORES_DIR / "2026_cbor_pairs" / "cbor_pairs_pool"
CBOR_KEY_CIPHERTEXTS_POOL = KEYSTORES_DIR / "2026_cbor_key_ciphertexts" / "cbor_key_ciphertexts_pool"
PQ_POOL = KEYSTORES_DIR / "2026_post_quantum" / "pq_pool"

requires_pycryptodome = pytest.mark.requires_pycryptodome

# Corpus cryptoconfs that are signature-free with a root keychain uid: (cryptoconf paths, keystore pool, marks).
# Pairs are the Extended JSON and WA-CBOR assets of the same cryptoconf.
SIGNATURE_FREE_CORPUS_CRYPTOCONFS = [
    pytest.param(["2026_current/01_single_layer.cryptoconf"], CLASSIC_POOL, id="current_01"),
    pytest.param(["2026_current/05_shamir_authenticators.cryptoconf"], CLASSIC_POOL, id="current_05"),
    pytest.param(
        ["2026_cbor_pairs/01_single_layer.cryptoconf.json", "2026_cbor_pairs/01_single_layer.cryptoconf.cbor"],
        CBOR_PAIRS_POOL,
        id="cbor_pairs_01",
    ),
] + [
    pytest.param(
        ["2026_cbor_key_ciphertexts/%s.cryptoconf.json" % name, "2026_cbor_key_ciphertexts/%s.cryptoconf.cbor" % name],
        CBOR_KEY_CIPHERTEXTS_POOL,
        id="cbor_key_ciphertexts_" + name,
        marks=[requires_pycryptodome] if "post_quantum" in name else [],
    )
    for name in ("01_single_layer", "02_shared_secret", "03_nested_symmetric", "04_post_quantum", "05_mixable")
]

SIGNED_CORPUS_CRYPTOCONFS = [
    pytest.param("2026_current/03_multiple_payload_layers.cryptoconf", CLASSIC_POOL, id="current_03"),
    pytest.param("2026_current/04_recursive_key_layers.cryptoconf", CLASSIC_POOL, id="current_04"),
    pytest.param("2026_current/06_signed_multi_trustee.cryptoconf", CLASSIC_POOL, id="current_06"),
    pytest.param(
        "2026_post_quantum/07_pq_hybrid.cryptoconf", PQ_POOL, id="pq_07", marks=[requires_pycryptodome]
    ),
]

RAW_KEY_SIZES = {"ECIES_X25519": 32, "ML_KEM_768": 1184}


@pytest.fixture(scope="module")
def export_script():
    return helpers.import_export_script()


def _iter_signature_confs(tree):
    if isinstance(tree, dict):
        for key, value in tree.items():
            if key in ("payload_plaintext_signatures", "payload_ciphertext_signatures", "payload_signatures"):
                yield from value
            else:
                yield from _iter_signature_confs(value)
    elif isinstance(tree, list):
        for item in tree:
            yield from _iter_signature_confs(item)


def check_device_profile_rules(device_profile_bytes: bytes, expected_cryptoconf: dict, export_script):
    """Check the rules of the device profile specification (CDDL and section 4/5 constraints) that apply to an
    exported profile, and return its tree."""
    device_profile = load_from_cbor_bytes(device_profile_bytes)
    assert dump_to_cbor_bytes(device_profile) == device_profile_bytes  # Deterministic encoding

    assert set(device_profile) == {"device_profile_format", "cryptoconf", "trustee_public_keys"}
    assert device_profile["device_profile_format"] == "flightbox_device_profile_1.0"
    cryptoconf = device_profile["cryptoconf"]
    assert cryptoconf == expected_cryptoconf
    check_cryptoconf_sanity(cryptoconf)
    assert isinstance(cryptoconf["keychain_uid"], uuid.UUID)  # Tag 37 in WA-CBOR, mandatory at root
    assert not list(_iter_signature_confs(cryptoconf))

    entries = device_profile["trustee_public_keys"]
    entry_identifiers = []
    for entry in entries:
        assert set(entry) == {"trustee", "keychain_uid", "key_algo", "public_key"}
        assert isinstance(entry["keychain_uid"], uuid.UUID)
        assert isinstance(entry["trustee"], dict) and entry["trustee"]["trustee_type"] in (
            "local_keyfactory",
            "authenticator",
        )
        if entry["trustee"]["trustee_type"] == "authenticator":
            assert isinstance(entry["trustee"]["keystore_uid"], uuid.UUID)
        key_algo = entry["key_algo"]
        public_key = entry["public_key"]
        if key_algo == "RSA_OAEP":
            assert set(public_key) == {"modulus", "public_exponent"}
            modulus, public_exponent = public_key["modulus"], public_key["public_exponent"]
            assert 256 <= len(modulus) <= 512 and modulus[0] != 0 and modulus[-1] & 1
            assert public_exponent and public_exponent[0] != 0
            exponent_value = int.from_bytes(public_exponent, "big")
            assert 3 <= exponent_value < int.from_bytes(modulus, "big") and exponent_value & 1
        else:
            assert key_algo in RAW_KEY_SIZES and isinstance(public_key, bytes)
            assert len(public_key) == RAW_KEY_SIZES[key_algo]
            if key_algo == "ECIES_X25519":
                assert int.from_bytes(public_key, "little") < helpers.X25519_FIELD_PRIME
        entry_identifiers.append(
            (export_script.get_trustee_identity(entry["trustee"]), entry["keychain_uid"], key_algo)
        )
    assert len(set(entry_identifiers)) == len(entry_identifiers)  # Unique entries

    # Exactly one entry per distinct (trustee identity, keychain uid, key algo) used by the cryptoconf
    used_identifiers = []
    for layer in export_script.iter_asymmetric_key_cipher_layers(cryptoconf):
        identifier = (
            export_script.get_trustee_identity(layer["key_cipher_trustee"]),
            layer.get("keychain_uid") or cryptoconf["keychain_uid"],
            layer["key_cipher_algo"],
        )
        if identifier not in used_identifiers:
            used_identifiers.append(identifier)
    assert entry_identifiers == used_identifiers

    _check_with_pycddl_if_available(device_profile_bytes)
    return device_profile


def _check_with_pycddl_if_available(device_profile_bytes):
    try:
        import pycddl
    except ImportError:  # Optional third-party checker (pip install pycddl)
        return
    text = DEVICE_PROFILE_SPECIFICATION_PATH.read_text(encoding="utf8")
    (cddl,) = re.findall(r"```cddl\n(.*?)```", text, re.S)
    pycddl.Schema(cddl).validate_cbor(device_profile_bytes)


def test_device_profile_specification_has_a_cddl_block():
    text = DEVICE_PROFILE_SPECIFICATION_PATH.read_text(encoding="utf8")
    (cddl,) = re.findall(r"```cddl\n(.*?)```", text, re.S)
    assert cddl.startswith("device-profile = {")


@pytest.mark.parametrize("cryptoconf_relpaths, keystore_pool_dir", SIGNATURE_FREE_CORPUS_CRYPTOCONFS)
def test_export_signature_free_corpus_cryptoconfs(cryptoconf_relpaths, keystore_pool_dir, tmp_path, export_script):
    exported_bytes = []
    for index, cryptoconf_relpath in enumerate(cryptoconf_relpaths):
        cryptoconf_path = CRYPTOCONFS_DIR / cryptoconf_relpath
        output_path = export_script.export_device_profile(
            cryptoconf_path, keystore_pool_dir, tmp_path / ("profile%d.cbor" % index)
        )
        assert output_path == tmp_path / ("profile%d.cbor" % index)
        device_profile_bytes = output_path.read_bytes()
        check_device_profile_rules(device_profile_bytes, load_from_document_file(cryptoconf_path), export_script)
        exported_bytes.append(device_profile_bytes)
    assert len(set(exported_bytes)) == 1  # Byte-identical profiles from both formats of a pair


@pytest.mark.parametrize("cryptoconf_relpath, keystore_pool_dir", SIGNED_CORPUS_CRYPTOCONFS)
def test_export_signature_stripped_corpus_cryptoconfs(cryptoconf_relpath, keystore_pool_dir, export_script):
    cryptoconf = load_from_document_file(CRYPTOCONFS_DIR / cryptoconf_relpath)
    assert list(_iter_signature_confs(cryptoconf))  # Really signed
    stripped_cryptoconf = helpers.strip_signatures(cryptoconf)
    assert not list(_iter_signature_confs(stripped_cryptoconf))
    device_profile = export_script.build_device_profile(stripped_cryptoconf, keystore_pool_dir)
    check_device_profile_rules(dump_to_cbor_bytes(device_profile), stripped_cryptoconf, export_script)


def test_exported_profile_matches_pool_keys(export_script):
    # RSA modulus and exponent of the exported profile are those of the PEM key of the pool
    from wacryptolib.keystore import ReadonlyFilesystemKeystore

    cryptoconf = load_from_document_file(CRYPTOCONFS_DIR / "2026_cbor_pairs/01_single_layer.cryptoconf.cbor")
    device_profile = export_script.build_device_profile(cryptoconf, CBOR_PAIRS_POOL)
    (entry,) = device_profile["trustee_public_keys"]
    assert entry["key_algo"] == "RSA_OAEP"
    keystore = ReadonlyFilesystemKeystore(CBOR_PAIRS_POOL / "local_keyfactory")
    public_key_pem = keystore.get_public_key(keychain_uid=entry["keychain_uid"], key_algo="RSA_OAEP")
    from wacryptolib.keygen import load_asymmetric_key_from_pem_bytestring

    public_key = load_asymmetric_key_from_pem_bytestring(public_key_pem, key_algo="RSA_OAEP")
    numbers = public_key.public_numbers() if hasattr(public_key, "public_numbers") else public_key
    assert int.from_bytes(entry["public_key"]["modulus"], "big") == numbers.n
    assert int.from_bytes(entry["public_key"]["public_exponent"], "big") == numbers.e


def test_export_cli_behaviour(tmp_path, export_script, capsys):
    cryptoconf_path = CRYPTOCONFS_DIR / "2026_cbor_pairs/01_single_layer.cryptoconf.json"

    # Extension matched in any letter case, and lowercased
    assert export_script.main([str(cryptoconf_path), str(CBOR_PAIRS_POOL), "-o", str(tmp_path / "Profile.CBOR")]) == 0
    output_path = tmp_path / "Profile.cbor"
    assert [path.name for path in tmp_path.iterdir()] == ["Profile.cbor"]
    original_bytes = output_path.read_bytes()

    # Existing output refused, unchanged
    output_path.write_bytes(b"existing")
    assert export_script.main([str(cryptoconf_path), str(CBOR_PAIRS_POOL), "-o", str(output_path)]) == 1
    assert "already exists" in capsys.readouterr().err
    assert output_path.read_bytes() == b"existing"

    # Overwritten with --force
    assert export_script.main([str(cryptoconf_path), str(CBOR_PAIRS_POOL), "-o", str(output_path), "--force"]) == 0
    assert output_path.read_bytes() == original_bytes

    # Bad extension
    assert export_script.main([str(cryptoconf_path), str(CBOR_PAIRS_POOL), "-o", str(tmp_path / "x.json")]) == 1
    assert "must end with '.cbor'" in capsys.readouterr().err

    # Missing root keychain uid
    cryptoconf = load_from_document_file(cryptoconf_path)
    del cryptoconf["keychain_uid"]
    no_uid_path = tmp_path / "no_uid.cryptoconf.cbor"
    no_uid_path.write_bytes(dump_to_cbor_bytes(cryptoconf))
    assert export_script.main([str(no_uid_path), str(CBOR_PAIRS_POOL), "-o", str(tmp_path / "a.cbor")]) == 1
    assert "root keychain_uid" in capsys.readouterr().err

    # Missing key in pool
    empty_pool = tmp_path / "empty_pool"
    (empty_pool / "local_keyfactory").mkdir(parents=True)
    assert export_script.main([str(cryptoconf_path), str(empty_pool), "-o", str(tmp_path / "b.cbor")]) == 1
    assert "Missing RSA_OAEP public key of keychain" in capsys.readouterr().err

    # Unsupported jsonrpc_api trustee
    cryptoconf = load_from_document_file(cryptoconf_path)
    cryptoconf["payload_cipher_layers"][0]["key_cipher_layers"][0]["key_cipher_trustee"] = dict(
        trustee_type="jsonrpc_api", jsonrpc_url="http://example.com/json/"
    )
    jsonrpc_path = tmp_path / "jsonrpc.cryptoconf.cbor"
    jsonrpc_path.write_bytes(dump_to_cbor_bytes(cryptoconf))
    assert export_script.main([str(jsonrpc_path), str(CBOR_PAIRS_POOL), "-o", str(tmp_path / "c.cbor")]) == 1
    assert "'jsonrpc_api' are not supported" in capsys.readouterr().err

    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "Profile.cbor",
        "empty_pool",
        "jsonrpc.cryptoconf.cbor",
        "no_uid.cryptoconf.cbor",
    ]


# SELF-CHECKS OF THE DEVICE PROFILE TEST HELPERS #


@pytest.fixture(scope="module")
def sample_device_profile(export_script):
    # RSA_OAEP, ECIES_X25519 and authenticators with UUIDs, without ML-KEM so that it works in every backend
    cryptoconf = load_from_document_file(CRYPTOCONFS_DIR / "2026_cbor_key_ciphertexts/02_shared_secret.cryptoconf.cbor")
    return export_script.build_device_profile(cryptoconf, CBOR_KEY_CIPHERTEXTS_POOL)


def _decode_with_cbor2(data):
    return cbor2.loads(data)


def test_helper_encoder_matches_wacryptolib(sample_device_profile):
    assert helpers.encode_cbor_item(sample_device_profile) == dump_to_cbor_bytes(sample_device_profile)
    assert helpers.dump_device_profile(sample_device_profile) == dump_to_cbor_bytes(sample_device_profile)
    tricky_tree = {"": [0, 23, 24, 255, 256, 65535, 65536, 2**32, 2**63 - 1, -1, -24, -25, -(2**63)], "bb": "é☕"}
    assert helpers.encode_cbor_item(tricky_tree) == dump_to_cbor_bytes(tricky_tree)


def _get_x25519_point_order_by_doubling(u, max_doublings=3):
    """Return 2**k if k <= max_doublings x-only doublings of the Curve25519 point of u-coordinate `u` reach the
    point at infinity, else None. x(2P) = (x^2 - 1)^2 / (4x(x^2 + Ax + 1)), infinite when the denominator is 0."""
    p, a = helpers.X25519_FIELD_PRIME, 486662
    for doubling_count in range(1, max_doublings + 1):
        denominator = 4 * u * (u * u + a * u + 1) % p
        if not denominator:
            return 2**doubling_count
        u = (u * u - 1) ** 2 * pow(denominator, p - 2, p) % p
    return None


def _expect_valid_mutation(mutated_bytes, original_tree, path, expected_value):
    expected_tree = helpers.replace_value_at_path(original_tree, path, expected_value)
    assert load_from_cbor_bytes(mutated_bytes) == expected_tree
    assert mutated_bytes == dump_to_cbor_bytes(expected_tree)


def test_helper_valid_mutators(sample_device_profile):
    profile = sample_device_profile
    uuid_paths = list(helpers.iter_uuid_paths(profile))
    assert ("cryptoconf", "keychain_uid") in uuid_paths
    assert any(path[-1] == "keystore_uid" for path in uuid_paths)
    for path in uuid_paths:
        _expect_valid_mutation(helpers.mutate_uuid_to_text(profile, path), profile, path, str(helpers.get_value_at_path(profile, path)))

    mutated = helpers.mutate_add_key(profile, ("cryptoconf",), key="key_ciphertext_format", value="cbor")
    expected = copy.deepcopy(profile)
    expected["cryptoconf"]["key_ciphertext_format"] = "cbor"
    assert load_from_cbor_bytes(mutated) == expected

    mutated = helpers.mutate_remove_key(profile, ("cryptoconf",), "keychain_uid")
    expected = copy.deepcopy(profile)
    del expected["cryptoconf"]["keychain_uid"]
    assert load_from_cbor_bytes(mutated) == expected

    x25519_index = helpers.find_public_key_entry_index(profile, "ECIES_X25519")
    rsa_index = helpers.find_public_key_entry_index(profile, "RSA_OAEP")
    valid_x25519_key = profile["trustee_public_keys"][x25519_index]["public_key"]
    key_path = ("trustee_public_keys", x25519_index, "public_key")
    new_keys = (
        [valid_x25519_key + b"\x00", valid_x25519_key[:31]]
        + helpers.get_low_order_x25519_public_keys()
        + helpers.get_non_canonical_x25519_public_keys(valid_x25519_key)
    )
    for new_key in new_keys:
        _expect_valid_mutation(helpers.mutate_public_key(profile, x25519_index, new_key), profile, key_path, new_key)
    low_order_values = [int.from_bytes(key, "little") for key in helpers.get_low_order_x25519_public_keys()]
    assert low_order_values[:2] == [0, 1] and low_order_values[-1] == helpers.X25519_FIELD_PRIME - 1
    for u in helpers.X25519_ORDER_8_POINTS:  # Really of order 8: infinity after 3 doublings, not before
        assert _get_x25519_point_order_by_doubling(u) == 8
    assert _get_x25519_point_order_by_doubling(int.from_bytes(valid_x25519_key, "little")) is None
    non_canonical = helpers.get_non_canonical_x25519_public_keys(valid_x25519_key)
    assert non_canonical[0][31] & 0x80 and non_canonical[0][:31] == valid_x25519_key[:31]
    assert int.from_bytes(non_canonical[2], "little") == helpers.X25519_FIELD_PRIME + 1

    rsa_key_path = ("trustee_public_keys", rsa_index, "public_key")
    for bits, kwargs in [(1024, {}), (4104, {}), (2048, dict(even_modulus=True)), (2048, dict(public_exponent=1)),
                         (2048, dict(public_exponent=65538))]:
        rsa_key = helpers.make_rsa_public_key(bits, **kwargs)
        modulus = int.from_bytes(rsa_key["modulus"], "big")
        assert modulus.bit_length() == bits and modulus & 1 == (0 if kwargs.get("even_modulus") else 1)
        assert rsa_key["modulus"][0] != 0 and rsa_key["public_exponent"][0] != 0
        _expect_valid_mutation(helpers.mutate_public_key(profile, rsa_index, rsa_key), profile, rsa_key_path, rsa_key)


def test_helper_ml_kem_coefficient_mutator():
    public_key = bytes(range(256)) * 4 + bytes(160)
    for index in (0, 1, 2, 767):
        mutated = helpers.set_ml_kem_coefficient(public_key, index, 3329)
        assert helpers.get_ml_kem_coefficient(mutated, index) == 3329
        assert len(mutated) == 1184
        differing_bytes = [i for i in range(1184) if mutated[i] != public_key[i]]
        assert differing_bytes and all((index // 2) * 3 <= i < (index // 2) * 3 + 3 for i in differing_bytes)
        for other_index in (index - 1, index + 1):  # Neighbour coefficients unchanged
            if 0 <= other_index < 768:
                assert helpers.get_ml_kem_coefficient(mutated, other_index) == helpers.get_ml_kem_coefficient(
                    public_key, other_index
                )


def test_helper_mutators_outside_sub_profile(sample_device_profile):
    # Valid WA-CBOR (wacryptolib loads them), but outside the device profile sub-profile
    profile = sample_device_profile
    format_path = ("device_profile_format",)
    threshold_path = ("cryptoconf", "payload_cipher_layers", 0, "key_cipher_layers", 1, "key_shared_secret_threshold")
    assert helpers.get_value_at_path(profile, threshold_path) == 2

    for path in [(), ("cryptoconf",), ("trustee_public_keys",), format_path, ("trustee_public_keys", 0, "public_key")]:
        mutated = helpers.mutate_indefinite_length(profile, path)
        assert mutated != dump_to_cbor_bytes(profile)
        assert load_from_cbor_bytes(mutated) == profile
    mutated = helpers.mutate_indefinite_length(profile, format_path, chunks=["flightbox_", "device_profile_1.0"])
    assert load_from_cbor_bytes(mutated) == profile

    for width in (16, 32, 64):
        assert load_from_cbor_bytes(helpers.mutate_float(profile, threshold_path, 2.0, width)) == profile  # 2.0 == 2
        assert isinstance(
            helpers.get_value_at_path(load_from_cbor_bytes(helpers.mutate_float(profile, threshold_path, 2.0, width)), threshold_path),
            float,
        )
    mutated = helpers.mutate_tag(profile, threshold_path, 2, tagged_value=b"\x02")  # Positive bignum
    assert load_from_cbor_bytes(mutated) == profile
    assert mutated != dump_to_cbor_bytes(profile)
    for out_of_range_integer in (2**63, 2**64 - 1, -(2**63) - 1, -(2**64)):  # Outside int64, plain major types 0/1
        mutated = helpers.mutate_value(profile, threshold_path, out_of_range_integer)
        assert helpers.get_value_at_path(load_from_cbor_bytes(mutated), threshold_path) == out_of_range_integer
        assert mutated == dump_to_cbor_bytes(helpers.replace_value_at_path(profile, threshold_path, out_of_range_integer))
    mutated = helpers.mutate_tag(profile, format_path, 0, tagged_value="2026-11-17T10:00:00Z")
    assert helpers.get_value_at_path(load_from_cbor_bytes(mutated), format_path).year == 2026
    assert load_from_cbor_bytes(helpers.mutate_self_described(profile)) == profile


def test_helper_invalid_wacbor_mutators(sample_device_profile):
    # Not WA-CBOR: wacryptolib rejects them, cbor2 shows what they hold
    from wacryptolib.utilities import WaCborDecodingError

    profile = sample_device_profile
    trustee_path = ("cryptoconf", "payload_cipher_layers", 0, "key_cipher_layers", 0, "key_cipher_trustee")

    mutated = helpers.mutate_duplicate_key(profile, ("cryptoconf",), "keychain_uid")
    assert len(mutated) == len(dump_to_cbor_bytes(profile)) + len(helpers.encode_cbor_item(["keychain_uid", profile["cryptoconf"]["keychain_uid"]])) - 1
    assert _decode_with_cbor2(mutated)["cryptoconf"]["keychain_uid"] == profile["cryptoconf"]["keychain_uid"]
    mutated_root = helpers.mutate_duplicate_key(profile, (), "device_profile_format", duplicate_value="other")
    assert _decode_with_cbor2(mutated_root)["device_profile_format"] == "other"  # cbor2 keeps the last value

    mutated_keyword = helpers.mutate_keyword_map(profile, trustee_path)
    assert _decode_with_cbor2(mutated_keyword)["cryptoconf"]["payload_cipher_layers"][0]["key_cipher_layers"][0][
        "key_cipher_trustee"
    ] == {"$binary": "AAAA"}

    mutated_tag = helpers.mutate_tag(profile, ("device_profile_format",), 99)
    decoded = _decode_with_cbor2(mutated_tag)["device_profile_format"]
    assert decoded.tag == 99 and decoded.value == "flightbox_device_profile_1.0"

    non_text_key = helpers.mutate_value(profile, trustee_path, helpers.RawMap([(1, "local_keyfactory")]))
    assert _decode_with_cbor2(non_text_key)["cryptoconf"]["payload_cipher_layers"][0]["key_cipher_layers"][0][
        "key_cipher_trustee"
    ] == {1: "local_keyfactory"}

    for invalid_bytes in (mutated, mutated_root, mutated_keyword, mutated_tag, non_text_key):
        with pytest.raises(WaCborDecodingError):
            load_from_cbor_bytes(invalid_bytes)


def test_helper_cryptoconf_splicer(sample_device_profile):
    profile = sample_device_profile
    sentinel = helpers.encode_cbor_item("SENTINEL-ITEM")
    spliced_sentinel = helpers.splice_cryptoconf_item(profile, sentinel)
    assert spliced_sentinel.count(sentinel) == 1

    # Splicing the genuine cryptoconf gives back the profile
    assert helpers.splice_cryptoconf_item(profile, dump_to_cbor_bytes(profile["cryptoconf"])) == dump_to_cbor_bytes(profile)

    invalid_documents = sorted((CRYPTOCONFS_DIR / "2026_cbor_pairs" / "invalid").glob("*.cryptoconf.cbor"))
    assert len(invalid_documents) == 5
    for invalid_document in invalid_documents + [None]:
        item = invalid_document.read_bytes() if invalid_document else b"\xa1\x61"  # Also a truncated item
        spliced = helpers.splice_cryptoconf_item(profile, item)
        assert spliced == spliced_sentinel.replace(sentinel, item)


def test_helper_signature_stripper():
    cryptoconf = load_from_document_file(CRYPTOCONFS_DIR / "2026_current/06_signed_multi_trustee.cryptoconf")
    stripped = helpers.strip_signatures(cryptoconf)
    check_cryptoconf_sanity(stripped)
    assert "payload_plaintext_signatures" in cryptoconf and "payload_plaintext_signatures" not in stripped
    for original_layer, stripped_layer in zip(cryptoconf["payload_cipher_layers"], stripped["payload_cipher_layers"]):
        assert stripped_layer["payload_ciphertext_signatures"] == []
        assert stripped_layer["key_cipher_layers"] == original_layer["key_cipher_layers"]
    legacy = copy.deepcopy(cryptoconf)
    for layer in legacy["payload_cipher_layers"]:
        layer["payload_signatures"] = layer.pop("payload_ciphertext_signatures")
    assert helpers.strip_signatures(legacy) == stripped


def test_helper_raw_profile_converter():
    # Invalid corpus cryptoconfs become encodable profiles, with a root keychain uid and keys for their layers
    invalid_paths = sorted((CRYPTOCONFS_DIR / "2026_current" / "invalid").glob("*.cryptoconf"))
    assert invalid_paths
    for invalid_path in invalid_paths:
        cryptoconf = load_from_document_file(invalid_path)
        device_profile = helpers.build_raw_device_profile(cryptoconf)
        assert device_profile["cryptoconf"]["keychain_uid"] == cryptoconf.get("keychain_uid", helpers.DEFAULT_ROOT_KEYCHAIN_UID)
        layers = list(helpers.iter_asymmetric_key_cipher_layers_leniently(device_profile["cryptoconf"]))
        assert len(device_profile["trustee_public_keys"]) <= len(layers)
        assert load_from_cbor_bytes(helpers.dump_device_profile(device_profile)) == device_profile

    # On a valid cryptoconf, the converter gives the same tree shape as the export script, with other keys
    cryptoconf = load_from_document_file(CRYPTOCONFS_DIR / "2026_cbor_key_ciphertexts/02_shared_secret.cryptoconf.cbor")
    exported = helpers.import_export_script().build_device_profile(cryptoconf, CBOR_KEY_CIPHERTEXTS_POOL)
    converted = helpers.build_raw_device_profile(cryptoconf)
    assert converted["cryptoconf"] == exported["cryptoconf"]
    assert [(e["trustee"], e["keychain_uid"], e["key_algo"]) for e in converted["trustee_public_keys"]] == [
        (e["trustee"], e["keychain_uid"], e["key_algo"]) for e in exported["trustee_public_keys"]
    ]

    # Options
    del cryptoconf["keychain_uid"]
    bare = helpers.build_raw_device_profile(cryptoconf, add_root_keychain_uid=False, add_public_keys=False)
    assert "keychain_uid" not in bare["cryptoconf"] and bare["trustee_public_keys"] == []
    extra_entry = dict(trustee=dict(trustee_type="local_keyfactory"), keychain_uid=uuid.uuid4(), key_algo="ECIES_X25519",
                       public_key=bytes(32))
    with_extra = helpers.build_raw_device_profile(cryptoconf, add_public_keys=False, extra_entries=[extra_entry])
    assert with_extra["trustee_public_keys"] == [extra_entry]


@requires_pycryptodome
def test_helper_raw_profile_converter_with_ml_kem():
    cryptoconf = load_from_document_file(CRYPTOCONFS_DIR / "2026_cbor_key_ciphertexts/04_post_quantum.cryptoconf.cbor")
    device_profile = helpers.build_raw_device_profile(cryptoconf)
    ml_kem_entry = device_profile["trustee_public_keys"][helpers.find_public_key_entry_index(device_profile, "ML_KEM_768")]
    public_key = ml_kem_entry["public_key"]
    assert len(public_key) == 1184
    assert all(helpers.get_ml_kem_coefficient(public_key, index) < helpers.ML_KEM_MODULUS for index in range(768))
