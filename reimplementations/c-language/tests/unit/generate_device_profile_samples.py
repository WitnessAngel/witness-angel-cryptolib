# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate wa_device_profile_samples.h, the device profiles of the profile loading unit tests (task 6.2 of the
OpenSpec change add-c-flightbox-encryptor), one or more per scenario of the flightbox-device-profile spec.

Valid profiles come from the export script (scripts/flightbox/export_device_profile.py) run over the signature-free
corpus cryptoconfs that have a root keychain uid, and from the raw converter of the test helpers
(tests/interop/device_profile_test_helpers.py). Invalid ones come from the helpers' mutators and splicer, and from
the invalid corpus cryptoconfs. Every sample has an expected status, an expected error location (or NULL when only
the status is checked), and for valid profiles the expected number of public key entries.

Run from the repository root, in the wacryptolib environment (pycryptodome backend, for ML-KEM keys):
    python reimplementations/c-language/tests/unit/generate_device_profile_samples.py
"""

import copy
import sys
import uuid
from pathlib import Path

UNIT_TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(UNIT_TESTS_DIR.parent / "interop"))

import device_profile_test_helpers as helpers  # noqa: E402
from wacryptolib.utilities import load_from_document_file  # noqa: E402

OUTPUT_PATH = UNIT_TESTS_DIR / "wa_device_profile_samples.h"

CRYPTOCONFS_DIR = helpers.COMPATIBILITY_ROOT / "cryptoconfs"
KEYSTORES_DIR = helpers.COMPATIBILITY_ROOT / "keystores"

# Signature-free corpus cryptoconfs with a root keychain uid, and their keystore pools (same list as task 1.4)
CORPUS_EXPORTS = [
    ("2026_current/01_single_layer.cryptoconf", "2026_current/classic_pool"),
    ("2026_current/05_shamir_authenticators.cryptoconf", "2026_current/classic_pool"),
    ("2026_cbor_pairs/01_single_layer.cryptoconf.cbor", "2026_cbor_pairs/cbor_pairs_pool"),
] + [
    ("2026_cbor_key_ciphertexts/%s.cryptoconf.cbor" % name, "2026_cbor_key_ciphertexts/cbor_key_ciphertexts_pool")
    for name in ("01_single_layer", "02_shared_secret", "03_nested_symmetric", "04_post_quantum", "05_mixable")
]

ROOT_UID = uuid.UUID("0d0d0d0d-0000-4000-8000-000000000001")
LAYER_UID = uuid.UUID("0d0d0d0d-0000-4000-8000-000000000002")
KEYSTORE_UID = uuid.UUID("0e0e0e0e-0000-4000-8000-000000000003")
OTHER_KEYSTORE_UID = uuid.UUID("0e0e0e0e-0000-4000-8000-000000000004")

LOCAL_TRUSTEE = {"trustee_type": "local_keyfactory"}
AUTHENTICATOR_TRUSTEE = {"trustee_type": "authenticator", "keystore_uid": KEYSTORE_UID, "keystore_owner": "Alice"}
OTHER_AUTHENTICATOR_TRUSTEE = {"trustee_type": "authenticator", "keystore_uid": OTHER_KEYSTORE_UID}
JSONRPC_TRUSTEE = {"trustee_type": "jsonrpc_api", "jsonrpc_url": "https://example.com/jsonrpc"}

PAYLOAD_0 = "cryptoconf.payload_cipher_layers[0]"
KEY_LAYER_0 = PAYLOAD_0 + ".key_cipher_layers[0]"
ENTRY_0 = "trustee_public_keys[0]"


def _payload_layer(key_cipher_layers, payload_cipher_algo="AES_CBC"):
    return dict(payload_cipher_algo=payload_cipher_algo, payload_ciphertext_signatures=[],
                key_cipher_layers=key_cipher_layers)


def _cryptoconf(*payload_cipher_layers, keychain_uid=ROOT_UID):
    cryptoconf = dict(payload_cipher_layers=list(payload_cipher_layers))
    if keychain_uid is not None:
        cryptoconf["keychain_uid"] = keychain_uid
    return cryptoconf


def _asymmetric_layer(key_cipher_algo, trustee, keychain_uid=None):
    layer = dict(key_cipher_algo=key_cipher_algo, key_cipher_trustee=copy.deepcopy(trustee))
    if keychain_uid is not None:
        layer["keychain_uid"] = keychain_uid
    return layer


def _shared_secret_layer(threshold, *shards_layers):
    return dict(key_cipher_algo=helpers.SHARED_SECRET_ALGO_MARKER, key_shared_secret_threshold=threshold,
                key_shared_secret_shards=[dict(key_cipher_layers=layers) for layers in shards_layers])


# Minimal valid profile of the spec: one AES_CBC payload layer, one RSA_OAEP layer for an authenticator trustee
MINIMAL_CRYPTOCONF = _cryptoconf(_payload_layer([_asymmetric_layer("RSA_OAEP", AUTHENTICATOR_TRUSTEE)]))
X25519_CRYPTOCONF = _cryptoconf(_payload_layer([_asymmetric_layer("ECIES_X25519", LOCAL_TRUSTEE)]))
ML_KEM_CRYPTOCONF = _cryptoconf(_payload_layer([_asymmetric_layer("ML_KEM_768", LOCAL_TRUSTEE)]))
# Every layer kind, several trustee kinds and a layer keychain uid
NESTED_CRYPTOCONF = _cryptoconf(
    _payload_layer([_asymmetric_layer("ECIES_X25519", LOCAL_TRUSTEE)], payload_cipher_algo="AES_EAX"),
    _payload_layer(
        [
            _asymmetric_layer("RSA_OAEP", AUTHENTICATOR_TRUSTEE),
            _shared_secret_layer(
                2,
                [_asymmetric_layer("ECIES_X25519", OTHER_AUTHENTICATOR_TRUSTEE)],
                [_asymmetric_layer("ML_KEM_768", JSONRPC_TRUSTEE)],
                [dict(key_cipher_algo="CHACHA20_POLY1305",
                      key_cipher_layers=[_asymmetric_layer("RSA_OAEP", LOCAL_TRUSTEE, keychain_uid=LAYER_UID)])],
            ),
        ],
        payload_cipher_algo="CHACHA20_POLY1305",
    ),
)
NESTED_ML_KEM_LAYER_PATH = (
    "cryptoconf.payload_cipher_layers[1].key_cipher_layers[1].key_shared_secret_shards[1].key_cipher_layers[0]"
)
NESTED_LAYER_UID_LAYER_PATH = (
    "cryptoconf.payload_cipher_layers[1].key_cipher_layers[1].key_shared_secret_shards[2].key_cipher_layers[0]"
    ".key_cipher_layers[0]"
)


# Real public keys of the corpus, instead of the helpers' synthetic keys generated at each run, so that the generated
# header only changes when the samples do
CORPUS_KEYS_POOL = KEYSTORES_DIR / "2026_cbor_key_ciphertexts" / "cbor_key_ciphertexts_pool"
CORPUS_KEYS_KEYCHAIN_UID = uuid.UUID("0c0c0c0c-0000-4000-8000-000000000001")


def _get_corpus_raw_public_key(key_algo):
    from wacryptolib.keystore import ReadonlyFilesystemKeystore

    keystore = ReadonlyFilesystemKeystore(CORPUS_KEYS_POOL / "local_keyfactory")
    public_key_pem = keystore.get_public_key(keychain_uid=CORPUS_KEYS_KEYCHAIN_UID, key_algo=key_algo)
    return helpers.import_export_script().convert_public_key_pem_to_raw(public_key_pem, key_algo=key_algo)


helpers.get_synthetic_raw_public_key = _get_corpus_raw_public_key


class SampleCollector:
    def __init__(self):
        self.samples = []
        self._names = set()

    def add(self, name, data, status="WA_STATUS_OK", location="", key_entry_count=0, alternative_status=None):
        assert name not in self._names, name
        self._names.add(name)
        self.samples.append(dict(name=name, data=bytes(data), status=status, location=location,
                                 key_entry_count=key_entry_count, alternative_status=alternative_status))

    def add_valid(self, name, device_profile):
        data = helpers.dump_device_profile(device_profile)
        assert helpers.encode_cbor_item(device_profile) == data  # Helpers encode like dump_to_cbor_bytes()
        self.add(name, data, key_entry_count=len(device_profile["trustee_public_keys"]))


def _add_valid_samples(collector):
    export_script = helpers.import_export_script()
    for cryptoconf_relpath, keystore_pool_relpath in CORPUS_EXPORTS:
        cryptoconf = load_from_document_file(CRYPTOCONFS_DIR / cryptoconf_relpath)
        device_profile = export_script.build_device_profile(cryptoconf, KEYSTORES_DIR / keystore_pool_relpath)
        collector.add_valid("corpus_" + cryptoconf_relpath.split("/")[0] + "_" + cryptoconf_relpath.split("/")[1][:2],
                            device_profile)

    collector.add_valid("minimal_rsa_authenticator", helpers.build_raw_device_profile(MINIMAL_CRYPTOCONF))
    collector.add_valid("nested_all_layer_kinds", helpers.build_raw_device_profile(NESTED_CRYPTOCONF))
    legacy_cryptoconf = copy.deepcopy(X25519_CRYPTOCONF)
    legacy_cryptoconf["payload_cipher_layers"][0]["payload_signatures"] = (
        legacy_cryptoconf["payload_cipher_layers"][0].pop("payload_ciphertext_signatures"))
    collector.add_valid("legacy_payload_signatures_alias", helpers.build_raw_device_profile(legacy_cryptoconf))
    empty_plaintext_signatures = copy.deepcopy(X25519_CRYPTOCONF)
    empty_plaintext_signatures["payload_plaintext_signatures"] = []
    collector.add_valid("empty_plaintext_signatures", helpers.build_raw_device_profile(empty_plaintext_signatures))

    # Key lookup ignores keystore owner
    device_profile = helpers.build_raw_device_profile(MINIMAL_CRYPTOCONF)
    device_profile["trustee_public_keys"][0]["trustee"]["keystore_owner"] = "Bob"
    collector.add_valid("keystore_owner_differs", device_profile)
    device_profile = helpers.build_raw_device_profile(MINIMAL_CRYPTOCONF)
    del device_profile["trustee_public_keys"][0]["trustee"]["keystore_owner"]
    collector.add_valid("keystore_owner_absent_from_entry", device_profile)

    # Unused entries: another algorithm, another keychain, another trustee
    x25519_key = helpers.get_synthetic_raw_public_key("ECIES_X25519")
    collector.add_valid("unused_entries", helpers.build_raw_device_profile(MINIMAL_CRYPTOCONF, extra_entries=[
        dict(trustee=AUTHENTICATOR_TRUSTEE, keychain_uid=ROOT_UID, key_algo="ECIES_X25519", public_key=x25519_key),
        dict(trustee=AUTHENTICATOR_TRUSTEE, keychain_uid=LAYER_UID, key_algo="RSA_OAEP",
             public_key=helpers.get_synthetic_raw_public_key("RSA_OAEP")),
        dict(trustee=JSONRPC_TRUSTEE, keychain_uid=ROOT_UID, key_algo="ECIES_X25519", public_key=x25519_key),
    ]))

    # Constraint bounds that pass: 4096-bit modulus (the default maximum), exponent 3, ML-KEM coefficient 3328
    collector.add_valid("rsa_4096_bits", helpers.build_raw_device_profile(
        MINIMAL_CRYPTOCONF, raw_public_keys={"RSA_OAEP": helpers.make_rsa_public_key(4096)}))
    collector.add_valid("rsa_2048_bits_exponent_3", helpers.build_raw_device_profile(
        MINIMAL_CRYPTOCONF, raw_public_keys={"RSA_OAEP": helpers.make_rsa_public_key(2048, public_exponent=3)}))
    ml_kem_key = helpers.get_synthetic_raw_public_key("ML_KEM_768")
    collector.add_valid("ml_kem_coefficient_3328", helpers.build_raw_device_profile(
        ML_KEM_CRYPTOCONF, raw_public_keys={"ML_KEM_768": helpers.set_ml_kem_coefficient(ml_kem_key, 767, 3328)}))

    # Nesting of 64 CBOR levels is accepted by the decoder (the profile then fails on the public key structure)


def _add_root_samples(collector):
    profile = helpers.build_raw_device_profile(X25519_CRYPTOCONF)
    for name, value in [("format_version_2", "flightbox_device_profile_2.0"), ("format_empty", ""),
                        ("format_bytes", b"flightbox_device_profile_1.0"), ("format_null", None)]:
        collector.add(name, helpers.mutate_value(profile, ("device_profile_format",), value),
                      "WA_STATUS_UNSUPPORTED_FORMAT", "device_profile_format")
    collector.add("format_missing", helpers.mutate_remove_key(profile, (), "device_profile_format"),
                  "WA_STATUS_UNSUPPORTED_FORMAT", "device_profile_format")
    collector.add("unknown_root_key", helpers.mutate_add_key(profile, ()), "WA_STATUS_INVALID_PROFILE",
                  "unexpected_key")
    collector.add("root_array", helpers.encode_cbor_item([profile]), "WA_STATUS_INVALID_PROFILE", "")
    # WA-CBOR documents are maps or arrays (wacryptolib rejects other top-level items too)
    collector.add("root_text", helpers.encode_cbor_item("flightbox_device_profile_1.0"), "WA_STATUS_DECODING_ERROR")
    collector.add("cryptoconf_missing", helpers.mutate_remove_key(profile, (), "cryptoconf"),
                  "WA_STATUS_INVALID_PROFILE", "cryptoconf")
    collector.add("cryptoconf_not_map", helpers.mutate_value(profile, ("cryptoconf",), []),
                  "WA_STATUS_INVALID_PROFILE", "cryptoconf")
    collector.add("trustee_public_keys_missing", helpers.mutate_remove_key(profile, (), "trustee_public_keys"),
                  "WA_STATUS_INVALID_PROFILE", "trustee_public_keys")
    collector.add("trustee_public_keys_map", helpers.mutate_value(profile, ("trustee_public_keys",), {}),
                  "WA_STATUS_INVALID_PROFILE", "trustee_public_keys")


def _add_sub_profile_samples(collector):
    profile = helpers.build_raw_device_profile(MINIMAL_CRYPTOCONF)
    layer_path = ("cryptoconf", "payload_cipher_layers", 0, "key_cipher_layers", 0)
    data = helpers.dump_device_profile(profile)

    # UUIDs as text
    collector.add("root_keychain_uid_as_text", helpers.mutate_uuid_to_text(profile, ("cryptoconf", "keychain_uid")),
                  "WA_STATUS_INVALID_PROFILE", "cryptoconf.keychain_uid")
    collector.add("entry_keychain_uid_as_text",
                  helpers.mutate_uuid_to_text(profile, ("trustee_public_keys", 0, "keychain_uid")),
                  "WA_STATUS_INVALID_PROFILE", ENTRY_0 + ".keychain_uid")
    collector.add("layer_keystore_uid_as_text",
                  helpers.mutate_uuid_to_text(profile, layer_path + ("key_cipher_trustee", "keystore_uid")),
                  "WA_STATUS_INVALID_PROFILE", KEY_LAYER_0 + ".key_cipher_trustee.keystore_uid")
    collector.add("entry_keystore_uid_as_text",
                  helpers.mutate_uuid_to_text(profile, ("trustee_public_keys", 0, "trustee", "keystore_uid")),
                  "WA_STATUS_INVALID_PROFILE", ENTRY_0 + ".trustee.keystore_uid")
    collector.add("uuid_as_bytes", helpers.mutate_value(profile, ("cryptoconf", "keychain_uid"), ROOT_UID.bytes),
                  "WA_STATUS_INVALID_PROFILE", "cryptoconf.keychain_uid")

    # Valid WA-CBOR outside the sub-profile
    collector.add("indefinite_length_root", helpers.mutate_indefinite_length(profile, ()), "WA_STATUS_UNSUPPORTED_TYPE")
    collector.add("indefinite_length_array",
                  helpers.mutate_indefinite_length(profile, ("cryptoconf", "payload_cipher_layers")),
                  "WA_STATUS_UNSUPPORTED_TYPE")
    collector.add("indefinite_length_text",
                  helpers.mutate_indefinite_length(profile, ("device_profile_format",),
                                                   chunks=["flightbox_device_", "profile_1.0"]),
                  "WA_STATUS_UNSUPPORTED_TYPE")
    collector.add("indefinite_length_bytes",
                  helpers.mutate_indefinite_length(profile, ("trustee_public_keys", 0, "public_key", "modulus")),
                  "WA_STATUS_UNSUPPORTED_TYPE")
    for width in (16, 32, 64):
        collector.add("float_%d" % width,
                      helpers.mutate_float(profile, layer_path[:3] + ("payload_cipher_algo",), 1.5, width),
                      "WA_STATUS_UNSUPPORTED_TYPE")
    collector.add("datetime_tag_0", helpers.mutate_tag(profile, ("device_profile_format",), 0,
                                                       "2026-01-01T00:00:00Z"), "WA_STATUS_UNSUPPORTED_TYPE")
    collector.add("bignum_tag_2", helpers.mutate_tag(profile, ("cryptoconf", "payload_cipher_layers"), 2, b"\x01"),
                  "WA_STATUS_UNSUPPORTED_TYPE")
    collector.add("bignum_tag_3", helpers.mutate_tag(profile, ("cryptoconf", "payload_cipher_layers"), 3, b"\x01"),
                  "WA_STATUS_UNSUPPORTED_TYPE")
    collector.add("decimal_tag_4", helpers.mutate_tag(profile, ("cryptoconf", "payload_cipher_layers"), 4, [-1, 15]),
                  "WA_STATUS_UNSUPPORTED_TYPE")
    collector.add("self_described_tag_55799", helpers.mutate_self_described(profile), "WA_STATUS_UNSUPPORTED_TYPE")
    collector.add("integer_above_int64",
                  helpers.mutate_value(profile, ("cryptoconf", "payload_cipher_layers"), 2**64 - 1),
                  "WA_STATUS_UNSUPPORTED_TYPE")
    collector.add("integer_below_int64",
                  helpers.mutate_value(profile, ("cryptoconf", "payload_cipher_layers"), -(2**64)),
                  "WA_STATUS_UNSUPPORTED_TYPE")

    # Not WA-CBOR at all
    collector.add("epoch_datetime_tag_1", helpers.mutate_tag(profile, ("cryptoconf", "payload_cipher_layers"), 1, 0),
                  "WA_STATUS_DECODING_ERROR")
    collector.add("uuid_tag_over_15_bytes",
                  helpers.mutate_value(profile, ("cryptoconf", "keychain_uid"), helpers.Tagged(37, b"\x01" * 15)),
                  "WA_STATUS_DECODING_ERROR")
    collector.add("duplicate_root_key", helpers.mutate_duplicate_key(profile, (), "cryptoconf"),
                  "WA_STATUS_DECODING_ERROR")
    collector.add("duplicate_layer_key", helpers.mutate_duplicate_key(profile, layer_path, "key_cipher_algo"),
                  "WA_STATUS_DECODING_ERROR")
    collector.add("keyword_map_binary",
                  helpers.mutate_keyword_map(profile, ("trustee_public_keys", 0, "public_key", "modulus")),
                  "WA_STATUS_DECODING_ERROR")
    collector.add("keyword_map_uuid",
                  helpers.mutate_keyword_map(profile, ("cryptoconf", "keychain_uid"), "$uuid", ROOT_UID.hex),
                  "WA_STATUS_DECODING_ERROR")
    collector.add("non_text_map_key",
                  helpers.mutate_value(profile, layer_path, helpers.RawMap([(1, "RSA_OAEP")])),
                  "WA_STATUS_DECODING_ERROR")
    collector.add("simple_value_undefined",
                  helpers.mutate_value(profile, ("cryptoconf", "payload_cipher_layers"), helpers.RawCbor(b"\xf7")),
                  "WA_STATUS_DECODING_ERROR")
    collector.add("invalid_utf8",
                  helpers.mutate_value(profile, ("device_profile_format",), helpers.RawCbor(b"\x62\xc3\x28")),
                  "WA_STATUS_DECODING_ERROR")
    collector.add("trailing_byte", data + b"\x00", "WA_STATUS_DECODING_ERROR")
    collector.add("truncated", data[:-1], "WA_STATUS_DECODING_ERROR")
    collector.add("empty", b"", "WA_STATUS_DECODING_ERROR")

    # Nesting: 64 levels decode (and then fail on the public key structure), 65 don't
    def nested_arrays(level_count):
        value = []
        for _ in range(level_count - 1):
            value = [value]
        return value

    public_key_path = ("trustee_public_keys", 0, "public_key")  # The public key value is at level 4
    collector.add("nesting_64_levels", helpers.mutate_value(profile, public_key_path, nested_arrays(61)),
                  "WA_STATUS_INVALID_PROFILE", ENTRY_0 + ".public_key")
    collector.add("nesting_65_levels", helpers.mutate_value(profile, public_key_path, nested_arrays(62)),
                  "WA_STATUS_NESTING_TOO_DEEP")

    # Invalid WA-CBOR cryptoconfs of the corpus, spliced as the cryptoconf value
    expected_statuses = {"malformed_datetime": ("WA_STATUS_UNSUPPORTED_TYPE", "WA_STATUS_DECODING_ERROR")}
    invalid_dir = CRYPTOCONFS_DIR / "2026_cbor_pairs" / "invalid"
    invalid_paths = sorted(invalid_dir.glob("*.cryptoconf.cbor"))
    assert len(invalid_paths) == 5, invalid_paths
    for invalid_path in invalid_paths:
        name = invalid_path.name.split(".")[0]
        status, alternative_status = expected_statuses.get(name, ("WA_STATUS_DECODING_ERROR", None))
        collector.add("spliced_invalid_corpus_" + name,
                      helpers.splice_cryptoconf_item(profile, invalid_path.read_bytes()), status,
                      alternative_status=alternative_status)


def _add_entry_samples(collector):
    profile = helpers.build_raw_device_profile(MINIMAL_CRYPTOCONF)
    x25519_profile = helpers.build_raw_device_profile(X25519_CRYPTOCONF)
    ml_kem_profile = helpers.build_raw_device_profile(ML_KEM_CRYPTOCONF)
    x25519_key = x25519_profile["trustee_public_keys"][0]["public_key"]
    ml_kem_key = ml_kem_profile["trustee_public_keys"][0]["public_key"]
    public_key_location = ENTRY_0 + ".public_key"

    # Wrong raw key sizes and types
    for name, key in [("x25519_key_33_bytes", x25519_key + b"\x00"), ("x25519_key_31_bytes", x25519_key[:31]),
                      ("x25519_key_as_text", x25519_key.hex()), ("x25519_key_as_rsa_map", {"modulus": x25519_key,
                                                                                         "public_exponent": b"\x03"})]:
        collector.add(name, helpers.mutate_public_key(x25519_profile, 0, key), "WA_STATUS_INVALID_PROFILE",
                      public_key_location)
    for name, key in [("ml_kem_key_1183_bytes", ml_kem_key[:-1]), ("ml_kem_key_1185_bytes", ml_kem_key + b"\x00"),
                      ("ml_kem_key_32_bytes", x25519_key)]:
        collector.add(name, helpers.mutate_public_key(ml_kem_profile, 0, key), "WA_STATUS_INVALID_PROFILE",
                      public_key_location)
    rsa_key = profile["trustee_public_keys"][0]["public_key"]
    collector.add("rsa_key_as_bytes", helpers.mutate_public_key(profile, 0, rsa_key["modulus"]),
                  "WA_STATUS_INVALID_PROFILE", public_key_location)
    collector.add("rsa_key_extra_field", helpers.mutate_add_key(profile, ("trustee_public_keys", 0, "public_key"),
                                                                "private_exponent", b"\x01"),
                  "WA_STATUS_INVALID_PROFILE", public_key_location + ".private_exponent")
    collector.add("rsa_key_missing_exponent",
                  helpers.mutate_remove_key(profile, ("trustee_public_keys", 0, "public_key"), "public_exponent"),
                  "WA_STATUS_INVALID_PROFILE", public_key_location + ".public_exponent")
    collector.add("rsa_key_modulus_as_text",
                  helpers.mutate_value(profile, ("trustee_public_keys", 0, "public_key", "modulus"), "AQAB"),
                  "WA_STATUS_INVALID_PROFILE", public_key_location + ".modulus")

    # Entry structure
    collector.add("entry_not_map", helpers.mutate_value(profile, ("trustee_public_keys", 0), []),
                  "WA_STATUS_INVALID_PROFILE", ENTRY_0)
    collector.add("entry_unknown_key", helpers.mutate_add_key(profile, ("trustee_public_keys", 0)),
                  "WA_STATUS_INVALID_PROFILE", ENTRY_0 + ".unexpected_key")
    for key in ("trustee", "keychain_uid", "key_algo", "public_key"):
        collector.add("entry_missing_" + key, helpers.mutate_remove_key(profile, ("trustee_public_keys", 0), key),
                      "WA_STATUS_INVALID_PROFILE", ENTRY_0 + "." + key)
    for name, key_algo in [("entry_key_algo_signature", "RSA_PSS"), ("entry_key_algo_symmetric", "AES_CBC"),
                           ("entry_key_algo_shared_secret", "[SHARED_SECRET]"), ("entry_key_algo_lowercase", "rsa_oaep")]:
        collector.add(name, helpers.mutate_value(profile, ("trustee_public_keys", 0, "key_algo"), key_algo),
                      "WA_STATUS_INVALID_PROFILE", ENTRY_0 + ".key_algo")
    collector.add("entry_trustee_unknown_type",
                  helpers.mutate_value(profile, ("trustee_public_keys", 0, "trustee", "trustee_type"), "server"),
                  "WA_STATUS_INVALID_PROFILE", ENTRY_0 + ".trustee.trustee_type")
    collector.add("entry_trustee_unknown_key",
                  helpers.mutate_add_key(profile, ("trustee_public_keys", 0, "trustee")),
                  "WA_STATUS_INVALID_PROFILE", ENTRY_0 + ".trustee.unexpected_key")
    collector.add("second_entry_invalid", helpers.encode_cbor_item(helpers.build_raw_device_profile(
        MINIMAL_CRYPTOCONF, extra_entries=[dict(trustee=LOCAL_TRUSTEE, keychain_uid=ROOT_UID, key_algo="RSA_OAEP")])),
        "WA_STATUS_INVALID_PROFILE", "trustee_public_keys[1].public_key")

    # Duplicate entries, keystore_owner not counting
    duplicate = copy.deepcopy(profile["trustee_public_keys"][0])
    duplicate["trustee"]["keystore_owner"] = "Bob"
    collector.add("duplicate_entry_other_owner", helpers.encode_cbor_item(
        helpers.build_raw_device_profile(MINIMAL_CRYPTOCONF, extra_entries=[duplicate])),
        "WA_STATUS_INVALID_PROFILE", "trustee_public_keys[1]")
    local_entry = dict(trustee=LOCAL_TRUSTEE, keychain_uid=ROOT_UID, key_algo="ECIES_X25519", public_key=x25519_key)
    collector.add("duplicate_local_keyfactory_entry", helpers.encode_cbor_item(
        helpers.build_raw_device_profile(X25519_CRYPTOCONF, extra_entries=[local_entry])),
        "WA_STATUS_INVALID_PROFILE", "trustee_public_keys[1]")


def _add_constraint_samples(collector):
    profile = helpers.build_raw_device_profile(MINIMAL_CRYPTOCONF)
    x25519_profile = helpers.build_raw_device_profile(X25519_CRYPTOCONF)
    ml_kem_profile = helpers.build_raw_device_profile(ML_KEM_CRYPTOCONF)
    x25519_key = x25519_profile["trustee_public_keys"][0]["public_key"]
    ml_kem_key = ml_kem_profile["trustee_public_keys"][0]["public_key"]
    rsa_key = helpers.make_rsa_public_key(2048)

    rsa_keys = [
        ("rsa_1024_bits", helpers.make_rsa_public_key(1024)),
        ("rsa_2040_bits", helpers.make_rsa_public_key(2040)),
        ("rsa_4104_bits", helpers.make_rsa_public_key(4104)),
        ("rsa_even_modulus", helpers.make_rsa_public_key(2048, even_modulus=True)),
        ("rsa_exponent_1", helpers.make_rsa_public_key(2048, public_exponent=1)),
        ("rsa_exponent_even", helpers.make_rsa_public_key(2048, public_exponent=65536)),
        ("rsa_exponent_equal_to_modulus", dict(modulus=rsa_key["modulus"], public_exponent=rsa_key["modulus"])),
        ("rsa_modulus_leading_zero", dict(modulus=b"\x00" + rsa_key["modulus"], public_exponent=b"\x01\x00\x01")),
        ("rsa_exponent_leading_zero", dict(modulus=rsa_key["modulus"], public_exponent=b"\x00\x01\x00\x01")),
    ]
    for name, key in rsa_keys:
        collector.add(name, helpers.mutate_public_key(profile, 0, key), "WA_STATUS_KEY_CONSTRAINT_VIOLATION", ENTRY_0)
    for index, key in enumerate(helpers.get_low_order_x25519_public_keys()):
        collector.add("x25519_low_order_%d" % index, helpers.mutate_public_key(x25519_profile, 0, key),
                      "WA_STATUS_KEY_CONSTRAINT_VIOLATION", ENTRY_0)
    for index, key in enumerate(helpers.get_non_canonical_x25519_public_keys(x25519_key)):
        collector.add("x25519_non_canonical_%d" % index, helpers.mutate_public_key(x25519_profile, 0, key),
                      "WA_STATUS_KEY_CONSTRAINT_VIOLATION", ENTRY_0)
    for coefficient_index, coefficient in [(0, 3329), (767, 4095), (384, 3329)]:
        collector.add("ml_kem_coefficient_%d_at_%d" % (coefficient, coefficient_index),
                      helpers.mutate_public_key(ml_kem_profile, 0, helpers.set_ml_kem_coefficient(
                          ml_kem_key, coefficient_index, coefficient)),
                      "WA_STATUS_KEY_CONSTRAINT_VIOLATION", ENTRY_0)
    # An unused entry is checked too, and named
    collector.add("unused_entry_low_order", helpers.encode_cbor_item(helpers.build_raw_device_profile(
        MINIMAL_CRYPTOCONF, extra_entries=[dict(trustee=LOCAL_TRUSTEE, keychain_uid=ROOT_UID, key_algo="ECIES_X25519",
                                                public_key=bytes(32))])),
        "WA_STATUS_KEY_CONSTRAINT_VIOLATION", "trustee_public_keys[1]")


def _add_cryptoconf_samples(collector):
    # Missing public keys
    collector.add("missing_public_key", helpers.encode_cbor_item(
        helpers.build_raw_device_profile(X25519_CRYPTOCONF, add_public_keys=False)),
        "WA_STATUS_MISSING_PUBLIC_KEY", KEY_LAYER_0)
    nested_profile = helpers.build_raw_device_profile(NESTED_CRYPTOCONF)
    for name, layer_path, removed_algo, removed_keychain_uid in [
        ("missing_public_key_in_shard", NESTED_ML_KEM_LAYER_PATH, "ML_KEM_768", ROOT_UID),
        ("missing_public_key_of_layer_keychain", NESTED_LAYER_UID_LAYER_PATH, "RSA_OAEP", LAYER_UID),
    ]:
        device_profile = copy.deepcopy(nested_profile)
        device_profile["trustee_public_keys"] = [
            entry for entry in device_profile["trustee_public_keys"]
            if not (entry["key_algo"] == removed_algo and entry["keychain_uid"] == removed_keychain_uid)]
        assert len(device_profile["trustee_public_keys"]) == len(nested_profile["trustee_public_keys"]) - 1
        collector.add(name, helpers.encode_cbor_item(device_profile), "WA_STATUS_MISSING_PUBLIC_KEY", layer_path)
    x25519_key = helpers.get_synthetic_raw_public_key("ECIES_X25519")
    for name, entry in [
        ("missing_key_other_keychain", dict(trustee=LOCAL_TRUSTEE, keychain_uid=LAYER_UID, key_algo="ECIES_X25519",
                                            public_key=x25519_key)),
        ("missing_key_other_algo", dict(trustee=LOCAL_TRUSTEE, keychain_uid=ROOT_UID, key_algo="ML_KEM_768",
                                        public_key=helpers.get_synthetic_raw_public_key("ML_KEM_768"))),
        ("missing_key_other_trustee", dict(trustee=OTHER_AUTHENTICATOR_TRUSTEE, keychain_uid=ROOT_UID,
                                           key_algo="ECIES_X25519", public_key=x25519_key)),
    ]:
        collector.add(name, helpers.encode_cbor_item(helpers.build_raw_device_profile(
            X25519_CRYPTOCONF, add_public_keys=False, extra_entries=[entry])),
            "WA_STATUS_MISSING_PUBLIC_KEY", KEY_LAYER_0)
    other_keystore_cryptoconf = copy.deepcopy(MINIMAL_CRYPTOCONF)
    profile = helpers.build_raw_device_profile(MINIMAL_CRYPTOCONF)
    other_keystore_cryptoconf["payload_cipher_layers"][0]["key_cipher_layers"][0]["key_cipher_trustee"][
        "keystore_uid"] = OTHER_KEYSTORE_UID
    collector.add("missing_key_other_keystore_uid", helpers.encode_cbor_item(dict(
        profile, cryptoconf=other_keystore_cryptoconf)), "WA_STATUS_MISSING_PUBLIC_KEY", KEY_LAYER_0)

    # Missing root keychain uid, even if every layer has its own
    cryptoconf = _cryptoconf(_payload_layer([_asymmetric_layer("ECIES_X25519", LOCAL_TRUSTEE, LAYER_UID)]),
                             keychain_uid=None)
    collector.add("missing_root_keychain_uid", helpers.encode_cbor_item(
        helpers.build_raw_device_profile(cryptoconf, add_root_keychain_uid=False)),
        "WA_STATUS_INVALID_PROFILE", "cryptoconf.keychain_uid")

    # Thresholds
    for name, threshold in [("threshold_zero", 0), ("threshold_above_shard_count", 3), ("threshold_negative", -1)]:
        cryptoconf = _cryptoconf(_payload_layer([_shared_secret_layer(
            threshold, [_asymmetric_layer("ECIES_X25519", LOCAL_TRUSTEE)],
            [_asymmetric_layer("ECIES_X25519", OTHER_AUTHENTICATOR_TRUSTEE)])]))
        collector.add(name, helpers.encode_cbor_item(helpers.build_raw_device_profile(cryptoconf)),
                      "WA_STATUS_INVALID_PROFILE", KEY_LAYER_0 + ".key_shared_secret_threshold")

    # Signatures
    both_keys = copy.deepcopy(X25519_CRYPTOCONF)
    both_keys["payload_cipher_layers"][0]["payload_signatures"] = []
    collector.add("both_signature_list_keys", helpers.encode_cbor_item(helpers.build_raw_device_profile(both_keys)),
                  "WA_STATUS_INVALID_PROFILE", PAYLOAD_0)
    signature_conf = dict(payload_digest_algo="SHA256", payload_signature_algo="ECC_DSS",
                          payload_signature_trustee=LOCAL_TRUSTEE)
    signed = copy.deepcopy(X25519_CRYPTOCONF)
    signed["payload_cipher_layers"][0]["payload_ciphertext_signatures"] = [signature_conf]
    collector.add("ciphertext_signature", helpers.encode_cbor_item(helpers.build_raw_device_profile(signed)),
                  "WA_STATUS_UNSUPPORTED_SIGNATURE", PAYLOAD_0 + ".payload_ciphertext_signatures")
    signed = copy.deepcopy(X25519_CRYPTOCONF)
    signed["payload_plaintext_signatures"] = [signature_conf]
    collector.add("plaintext_signature", helpers.encode_cbor_item(helpers.build_raw_device_profile(signed)),
                  "WA_STATUS_UNSUPPORTED_SIGNATURE", "cryptoconf.payload_plaintext_signatures")

    # Output fields and unknown keys
    for name, key, value in [("layer_key_ciphertext", "key_ciphertext", b"\x00"),
                             ("layer_key_ciphertext_format", "key_ciphertext_format", "cbor")]:
        cryptoconf = copy.deepcopy(X25519_CRYPTOCONF)
        cryptoconf["payload_cipher_layers"][0]["key_cipher_layers"][0][key] = value
        collector.add(name, helpers.encode_cbor_item(helpers.build_raw_device_profile(cryptoconf)),
                      "WA_STATUS_INVALID_PROFILE", KEY_LAYER_0 + "." + key)
    cryptoconf = copy.deepcopy(X25519_CRYPTOCONF)
    cryptoconf["payload_cipher_layers"][0]["payload_macs"] = None
    collector.add("payload_layer_payload_macs", helpers.encode_cbor_item(helpers.build_raw_device_profile(cryptoconf)),
                  "WA_STATUS_INVALID_PROFILE", PAYLOAD_0 + ".payload_macs")

    # Key cipher nesting deeper than WA_MAX_KEY_CIPHER_NESTING_DEPTH (8)
    key_cipher_layers = [_asymmetric_layer("ECIES_X25519", LOCAL_TRUSTEE)]
    for _ in range(8):
        key_cipher_layers = [dict(key_cipher_algo="AES_CBC", key_cipher_layers=key_cipher_layers)]
    collector.add("key_cipher_nesting_9_levels", helpers.encode_cbor_item(
        helpers.build_raw_device_profile(_cryptoconf(_payload_layer(key_cipher_layers)))),
        "WA_STATUS_NESTING_TOO_DEEP", KEY_LAYER_0 + ".key_cipher_layers[0]" * 7 + ".key_cipher_layers")

    # Invalid Extended JSON cryptoconfs of the corpus, through the raw converter (status only)
    invalid_paths = sorted((CRYPTOCONFS_DIR / "2026_current" / "invalid").glob("*.cryptoconf"))
    assert invalid_paths
    for invalid_path in invalid_paths:
        cryptoconf = load_from_document_file(invalid_path)
        collector.add("invalid_corpus_" + invalid_path.name.split(".")[0], helpers.encode_cbor_item(
            helpers.build_raw_device_profile(cryptoconf)), "WA_STATUS_INVALID_PROFILE", None)


def _c_string(text):
    assert '"' not in text and "\\" not in text
    return '"%s"' % text


def collect_device_profile_samples() -> list:
    """Every sample, as a dict with name, data (CBOR bytes), status, alternative_status, location (None: not
    checked) and key_entry_count; also used by the interoperability tests of the C CLI."""
    collector = SampleCollector()
    _add_valid_samples(collector)
    _add_root_samples(collector)
    _add_sub_profile_samples(collector)
    _add_entry_samples(collector)
    _add_constraint_samples(collector)
    _add_cryptoconf_samples(collector)
    return collector.samples


def main():
    samples = collect_device_profile_samples()

    lines = [
        "/* This file is part of Witness Angel Cryptolib",
        " * SPDX-FileCopyrightText: Copyright Prolifik SARL",
        " * SPDX-License-Identifier: GPL-2.0-or-later",
        " */",
        "",
        "/* GENERATED by generate_device_profile_samples.py (export script and test helpers over the compatibility",
        " * corpus): do not edit. */",
        "",
        "#ifndef WA_DEVICE_PROFILE_SAMPLES_H",
        "#define WA_DEVICE_PROFILE_SAMPLES_H",
        "",
        "#include <stddef.h>",
        "",
        '#include "wa_flightbox/wa_status_codes.h"',
        "",
        "/* Hex of the CBOR bytes, in lines (C99 compilers need not support string literals beyond 4095 characters),",
        " * ended by NULL */",
        "typedef struct wa_device_profile_sample {",
        "    const char *name;",
        "    const char *const *cbor_hex_lines;",
        "    wa_status_t expected_status;",
        "    wa_status_t alternative_status; /* Also accepted (spec: either status), or WA_STATUS_OK */",
        "    const char *expected_location;  /* NULL: not checked */",
        "    size_t expected_key_entry_count;",
        "} wa_device_profile_sample_t;",
        "",
    ]
    for sample_index, sample in enumerate(samples):
        hex_data = sample["data"].hex()
        hex_lines = [hex_data[i : i + 112] for i in range(0, len(hex_data), 112)]
        lines.append("static const char *const wa_device_profile_sample_%d_hex[] = {" % sample_index)
        lines += ["    %s," % _c_string(hex_line) for hex_line in hex_lines]
        lines += ["    NULL};", ""]
    lines.append("static const wa_device_profile_sample_t wa_device_profile_samples[] = {")
    for sample_index, sample in enumerate(samples):
        location = "NULL" if sample["location"] is None else _c_string(sample["location"])
        lines.append("    {%s, wa_device_profile_sample_%d_hex, %s, %s, %s, %d}," % (
            _c_string(sample["name"]), sample_index, sample["status"], sample["alternative_status"] or "WA_STATUS_OK",
            location, sample["key_entry_count"]))
    lines += ["};", "", "#endif /* WA_DEVICE_PROFILE_SAMPLES_H */", ""]
    OUTPUT_PATH.write_text("\n".join(lines), encoding="ascii", newline="\n")
    print("%d samples written to %s" % (len(samples), OUTPUT_PATH))


if __name__ == "__main__":
    main()
