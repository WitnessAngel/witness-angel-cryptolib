# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Cryptainers of the C encryptor, read and decrypted by wacryptolib (task 9.5).

Cryptainers are made by the driver's "encrypt-cryptainer" subcommand (the library behind the CLI, with a seeded
random source and a fixed clock), from device profiles exported from:
- every valid corpus cryptoconf having a root keychain uid, all generations and both serializations of the WA-CBOR
  pairs, signed ones with their signatures stripped (test_corpus_cryptoconfs_are_all_used checks the split);
- synthetic cryptoconfs over the local keyfactory keys of the post-quantum corpus pool, for what the corpus lacks.

Each cryptainer must load from the filesystem, pass strict validation (Python and JSON-Schema modes), equal its
re-encoding by wacryptolib's writer of its format, carry the key ciphertext formats of its format, have the tree shape
of a cryptainer made by wacryptolib from the same cryptoconf, and be decrypted by wacryptolib with no report error,
the key structs inside its asymmetric key ciphertexts carrying the same metadata as the cryptainer.
"""

import uuid
import zlib
from pathlib import Path
from unittest import mock

import pytest

from c_flightbox_interop_support import (
    COMPATIBILITY_ROOT,
    check_key_ciphertext_formats,
    copy_keystore_pool,
    copy_keystore_pool_dir,
    corpus,
    export_device_profile_bytes,
    get_tree_shape,
    get_valid_corpus_cryptoconfs,
    has_signatures,
    load_corpus_cryptoconf,
    profile_helpers,
)

POST_QUANTUM_POOL_DIR = COMPATIBILITY_ROOT / "keystores" / "2026_post_quantum" / "pq_pool"
SYNTHETIC_KEYCHAIN_UIDS = [uuid.UUID("0c0c0c0c-0000-4000-8000-00000000000%d" % index) for index in (1, 2, 3)]
SHARED_SECRET_ALGO_MARKER = "[SHARED_SECRET]"
CRYPTAINER_SUFFIXES = {"json": ".crypt.json", "cbor": ".crypt.cbor"}
OTHER_DOCUMENT_FORMATS = {"json": "cbor", "cbor": "json"}

# PROFILES #


def _get_corpus_cryptoconfs():
    """Every valid corpus cryptoconf having a root keychain uid (those without one are rejection cases of
    test_c_flightbox_rejections.py), as {profile name: (path relative to compatibility/cryptoconfs, whether its
    signatures must be stripped)}. Signed ones get the "_unsigned" suffix; unsigned ones are used as they are, legacy
    "payload_signatures" key included."""
    cryptoconfs = {}
    for name, relative_path in get_valid_corpus_cryptoconfs():
        cryptoconf = load_corpus_cryptoconf(relative_path)[0]
        if cryptoconf.get("keychain_uid"):
            must_strip_signatures = has_signatures(cryptoconf)
            cryptoconfs[name + ("_unsigned" if must_strip_signatures else "")] = (relative_path, must_strip_signatures)
    return cryptoconfs


CORPUS_CRYPTOCONFS = _get_corpus_cryptoconfs()


def _local_layer(key_algo, keychain_uid=None):
    layer = dict(key_cipher_algo=key_algo, key_cipher_trustee=dict(trustee_type="local_keyfactory"))
    if keychain_uid is not None:
        layer["keychain_uid"] = keychain_uid
    return layer


def _shared_secret_layer(threshold, shards_key_cipher_layers):
    return dict(
        key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
        key_shared_secret_threshold=threshold,
        key_shared_secret_shards=[dict(key_cipher_layers=layers) for layers in shards_key_cipher_layers],
    )


def _payload_layer(payload_cipher_algo, key_cipher_layers):
    return dict(
        payload_cipher_algo=payload_cipher_algo, key_cipher_layers=key_cipher_layers, payload_ciphertext_signatures=[]
    )


def _build_synthetic_cryptoconfs():
    keychain_1, keychain_2, keychain_3 = SYNTHETIC_KEYCHAIN_UIDS
    return {
        # Every payload algorithm, in several payload layers, each key wrapped by every asymmetric algorithm
        "synthetic_all_payload_algos": dict(
            keychain_uid=keychain_1,
            payload_cipher_layers=[
                _payload_layer("AES_CBC", [_local_layer("ML_KEM_768")]),
                _payload_layer("AES_EAX", [_local_layer("ECIES_X25519", keychain_2), _local_layer("RSA_OAEP")]),
                _payload_layer("CHACHA20_POLY1305", [_local_layer("RSA_OAEP", keychain_3)]),
            ],
        ),
        # Symmetric key cipher layers nested in each other, with every symmetric algorithm
        "synthetic_nested_symmetric_layers": dict(
            keychain_uid=keychain_2,
            payload_cipher_layers=[
                _payload_layer(
                    "CHACHA20_POLY1305",
                    [
                        dict(
                            key_cipher_algo="AES_CBC",
                            key_cipher_layers=[
                                dict(
                                    key_cipher_algo="CHACHA20_POLY1305",
                                    key_cipher_layers=[
                                        dict(key_cipher_algo="AES_EAX", key_cipher_layers=[_local_layer("ML_KEM_768")]),
                                        _local_layer("ECIES_X25519", keychain_1),
                                    ],
                                )
                            ],
                        )
                    ],
                )
            ],
        ),
        # A 1-of-2 shared secret, one shard of which is a 3-of-3 shared secret (thresholds 1 and n)
        "synthetic_nested_shared_secrets": dict(
            keychain_uid=keychain_3,
            payload_cipher_layers=[
                _payload_layer(
                    "AES_EAX",
                    [
                        _shared_secret_layer(
                            1,
                            [
                                [_local_layer("RSA_OAEP", keychain_1)],
                                [
                                    _shared_secret_layer(
                                        3,
                                        [
                                            [_local_layer("ECIES_X25519")],
                                            [_local_layer("ML_KEM_768", keychain_2)],
                                            [dict(key_cipher_algo="AES_CBC", key_cipher_layers=[_local_layer("RSA_OAEP")])],
                                        ],
                                    )
                                ],
                            ],
                        )
                    ],
                )
            ],
        ),
    }


SYNTHETIC_CRYPTOCONFS = _build_synthetic_cryptoconfs()
PROFILE_NAMES = sorted(CORPUS_CRYPTOCONFS) + sorted(SYNTHETIC_CRYPTOCONFS)

_profile_cache = {}


def get_profile(profile_name):
    """(cryptoconf, keystore pool dir, passphrase mapper sidecar data, device profile bytes) of a profile name."""
    if profile_name not in _profile_cache:
        if profile_name in CORPUS_CRYPTOCONFS:
            relative_path, must_strip_signatures = CORPUS_CRYPTOCONFS[profile_name]
            cryptoconf, sidecar, pool_dir = load_corpus_cryptoconf(relative_path)
            if must_strip_signatures:
                cryptoconf = profile_helpers.strip_signatures(cryptoconf)
            passphrase_mapper = sidecar.get("passphrase_mapper", {})
        else:
            cryptoconf, pool_dir, passphrase_mapper = SYNTHETIC_CRYPTOCONFS[profile_name], POST_QUANTUM_POOL_DIR, {}
        _profile_cache[profile_name] = (
            cryptoconf,
            pool_dir,
            passphrase_mapper,
            export_device_profile_bytes(cryptoconf, pool_dir),
        )
    return _profile_cache[profile_name]


def test_corpus_cryptoconfs_are_all_used():
    """Every valid corpus cryptoconf, of every generation, is a profile here, or a rejection case of
    test_c_flightbox_rejections.py when it has no root keychain uid (only the 2022 generations, older than the root
    keychain_uid field)."""
    valid_paths = {relative_path for _name, relative_path in get_valid_corpus_cryptoconfs()}
    profile_paths = {relative_path for relative_path, _must_strip_signatures in CORPUS_CRYPTOCONFS.values()}
    rootless_paths = {path for path in valid_paths if not load_corpus_cryptoconf(path)[0].get("keychain_uid")}
    assert len(valid_paths) >= 41
    assert profile_paths == valid_paths - rootless_paths
    generations = {path.name for path in (COMPATIBILITY_ROOT / "cryptoconfs").iterdir() if path.is_dir()}
    assert {path.split("/")[0] for path in valid_paths} == generations
    assert {path.split("/")[0] for path in rootless_paths} == {"2022_v0.9_genuine", "2022_v0.10_genuine"}


def test_profiles_cover_the_specified_algorithms():
    """The profiles cover every algorithm of the C encryptor, multiple payload layers, nested symmetric layers, and
    nested shared secrets with thresholds 1 and n."""
    payload_cipher_algos = set()
    key_cipher_algos = set()
    shared_secret_thresholds = set()  # (threshold, shard count, nested in a shard)

    def _walk(key_cipher_layers, is_in_shard):
        for layer in key_cipher_layers:
            key_cipher_algos.add(layer["key_cipher_algo"])
            if layer["key_cipher_algo"] == SHARED_SECRET_ALGO_MARKER:
                shards = layer["key_shared_secret_shards"]
                shared_secret_thresholds.add((layer["key_shared_secret_threshold"], len(shards), is_in_shard))
                for shard in shards:
                    _walk(shard["key_cipher_layers"], True)
            elif "key_cipher_layers" in layer:
                _walk(layer["key_cipher_layers"], is_in_shard)

    has_multiple_payload_layers = False
    for profile_name in PROFILE_NAMES:
        cryptoconf = get_profile(profile_name)[0]
        has_multiple_payload_layers |= len(cryptoconf["payload_cipher_layers"]) > 1
        for payload_cipher_layer in cryptoconf["payload_cipher_layers"]:
            payload_cipher_algos.add(payload_cipher_layer["payload_cipher_algo"])
            _walk(payload_cipher_layer["key_cipher_layers"], False)

    symmetric_algos = {"AES_CBC", "AES_EAX", "CHACHA20_POLY1305"}
    assert payload_cipher_algos == symmetric_algos
    assert key_cipher_algos == symmetric_algos | {"RSA_OAEP", "ECIES_X25519", "ML_KEM_768", SHARED_SECRET_ALGO_MARKER}
    assert has_multiple_payload_layers
    assert any(threshold == 1 for threshold, _count, _nested in shared_secret_thresholds)
    assert any(threshold == count for threshold, count, _nested in shared_secret_thresholds)
    assert any(nested for _threshold, _count, nested in shared_secret_thresholds)


# METADATA AND PAYLOADS #

METADATA_SAMPLES = {
    "null": None,
    "ascii": {
        "device_id": "fb-07",
        "sequence": 42,
        "negative": -(2**40),
        "flags": [True, False, None],
        "recording_uid": uuid.UUID("12345678-1234-4234-8234-123456789abc"),
        "raw": b"\x00\x01\xfe\xff",
        "empty": {},
    },
    "non_ascii": {
        "label": "Café — 東京 \U0001f681",
        "été": {"tags": ["ü", "π", ""], "count": 0},
        "quote\"and\\backslash\n": "\x7f\x01",
    },
}
METADATA_KINDS = tuple(METADATA_SAMPLES)

PAYLOAD_SIZES = (0, 1, 15, 16, 17, 4099, 65539, 1048579)
# Odd chunk sizes, never tiny for big payloads (0: a single chunk)
CHUNK_SIZES = {0: 0, 1: 1, 15: 4, 16: 3, 17: 5, 4099: 97, 65539: 4093, 1048579: 65537}


def _generate_payload(size):
    return corpus.generate_sha256_counter_bytes(b"c-flightbox-payload-%d" % size, size)


def _get_seed(*items):
    return zlib.crc32(repr(items).encode("utf8")) + 1


# ENCRYPTION AND CHECKS #


def encrypt_with_c_driver(c_build, profile_name, document_format, payload, metadata_kind, is_offloaded, chunk_size, work_dir):
    """Encrypt a payload with the C driver, and return the cryptainer path (named as wacryptolib expects)."""
    from wacryptolib.utilities import dump_to_cbor_bytes

    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    profile_path = work_dir / "profile.cbor"
    profile_path.write_bytes(get_profile(profile_name)[3])
    input_path = work_dir / "payload.bin"
    input_path.write_bytes(payload)
    cryptainer_path = work_dir / ("sample" + CRYPTAINER_SUFFIXES[document_format])
    arguments = [
        "encrypt-cryptainer",
        "--profile", profile_path,
        "--input", input_path,
        "--output-cryptainer", cryptainer_path,
        "--format", document_format,
        "--chunk-size", chunk_size,
        "--seed", _get_seed(profile_name, document_format, len(payload), metadata_kind, is_offloaded),
    ]  # fmt: skip
    if is_offloaded:
        arguments += ["--output-payload", cryptainer_path.with_name(cryptainer_path.name + ".payload")]
    metadata = METADATA_SAMPLES[metadata_kind]
    if metadata is not None:
        metadata_path = work_dir / "metadata.cbor"
        metadata_path.write_bytes(dump_to_cbor_bytes(metadata))
        arguments += ["--metadata", metadata_path]

    output = c_build.run_driver(*arguments)
    assert output["status"] == "WA_STATUS_OK", output
    # Allocator diagnostics of the C driver (the Rust one has no allocator hook to measure them with)
    if c_build.is_c_implementation:
        assert output["leaked_block_count"] == 0, output
        assert output["unwiped_secret_release_count"] == 0, output
    return cryptainer_path


_reference_shapes = {}


def get_reference_tree_shape(profile_name, document_format, metadata_kind, work_dir):
    """Tree shape of the cryptainer wacryptolib makes from the same cryptoconf, with key_ciphertext_format set to
    the document format (its payload ciphertext is inline, like that of a C cryptainer loaded from the filesystem)."""
    from wacryptolib.cryptainer import encrypt_payload_into_cryptainer

    cache_key = (profile_name, document_format, metadata_kind)
    if cache_key not in _reference_shapes:
        cryptoconf, pool_dir, _passphrase_mapper, _profile_bytes = get_profile(profile_name)
        cryptainer = encrypt_payload_into_cryptainer(
            b"reference",
            cryptoconf=cryptoconf,
            cryptainer_metadata=METADATA_SAMPLES[metadata_kind],
            keystore_pool=copy_keystore_pool(pool_dir, work_dir),
            key_ciphertext_format=document_format,
        )
        _reference_shapes[cache_key] = get_tree_shape(cryptainer)
    return _reference_shapes[cache_key]


def decrypt_with_wacryptolib(cryptainer, profile_name, work_dir, withheld_keystore_uids=(), key_structs=None):
    """Decrypt with a fresh copy of the profile's keystore pool and its sidecar passphrases, private keys of the
    withheld authenticator keystores being deleted; return (payload or None, set of report error types).

    If `key_structs` is a list, the key structs decrypted by asymmetric layers are appended to it (wacryptolib's
    decryptor doesn't use their metadata itself)."""
    from wacryptolib.cryptainer import _decryptor, decrypt_payload_from_cryptainer
    from wacryptolib.keystore import FilesystemKeystorePool

    _cryptoconf, pool_dir, passphrase_mapper, _profile_bytes = get_profile(profile_name)
    pool_copy_dir = copy_keystore_pool_dir(pool_dir, work_dir)
    for keystore_uid in withheld_keystore_uids:
        keystore_dir = pool_copy_dir / FilesystemKeystorePool.FOREIGN_KEYSTORES_DIRNAME / (
            FilesystemKeystorePool.FOREIGN_KEYSTORE_PREFIX + str(keystore_uid)
        )
        private_key_paths = list(keystore_dir.glob("*_private_key.pem"))
        assert private_key_paths, keystore_dir
        for private_key_path in private_key_paths:
            private_key_path.unlink()
    original_check_key_struct_sanity = _decryptor._check_key_struct_sanity

    def _check_and_capture_key_struct(key_struct):
        original_check_key_struct_sanity(key_struct)
        if key_structs is not None:
            key_structs.append(key_struct)

    with mock.patch.object(_decryptor, "_check_key_struct_sanity", _check_and_capture_key_struct):
        payload, operation_report = decrypt_payload_from_cryptainer(
            cryptainer,
            keystore_pool=FilesystemKeystorePool(pool_copy_dir),
            passphrase_mapper=corpus.parse_passphrase_mapper(passphrase_mapper),
        )
    return payload, {entry["entry_type"] for entry in operation_report.get_error_entries()}


def check_c_cryptainer(cryptainer_path, profile_name, document_format, payload, metadata_kind, is_offloaded, work_dir):
    """Every check of a C cryptainer; return the cryptainer loaded from the filesystem."""
    from wacryptolib.cryptainer import (
        OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER,
        check_cryptainer_sanity,
        extract_metadata_from_cryptainer,
        load_cryptainer_from_filesystem,
    )
    from wacryptolib.utilities import detect_document_format, dump_to_document_bytes, load_from_document_bytes

    payload_path = cryptainer_path.with_name(cryptainer_path.name + ".payload")
    assert payload_path.exists() == is_offloaded

    # The document, as written, equals its re-encoding by wacryptolib's default writer of its format
    cryptainer_bytes = cryptainer_path.read_bytes()
    assert detect_document_format(cryptainer_bytes) == document_format
    raw_cryptainer = load_from_document_bytes(cryptainer_bytes, filename=cryptainer_path.name)
    assert dump_to_document_bytes(raw_cryptainer, document_format) == cryptainer_bytes
    assert (raw_cryptainer["payload_ciphertext_struct"] == OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER) == is_offloaded

    # Strict validation, of the raw Extended JSON tree in JSON-Schema mode, and of the loaded cryptainer
    check_cryptainer_sanity(corpus.get_raw_extjson_tree(cryptainer_path, raw_cryptainer), jsonschema_mode=True)
    cryptainer = load_cryptainer_from_filesystem(cryptainer_path)
    check_cryptainer_sanity(cryptainer)

    assert extract_metadata_from_cryptainer(cryptainer) == METADATA_SAMPLES[metadata_kind]
    check_key_ciphertext_formats(cryptainer, document_format)
    assert get_tree_shape(cryptainer) == get_reference_tree_shape(profile_name, document_format, metadata_kind, work_dir)

    key_structs = []
    decrypted_payload, error_types = decrypt_with_wacryptolib(cryptainer, profile_name, work_dir, key_structs=key_structs)
    assert decrypted_payload == payload, error_types
    assert not error_types

    # The key structs inside asymmetric key ciphertexts carry the cryptainer metadata too, exactly
    assert key_structs
    for key_struct in key_structs:
        assert sorted(key_struct) == ["cryptainer_metadata", "key_bytes"]
        assert key_struct["cryptainer_metadata"] == METADATA_SAMPLES[metadata_kind]
    return cryptainer


def _get_case_dir(tmp_path, *items):
    return tmp_path / "-".join(str(item) for item in items)


# TESTS #


@pytest.mark.parametrize("profile_name", PROFILE_NAMES)
def test_profile_cryptainers(c_build, document_format, profile_name, tmp_path):
    """Each profile, inline in one chunk and offloaded in odd chunks, with two metadata samples."""
    profile_index = PROFILE_NAMES.index(profile_name)
    payload = _generate_payload(4099)
    for is_offloaded, chunk_size in ((False, 0), (True, 1000)):
        metadata_kind = METADATA_KINDS[(profile_index + is_offloaded) % len(METADATA_KINDS)]
        case_dir = _get_case_dir(tmp_path, is_offloaded, metadata_kind)
        cryptainer_path = encrypt_with_c_driver(
            c_build, profile_name, document_format, payload, metadata_kind, is_offloaded, chunk_size, case_dir
        )
        check_c_cryptainer(cryptainer_path, profile_name, document_format, payload, metadata_kind, is_offloaded, case_dir)


@pytest.mark.parametrize("is_offloaded", [False, True], ids=["inline", "offloaded"])
@pytest.mark.parametrize("payload_size", PAYLOAD_SIZES)
def test_payload_sizes(c_build, document_format, payload_size, is_offloaded, tmp_path):
    """Payload sizes around block boundaries, through every payload algorithm, in odd chunks."""
    profile_name = "synthetic_all_payload_algos"
    metadata_kind = METADATA_KINDS[(PAYLOAD_SIZES.index(payload_size) + is_offloaded) % len(METADATA_KINDS)]
    payload = _generate_payload(payload_size)
    cryptainer_path = encrypt_with_c_driver(
        c_build, profile_name, document_format, payload, metadata_kind, is_offloaded, CHUNK_SIZES[payload_size], tmp_path
    )
    check_c_cryptainer(cryptainer_path, profile_name, document_format, payload, metadata_kind, is_offloaded, tmp_path)


CONVERSION_PROFILE_NAMES = (
    "cbor_key_ciphertexts_05_mixable_cbor",
    "current_05_shamir_authenticators",
    "synthetic_nested_shared_secrets",
)


@pytest.mark.parametrize("is_offloaded", [False, True], ids=["inline", "offloaded"])
@pytest.mark.parametrize("profile_name", CONVERSION_PROFILE_NAMES)
def test_converted_cryptainers(c_build, document_format, profile_name, is_offloaded, tmp_path):
    """A sample of C cryptainers, converted to the other format with "convert-format", and decrypted again (their
    key ciphertexts keep their own format)."""
    from click.testing import CliRunner

    from wacryptolib.cli import wacryptolib_cli as cli
    from wacryptolib.cryptainer import check_cryptainer_sanity, load_cryptainer_from_filesystem
    from wacryptolib.utilities import detect_document_format

    payload = _generate_payload(65539)
    metadata_kind = "non_ascii"
    cryptainer_path = encrypt_with_c_driver(
        c_build, profile_name, document_format, payload, metadata_kind, is_offloaded, 8191, tmp_path / "source"
    )
    check_c_cryptainer(cryptainer_path, profile_name, document_format, payload, metadata_kind, is_offloaded, tmp_path)

    target_format = OTHER_DOCUMENT_FORMATS[document_format]
    target_path = tmp_path / "converted" / ("sample" + CRYPTAINER_SUFFIXES[target_format])
    target_path.parent.mkdir()
    result = CliRunner().invoke(cli, ["convert-format", str(cryptainer_path), "-o", str(target_path)])
    assert result.exit_code == 0, result.output
    assert detect_document_format(target_path.read_bytes()) == target_format
    assert target_path.with_name(target_path.name + ".payload").exists() == is_offloaded

    converted_cryptainer = load_cryptainer_from_filesystem(target_path)
    check_cryptainer_sanity(converted_cryptainer)
    check_key_ciphertext_formats(converted_cryptainer, document_format)
    decrypted_payload, error_types = decrypt_with_wacryptolib(converted_cryptainer, profile_name, tmp_path)
    assert decrypted_payload == payload, error_types
    assert not error_types


WITHHOLDING_PROFILE_NAME = "current_05_shamir_authenticators"  # 2-of-3 Shamir shared secret over authenticators


def _get_authenticator_keystore_uids(cryptoconf):
    return sorted(
        {
            layer["key_cipher_trustee"]["keystore_uid"]
            for _path, layer in profile_helpers.iter_asymmetric_key_cipher_layers_leniently(cryptoconf)
            if layer["key_cipher_trustee"]["trustee_type"] == "authenticator"
        }
    )


def test_shard_subsets(c_build, document_format, tmp_path):
    """Each trustee key of a 2-of-3 shared secret withheld in turn: decryption succeeds, with only the expected
    key decryption entries; with two keys withheld, it fails."""
    cryptoconf = get_profile(WITHHOLDING_PROFILE_NAME)[0]
    keystore_uids = _get_authenticator_keystore_uids(cryptoconf)
    assert len(keystore_uids) == 3
    assert cryptoconf["payload_cipher_layers"][0]["key_cipher_layers"][0]["key_shared_secret_threshold"] == 2

    payload = _generate_payload(4099)
    cryptainer_path = encrypt_with_c_driver(
        c_build, WITHHOLDING_PROFILE_NAME, document_format, payload, "ascii", True, 1000, tmp_path / "cryptainer"
    )
    cryptainer = check_c_cryptainer(
        cryptainer_path, WITHHOLDING_PROFILE_NAME, document_format, payload, "ascii", True, tmp_path
    )

    for withheld_keystore_uid in keystore_uids:
        decrypted_payload, error_types = decrypt_with_wacryptolib(
            cryptainer, WITHHOLDING_PROFILE_NAME, tmp_path, withheld_keystore_uids=[withheld_keystore_uid]
        )
        assert decrypted_payload == payload, (withheld_keystore_uid, error_types)
        assert error_types <= corpus.TRUSTEE_DEPENDENT_ERROR_TYPES, (withheld_keystore_uid, error_types)

    for kept_keystore_uid in keystore_uids:
        withheld_keystore_uids = [keystore_uid for keystore_uid in keystore_uids if keystore_uid != kept_keystore_uid]
        decrypted_payload, error_types = decrypt_with_wacryptolib(
            cryptainer, WITHHOLDING_PROFILE_NAME, tmp_path, withheld_keystore_uids=withheld_keystore_uids
        )
        assert decrypted_payload is None, kept_keystore_uid
        assert "ASYMMETRIC_DECRYPTION_ERROR" in error_types, (kept_keystore_uid, error_types)
