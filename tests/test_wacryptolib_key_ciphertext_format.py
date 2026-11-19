# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests of the "key_ciphertext_format" field: structures serialized then encrypted into key ciphertexts may be
Extended JSON (default, field absent) or WA-CBOR (field "cbor"), see the key-ciphertext-format specification."""

import copy
import hashlib
import itertools
import logging
import uuid
from pathlib import Path
from unittest import mock

import pytest

from wacryptolib.cipher import check_cipherdict_sanity
from wacryptolib.cryptainer import (
    LOCAL_KEYFACTORY_TRUSTEE_MARKER,
    SHARED_SECRET_ALGO_MARKER,
    CryptainerDecryptor,
    CryptainerEncryptionPipeline,
    CryptainerEncryptor,
    CryptainerStorage,
    FlightBox,
    OperationReport,
    check_cryptainer_sanity,
    check_cryptoconf_sanity,
    decrypt_payload_from_cryptainer,
    encrypt_payload_and_stream_cryptainer_to_filesystem,
    encrypt_payload_into_cryptainer,
    gather_decryptable_symkeys,
    get_key_ciphertext_format,
    get_revelation_request_data,
    get_trustee_id,
    load_cryptainer_from_filesystem,
)
from wacryptolib.cryptainer._decryptor import DecryptionErrorCriticity, DecryptionErrorType
from wacryptolib.cryptainer._encryptor import FlightboxUtilitiesImpl
from wacryptolib.exceptions import DecryptionError, SchemaValidationError
from wacryptolib.keygen import SUPPORTED_SYMMETRIC_KEY_ALGOS
from wacryptolib.keystore import InMemoryKeystorePool, generate_keypair_for_storage
from wacryptolib.utilities import (
    WaCborError,
    convert_to_extjson,
    dump_to_cbor_bytes,
    dump_to_json_bytes,
    generate_uuid0,
    load_from_cbor_bytes,
    load_from_json_bytes,
)

from test_wacryptolib_cryptainer import (
    DUMMY_GATEWAY_URLS,
    _build_fake_gateway_revelation_request_list,
    _check_operation_report_entry,
    _create_keystore_and_keypair_protected_by_passphrase_in_foreign_keystore,
    _create_response_keyair_in_local_keyfactory_and_build_fake_revelation_request_info,
    _patched_gateway_revelation_request_list,
)

REPOSITORY_DIR = Path(__file__).resolve().parents[1]

LOADERS = {"json": load_from_json_bytes, "cbor": load_from_cbor_bytes}


def _local_layer(key_cipher_algo="RSA_OAEP", **extra):
    return dict(key_cipher_algo=key_cipher_algo, key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER, **extra)


def _payload_layer(payload_cipher_algo, key_cipher_layers):
    return dict(
        payload_cipher_algo=payload_cipher_algo, key_cipher_layers=key_cipher_layers, payload_ciphertext_signatures=[]
    )


# Two payload layers, an asymmetric layer, a shared secret, and symmetric key layers in a shard and at top level (no
# ML_KEM_768, so that it also runs on the fallback backend: the corpus covers it)
COMPLEX_LOCAL_CRYPTOCONF = dict(
    payload_cipher_layers=[
        _payload_layer(
            "AES_CBC",
            [
                _local_layer("RSA_OAEP"),
                dict(
                    key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
                    key_shared_secret_threshold=2,
                    key_shared_secret_shards=[
                        dict(key_cipher_layers=[_local_layer("ECIES_X25519")]),
                        dict(key_cipher_layers=[dict(key_cipher_algo="AES_EAX", key_cipher_layers=[_local_layer("RSA_OAEP")])]),
                        dict(key_cipher_layers=[_local_layer("RSA_OAEP")]),
                    ],
                ),
            ],
        ),
        _payload_layer(
            "CHACHA20_POLY1305",
            [dict(key_cipher_algo="CHACHA20_POLY1305", key_cipher_layers=[_local_layer("RSA_OAEP")])],
        ),
    ]
)


def _iter_key_ciphertext_holders(cryptainer):
    """Yield the payload cipher layers and symmetric key cipher layers, i.e. the holders of a "key_ciphertext"."""

    def _walk_key_cipher_layers(key_cipher_layers):
        for key_cipher_layer in key_cipher_layers:
            if key_cipher_layer["key_cipher_algo"] == SHARED_SECRET_ALGO_MARKER:
                for shard in key_cipher_layer["key_shared_secret_shards"]:
                    yield from _walk_key_cipher_layers(shard["key_cipher_layers"])
            elif key_cipher_layer["key_cipher_algo"] in SUPPORTED_SYMMETRIC_KEY_ALGOS:
                yield key_cipher_layer
                yield from _walk_key_cipher_layers(key_cipher_layer["key_cipher_layers"])

    for payload_cipher_layer in cryptainer["payload_cipher_layers"]:
        yield payload_cipher_layer
        yield from _walk_key_cipher_layers(payload_cipher_layer["key_cipher_layers"])


def _has_key_ciphertext_format_field(data_tree):
    if isinstance(data_tree, dict):
        return "key_ciphertext_format" in data_tree or any(_has_key_ciphertext_format_field(v) for v in data_tree.values())
    if isinstance(data_tree, list):
        return any(_has_key_ciphertext_format_field(v) for v in data_tree)
    return False


def _check_key_ciphertext_formats(cryptainer, expected_format):
    holders = list(_iter_key_ciphertext_holders(cryptainer))
    assert holders
    for holder in holders:
        if expected_format == "json":
            assert "key_ciphertext_format" not in holder
        else:
            assert holder["key_ciphertext_format"] == expected_format
        LOADERS[expected_format](holder["key_ciphertext"])  # The outermost cipherdict is in the declared format
    if expected_format == "json":
        assert not _has_key_ciphertext_format_field(cryptainer)


# FLIGHTBOX CORE, WITH FAKE DETERMINISTIC UTILITIES


class DeterministicFlightboxUtilities:
    """Fake platform utilities, whose randomness is replaced by counters, and whose "encryption" just reverses
    bytes, so that outputs are reproducible and every serialized structure can be read back."""

    logger = logging.getLogger("deterministic_flightbox")

    SUPPORTED_SYMMETRIC_CIPHER_ALGOS = ["AES_CBC", "AES_EAX", "CHACHA20_POLY1305"]
    SUPPORTED_ASYMMETRIC_CIPHER_ALGOS = ["ECIES_X25519", "ML_KEM_768", "RSA_OAEP"]

    def __init__(self):
        self._counter = 0

    def _next(self):
        self._counter += 1
        return self._counter

    def raise_validation_error(self, msg):
        raise ValueError(msg)

    def dump_to_json_bytes(self, data):
        return dump_to_json_bytes(data)

    def dump_to_cbor_bytes(self, data):
        return dump_to_cbor_bytes(data)

    def generate_uuid0(self):
        return uuid.UUID(int=self._next())

    def split_secret_into_shards(self, secret, *, shard_count, threshold_count):
        return [
            (index, hashlib.sha256(b"%d/%d/" % (index, threshold_count) + secret).digest()[:16])
            for index in range(1, shard_count + 1)
        ]

    def generate_symkey(self, cipher_algo):
        seed = b"%s-%d" % (cipher_algo.encode("ascii"), self._next())
        return {"key": hashlib.sha256(seed).digest(), "iv": hashlib.md5(seed).digest()}

    def get_public_key(self, trustee, key_algo, keychain_uid):
        return "PUBLIC-KEY/%s/%s/%s" % (
            key_algo, keychain_uid, sorted(trustee.items()) if isinstance(trustee, dict) else trustee
        )

    def encrypt_bytestring(self, plaintext, *, cipher_algo, key_dict):
        tag = hashlib.sha256(repr((cipher_algo, sorted(key_dict))).encode("ascii") + plaintext).digest()
        return {"ciphertext": b"<" + cipher_algo.encode("ascii") + b">" + plaintext[::-1], "tag": tag[:16]}


def _fake_decrypt(cipherdict, cipher_algo):
    prefix = b"<" + cipher_algo.encode("ascii") + b">"
    assert cipherdict["ciphertext"].startswith(prefix)
    return cipherdict["ciphertext"][len(prefix):][::-1]


DETERMINISTIC_CRYPTOCONF = dict(
    payload_cipher_layers=[
        _payload_layer(
            "AES_CBC",
            [
                _local_layer("RSA_OAEP"),
                dict(
                    key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
                    key_shared_secret_threshold=2,
                    key_shared_secret_shards=[
                        dict(
                            key_cipher_layers=[
                                dict(
                                    key_cipher_algo="ECIES_X25519",
                                    key_cipher_trustee=dict(
                                        trustee_type="authenticator",
                                        keystore_uid=uuid.UUID(int=0xABC),
                                        keystore_owner="Jo",
                                    ),
                                )
                            ]
                        ),
                        dict(
                            key_cipher_layers=[
                                dict(
                                    key_cipher_algo="AES_EAX",
                                    key_cipher_layers=[_local_layer("ML_KEM_768", keychain_uid=uuid.UUID(int=0xDEF))],
                                ),
                            ]
                        ),
                        dict(key_cipher_layers=[_local_layer("RSA_OAEP")]),
                    ],
                ),
            ],
        ),
        _payload_layer(
            "CHACHA20_POLY1305",
            [dict(key_cipher_algo="CHACHA20_POLY1305", key_cipher_layers=[_local_layer("RSA_OAEP")])],
        ),
    ],
)

DETERMINISTIC_CRYPTAINER_METADATA = {"camera": "Front door", "frames": 42, "tags": ["a", "b"]}

# Digest of the cryptainer and secrets generated from DETERMINISTIC_CRYPTOCONF, captured with the flightbox core of
# BEFORE the introduction of key ciphertext formats: Extended JSON mode must keep producing exactly the same output
PRE_KEY_CIPHERTEXT_FORMAT_JSON_OUTPUT_DIGEST = "b58104d802e831ec3706225d13e55df1d552a074bf333238f021429a410d9013"


def _generate_deterministic_cryptainer(utilities=None, **kwargs):
    flightbox = FlightBox(utilities or DeterministicFlightboxUtilities())
    return flightbox.generate_cryptainer_base_and_secrets(
        cryptoconf=DETERMINISTIC_CRYPTOCONF, cryptainer_metadata=DETERMINISTIC_CRYPTAINER_METADATA, **kwargs
    )


@pytest.mark.parametrize("kwargs", [{}, {"key_ciphertext_format": "json"}])
def test_flightbox_json_mode_output_is_unchanged(kwargs):
    cryptainer, secrets = _generate_deterministic_cryptainer(**kwargs)
    output_digest = hashlib.sha256(dump_to_json_bytes(dict(cryptainer=cryptainer, secrets=secrets))).hexdigest()
    assert output_digest == PRE_KEY_CIPHERTEXT_FORMAT_JSON_OUTPUT_DIGEST
    _check_key_ciphertext_formats(cryptainer, "json")


@pytest.mark.parametrize("key_ciphertext_format", ["json", "cbor"])
def test_flightbox_serializes_every_inner_structure_in_the_chosen_format(key_ciphertext_format):
    class TransparentShardsUtilities(DeterministicFlightboxUtilities):
        def split_secret_into_shards(self, secret, *, shard_count, threshold_count):
            return [(index, secret) for index in range(1, shard_count + 1)]  # Each shard reveals the secret

    cryptainer, secrets = _generate_deterministic_cryptainer(
        TransparentShardsUtilities(), key_ciphertext_format=key_ciphertext_format
    )
    _check_key_ciphertext_formats(cryptainer, key_ciphertext_format)

    parsed_kinds = []

    def _load(data, document_format, kind):
        parsed_kinds.append(kind)
        return LOADERS[document_format](data)  # Strict loaders: Extended JSON bytes are not WA-CBOR, and conversely

    def _unravel_key_ciphertext(key_ciphertext, document_format, key_cipher_layers):
        for key_cipher_layer in reversed(key_cipher_layers):
            key_cipher_algo = key_cipher_layer["key_cipher_algo"]
            key_cipherdict = _load(key_ciphertext, document_format, "cipherdict")
            if key_cipher_algo == SHARED_SECRET_ALGO_MARKER:
                shards = []
                for shard_ciphertext, shard_conf in zip(
                    key_cipherdict["shard_ciphertexts"], key_cipher_layer["key_shared_secret_shards"]
                ):
                    shard_bytes = _unravel_key_ciphertext(
                        shard_ciphertext, document_format, shard_conf["key_cipher_layers"]
                    )
                    shards.append(_load(shard_bytes, document_format, "shard"))
                assert len({shard[1] for shard in shards}) == 1
                key_ciphertext = shards[0][1]
            elif key_cipher_algo in SUPPORTED_SYMMETRIC_KEY_ALGOS:
                sub_symkey_format = get_key_ciphertext_format(key_cipher_layer)
                sub_symkey_bytes = _unravel_key_ciphertext(
                    key_cipher_layer["key_ciphertext"], sub_symkey_format, key_cipher_layer["key_cipher_layers"]
                )
                _load(sub_symkey_bytes, sub_symkey_format, "symkey")
                key_ciphertext = _fake_decrypt(key_cipherdict, key_cipher_algo)
            else:
                key_struct = _load(_fake_decrypt(key_cipherdict, key_cipher_algo), document_format, "key_struct")
                assert key_struct["cryptainer_metadata"] == DETERMINISTIC_CRYPTAINER_METADATA
                key_ciphertext = key_struct["key_bytes"]
        return key_ciphertext

    for payload_cipher_layer, extract in zip(
        cryptainer["payload_cipher_layers"], secrets["payload_cipher_layer_extracts"]
    ):
        payload_layer_format = get_key_ciphertext_format(payload_cipher_layer)
        symkey_bytes = _unravel_key_ciphertext(
            payload_cipher_layer["key_ciphertext"], payload_layer_format, payload_cipher_layer["key_cipher_layers"]
        )
        assert _load(symkey_bytes, payload_layer_format, "symkey") == extract["symkey"]

    assert sorted(set(parsed_kinds)) == ["cipherdict", "key_struct", "shard", "symkey"]


def test_flightbox_rejects_unknown_key_ciphertext_format_before_key_generation():
    utilities = DeterministicFlightboxUtilities()
    with pytest.raises(ValueError, match="Unknown key ciphertext format 'yaml'"):
        _generate_deterministic_cryptainer(utilities, key_ciphertext_format="yaml")
    assert utilities._counter == 0  # Neither UUIDs nor keys were generated


def test_micropython_flightbox_core_is_a_verbatim_copy():
    original_path = REPOSITORY_DIR / "src" / "wacryptolib" / "cryptainer" / "_flightbox.py"
    copy_path = REPOSITORY_DIR / "reimplementations" / "micropython" / "src" / "cryptainer" / "_flightbox.py"
    assert copy_path.read_bytes() == original_path.read_bytes(), "Re-copy _flightbox.py into the MicroPython port"


# ENCRYPTION API


def test_encryption_api_defaults_and_cbor_mode(tmp_path):
    keystore_pool = InMemoryKeystorePool()
    payload = b"some payload"

    cryptainer = encrypt_payload_into_cryptainer(
        payload, cryptoconf=COMPLEX_LOCAL_CRYPTOCONF, cryptainer_metadata=None, keystore_pool=keystore_pool
    )
    _check_key_ciphertext_formats(cryptainer, "json")

    for key_ciphertext_format in ("json", "cbor"):
        cryptainer = encrypt_payload_into_cryptainer(
            payload,
            cryptoconf=COMPLEX_LOCAL_CRYPTOCONF,
            cryptainer_metadata={"place": "here"},
            keystore_pool=keystore_pool,
            key_ciphertext_format=key_ciphertext_format,
        )
        _check_key_ciphertext_formats(cryptainer, key_ciphertext_format)
        check_cryptainer_sanity(cryptainer)  # Strict validation parses readable cipherdicts in the declared format
        check_cryptainer_sanity(convert_to_extjson(cryptainer), jsonschema_mode=True)
        result, operation_report = decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)
        assert result == payload, operation_report.format_entries()
        assert not operation_report.has_errors()

    # Streamed encryption, with the default then explicit formats
    for kwargs, expected_format in [({}, "json"), (dict(key_ciphertext_format="cbor"), "cbor")]:
        cryptainer_filepath = tmp_path / ("streamed_%s.crypt.json" % expected_format)
        encrypt_payload_and_stream_cryptainer_to_filesystem(
            payload,
            cryptainer_filepath=cryptainer_filepath,
            cryptoconf=COMPLEX_LOCAL_CRYPTOCONF,
            cryptainer_metadata=None,
            keystore_pool=keystore_pool,
            **kwargs
        )
        cryptainer = load_cryptainer_from_filesystem(cryptainer_filepath)
        _check_key_ciphertext_formats(cryptainer, expected_format)
        result, operation_report = decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)
        assert result == payload

    pipeline = CryptainerEncryptionPipeline(
        tmp_path / "pipeline.crypt.cbor",
        cryptoconf=COMPLEX_LOCAL_CRYPTOCONF,
        cryptainer_metadata=None,
        signature_policy=None,
        keystore_pool=keystore_pool,
    )
    pipeline.encrypt_chunk(payload)
    pipeline.finalize()
    _check_key_ciphertext_formats(load_cryptainer_from_filesystem(tmp_path / "pipeline.crypt.cbor"), "json")


def test_cbor_mode_never_serializes_extended_json():
    keystore_pool = InMemoryKeystorePool()
    with mock.patch.object(FlightboxUtilitiesImpl, "dump_to_json_bytes", side_effect=AssertionError("JSON used")):
        cryptainer = encrypt_payload_into_cryptainer(
            b"data",
            cryptoconf=COMPLEX_LOCAL_CRYPTOCONF,
            cryptainer_metadata={"camera": 3},
            keystore_pool=keystore_pool,
            key_ciphertext_format="cbor",
        )
    result, _operation_report = decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)
    assert result == b"data"


def test_unknown_key_ciphertext_format_is_rejected_before_key_generation(tmp_path):
    keystore_pool = InMemoryKeystorePool()
    with mock.patch.object(FlightboxUtilitiesImpl, "generate_symkey", side_effect=AssertionError("Key generated")):
        with pytest.raises(ValueError, match="Unknown key ciphertext format"):
            CryptainerEncryptor(signature_policy=None, key_ciphertext_format="yaml")
        with pytest.raises(ValueError, match="Unknown key ciphertext format"):
            encrypt_payload_into_cryptainer(
                b"data", cryptoconf=COMPLEX_LOCAL_CRYPTOCONF, cryptainer_metadata=None, key_ciphertext_format="yaml"
            )
        with pytest.raises(ValueError, match="Unknown key ciphertext format"):
            encrypt_payload_and_stream_cryptainer_to_filesystem(
                b"data",
                cryptainer_filepath=tmp_path / "x.crypt.json",
                cryptoconf=COMPLEX_LOCAL_CRYPTOCONF,
                cryptainer_metadata=None,
                key_ciphertext_format="CBOR",  # Values are case-sensitive
            )
        with pytest.raises(ValueError, match="Unknown key ciphertext format"):
            CryptainerStorage(tmp_path, keystore_pool=keystore_pool, key_ciphertext_format="yaml")
    assert list(tmp_path.iterdir()) == []  # Not even the offloaded payload file was created


@pytest.mark.parametrize("offload_payload_ciphertext", [True, False])  # Streamed or in-memory encryption
@pytest.mark.parametrize(
    "cryptainer_file_format, key_ciphertext_format, expected_format",
    [
        ("json", None, "json"),
        ("cbor", None, "cbor"),  # Storage default follows the file format
        ("cbor", "json", "json"),
        ("json", "cbor", "cbor"),
    ],
)
def test_cryptainer_storage_key_ciphertext_format(
    tmp_path, offload_payload_ciphertext, cryptainer_file_format, key_ciphertext_format, expected_format
):
    keystore_pool = InMemoryKeystorePool()
    extra_kwargs = {} if key_ciphertext_format is None else dict(key_ciphertext_format=key_ciphertext_format)
    storage = CryptainerStorage(
        tmp_path,
        keystore_pool=keystore_pool,
        default_cryptoconf=COMPLEX_LOCAL_CRYPTOCONF,
        offload_payload_ciphertext=offload_payload_ciphertext,
        cryptainer_file_format=cryptainer_file_format,
        **extra_kwargs
    )
    cryptainer_name = storage.encrypt_file("clip.mp4", payload=b"video", cryptainer_metadata=None)
    assert cryptainer_name == "clip.mp4.crypt." + cryptainer_file_format
    _check_key_ciphertext_formats(storage.load_cryptainer_from_storage(cryptainer_name), expected_format)
    result, _operation_report = storage.decrypt_cryptainer_from_storage(cryptainer_name)
    assert result == b"video"

    stream = storage.create_cryptainer_encryption_stream(
        "stream.mp4", cryptainer_metadata=None, signature_policy=None, dump_initial_cryptainer=False
    )
    stream.encrypt_chunk(b"streamed video")
    stream.finalize()
    _check_key_ciphertext_formats(
        storage.load_cryptainer_from_storage("stream.mp4.crypt." + cryptainer_file_format), expected_format
    )


def test_cbor_key_ciphertexts_are_smaller():
    keystore_pool = InMemoryKeystorePool()
    cryptoconf = dict(payload_cipher_layers=[_payload_layer("AES_CBC", [_local_layer("RSA_OAEP")])])
    chunk_counts = {}
    for key_ciphertext_format in ("json", "cbor"):
        cryptainer = encrypt_payload_into_cryptainer(
            b"same payload",
            cryptoconf=cryptoconf,
            cryptainer_metadata=None,
            keystore_pool=keystore_pool,
            key_ciphertext_format=key_ciphertext_format,
        )
        key_cipherdict = LOADERS[key_ciphertext_format](cryptainer["payload_cipher_layers"][0]["key_ciphertext"])
        chunk_counts[key_ciphertext_format] = len(key_cipherdict["ciphertext_chunks"])
    assert chunk_counts == {"json": 6, "cbor": 2}


def test_metadata_unencodable_in_wacbor_fails_encryption_before_writing(tmp_path):
    keystore_pool = InMemoryKeystorePool()
    deep_metadata = current = {}
    for _ in range(63):  # The key struct adds one level, beyond the WA-CBOR nesting limit of 64
        current["x"] = current = {}
    cryptainer_filepath = tmp_path / "deep.crypt.json"
    with pytest.raises(SchemaValidationError, match="deeper than 63 levels"):  # At upfront validation
        encrypt_payload_and_stream_cryptainer_to_filesystem(
            b"data",
            cryptainer_filepath=cryptainer_filepath,
            cryptoconf=COMPLEX_LOCAL_CRYPTOCONF,
            cryptainer_metadata=deep_metadata,
            keystore_pool=keystore_pool,
            key_ciphertext_format="cbor",
        )
    assert not cryptainer_filepath.exists()


# VALIDATION


def _get_mutable_cryptainer(*args, **kwargs):
    return copy.deepcopy(encrypt_payload_into_cryptainer(*args, **kwargs))  # Not a frozen ValidatedCryptainer


def _get_cbor_mode_cryptainer():
    return _get_mutable_cryptainer(
        b"data",
        cryptoconf=COMPLEX_LOCAL_CRYPTOCONF,
        cryptainer_metadata=None,
        keystore_pool=InMemoryKeystorePool(),
        key_ciphertext_format="cbor",
    )


@pytest.mark.parametrize("holder_index", [0, 1, 2])  # Payload cipher layer, nested and top-level symmetric layers
def test_cryptainer_validation_rejects_unknown_key_ciphertext_format(holder_index):
    cryptainer = _get_cbor_mode_cryptainer()
    holders = list(_iter_key_ciphertext_holders(cryptainer))
    assert len(holders) == 4
    holders[holder_index]["key_ciphertext_format"] = "yaml"
    with pytest.raises(SchemaValidationError, match="key_ciphertext_format"):
        check_cryptainer_sanity(cryptainer)
    with pytest.raises(SchemaValidationError):
        check_cryptainer_sanity(convert_to_extjson(cryptainer), jsonschema_mode=True)


@pytest.mark.parametrize("value", ["json", "cbor"])
def test_cryptoconf_validation_rejects_key_ciphertext_format(value):
    cryptoconf = dict(payload_cipher_layers=[_payload_layer("AES_CBC", [_local_layer("RSA_OAEP")])])
    check_cryptoconf_sanity(cryptoconf)
    cryptoconf["payload_cipher_layers"][0]["key_ciphertext_format"] = value
    with pytest.raises(SchemaValidationError, match="key_ciphertext_format"):
        check_cryptoconf_sanity(cryptoconf)
    with pytest.raises(SchemaValidationError):
        check_cryptoconf_sanity(convert_to_extjson(cryptoconf), jsonschema_mode=True)
    with pytest.raises(SchemaValidationError):
        encrypt_payload_into_cryptainer(b"data", cryptoconf=cryptoconf, cryptainer_metadata=None)


# DECRYPTION


def _create_authenticators(keystore_pool, count):
    authenticators = []
    keystore_uids = [generate_uuid0() for _ in range(count)]
    keystore_pool._register_fake_imported_storage_uids(storage_uids=keystore_uids)
    for index, keystore_uid in enumerate(keystore_uids):
        keychain_uid = generate_uuid0()
        passphrase = "passphrase%d" % index
        generate_keypair_for_storage(
            key_algo="RSA_OAEP",
            keystore=keystore_pool.get_foreign_keystore(keystore_uid),
            keychain_uid=keychain_uid,
            passphrase=passphrase,
        )
        trustee = dict(trustee_type="authenticator", keystore_uid=keystore_uid, keystore_owner="owner%d" % index)
        key_cipher_layer = dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=trustee, keychain_uid=keychain_uid)
        authenticators.append((get_trustee_id(trustee), passphrase, key_cipher_layer))
    return authenticators


def test_shared_secret_with_cbor_key_ciphertexts():
    keystore_pool = InMemoryKeystorePool()
    authenticators = _create_authenticators(keystore_pool, count=3)
    cryptoconf = dict(
        payload_cipher_layers=[
            _payload_layer(
                "AES_EAX",
                [
                    _local_layer("RSA_OAEP"),
                    dict(
                        key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
                        key_shared_secret_threshold=2,
                        key_shared_secret_shards=[
                            dict(key_cipher_layers=[key_cipher_layer]) for (_, _, key_cipher_layer) in authenticators
                        ],
                    ),
                ],
            )
        ]
    )
    payload = b"shared secret payload"
    cryptainer = encrypt_payload_into_cryptainer(
        payload, cryptoconf=cryptoconf, cryptainer_metadata=None, keystore_pool=keystore_pool, key_ciphertext_format="cbor"
    )
    payload_cipher_layer = cryptainer["payload_cipher_layers"][0]
    assert payload_cipher_layer["key_ciphertext_format"] == "cbor"
    shared_secret_cipherdict = load_from_cbor_bytes(payload_cipher_layer["key_ciphertext"])
    for shard_ciphertext in shared_secret_cipherdict["shard_ciphertexts"]:
        check_cipherdict_sanity(load_from_cbor_bytes(shard_ciphertext), cipher_algo="RSA_OAEP")

    for subset in itertools.combinations(authenticators, 2):
        passphrase_mapper = {trustee_id: [passphrase] for (trustee_id, passphrase, _) in subset}
        result, operation_report = decrypt_payload_from_cryptainer(
            cryptainer, keystore_pool=keystore_pool, passphrase_mapper=passphrase_mapper
        )
        assert result == payload, operation_report.format_entries()

    trustee_id, passphrase, _ = authenticators[0]
    result, operation_report = decrypt_payload_from_cryptainer(
        cryptainer, keystore_pool=keystore_pool, passphrase_mapper={trustee_id: [passphrase]}
    )
    assert result is None
    assert operation_report.has_errors()


class _MixedFormatFlightBox(FlightBox):
    """Writes the key ciphertext of CHACHA20_POLY1305 payload layers and of symmetric key layers in WA-CBOR, and
    the others in Extended JSON."""

    def _encrypt_payload_symkey(self, *, payload_cipher_layer, key_ciphertext_format, **kwargs):
        key_ciphertext_format = "cbor" if payload_cipher_layer["payload_cipher_algo"] == "CHACHA20_POLY1305" else "json"
        super()._encrypt_payload_symkey(
            payload_cipher_layer=payload_cipher_layer, key_ciphertext_format=key_ciphertext_format, **kwargs
        )

    def _encrypt_key_through_single_layer(self, *, key_cipher_layer, key_ciphertext_format, **kwargs):
        if key_cipher_layer["key_cipher_algo"] in SUPPORTED_SYMMETRIC_KEY_ALGOS:
            key_ciphertext_format = "cbor"  # Only its sub-chain is affected, its cipherdict is serialized by the caller
        return super()._encrypt_key_through_single_layer(
            key_cipher_layer=key_cipher_layer, key_ciphertext_format=key_ciphertext_format, **kwargs
        )


def test_mixed_key_ciphertext_formats_in_one_cryptainer():
    keystore_pool = InMemoryKeystorePool()
    cryptoconf = dict(
        payload_cipher_layers=[
            _payload_layer(
                "AES_CBC",
                [dict(key_cipher_algo="AES_EAX", key_cipher_layers=[_local_layer("RSA_OAEP")]), _local_layer("ECIES_X25519")],
            ),
            _payload_layer("CHACHA20_POLY1305", [_local_layer("RSA_OAEP")]),
        ]
    )
    with mock.patch("wacryptolib.cryptainer._encryptor.FlightBox", _MixedFormatFlightBox):
        cryptainer = encrypt_payload_into_cryptainer(
            b"mixed", cryptoconf=cryptoconf, cryptainer_metadata=None, keystore_pool=keystore_pool
        )
    first_layer, second_layer = cryptainer["payload_cipher_layers"]
    assert "key_ciphertext_format" not in first_layer
    load_from_json_bytes(first_layer["key_ciphertext"])
    symmetric_key_layer = first_layer["key_cipher_layers"][0]
    assert symmetric_key_layer["key_ciphertext_format"] == "cbor"
    load_from_cbor_bytes(symmetric_key_layer["key_ciphertext"])
    assert second_layer["key_ciphertext_format"] == "cbor"
    load_from_cbor_bytes(second_layer["key_ciphertext"])

    check_cryptainer_sanity(cryptainer)
    result, operation_report = decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)
    assert result == b"mixed", operation_report.format_entries()
    assert not operation_report.has_errors()


def test_key_ciphertext_format_contradicting_the_content():
    keystore_pool = InMemoryKeystorePool()
    cryptainer = _get_mutable_cryptainer(
        b"data", cryptoconf=COMPLEX_LOCAL_CRYPTOCONF, cryptainer_metadata=None, keystore_pool=keystore_pool
    )
    payload_cipher_layer = cryptainer["payload_cipher_layers"][1]
    payload_cipher_layer["key_ciphertext_format"] = "cbor"  # Whereas it is an Extended JSON chain

    # Decryption validates cryptainers upfront, and readable cipherdicts are parsed in their declared format
    with pytest.raises(SchemaValidationError, match="Unparseable .* key cipherdict .* 'cbor'"):
        check_cryptainer_sanity(cryptainer)
    with pytest.raises(SchemaValidationError, match="Unparseable .* key cipherdict .* 'cbor'"):
        decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)

    # Without upfront validation, decryption of the layer fails, without any attempt to parse Extended JSON
    operation_report = OperationReport()
    with mock.patch("wacryptolib.cryptainer._base.load_from_json_bytes", side_effect=AssertionError("JSON parsed")):
        result = CryptainerDecryptor(keystore_pool=keystore_pool)._decrypt_single_payload_cipher_layer(
            payload_ciphertext=b"whatever",
            payload_cipher_layer=payload_cipher_layer,
            verify_integrity_tags=True,
            default_keychain_uid=cryptainer["keychain_uid"],
            cryptainer_metadata=None,
            operation_report=operation_report,
            predecrypted_symkey_mapper=None,
        )
    assert result is None
    _check_operation_report_entry(
        operation_report=operation_report,
        entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
        entry_criticity=DecryptionErrorCriticity.ERROR,
        entry_msg_match="Malformed key cipherdict for algorithm CHACHA20_POLY1305",
        exception_class=DecryptionError,
    )
    (entry,) = [entry for entry in operation_report.get_error_entries() if entry["entry_exception"]]
    assert "Unparseable CHACHA20_POLY1305 key cipherdict, in format 'cbor'" in str(entry["entry_exception"])


# REVELATION REQUESTS


@pytest.mark.parametrize("key_ciphertext_format", ["json", "cbor"])
def test_revelation_request_data_is_extended_json(key_ciphertext_format):
    keystore_pool = InMemoryKeystorePool()
    authenticators = _create_authenticators(keystore_pool, count=3)
    cryptoconf = dict(
        payload_cipher_layers=[
            _payload_layer("AES_CBC", [authenticators[0][2]]),
            _payload_layer(
                "AES_EAX",
                [
                    dict(
                        key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
                        key_shared_secret_threshold=1,
                        key_shared_secret_shards=[
                            dict(key_cipher_layers=[authenticators[1][2]]),
                            dict(key_cipher_layers=[dict(key_cipher_algo="AES_CBC", key_cipher_layers=[authenticators[2][2]])]),
                        ],
                    )
                ],
            ),
        ]
    )
    cryptainer = encrypt_payload_into_cryptainer(
        b"data",
        cryptoconf=cryptoconf,
        cryptainer_metadata=None,
        keystore_pool=keystore_pool,
        key_ciphertext_format=key_ciphertext_format,
    )
    decryptable_symkeys_per_trustee = gather_decryptable_symkeys([("data.crypt.json", cryptainer)])
    assert len(decryptable_symkeys_per_trustee) == 3
    for _trustee_conf, symkey_decryption_requests in decryptable_symkeys_per_trustee.values():
        (symkey_decryption_request,) = symkey_decryption_requests
        request_data = symkey_decryption_request["symkey_decryption_request_data"]
        check_cipherdict_sanity(load_from_json_bytes(request_data), cipher_algo="RSA_OAEP")  # Like authenticators do

    first_key_ciphertext = cryptainer["payload_cipher_layers"][0]["key_ciphertext"]
    request_data = get_revelation_request_data(first_key_ciphertext, key_ciphertext_format=key_ciphertext_format)
    if key_ciphertext_format == "json":
        assert request_data is first_key_ciphertext  # Unchanged, byte for byte
    else:
        assert request_data == dump_to_json_bytes(load_from_cbor_bytes(first_key_ciphertext))


def test_remote_decryption_round_trip_with_cbor_key_ciphertexts():
    passphrase = "tata"
    keychain_uid = generate_uuid0()
    keystore_pool, _foreign_keystore, key_cipher_trustee = (
        _create_keystore_and_keypair_protected_by_passphrase_in_foreign_keystore(
            keystore_uid=generate_uuid0(), keychain_uid=keychain_uid, passphrase=passphrase
        )
    )
    cryptoconf = dict(
        payload_cipher_layers=[
            _payload_layer(
                "AES_CBC",
                [dict(key_cipher_algo="RSA_OAEP", keychain_uid=keychain_uid, key_cipher_trustee=key_cipher_trustee)],
            )
        ]
    )
    payload = b"remote payload"
    cryptainer = encrypt_payload_into_cryptainer(
        payload, cryptoconf=cryptoconf, cryptainer_metadata=None, keystore_pool=keystore_pool, key_ciphertext_format="cbor"
    )
    revelation_requestor_uid = generate_uuid0()
    # The fake gateway parses request data with load_from_json_bytes() and returns the key struct bytes as they are
    revelation_requests_info = _create_response_keyair_in_local_keyfactory_and_build_fake_revelation_request_info(
        revelation_requestor_uid,
        [("remote.crypt.json", cryptainer)],
        keystore_pool,
        [(get_trustee_id(key_cipher_trustee), passphrase)],
    )
    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(revelation_requests_info)
    ):
        result, operation_report = decrypt_payload_from_cryptainer(
            cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper=None,  # The local decryption would fail
            gateway_urls=DUMMY_GATEWAY_URLS,
            revelation_requestor_uid=revelation_requestor_uid,
        )
    assert result == payload, operation_report.format_entries()
    assert not operation_report.has_errors()
    assert any(
        "Predecrypted symmetric key found" in entry["entry_message"] for entry in operation_report.get_all_entries()
    )


def test_predecrypted_key_struct_lookup_honors_the_key_ciphertext_format():
    key_ciphertext = dump_to_cbor_bytes({"ciphertext_chunks": [b"x" * 256]})
    request_data = get_revelation_request_data(key_ciphertext, key_ciphertext_format="cbor")
    assert load_from_json_bytes(request_data) == {"ciphertext_chunks": [b"x" * 256]}
    cbor_key_struct = dump_to_cbor_bytes(dict(key_bytes=b"symkey", cryptainer_metadata=None))
    json_key_struct = dump_to_json_bytes(dict(key_bytes=b"other", cryptainer_metadata=None))

    def _lookup(key_struct_list):
        operation_report = OperationReport()
        key_bytes = CryptainerDecryptor._get_predecrypted_symkey_or_none(
            key_ciphertext,
            key_ciphertext_format="cbor",
            key_cipher_algo="RSA_OAEP",
            predecrypted_symkey_mapper={request_data: key_struct_list},
            operation_report=operation_report,
        )
        return key_bytes, operation_report

    # The first response which is valid in the format of the chain is used, invalid ones are reported
    key_bytes, operation_report = _lookup([b"garbage", json_key_struct, cbor_key_struct])
    assert key_bytes == b"symkey"
    _check_operation_report_entry(
        operation_report=operation_report,
        entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        entry_criticity=DecryptionErrorCriticity.ERROR,
        entry_msg_match="Malformed remote key struct (RSA_OAEP)",
        exception_class=DecryptionError,
        occurrence_count=2,
    )

    key_bytes, operation_report = _lookup([json_key_struct])
    assert key_bytes is None  # Then the decryptor falls back to trustees

    # Request data of Extended JSON chains is the key ciphertext itself, as before
    assert get_revelation_request_data(b'{"a": 1}', key_ciphertext_format="json") == b'{"a": 1}'
