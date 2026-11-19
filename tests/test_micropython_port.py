# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests of the MicroPython flightbox port (reimplementations/micropython/), run with CPython: they cover the logic
of its own modules, not what differs on a MicroPython interpreter (builtins, stdlib stubs of lib/, memory limits)."""

import ast
import base64
import copy
import functools
import importlib
import importlib.util
import logging
import sys
import types
import uuid
from pathlib import Path

import pytest

from wacryptolib.cipher import encrypt_bytestring
from wacryptolib.cryptainer import (
    SHARED_SECRET_ALGO_MARKER,
    check_cryptainer_sanity,
    check_cryptoconf_sanity,
    decrypt_payload_from_cryptainer,
)
from wacryptolib.keygen import load_asymmetric_key_from_pem_bytestring
from wacryptolib.keystore import InMemoryKeystorePool, generate_keypair_for_storage
from wacryptolib.shared_secret import recombine_secret_from_shards
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes

REPOSITORY_DIR = Path(__file__).resolve().parents[1]
MICROPYTHON_DIR = REPOSITORY_DIR / "reimplementations" / "micropython"


def _load_module_from_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# UUID STUB


@pytest.fixture(scope="module")
def uuid_stub():
    return _load_module_from_path("micropython_uuid_stub", MICROPYTHON_DIR / "stubs" / "uuid.py")


def test_micropython_uuid_stub_is_vendored_verbatim():
    assert (MICROPYTHON_DIR / "lib" / "uuid.py").read_bytes() == (MICROPYTHON_DIR / "stubs" / "uuid.py").read_bytes()


def test_micropython_uuid_stub_has_value_semantics(uuid_stub):
    reference = uuid.UUID("5e840838-7532-4b32-ba72-ccd17f7c923a")

    uid = uuid_stub.UUID(str(reference))
    assert (uid.bytes, uid.int, uid.hex, str(uid)) == (reference.bytes, reference.int, reference.hex, str(reference))

    for other in (
        uuid_stub.UUID(bytes=reference.bytes),
        uuid_stub.UUID(bytes=bytearray(reference.bytes)),
        uuid_stub.UUID(int=reference.int),
        uuid_stub.UUID(hex=reference.hex),
        uuid_stub.UUID("urn:uuid:{%s}" % reference),
    ):
        assert other is not uid
        assert other == uid and not (other != uid)
        assert hash(other) == hash(uid)
        assert isinstance(other.bytes, bytes)
        assert {uid: "value"}[other] == "value"  # A keystore dict is keyed by value, not by object identity

    different = uuid_stub.UUID(int=reference.int + 1)
    assert different != uid and different not in {uid: "value"}
    assert uid != str(reference) and uid != reference.bytes
    assert uuid_stub.UUID(int=0).bytes == bytes(16)  # The nil UUID is a valid value
    assert uuid_stub.uuid4() != uuid_stub.uuid4()

    for invalid_arguments in (dict(hex="1234"), dict(bytes=b"123"), dict(int=1 << 128), dict(int=-1)):
        with pytest.raises(ValueError):
            uuid_stub.UUID(**invalid_arguments)
    for invalid_arguments in (dict(), dict(hex=reference.hex, int=reference.int)):
        with pytest.raises(TypeError):
            uuid_stub.UUID(**invalid_arguments)


# PORT MODULES


@pytest.fixture(scope="module")
def port():
    """The port's "cryptainer" package, imported like its main.py does on CPython: stdlib modules and installed
    packages take precedence over the stubs and vendored copies of lib/."""
    added_paths = [str(MICROPYTHON_DIR / "src"), str(MICROPYTHON_DIR / "lib")]
    sys.path.extend(added_paths)
    try:
        names = dict(vars(importlib.import_module("cryptainer.input_validation")))
        names.update(vars(importlib.import_module("cryptainer.flightbox_utilities_implementation")))
        yield types.SimpleNamespace(**names)  # The public names of both modules
    finally:
        for added_path in added_paths:
            sys.path.remove(added_path)


# SHAMIR SHARED SECRETS


SHAMIR_SOURCE_PATH = REPOSITORY_DIR / "src" / "wacryptolib" / "_crypto_backend" / "pycryptodome_secret_sharing.py"
SHAMIR_COPY_PATH = MICROPYTHON_DIR / "src" / "cryptainer" / "pycryptodome_secret_sharing.py"


def test_micropython_shamir_module_is_a_verbatim_copy():
    assert SHAMIR_COPY_PATH.read_bytes() == SHAMIR_SOURCE_PATH.read_bytes(), "Both Shamir modules must be kept equal"


def test_shamir_module_calls_builtin_constructors_without_keywords():
    # MicroPython's int(), bytes()... take no keyword arguments ("function doesn't take keyword arguments")
    tree = ast.parse(SHAMIR_SOURCE_PATH.read_text(encoding="utf8"))
    keyword_calls = [
        "%s() at line %d" % (node.func.id, node.lineno)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("int", "bytes", "bytearray", "str", "bin", "range")
        and node.keywords
    ]
    assert not keyword_calls, keyword_calls


@pytest.mark.parametrize("shard_count, threshold_count", [(1, 1), (2, 1), (2, 2), (5, 3)])
def test_micropython_shamir_shards_are_recombined_by_wacryptolib(port, shard_count, threshold_count):
    utilities = port.FlightboxUtilitiesImpl(logger=logging.getLogger("micropython_port"), keystore_data={})
    secret = b"A secret longer than a single chunk of 16 bytes"
    shards = utilities.split_secret_into_shards(secret, shard_count=shard_count, threshold_count=threshold_count)
    assert [shard[0] for shard in shards] == list(range(1, shard_count + 1))
    assert recombine_secret_from_shards(shards[-threshold_count:]) == secret


# VALIDATING FLIGHTBOX


KEYSTORE_UID = uuid.UUID("5e840838-7532-4b32-ba72-ccd17f7c923a")
KEYCHAIN_UID = uuid.UUID("acd7f9f7-849b-44af-9765-9d4913b7f8dd")

# The points of low order of Curve25519, under their canonical encodings
X25519_LOW_ORDER_PUBLIC_KEYS = [
    bytes(32),
    b"\x01" + bytes(31),
    bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
    (2**255 - 19 - 1).to_bytes(32, "little"),
]


@pytest.fixture(scope="module")
def trustee_keys():
    """A wacryptolib keystore pool holding an RSA and an X25519 keypair, and the public key parameters that the
    keystore data of the port expects for them."""
    keystore_pool = InMemoryKeystorePool()
    keystore_pool._register_fake_imported_storage_uids([KEYSTORE_UID])
    keystore = keystore_pool.get_foreign_keystore(KEYSTORE_UID)
    public_key_parameters = {}
    for key_algo in ("RSA_OAEP", "ECIES_X25519"):
        generate_keypair_for_storage(key_algo, keystore=keystore, keychain_uid=KEYCHAIN_UID, passphrase=None)
        public_key_pem = keystore.get_public_key(keychain_uid=KEYCHAIN_UID, key_algo=key_algo)
        if key_algo == "RSA_OAEP":
            public_key = load_asymmetric_key_from_pem_bytestring(public_key_pem, key_algo=key_algo)
            public_key_parameters.update(n=int(public_key.n), e=int(public_key.e))
        else:  # The raw key ends the SubjectPublicKeyInfo structure
            base64_lines = [line for line in public_key_pem.decode("ascii").splitlines() if "-----" not in line]
            public_key_parameters.update(x25519=base64.b64decode("".join(base64_lines))[-32:])
    return keystore_pool, public_key_parameters


def _keystore_data(public_key_parameters):
    return {KEYSTORE_UID: {KEYCHAIN_UID: dict(public_key_parameters)}}


class _RandomDrawError(Exception):
    pass


def _build_flightbox(port, keystore_data, forbid_random_draws=False):
    utilities = port.FlightboxUtilitiesImpl(logger=logging.getLogger("micropython_port"), keystore_data=keystore_data)
    if forbid_random_draws:  # Random draws all happen in these calls, or after them

        def _forbidden_call(*args, **kwargs):
            raise _RandomDrawError("Random draw attempted")

        utilities.generate_uuid0 = utilities.generate_symkey = utilities.encrypt_bytestring = _forbidden_call
        utilities.split_secret_into_shards = _forbidden_call
    return port.ValidatingFlightBox(utilities)


def _trustee(**extra):
    # A new UUID object each time: keys are looked up by value
    return dict(trustee_type="authenticator", keystore_uid=uuid.UUID(str(KEYSTORE_UID)), **extra)


def _asymmetric_layer(key_cipher_algo="ECIES_X25519", **extra):
    return dict(key_cipher_algo=key_cipher_algo, key_cipher_trustee=_trustee(), **extra)


def _symmetric_layer(key_cipher_layers, key_cipher_algo="AES_CBC"):
    return dict(key_cipher_algo=key_cipher_algo, key_cipher_layers=key_cipher_layers)


def _shared_secret_layer(threshold, shard_layers):
    return dict(
        key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
        key_shared_secret_threshold=threshold,
        key_shared_secret_shards=[dict(key_cipher_layers=key_cipher_layers) for key_cipher_layers in shard_layers],
    )


def _cryptoconf(key_cipher_layers=None, **extra):
    payload_cipher_layer = dict(
        payload_cipher_algo="AES_CBC",
        key_cipher_layers=[_asymmetric_layer()] if key_cipher_layers is None else key_cipher_layers,
        payload_ciphertext_signatures=[],
    )
    return dict(payload_cipher_layers=[payload_cipher_layer], keychain_uid=uuid.UUID(str(KEYCHAIN_UID)), **extra)


def _nested_key_cipher_layers(level_count):
    """Return a "key_cipher_layers" list whose innermost list is `level_count - 1` levels deeper."""
    key_cipher_layers = [_asymmetric_layer()]
    for _ in range(level_count - 1):
        key_cipher_layers = [_symmetric_layer(key_cipher_layers)]
    return key_cipher_layers


def _nested_dicts(level_count):
    return functools.reduce(lambda tree, _: {"sub": tree}, range(level_count - 1), {})


def _finish_and_decrypt_cryptainer(cryptainer, secrets, keystore_pool):
    """Perform steps 2 and 3 with wacryptolib's primitives (the port stops after step 1), then check and decrypt."""
    payload = b"Some payload of the micropython port" * 5
    payload_current = payload
    for payload_cipher_layer, extract in zip(
        cryptainer["payload_cipher_layers"], secrets["payload_cipher_layer_extracts"]
    ):
        payload_cipherdict = encrypt_bytestring(
            payload_current, cipher_algo=extract["cipher_algo"], key_dict=extract["symkey"]
        )
        payload_current = payload_cipherdict.pop("ciphertext")
        payload_cipher_layer["payload_macs"] = payload_cipherdict
    cryptainer["payload_ciphertext_struct"] = dict(ciphertext_location="inline", ciphertext_value=payload_current)
    cryptainer["cryptainer_state"] = "FINISHED"

    cryptainer = load_from_json_bytes(dump_to_json_bytes(cryptainer))  # As read back from a file
    check_cryptainer_sanity(cryptainer)
    decrypted_payload, operation_report = decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)
    assert operation_report.get_error_count() == 0, operation_report.get_error_entries()
    assert decrypted_payload == payload


def test_micropython_cryptainers_are_decrypted_by_wacryptolib(port, trustee_keys):
    keystore_pool, public_key_parameters = trustee_keys
    flightbox = _build_flightbox(port, _keystore_data(public_key_parameters))

    cryptoconf = dict(
        keychain_uid=KEYCHAIN_UID,
        payload_plaintext_signatures=[],
        payload_cipher_layers=[
            dict(
                payload_cipher_algo="AES_CBC",
                key_cipher_layers=[
                    _asymmetric_layer("RSA_OAEP"),
                    _symmetric_layer([_asymmetric_layer("ECIES_X25519", keychain_uid=KEYCHAIN_UID)]),
                    _shared_secret_layer(
                        2,
                        [
                            [_asymmetric_layer("RSA_OAEP")],
                            [_asymmetric_layer("ECIES_X25519")],
                            [_symmetric_layer([_asymmetric_layer("RSA_OAEP")]), _asymmetric_layer("ECIES_X25519")],
                        ],
                    ),
                ],
                payload_ciphertext_signatures=[],
            ),
            dict(
                payload_cipher_algo="AES_CBC",
                key_cipher_layers=[_asymmetric_layer("ECIES_X25519")],
                payload_signatures=[],  # Legacy naming
            ),
        ],
    )
    cryptoconf_original = copy.deepcopy(cryptoconf)
    check_cryptoconf_sanity(cryptoconf)
    cryptainer_metadata = {
        "text": "é",
        "integer": -(2**63),
        "boolean": True,
        "nothing": None,
        "bytes": b"\x00\xff",
        "uid": KEYSTORE_UID,
        "list": [1, {"deep": []}],
        "$binary": "allowed, since this dict has several keys",
    }
    cryptainer_metadata_original = copy.deepcopy(cryptainer_metadata)

    cryptainer, secrets = flightbox.generate_cryptainer_base_and_secrets(cryptoconf, cryptainer_metadata)

    assert cryptoconf == cryptoconf_original
    assert cryptainer["cryptainer_metadata"] == cryptainer_metadata_original
    cryptainer["cryptainer_metadata"]["list"][1]["deep"].append("mutated")  # The cryptainer has its own copy
    assert cryptainer_metadata == cryptainer_metadata_original
    cryptainer["cryptainer_metadata"] = copy.deepcopy(cryptainer_metadata_original)

    assert "payload_signatures" not in cryptainer["payload_cipher_layers"][1]
    _finish_and_decrypt_cryptainer(cryptainer, secrets, keystore_pool=keystore_pool)

    # The key cipher nesting cap and the metadata nesting limit are inclusive
    assert port.MAX_KEY_CIPHER_NESTING >= 8  # Minimum allowed by the encryptor specification
    cryptoconf = _cryptoconf(_nested_key_cipher_layers(port.MAX_KEY_CIPHER_NESTING))
    cryptainer_metadata = _nested_dicts(port.MAX_METADATA_NESTING)
    cryptainer, secrets = flightbox.generate_cryptainer_base_and_secrets(cryptoconf, cryptainer_metadata)
    _finish_and_decrypt_cryptainer(cryptainer, secrets, keystore_pool=keystore_pool)

    # Without root keychain uid, each asymmetric layer must have its own one
    cryptoconf = _cryptoconf([_asymmetric_layer("RSA_OAEP", keychain_uid=KEYCHAIN_UID)])
    del cryptoconf["keychain_uid"]
    cryptainer, secrets = flightbox.generate_cryptainer_base_and_secrets(cryptoconf)
    assert cryptainer["keychain_uid"] != KEYCHAIN_UID  # Generated
    _finish_and_decrypt_cryptainer(cryptainer, secrets, keystore_pool=keystore_pool)


def _invalid_input_cases():
    """Yield (case name, error class name, cryptoconf, kwargs) tuples, each input having a single defect."""

    def _mutated(mutator, **kwargs):
        cryptoconf = _cryptoconf(**kwargs)
        mutator(cryptoconf, cryptoconf["payload_cipher_layers"][0])
        return cryptoconf

    def _with_trustee(trustee):
        return _cryptoconf([dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=trustee)])

    invalid, unsupported, too_deep, missing_key = (
        "InvalidInputError",
        "UnsupportedFeatureError",
        "NestingTooDeepError",
        "MissingPublicKeyError",
    )
    signature_conf = dict(
        payload_digest_algo="SHA256", payload_signature_algo="RSA_PSS", payload_signature_trustee=_trustee()
    )
    single_shard_layer = [_shared_secret_layer(1, [[_asymmetric_layer()]])]

    # Schema violations (encryptor specification, section 5.1)
    cases = [
        ("cryptoconf_not_dict", [_cryptoconf()]),
        ("cryptoconf_unknown_key", _cryptoconf(unknown_key=1)),
        ("cryptoconf_output_field", _cryptoconf(cryptainer_state="STARTED")),
        ("cryptoconf_no_layers_key", dict(keychain_uid=KEYCHAIN_UID)),
        ("payload_layers_empty", dict(payload_cipher_layers=[], keychain_uid=KEYCHAIN_UID)),
        ("payload_layers_tuple", _mutated(lambda c, l: c.update(payload_cipher_layers=(l,)))),
        ("payload_layer_not_dict", _mutated(lambda c, l: c.update(payload_cipher_layers=["AES_CBC"]))),
        ("payload_layer_output_field", _mutated(lambda c, l: l.update(key_ciphertext=b"x"))),
        ("payload_layer_format_field", _mutated(lambda c, l: l.update(key_ciphertext_format="json"))),
        ("payload_layer_no_algo", _mutated(lambda c, l: l.pop("payload_cipher_algo"))),
        ("payload_algo_unknown", _mutated(lambda c, l: l.update(payload_cipher_algo="aes_cbc"))),
        ("payload_algo_asymmetric", _mutated(lambda c, l: l.update(payload_cipher_algo="RSA_OAEP"))),
        ("root_keychain_uid_text", _mutated(lambda c, l: c.update(keychain_uid=str(KEYCHAIN_UID)))),
        ("root_keychain_uid_null", _mutated(lambda c, l: c.update(keychain_uid=None))),
        ("no_signature_key", _mutated(lambda c, l: l.pop("payload_ciphertext_signatures"))),
        ("both_signature_keys", _mutated(lambda c, l: l.update(payload_signatures=[]))),
        ("signatures_not_list", _mutated(lambda c, l: l.update(payload_ciphertext_signatures=None))),
        ("plaintext_signatures_not_list", _cryptoconf(payload_plaintext_signatures={})),
        ("key_layers_empty", _cryptoconf([])),
        ("key_layers_tuple", _cryptoconf((_asymmetric_layer(),))),
        (
            "key_layers_empty_in_second_layer",
            _mutated(lambda c, l: c["payload_cipher_layers"].append(dict(l, key_cipher_layers=[]))),
        ),
        ("key_layer_not_dict", _cryptoconf(["RSA_OAEP"])),
        ("key_layer_no_algo", _cryptoconf([dict(key_cipher_trustee=_trustee())])),
        ("key_algo_unknown", _cryptoconf([_asymmetric_layer("ML_DSA_65")])),
        ("key_algo_lowercase", _cryptoconf([_asymmetric_layer("rsa_oaep")])),
        ("asymmetric_layer_unknown_key", _cryptoconf([_asymmetric_layer(key_cipher_layers=[])])),
        ("asymmetric_layer_no_trustee", _cryptoconf([dict(key_cipher_algo="RSA_OAEP")])),
        ("layer_keychain_uid_text", _cryptoconf([_asymmetric_layer(keychain_uid=str(KEYCHAIN_UID))])),
        ("layer_keychain_uid_null", _cryptoconf([_asymmetric_layer(keychain_uid=None)])),
        ("trustee_not_dict", _with_trustee("authenticator")),
        ("trustee_unknown_type", _with_trustee(dict(trustee_type="oracle"))),
        ("trustee_unhashable_type", _with_trustee(dict(trustee_type=["authenticator"]))),
        ("trustee_no_type", _with_trustee(dict(keystore_uid=KEYSTORE_UID))),
        ("trustee_no_keystore_uid", _with_trustee(dict(trustee_type="authenticator"))),
        ("trustee_keystore_uid_text", _with_trustee(dict(_trustee(), keystore_uid=str(KEYSTORE_UID)))),
        ("trustee_keystore_owner_not_text", _with_trustee(_trustee(keystore_owner=3))),
        ("trustee_unknown_key", _with_trustee(_trustee(jsonrpc_url="http://example.com"))),
        ("trustee_keyfactory_with_keystore", _with_trustee(dict(_trustee(), trustee_type="local_keyfactory"))),
        ("trustee_jsonrpc_without_url", _with_trustee(dict(trustee_type="jsonrpc_api"))),
        ("symmetric_layer_no_sublayers", _cryptoconf([dict(key_cipher_algo="AES_CBC")])),
        (
            "symmetric_layer_with_trustee",
            _cryptoconf([dict(_symmetric_layer([_asymmetric_layer()]), key_cipher_trustee=_trustee())]),
        ),
        ("shards_empty", _cryptoconf([_shared_secret_layer(1, [])])),
        ("shard_layers_empty", _cryptoconf([_shared_secret_layer(1, [[]])])),
        (
            "shard_unknown_key",
            _mutated(
                lambda c, l: l["key_cipher_layers"][0]["key_shared_secret_shards"][0].update(keychain_uid=KEYCHAIN_UID),
                key_cipher_layers=copy.deepcopy(single_shard_layer),
            ),
        ),
        (
            "shared_secret_no_threshold",
            _mutated(
                lambda c, l: l["key_cipher_layers"][0].pop("key_shared_secret_threshold"),
                key_cipher_layers=copy.deepcopy(single_shard_layer),
            ),
        ),
    ]
    for name, threshold in [("bool", True), ("zero", 0), ("too_high", 3), ("text", "1"), ("float", 1.0)]:
        two_shards = [[_asymmetric_layer()], [_asymmetric_layer()]]
        cases.append(("threshold_" + name, _cryptoconf([_shared_secret_layer(threshold, two_shards)])))
    for name, cryptoconf in cases:
        yield name, invalid, cryptoconf, {}
    yield "unknown_key_ciphertext_format", invalid, _cryptoconf(), dict(key_ciphertext_format="yaml")

    # Valid inputs outside the subset of the port
    cases = [
        ("payload_algo_unsupported", _mutated(lambda c, l: l.update(payload_cipher_algo="AES_EAX"))),
        (
            "symmetric_key_algo_unsupported",
            _cryptoconf([_symmetric_layer([_asymmetric_layer()], key_cipher_algo="CHACHA20_POLY1305")]),
        ),
        ("asymmetric_key_algo_unsupported", _cryptoconf([_asymmetric_layer("ML_KEM_768")])),
        (
            "trustee_type_unsupported_in_second_layer",
            _cryptoconf(
                [
                    _asymmetric_layer(),
                    dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=dict(trustee_type="local_keyfactory")),
                ]
            ),
        ),
        ("trustee_jsonrpc_unsupported", _with_trustee(dict(trustee_type="jsonrpc_api", jsonrpc_url="http://x"))),
        ("ciphertext_signatures", _mutated(lambda c, l: l.update(payload_ciphertext_signatures=[signature_conf]))),
        (
            "legacy_signatures",
            _mutated(
                lambda c, l: l.pop("payload_ciphertext_signatures") or l.update(payload_signatures=[signature_conf])
            ),
        ),
        ("plaintext_signatures", _cryptoconf(payload_plaintext_signatures=[signature_conf])),
    ]
    for name, cryptoconf in cases:
        yield name, unsupported, cryptoconf, {}
    yield "cbor_key_ciphertext_format", unsupported, _cryptoconf(), dict(key_ciphertext_format="cbor")

    # Nesting of key cipher layers: 8 levels are accepted (see the test above)
    yield "key_layers_too_deep", too_deep, _cryptoconf(_nested_key_cipher_layers(9)), {}
    yield "key_layers_far_too_deep", too_deep, _cryptoconf(_nested_key_cipher_layers(60)), {}
    shard_layers_at_level_3_to_9 = _nested_key_cipher_layers(7)
    yield "shards_too_deep", too_deep, _cryptoconf(
        [_symmetric_layer([_shared_secret_layer(1, [shard_layers_at_level_3_to_9])])]
    ), {}

    # Unresolvable keys
    cases = [
        ("missing_keychain", _cryptoconf([_asymmetric_layer(keychain_uid=uuid.UUID(int=0))])),
        ("missing_keystore", _with_trustee(dict(trustee_type="authenticator", keystore_uid=uuid.UUID(int=1)))),
        (
            "missing_keychain_in_shard",
            _cryptoconf(
                [_shared_secret_layer(1, [[_asymmetric_layer()], [_asymmetric_layer(keychain_uid=uuid.UUID(int=0))]])]
            ),
        ),
        ("no_keychain_uid_at_all", _mutated(lambda c, l: c.pop("keychain_uid"))),
    ]
    for name, cryptoconf in cases:
        yield name, missing_key, cryptoconf, {}

    # Cryptainer metadata (encryptor specification, section 5.4)
    for name, error_class_name, cryptainer_metadata in [
        ("list", invalid, [1]),
        ("text", invalid, "text"),
        ("empty_tuple", invalid, ()),
        ("integer_key", invalid, {1: "a"}),
        ("keyword_map", invalid, {"y": {"$binary": "oops"}}),
        ("keyword_map_at_root", invalid, {"$uuid": "5e840838-7532-4b32-ba72-ccd17f7c923a"}),
        ("keyword_map_in_list", invalid, {"y": [[{"$numberLong": "1"}]]}),
        ("undefined_keyword", invalid, {"y": {"$undefined": True}}),
        ("bytearray", unsupported, {"y": bytearray(b"ab")}),
        ("set", unsupported, {"y": {1, 2}}),
        ("tuple", unsupported, {"y": (1, 2)}),
        ("float", unsupported, {"y": 0.5}),
        ("infinity", unsupported, {"y": float("inf")}),
        ("big_integer", unsupported, {"y": 2**63}),
        ("too_deep", too_deep, _nested_dicts(64)),
        ("too_deep_lists", too_deep, {"sub": functools.reduce(lambda tree, _: [tree], range(63), [])}),
    ]:
        yield "metadata_" + name, error_class_name, _cryptoconf(), dict(cryptainer_metadata=cryptainer_metadata)


@pytest.mark.parametrize(
    "error_class_name, cryptoconf, kwargs",
    [pytest.param(*case[1:], id=case[0]) for case in _invalid_input_cases()],
)
def test_micropython_flightbox_rejects_bad_inputs_before_any_random_draw(
    port, trustee_keys, error_class_name, cryptoconf, kwargs
):
    _keystore_pool, public_key_parameters = trustee_keys
    flightbox = _build_flightbox(port, _keystore_data(public_key_parameters), forbid_random_draws=True)
    cryptoconf_original = copy.deepcopy(cryptoconf)

    with pytest.raises(port.FlightboxError) as exc_info:
        flightbox.generate_cryptainer_base_and_secrets(cryptoconf, **kwargs)

    assert type(exc_info.value) is getattr(port, error_class_name)  # A dedicated error category
    assert isinstance(exc_info.value, RuntimeError)  # Backwards compatibility
    assert cryptoconf == cryptoconf_original

    # The defect was the cause of the rejection: valid inputs go as far as the first random draw
    with pytest.raises(_RandomDrawError):
        flightbox.generate_cryptainer_base_and_secrets(_cryptoconf(), cryptainer_metadata={"valid": [None]})


def test_micropython_flightbox_rejects_invalid_public_keys_before_any_random_draw(port, trustee_keys):
    _keystore_pool, public_key_parameters = trustee_keys
    n, e, x25519 = public_key_parameters["n"], public_key_parameters["e"], public_key_parameters["x25519"]
    hpke_x25519_seal = importlib.import_module("hpke_x25519_seal")
    get_public_key_kwargs = dict(trustee=_trustee(), keychain_uid=KEYCHAIN_UID)

    invalid_rsa_numbers = [
        (n, 1),  # Leaves the OAEP encoding readable by anyone
        (n, 2),
        (n, 0),
        (n, -65537),
        (n, n),
        (n, n + 2),
        (n + 1, e),  # Even modulus
        (n * 3, 3),  # Exponent sharing a factor with the modulus
        (n >> 1 | 1, e),  # 2047 bits
        ((1 << 4096) + 1, e),  # Beyond the maximum modulus size
        (True, e),
        (n, True),
        (float(e), e),
        (str(n), e),
        (n, None),
    ]
    invalid_x25519_keys = X25519_LOW_ORDER_PUBLIC_KEYS + [
        (2**255 - 19).to_bytes(32, "little"),  # Non-canonical encodings
        x25519[:31] + bytes([x25519[31] | 0x80]),
        x25519[:31],
        x25519 + b"\x00",
        bytearray(x25519),
        x25519.hex(),
        None,
    ]
    invalid_keys = [("RSA_OAEP", dict(n=invalid_n, e=invalid_e)) for invalid_n, invalid_e in invalid_rsa_numbers]
    invalid_keys += [("ECIES_X25519", dict(x25519=invalid_x25519)) for invalid_x25519 in invalid_x25519_keys]

    for key_algo, invalid_parameters in invalid_keys:
        flightbox = _build_flightbox(port, _keystore_data(invalid_parameters), forbid_random_draws=True)
        with pytest.raises(port.KeyConstraintError):
            flightbox.generate_cryptainer_base_and_secrets(_cryptoconf([_asymmetric_layer(key_algo)]))
        with pytest.raises(port.KeyConstraintError):  # Also enforced without upfront validation
            flightbox._fbu.get_public_key(key_algo=key_algo, **get_public_key_kwargs)

    for low_order_public_key in X25519_LOW_ORDER_PUBLIC_KEYS:  # These constants really are what the sealing rejects
        with pytest.raises(ValueError, match="low order point"):
            hpke_x25519_seal.seal(low_order_public_key, b"plaintext")

    # A keystore entry holding the key of another algo only
    flightbox = _build_flightbox(port, _keystore_data(dict(x25519=x25519)), forbid_random_draws=True)
    with pytest.raises(port.MissingPublicKeyError):
        flightbox.generate_cryptainer_base_and_secrets(_cryptoconf([_asymmetric_layer("RSA_OAEP")]))

    # Extreme valid values are accepted
    utilities = _build_flightbox(port, _keystore_data(dict(n=(1 << 4096) - 3, e=3, x25519=x25519)))._fbu
    assert utilities.get_public_key(key_algo="RSA_OAEP", **get_public_key_kwargs).n == (1 << 4096) - 3
    assert utilities.get_public_key(key_algo="ECIES_X25519", **get_public_key_kwargs) == x25519
    utilities = _build_flightbox(port, _keystore_data(dict(n=(1 << 2047) + 1, e=(1 << 2047) - 1)))._fbu
    assert utilities.get_public_key(key_algo="RSA_OAEP", **get_public_key_kwargs).e == (1 << 2047) - 1


def test_micropython_utilities_reject_unsupported_algos_without_assertions(port, trustee_keys):
    # Assertions are stripped by "micropython -O" and by mpy-cross optimizations, so real exceptions are needed
    _keystore_pool, public_key_parameters = trustee_keys
    utilities = _build_flightbox(port, _keystore_data(public_key_parameters))._fbu

    for cipher_algo in ("AES_EAX", "CHACHA20_POLY1305", "RSA_OAEP", "aes_cbc", None):
        with pytest.raises(port.UnsupportedFeatureError):
            utilities.generate_symkey(cipher_algo)
    for key_algo in ("ML_KEM_768", "AES_CBC", None):
        with pytest.raises(port.UnsupportedFeatureError):
            utilities.get_public_key(trustee=_trustee(), key_algo=key_algo, keychain_uid=KEYCHAIN_UID)
    with pytest.raises(port.UnsupportedFeatureError):
        utilities.encrypt_bytestring(b"data", cipher_algo="AES_EAX", key_dict=dict(key=bytes(32), nonce=bytes(16)))
    with pytest.raises(port.InvalidInputError, match="some message"):
        utilities.raise_validation_error("some message")

    # The bare core, without upfront validation, gets these errors too, instead of an AES_CBC-shaped key
    flightbox = port.FlightBox(utilities)
    cryptoconf = _cryptoconf()
    cryptoconf["payload_cipher_layers"][0]["payload_cipher_algo"] = "CHACHA20_POLY1305"
    with pytest.raises(port.UnsupportedFeatureError, match="Unsupported symmetric cipher algo 'CHACHA20_POLY1305'"):
        flightbox.generate_cryptainer_base_and_secrets(cryptoconf)
    with pytest.raises(port.InvalidInputError, match="Unsupported key cipher algo 'ML_KEM_768'"):
        flightbox.generate_cryptainer_base_and_secrets(_cryptoconf([_asymmetric_layer("ML_KEM_768")]))
