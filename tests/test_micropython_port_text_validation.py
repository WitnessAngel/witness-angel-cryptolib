# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests of the text string check of the MicroPython flightbox port (reimplementations/micropython/), run with
CPython: a MicroPython str may hold ill-formed UTF-8 (encoded surrogates, overlong forms...), which wacryptolib can't
load, so the port must refuse it before any random draw (finding MPY3-1). Such strings are simulated here by a str
subclass whose encode() returns the raw bytes, like MicroPython's."""

import base64
import importlib
import logging
import sys
import types
import uuid
from pathlib import Path

import pytest

from wacryptolib.cipher import encrypt_bytestring
from wacryptolib.cryptainer import check_cryptainer_sanity, decrypt_payload_from_cryptainer
from wacryptolib.keygen import load_asymmetric_key_from_pem_bytestring
from wacryptolib.keystore import InMemoryKeystorePool, generate_keypair_for_storage
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes

REPOSITORY_DIR = Path(__file__).resolve().parents[1]
MICROPYTHON_DIR = REPOSITORY_DIR / "reimplementations" / "micropython"

KEYSTORE_UID = uuid.UUID("5e840838-7532-4b32-ba72-ccd17f7c923a")
KEYCHAIN_UID = uuid.UUID("acd7f9f7-849b-44af-9765-9d4913b7f8dd")

# Byte forms which MicroPython's bytes.decode() accepts, but which are not well-formed UTF-8
ILL_FORMED_UTF8_SAMPLES = (
    b"\xed\xa0\x80",  # U+D800, a high surrogate
    b"\xed\xbf\xbf",  # U+DFFF, a low surrogate
    b"\xed\xa0\xbd\xed\xb8\x80",  # The surrogate pair of U+1F600, encoded as two "characters" (CESU-8)
    b"\xc0\x80",  # Overlong NUL
    b"\xc1\xbf",  # Overlong U+007F
    b"\xe0\x80\xaf",  # Overlong "/"
    b"\xe0\x9f\xbf",  # Overlong U+07FF
    b"\xf0\x80\x80\xaf",  # Overlong "/"
    b"\xf0\x8f\xbf\xbf",  # Overlong U+FFFF
    b"\xf4\x90\x80\x80",  # U+110000
    b"\xf5\x80\x80\x80",
    b"\xf8\x88\x80\x80\x80",
    b"\x80",
    b"\xc3",
    b"\xe2\x82",
    b"\xf0\x9f\x98",
    b"\xe9t\xe9",  # Latin-1
    b"\xff",
)

# Valid non-ASCII text, at the boundaries of each UTF-8 sequence length and around the surrogates
WELL_FORMED_TEXTS = (
    "",
    "plain ASCII \x00\x1f\x7f",
    "\x80é\u07ff",
    "\u0800录音机日本語\ud7ff\ue000\ufffd\ufffe\uffff",
    "\U00010000\U0001f600\U0001f3a5\U0010fffd\U0010ffff",
    "Jérôme \U0001f600 录音",
)


class MicroPythonStr(str):
    """A str holding raw bytes that may be ill-formed UTF-8, like a MicroPython str built by bytes.decode()."""

    def __new__(cls, raw):
        instance = super().__new__(cls, raw.decode("utf-8", "replace"))
        instance.raw = raw
        return instance

    def encode(self, *args, **kwargs):
        return self.raw

    def __add__(self, other):
        return MicroPythonStr(self.raw + other.encode())

    def __radd__(self, other):  # Taken before str.__add__(), this being a subclass
        return MicroPythonStr(other.encode() + self.raw)

    __hash__ = str.__hash__  # Usable as a dict key


@pytest.fixture(scope="module")
def port():
    """The port's modules, imported like its main.py does on CPython (stdlib modules and installed packages take
    precedence over the stubs and vendored copies of lib/), lib/ staying importable for lazy imports."""
    added_paths = [str(MICROPYTHON_DIR / "src"), str(MICROPYTHON_DIR / "lib")]
    sys.path.extend(added_paths)
    try:
        yield types.SimpleNamespace(
            text_validation=importlib.import_module("cryptainer.text_validation"),
            flightbox=importlib.import_module("cryptainer._flightbox"),
            utilities=importlib.import_module("cryptainer.flightbox_utilities_implementation"),
        )
    finally:
        for added_path in added_paths:
            sys.path.remove(added_path)


@pytest.fixture(scope="module")
def trustee_keys():
    """A wacryptolib keystore pool holding an RSA and an X25519 keypair, and the keystore data of the port for them."""
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
    return keystore_pool, {KEYSTORE_UID: {KEYCHAIN_UID: public_key_parameters}}


def _build_utilities_without_random_draws(port, keystore_data=None):
    """Utilities which fail the test on any random draw."""

    class _Utilities(port.utilities.FlightboxUtilitiesImpl):
        def generate_uuid0(self):
            raise AssertionError("Random draw for a UUID")

        def generate_symkey(self, cipher_algo):
            raise AssertionError("Random draw for a symkey")

        def split_secret_into_shards(self, secret, *, shard_count, threshold_count):
            raise AssertionError("Random draw for shards")

    return _Utilities(logger=logging.getLogger("micropython_port"), keystore_data=keystore_data or {})


def _asymmetric_layer(key_cipher_algo, **trustee_extra):
    trustee = dict(trustee_type="authenticator", keystore_uid=KEYSTORE_UID, **trustee_extra)
    return dict(key_cipher_algo=key_cipher_algo, key_cipher_trustee=trustee)


def _cryptoconf(*key_cipher_layers, payload_cipher_algo="AES_CBC"):
    return dict(
        keychain_uid=KEYCHAIN_UID,
        payload_cipher_layers=[
            dict(
                payload_cipher_algo=payload_cipher_algo,
                key_cipher_layers=list(key_cipher_layers) or [_asymmetric_layer("ECIES_X25519")],
                payload_ciphertext_signatures=[],
            )
        ],
    )


def _finish_cryptainer(cryptainer, secrets, payload):
    """Perform steps 2 and 3 with wacryptolib's primitives (the port stops after step 1)."""
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
    return cryptainer


def test_micropython_utf8_check_matches_a_strict_decoder(port):
    is_well_formed_utf8 = port.text_validation.is_well_formed_utf8

    for raw in ILL_FORMED_UTF8_SAMPLES:
        for data in (raw, b"abc" + raw, raw + b"xyz", "é".encode() + raw + "\U0001f600".encode()):
            assert not is_well_formed_utf8(data), data

    for text in WELL_FORMED_TEXTS:
        assert is_well_formed_utf8(text.encode()), text

    # Every scalar value is accepted, and every encoded surrogate refused
    for code_point in list(range(0, 0x3000)) + list(range(0x3000, 0x110000, 251)) + [0xFFFF, 0x10000, 0x10FFFF]:
        if 0xD800 <= code_point <= 0xDFFF:
            assert not is_well_formed_utf8(chr(code_point).encode("utf-8", "surrogatepass")), hex(code_point)
        else:
            assert is_well_formed_utf8(chr(code_point).encode()), hex(code_point)

    # Same verdict as CPython's strict decoder, on all sequences of 1 or 2 bytes, and on all 3 and 4 byte
    # sequences whose lead byte is not ASCII, with a sample of continuation bytes
    def strict_verdict(data):
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True

    tail_bytes = (0x00, 0x41, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xFF)
    for first in range(256):
        assert is_well_formed_utf8(bytes([first])) == strict_verdict(bytes([first])), first
        for second in range(256):
            data = bytes([first, second])
            assert is_well_formed_utf8(data) == strict_verdict(data), data
            if first < 0xE0:
                continue
            for third in tail_bytes:
                data = bytes([first, second, third])
                assert is_well_formed_utf8(data) == strict_verdict(data), data
                if first >= 0xF0:
                    for fourth in tail_bytes:
                        data = bytes([first, second, third, fourth])
                        assert is_well_formed_utf8(data) == strict_verdict(data), data


def test_micropython_text_check_refuses_lone_surrogates_and_ill_formed_bytes(port):
    is_well_formed_text = port.text_validation.is_well_formed_text

    for text in WELL_FORMED_TEXTS:
        assert is_well_formed_text(text)
        assert is_well_formed_text(MicroPythonStr(text.encode()))

    for text in ("\ud800", "abc\udfff", "\udc00x", "\ud83d"):  # CPython's own lone surrogates
        assert not is_well_formed_text(text)

    for raw in ILL_FORMED_UTF8_SAMPLES:
        assert not is_well_formed_text(MicroPythonStr(b"label " + raw))


def test_micropython_text_check_walks_whole_data_trees(port):
    find_ill_formed_text = port.text_validation.find_ill_formed_text
    bad = MicroPythonStr(b"cam\xed\xa0\x80")

    for tree in (None, 12, b"\xed\xa0\x80", KEYCHAIN_UID, True, 1.5, "fine \U0001f600", {}, [], ()):
        assert find_ill_formed_text(tree) is None
    assert find_ill_formed_text({"é": ["录", ("\U0010ffff", {b"k": b"\xff"}), {1: "x"}]}) is None

    assert find_ill_formed_text(bad) == ""
    assert find_ill_formed_text("\ud800") == ""
    assert find_ill_formed_text({"label": bad}) == "['label']"
    assert find_ill_formed_text({bad: 1}) == " (a key)"
    assert find_ill_formed_text({"a": {"b": {bad: None}}}) == "['a']['b'] (a key)"
    assert find_ill_formed_text({"a": [1, {"b": ("x", [bad])}]}) == "['a'][1]['b'][1][0]"
    assert find_ill_formed_text([{"ok": "fine"}, {"x": "\udfff"}]) == "[1]['x']"


@pytest.mark.parametrize("bad_text_source", ILL_FORMED_UTF8_SAMPLES[:12] + ("\ud800", "x\udfff"), ids=ascii)
def test_micropython_validating_flightbox_refuses_ill_formed_text_before_any_random_draw(port, bad_text_source):
    # Bytes give a MicroPython-like str, and a str is one of CPython's lone surrogates
    bad_text = MicroPythonStr(bad_text_source) if isinstance(bad_text_source, bytes) else bad_text_source
    flightbox = port.utilities.ValidatingFlightBox(flightbox_utilities=_build_utilities_without_random_draws(port))

    def check_refused(cryptoconf, cryptainer_metadata, expected_location):
        with pytest.raises(RuntimeError, match="not a sequence of Unicode scalar values") as exc_info:
            flightbox.generate_cryptainer_base_and_secrets(cryptoconf, cryptainer_metadata=cryptainer_metadata)
        assert expected_location in str(exc_info.value)

    # Keys and values of the metadata, at any depth
    check_refused(_cryptoconf(), {"label": bad_text}, "cryptainer_metadata['label']")
    check_refused(_cryptoconf(), {"k" + bad_text: 1}, "cryptainer_metadata (a key)")
    check_refused(_cryptoconf(), {"a": [1, {"b": ("x", [bad_text])}]}, "cryptainer_metadata['a'][1]['b'][1][0]")
    check_refused(_cryptoconf(), {"a": {"b": {bad_text: None}}}, "cryptainer_metadata['a']['b'] (a key)")

    # Any text of the cryptoconf, which is copied into the cryptainer
    trustee_layer = _asymmetric_layer("ECIES_X25519", keystore_owner="owner " + bad_text)
    check_refused(_cryptoconf(trustee_layer), None, "['key_cipher_trustee']['keystore_owner']")
    check_refused(_cryptoconf(payload_cipher_algo="AES_CBC" + bad_text), None, "['payload_cipher_algo']")
    cryptoconf = _cryptoconf()
    cryptoconf["keychain_uid"] = str(KEYCHAIN_UID) + bad_text  # A uid given as text
    check_refused(cryptoconf, None, "cryptoconf['keychain_uid']")
    cryptoconf = _cryptoconf()
    cryptoconf["payload_cipher_layers"][0]["extra_field"] = {bad_text: "value"}
    check_refused(cryptoconf, None, "cryptoconf['payload_cipher_layers'][0]['extra_field'] (a key)")

    # The base FlightBox class, for comparison, draws random bytes before finding anything
    bare_flightbox = port.flightbox.FlightBox(flightbox_utilities=_build_utilities_without_random_draws(port))
    with pytest.raises(AssertionError, match="Random draw"):
        bare_flightbox.generate_cryptainer_base_and_secrets(_cryptoconf(), cryptainer_metadata={"label": bad_text})


def test_micropython_json_serialization_refuses_ill_formed_utf8(port, monkeypatch):
    """Last resort of a bare FlightBox: a key struct whose JSON is not well-formed UTF-8 (as MicroPython's json module
    writes ill-formed strings as is) is refused, so that no cryptainer is produced."""
    utilities = port.utilities.FlightboxUtilitiesImpl(logger=logging.getLogger("micropython_port"), keystore_data={})
    assert utilities.dump_to_json_bytes({"a": "é\U0001f600"}) == b'{"a": "\\u00e9\\ud83d\\ude00"}'

    monkeypatch.setattr(port.utilities, "dump_to_json_bytes", lambda data: b'{"a": "cam\xed\xa0\x80"}')
    with pytest.raises(RuntimeError, match=r"cryptainer_metadata \(in a key struct\) is not a sequence of Unicode"):
        utilities.dump_to_json_bytes({"a": "anything"})
    monkeypatch.setattr(port.utilities, "dump_to_json_bytes", lambda data: '{"a": "é"}'.encode())
    assert utilities.dump_to_json_bytes({"a": "anything"}) == '{"a": "é"}'.encode()


@pytest.mark.parametrize("bare", [False, True])
def test_micropython_well_formed_non_ascii_text_decrypts_with_wacryptolib(port, trustee_keys, bare):
    keystore_pool, keystore_data = trustee_keys
    utilities = port.utilities.FlightboxUtilitiesImpl(
        logger=logging.getLogger("micropython_port"), keystore_data=keystore_data
    )
    flightbox_class = port.flightbox.FlightBox if bare else port.utilities.ValidatingFlightBox
    flightbox = flightbox_class(flightbox_utilities=utilities)

    cryptainer_metadata = {
        "accents": "éàüçÉ",
        "cjk": "录音机 日本語",
        "emoji": "\U0001f600\U0001f3a5",
        "boundaries": list(WELL_FORMED_TEXTS),
        "clé \U0010ffff": {"\uffff": ["ü", {"\U0001f600": "\U0010ffff"}]},
    }
    cryptoconf = _cryptoconf(
        _asymmetric_layer("RSA_OAEP", keystore_owner="Jérôme 录音 \U0001f600"),
        dict(key_cipher_algo="AES_CBC", key_cipher_layers=[_asymmetric_layer("ECIES_X25519")]),
    )
    cryptainer, secrets = flightbox.generate_cryptainer_base_and_secrets(
        cryptoconf, cryptainer_metadata=cryptainer_metadata
    )

    payload = b"some recording \x00\xff" * 10
    cryptainer = _finish_cryptainer(cryptainer, secrets, payload)
    assert cryptainer["cryptainer_metadata"] == cryptainer_metadata
    keystore_owner = cryptainer["payload_cipher_layers"][0]["key_cipher_layers"][0]["key_cipher_trustee"]
    assert keystore_owner["keystore_owner"] == "Jérôme 录音 \U0001f600"

    decrypted, report = decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)
    assert decrypted == payload
    assert not report.get_error_entries()
