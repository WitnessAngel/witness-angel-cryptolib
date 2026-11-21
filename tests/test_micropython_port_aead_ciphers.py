# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests of the AEAD symmetric cipher of the MicroPython flightbox port (reimplementations/micropython/), run with
CPython: the port's cryptainers must be able to have an integrity-protected payload (finding MPY2-1), which
AES_CBC can't give without signatures."""

import base64
import importlib
import logging
import re
import sys
import types
import uuid
from pathlib import Path

import pytest

from wacryptolib.cipher import decrypt_bytestring, encrypt_bytestring
from wacryptolib.cryptainer import (
    check_cryptainer_sanity,
    check_cryptoconf_sanity,
    decrypt_payload_from_cryptainer,
    DecryptionErrorType,
)
from wacryptolib.keygen import check_symkey_dict_sanity, load_asymmetric_key_from_pem_bytestring
from wacryptolib.keystore import InMemoryKeystorePool, generate_keypair_for_storage
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes

REPOSITORY_DIR = Path(__file__).resolve().parents[1]
MICROPYTHON_DIR = REPOSITORY_DIR / "reimplementations" / "micropython"

KEYSTORE_UID = uuid.UUID("5e840838-7532-4b32-ba72-ccd17f7c923a")
KEYCHAIN_UID = uuid.UUID("acd7f9f7-849b-44af-9765-9d4913b7f8dd")

AEAD_CIPHER_ALGOS = ("AES_EAX", "CHACHA20_POLY1305")


@pytest.fixture(scope="module")
def port():
    """The port's "cryptainer" package, imported like its main.py does on CPython (stdlib modules and installed
    packages take precedence over the stubs and vendored copies of lib/), lib/ staying importable for lazy imports."""
    added_paths = [str(MICROPYTHON_DIR / "src"), str(MICROPYTHON_DIR / "lib")]
    sys.path.extend(added_paths)
    try:
        names = dict(vars(importlib.import_module("cryptainer._flightbox")))
        names.update(vars(importlib.import_module("cryptainer.flightbox_utilities_implementation")))
        yield types.SimpleNamespace(**names)
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


def _build_utilities(port, keystore_data=None):
    return port.FlightboxUtilitiesImpl(logger=logging.getLogger("micropython_port"), keystore_data=keystore_data or {})


def _asymmetric_layer(key_cipher_algo):
    trustee = dict(trustee_type="authenticator", keystore_uid=KEYSTORE_UID)
    return dict(key_cipher_algo=key_cipher_algo, key_cipher_trustee=trustee)


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


def test_micropython_chacha20_poly1305_matches_wacryptolib(port):
    utilities = _build_utilities(port)
    assert "CHACHA20_POLY1305" in utilities.SUPPORTED_SYMMETRIC_CIPHER_ALGOS

    symkey = utilities.generate_symkey("CHACHA20_POLY1305")
    assert sorted(symkey) == ["key", "nonce"] and (len(symkey["key"]), len(symkey["nonce"])) == (32, 12)
    check_symkey_dict_sanity(symkey, cipher_algo="CHACHA20_POLY1305")
    assert utilities.generate_symkey("CHACHA20_POLY1305") != symkey

    for plaintext_length in (0, 1, 63, 64, 65, 1000):
        plaintext = bytes(range(256)) * 4
        plaintext = plaintext[:plaintext_length]
        cipherdict = utilities.encrypt_bytestring(plaintext, cipher_algo="CHACHA20_POLY1305", key_dict=symkey)
        assert cipherdict == encrypt_bytestring(plaintext, cipher_algo="CHACHA20_POLY1305", key_dict=symkey)
        assert decrypt_bytestring(cipherdict, cipher_algo="CHACHA20_POLY1305", key_dict=symkey) == plaintext

    with pytest.raises(ValueError, match="32 bytes"):
        utilities.encrypt_bytestring(b"data", cipher_algo="CHACHA20_POLY1305", key_dict=dict(key=bytes(16), nonce=bytes(12)))


def test_micropython_rejects_unsupported_symmetric_cipher_algos(port):
    utilities = _build_utilities(port)
    for cipher_algo in ("AES_EAX", "aes_cbc", "RSA_OAEP"):
        assert cipher_algo not in utilities.SUPPORTED_SYMMETRIC_CIPHER_ALGOS
        with pytest.raises(RuntimeError, match="Unsupported"):
            utilities.generate_symkey(cipher_algo)


def test_micropython_aead_cryptainers_are_decrypted_by_wacryptolib_and_tamper_evident(port, trustee_keys):
    keystore_pool, keystore_data = trustee_keys
    flightbox = port.FlightBox(_build_utilities(port, keystore_data))
    cryptoconf = dict(
        keychain_uid=KEYCHAIN_UID,
        payload_cipher_layers=[
            dict(
                payload_cipher_algo="CHACHA20_POLY1305",
                key_cipher_layers=[
                    dict(
                        key_cipher_algo="CHACHA20_POLY1305",
                        key_cipher_layers=[_asymmetric_layer("RSA_OAEP")],
                    ),
                    _asymmetric_layer("ECIES_X25519"),
                ],
                payload_ciphertext_signatures=[],
            ),
            dict(
                payload_cipher_algo="AES_CBC",  # Any AEAD layer of the chain makes the whole payload tamper-evident
                key_cipher_layers=[_asymmetric_layer("ECIES_X25519")],
                payload_ciphertext_signatures=[],
            ),
        ],
    )
    check_cryptoconf_sanity(cryptoconf)
    payload = b"PAY 1000 EUR TO ALICE" * 10

    for payload_cipher_layer_count in (1, 2):
        cryptoconf_variant = dict(
            cryptoconf, payload_cipher_layers=cryptoconf["payload_cipher_layers"][:payload_cipher_layer_count]
        )
        cryptainer, secrets = flightbox.generate_cryptainer_base_and_secrets(
            cryptoconf_variant, cryptainer_metadata={"device": "cam1"}
        )
        extracts = secrets["payload_cipher_layer_extracts"]
        assert extracts[0]["cipher_algo"] == "CHACHA20_POLY1305"
        check_symkey_dict_sanity(extracts[0]["symkey"], cipher_algo="CHACHA20_POLY1305")
        symmetric_key_layer = cryptainer["payload_cipher_layers"][0]["key_cipher_layers"][0]
        assert isinstance(symmetric_key_layer["key_ciphertext"], bytes)  # The protected sub-symkey

        cryptainer = _finish_cryptainer(cryptainer, secrets, payload=payload)
        decrypted_payload, operation_report = decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)
        assert operation_report.get_error_count() == 0, operation_report.get_error_entries()
        assert decrypted_payload == payload

        # A single bit flipped anywhere in the payload ciphertext is detected, unlike with AES_CBC layers only
        payload_ciphertext = cryptainer["payload_ciphertext_struct"]["ciphertext_value"]
        for flipped_byte_index in (0, 16, len(payload_ciphertext) - 1):
            tampered_ciphertext = bytearray(payload_ciphertext)
            tampered_ciphertext[flipped_byte_index] ^= 0x01
            cryptainer["payload_ciphertext_struct"]["ciphertext_value"] = bytes(tampered_ciphertext)
            decrypted_payload, operation_report = decrypt_payload_from_cryptainer(
                cryptainer, keystore_pool=keystore_pool
            )
            assert decrypted_payload is None
            assert operation_report.get_error_entries()[-1]["entry_type"] == (
                DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR
            )
        cryptainer["payload_ciphertext_struct"]["ciphertext_value"] = payload_ciphertext


def test_micropython_demo_uses_an_aead_payload_cipher():
    main_source = (MICROPYTHON_DIR / "main.py").read_text(encoding="utf8")
    payload_cipher_algos = re.findall(r"""payload_cipher_algo\s*=\s*["'](\w+)["']""", main_source)
    assert payload_cipher_algos and all(algo in AEAD_CIPHER_ALGOS for algo in payload_cipher_algos)
