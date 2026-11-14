#!/usr/bin/env python
# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Add a NEW generation of compatibility fixtures, produced by the in-tree wacryptolib (see compatibility/README.md).

    python scripts/compatibility/generate_current.py classic 2026_current
    python scripts/compatibility/generate_current.py post_quantum 2026_post_quantum
    python scripts/compatibility/generate_current.py edge_cases 2026_edge_cases

Missing shared plaintexts are added too. The generation is staged, then committed into the corpus, then fully
checked like the test suite does; it is removed again if any check fails. Existing generations are never touched.
"""

import argparse
import contextlib
import copy
import filecmp
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock
from uuid import UUID

import _corpus
from _corpus import corpus

from wacryptolib.authenticator import initialize_authenticator
from wacryptolib.cipher import encrypt_bytestring
from wacryptolib.cryptainer import (
    LOCAL_KEYFACTORY_TRUSTEE_MARKER,
    SHARED_SECRET_ALGO_MARKER,
    dump_cryptainer_to_filesystem,
    encrypt_payload_and_stream_cryptainer_to_filesystem,
    encrypt_payload_into_cryptainer,
)
from wacryptolib.keygen import (
    _serialize_key_object_to_pem_bytestring,
    generate_keypair,
    generate_symkey,
    load_asymmetric_key_from_pem_bytestring,
)
from wacryptolib.keystore import FilesystemKeystore, FilesystemKeystorePool, generate_keypair_for_storage
from wacryptolib.operations import import_keystore_from_path
from wacryptolib.signature import sign_message

# Sizes around AES blocks (16), RSA-OAEP chunks (60), and multi-chunk sizes which are multiples of neither
PLAINTEXT_SIZES = (0, 1, 15, 16, 17, 31, 32, 33, 59, 60, 61, 255, 256, 257, 4099, 65539, 1048579)
MAX_ASYMMETRIC_PLAINTEXT_SIZE = 4099  # Asymmetric vectors stay small (RSA-OAEP chunking is slow and bulky)
SIGNED_PLAINTEXT_SIZE = 257

LOCAL_KEYCHAIN_UID1 = UUID("0c0c0c0c-0000-4000-8000-000000000001")  # Default keychain of all cryptoconfs
LOCAL_KEYCHAIN_UID2 = UUID("0c0c0c0c-0000-4000-8000-000000000002")
LOCAL_KEYCHAIN_UID3 = UUID("0c0c0c0c-0000-4000-8000-000000000003")
LOCAL_KEYCHAIN_UIDS = (LOCAL_KEYCHAIN_UID1, LOCAL_KEYCHAIN_UID2, LOCAL_KEYCHAIN_UID3)

KEYSTORE_PASSPHRASE_HINT = "Dummy compatibility passphrase, see the pool sidecar"

# Private key PEM protections of wacryptolib <= 0.12 (i.e. before commit f4992a1), per key algo
LEGACY_PEM_EXPORT_PARAMS = {
    "RSA_OAEP": dict(pkcs=8, protection="PBKDF2WithHMAC-SHA1AndAES256-CBC"),
    "RSA_PSS": dict(pkcs=8, protection="PBKDF2WithHMAC-SHA1AndAES256-CBC"),
    "DSA_DSS": dict(pkcs8=True, protection="PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC"),
    "ECC_DSS": dict(use_pkcs8=True, protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"),
}


def generate_legacy_protected_keypair_for_storage(key_algo: str, *, keystore, keychain_uid: UUID, passphrase: str):
    """Like generate_keypair_for_storage(), but protecting the private key like wacryptolib <= 0.12 did."""
    keypair = generate_keypair(key_algo=key_algo, serialize=False)
    private_key_pem = keypair["private_key"].export_key(
        format="PEM", passphrase=passphrase, **LEGACY_PEM_EXPORT_PARAMS[key_algo]
    )
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode("ascii")
    public_key_pem = _serialize_key_object_to_pem_bytestring(keypair["public_key"], key_algo=key_algo)
    keystore.set_keypair(
        keychain_uid=keychain_uid, key_algo=key_algo, public_key=public_key_pem, private_key=private_key_pem
    )


class AuthenticatorSpec:
    """A dummy authenticator, whose keypairs all share a single keychain UID and passphrase."""

    def __init__(self, name: str, keystore_uid: str, key_algos: tuple, legacy_pem_protection=False):
        self.keystore_owner = "compat-%s" % name
        self.passphrase = "compat-%s-passphrase" % name
        self.keystore_uid = UUID(keystore_uid)
        self.keychain_uid = UUID(keystore_uid[:-4] + "00c1")
        self.key_algos = key_algos
        self.legacy_pem_protection = legacy_pem_protection  # Private keys protected like wacryptolib <= 0.12 did

    @property
    def trustee(self) -> dict:
        return dict(trustee_type="authenticator", keystore_uid=self.keystore_uid, keystore_owner=self.keystore_owner)

    @property
    def trustee_id(self) -> str:
        return "authenticator@%s" % self.keystore_uid

    def key_layer(self, key_cipher_algo: str) -> dict:
        assert key_cipher_algo in self.key_algos, key_cipher_algo
        return dict(key_cipher_algo=key_cipher_algo, key_cipher_trustee=self.trustee, keychain_uid=self.keychain_uid)


def local_key_layer(key_cipher_algo: str, keychain_uid: UUID = None) -> dict:
    layer = dict(key_cipher_algo=key_cipher_algo, key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
    if keychain_uid:
        layer["keychain_uid"] = keychain_uid
    return layer


def symmetric_key_layer(key_cipher_algo: str, key_cipher_layers: list) -> dict:
    return dict(key_cipher_algo=key_cipher_algo, key_cipher_layers=key_cipher_layers)


def shared_secret_layer(threshold: int, shards: list) -> dict:
    return dict(
        key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
        key_shared_secret_threshold=threshold,
        key_shared_secret_shards=[dict(key_cipher_layers=shard_layers) for shard_layers in shards],
    )


def local_signature(signature_algo: str, digest_algo: str, keychain_uid: UUID = None) -> dict:
    signature = dict(
        payload_digest_algo=digest_algo,
        payload_signature_algo=signature_algo,
        payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
    )
    if keychain_uid:
        signature["keychain_uid"] = keychain_uid
    return signature


def payload_layer(payload_cipher_algo: str, key_cipher_layers: list, signatures=()) -> dict:
    return dict(
        payload_cipher_algo=payload_cipher_algo,
        key_cipher_layers=key_cipher_layers,
        payload_ciphertext_signatures=list(signatures),
    )


def cryptoconf(*payload_layers, plaintext_signatures=None) -> dict:
    conf = dict(keychain_uid=LOCAL_KEYCHAIN_UID1, payload_cipher_layers=list(payload_layers))
    if plaintext_signatures:
        conf["payload_plaintext_signatures"] = plaintext_signatures
    return conf


# PROFILES OF GENERATIONS #

ALICE = AuthenticatorSpec("alice", "a11ce000-0000-4000-8000-000000000001", ("RSA_OAEP", "ECIES_X25519"))
BOB = AuthenticatorSpec("bob", "b0b00000-0000-4000-8000-000000000002", ("RSA_OAEP", "ECIES_X25519"))
CAROL = AuthenticatorSpec("carol", "ca201000-0000-4000-8000-000000000003", ("RSA_OAEP", "ECIES_X25519"))

DAVE = AuthenticatorSpec("dave", "da7e0000-0000-4000-8000-000000000004", ("ML_KEM_768", "ECIES_X25519", "ML_DSA_65"))
ERIN = AuthenticatorSpec("erin", "e1210000-0000-4000-8000-000000000005", ("ML_KEM_768", "ECIES_X25519", "ML_DSA_65"))
FRANK = AuthenticatorSpec("frank", "f2a40000-0000-4000-8000-000000000006", ("ML_KEM_768", "ECIES_X25519", "ML_DSA_65"))


def _shamir_scenarios(authenticators, threshold):
    """All passphrases, exactly-threshold subsets (first and last authenticators), and below-threshold subsets.

    Shards are decrypted in order until the threshold is reached, so only a failing shard BEFORE that point gets
    reported (as a non-fatal asymmetric decryption error).
    """
    names = [authenticator.keystore_owner.replace("compat-", "") for authenticator in authenticators]

    def mapper(subset):
        return {authenticator.trustee_id: [authenticator.passphrase] for authenticator in subset}

    scenarios = [
        dict(
            name="all_passphrases",
            description="Every authenticator passphrase is provided",
            passphrase_mapper=mapper(authenticators),
            expected="success",
        ),
        dict(
            name="threshold_exact_%s" % "_".join(names[:threshold]),
            description="Exactly %d authenticator passphrases, of the first shards (the last shards are not needed)"
            % threshold,
            passphrase_mapper=mapper(authenticators[:threshold]),
            expected="success",
        ),
        dict(
            name="threshold_exact_%s" % "_".join(names[-threshold:]),
            description="Exactly %d authenticator passphrases, of the last shards (the first ones fail)" % threshold,
            passphrase_mapper=mapper(authenticators[-threshold:]),
            expected="success",
            expected_warnings=["ASYMMETRIC_DECRYPTION_ERROR"],
        ),
        dict(
            name="below_threshold_%s" % names[0],
            description="Fewer authenticator passphrases than the threshold of %d" % threshold,
            passphrase_mapper=mapper(authenticators[: threshold - 1]),
            expected="failure",
        ),
        dict(
            name="no_passphrase",
            description="No passphrase at all",
            passphrase_mapper={},
            expected="failure",
        ),
    ]
    return scenarios


NO_PASSPHRASE_SCENARIOS = [
    dict(
        name="local_keys_only",
        description="Only unprotected local keyfactory keys are involved",
        passphrase_mapper={},
        expected="success",
    )
]


def build_classic_profile():
    authenticators = [ALICE, BOB, CAROL]
    cryptoconfs = {
        "01_single_layer": dict(
            level=1,
            description="Single AES_EAX payload layer, its key wrapped with a local RSA_OAEP key",
            cryptoconf=cryptoconf(payload_layer("AES_EAX", [local_key_layer("RSA_OAEP")])),
        ),
        "02_ciphertext_signature": dict(
            level=2,
            description="AES_CBC payload layer with a local RSA_OAEP key layer and a DSA_DSS ciphertext signature",
            cryptoconf=cryptoconf(
                payload_layer("AES_CBC", [local_key_layer("RSA_OAEP")], [local_signature("DSA_DSS", "SHA256")])
            ),
        ),
        "03_multiple_payload_layers": dict(
            level=3,
            description="Three payload layers (AES_EAX, AES_CBC, CHACHA20_POLY1305), with RSA_OAEP and ECIES_X25519 "
            "key layers and an ECC_DSS ciphertext signature",
            cryptoconf=cryptoconf(
                payload_layer("AES_EAX", [local_key_layer("RSA_OAEP")]),
                payload_layer("AES_CBC", [local_key_layer("ECIES_X25519")]),
                payload_layer(
                    "CHACHA20_POLY1305",
                    [local_key_layer("RSA_OAEP", LOCAL_KEYCHAIN_UID2)],
                    [local_signature("ECC_DSS", "SHA512")],
                ),
            ),
        ),
        "04_recursive_key_layers": dict(
            level=4,
            description="Symmetric key layers nested in key layers (AES_EAX, CHACHA20_POLY1305 then AES_CBC), "
            "wrapped by RSA_OAEP and ECIES_X25519 keys of several keychains, with an RSA_PSS ciphertext signature",
            cryptoconf=cryptoconf(
                payload_layer(
                    "AES_CBC",
                    [
                        local_key_layer("RSA_OAEP"),
                        symmetric_key_layer(
                            "AES_EAX",
                            [local_key_layer("RSA_OAEP", LOCAL_KEYCHAIN_UID3), local_key_layer("ECIES_X25519")],
                        ),
                    ],
                ),
                payload_layer(
                    "CHACHA20_POLY1305",
                    [
                        symmetric_key_layer(
                            "CHACHA20_POLY1305",
                            [symmetric_key_layer("AES_CBC", [local_key_layer("RSA_OAEP", LOCAL_KEYCHAIN_UID2)])],
                        )
                    ],
                    [local_signature("RSA_PSS", "SHA3_512")],
                ),
            ),
        ),
        "05_shamir_authenticators": dict(
            level=5,
            description="CHACHA20_POLY1305 payload layer whose key is a 2-of-3 Shamir shared secret over three "
            "passphrase-protected authenticators (RSA_OAEP and ECIES_X25519 keys)",
            cryptoconf=cryptoconf(
                payload_layer(
                    "CHACHA20_POLY1305",
                    [
                        shared_secret_layer(
                            2,
                            [
                                [ALICE.key_layer("RSA_OAEP")],
                                [BOB.key_layer("ECIES_X25519")],
                                [CAROL.key_layer("RSA_OAEP")],
                            ],
                        )
                    ],
                )
            ),
            authenticators=authenticators,
        ),
        "06_signed_multi_trustee": dict(
            level=6,
            description="Plaintext signatures (RSA_PSS, ECC_DSS), two payload layers, a local ECIES_X25519 key "
            "layer plus a 2-of-3 Shamir shared secret over authenticators with nested symmetric and local key "
            "layers, and a DSA_DSS ciphertext signature",
            cryptoconf=cryptoconf(
                payload_layer("AES_EAX", [local_key_layer("RSA_OAEP")]),
                payload_layer(
                    "AES_CBC",
                    [
                        local_key_layer("ECIES_X25519", LOCAL_KEYCHAIN_UID2),
                        shared_secret_layer(
                            2,
                            [
                                [ALICE.key_layer("RSA_OAEP")],
                                [BOB.key_layer("ECIES_X25519"), local_key_layer("RSA_OAEP", LOCAL_KEYCHAIN_UID3)],
                                [symmetric_key_layer("AES_EAX", [CAROL.key_layer("RSA_OAEP")])],
                            ],
                        ),
                    ],
                    [local_signature("DSA_DSS", "SHA512")],
                ),
                plaintext_signatures=[
                    local_signature("RSA_PSS", "SHA256"),
                    local_signature("ECC_DSS", "SHA3_256", LOCAL_KEYCHAIN_UID2),
                ],
            ),
            authenticators=authenticators,
        ),
    }
    invalid_cryptoconfs = {
        "no_payload_cipher_layer": dict(
            description="No payload cipher layer at all",
            cryptoconf=dict(payload_cipher_layers=[]),
        ),
        "no_key_cipher_layer": dict(
            description="A payload cipher layer without any key cipher layer",
            cryptoconf=dict(payload_cipher_layers=[payload_layer("AES_CBC", [])]),
        ),
        "shared_secret_threshold_zero": dict(
            description="A shared secret with a threshold of zero",
            cryptoconf=dict(
                payload_cipher_layers=[
                    payload_layer("AES_CBC", [shared_secret_layer(0, [[local_key_layer("RSA_OAEP")]])])
                ]
            ),
        ),
        "shared_secret_threshold_above_shard_count": dict(
            description="A shared secret whose threshold exceeds its number of shards",
            cryptoconf=dict(
                payload_cipher_layers=[
                    payload_layer(
                        "AES_CBC",
                        [shared_secret_layer(3, [[local_key_layer("RSA_OAEP")], [local_key_layer("RSA_OAEP")]])],
                    )
                ]
            ),
        ),
        "unknown_payload_cipher_algo": dict(
            description="An unknown payload cipher algorithm",
            cryptoconf=dict(payload_cipher_layers=[payload_layer("AES_XYZ", [local_key_layer("RSA_OAEP")])]),
        ),
        "asymmetric_payload_cipher_algo": dict(
            description="An asymmetric algorithm used as payload cipher",
            cryptoconf=dict(payload_cipher_layers=[payload_layer("RSA_OAEP", [local_key_layer("RSA_OAEP")])]),
        ),
        "unknown_trustee_type": dict(
            description="A key cipher trustee of unknown type",
            cryptoconf=dict(
                payload_cipher_layers=[
                    payload_layer(
                        "AES_CBC", [dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=dict(trustee_type="oracle"))]
                    )
                ]
            ),
        ),
    }
    cryptainers = {
        "01_single_layer_empty_payload": dict(
            cryptoconf="01_single_layer", plaintext_size=0, scenarios=NO_PASSPHRASE_SCENARIOS,
            description="Empty payload, inline",
        ),
        "02_signed_inline": dict(
            cryptoconf="02_ciphertext_signature", plaintext_size=33, scenarios=NO_PASSPHRASE_SCENARIOS,
            description="Small payload, inline, with a ciphertext signature",
        ),
        "03_multiple_layers_offloaded_with_metadata": dict(
            cryptoconf="03_multiple_payload_layers", plaintext_size=65539, offloaded=True,
            cryptainer_metadata={"compat_device": "compat-camera-1", "compat_index": 3, "compat_tags": ["a", "b"]},
            scenarios=NO_PASSPHRASE_SCENARIOS,
            description="64 KiB payload through three payload layers, offloaded, with cryptainer metadata",
        ),
        "04_recursive_key_layers_streamed": dict(
            cryptoconf="04_recursive_key_layers", plaintext_size=1048579, streamed=True,
            scenarios=NO_PASSPHRASE_SCENARIOS,
            description="1 MiB payload encrypted by the streaming pipeline (offloaded), with nested key layers",
        ),
        "05_shamir_authenticators": dict(
            cryptoconf="05_shamir_authenticators", plaintext_size=4099,
            scenarios=_shamir_scenarios(authenticators, threshold=2),
            description="Payload protected by a 2-of-3 Shamir shared secret over authenticators, inline",
        ),
        "06_signed_multi_trustee_offloaded": dict(
            cryptoconf="06_signed_multi_trustee", plaintext_size=257, offloaded=True,
            cryptainer_metadata={"compat_device": "compat-recorder-2"},
            scenarios=_shamir_scenarios(authenticators, threshold=2),
            description="Payload with plaintext and ciphertext signatures, local and Shamir authenticator key "
            "layers, offloaded, with cryptainer metadata",
        ),
        "07_corrupted_ciphertext_signature": dict(
            cryptoconf="02_ciphertext_signature", plaintext_size=61, corrupt_ciphertext_signature=True,
            scenarios=[
                dict(
                    name="local_keys_only",
                    description="Decryption succeeds, but the corrupted signature is reported",
                    passphrase_mapper={},
                    expected="success",
                    expected_warnings=["SIGNATURE_ERROR"],
                )
            ],
            description="Inline cryptainer whose ciphertext signature value was corrupted after encryption",
        ),
    }
    return dict(
        pool_name="classic_pool",
        pool_description="Local keyfactory (RSA_OAEP, RSA_PSS, DSA_DSS, ECC_DSS, ECIES_X25519 keys of three "
        "keychains, unprotected) and three imported authenticators with passphrase-protected RSA_OAEP and "
        "ECIES_X25519 keys",
        local_key_algos=("RSA_OAEP", "RSA_PSS", "DSA_DSS", "ECC_DSS", "ECIES_X25519"),
        authenticators=authenticators,
        cipher_algos=("AES_CBC", "AES_EAX", "CHACHA20_POLY1305", "RSA_OAEP", "ECIES_X25519"),
        signature_algos=("RSA_PSS", "DSA_DSS", "ECC_DSS"),
        digest_list_vector=True,
        tampered_signature_algo="RSA_PSS",
        cryptoconfs=cryptoconfs,
        invalid_cryptoconfs=invalid_cryptoconfs,
        cryptainers=cryptainers,
    )


def build_post_quantum_profile():
    authenticators = [DAVE, ERIN, FRANK]
    cryptoconfs = {
        "07_pq_hybrid": dict(
            level=7,
            description="Hybrid classical + post-quantum stack: AES_EAX payload layer whose key is wrapped by local "
            "RSA_OAEP and ML_KEM_768 keys, then by a 2-of-3 Shamir shared secret over authenticators (ML_KEM_768, "
            "ECIES_X25519 + ML_KEM_768, ML_KEM_768), with ML_DSA_65 plaintext and ciphertext signatures",
            cryptoconf=cryptoconf(
                payload_layer(
                    "AES_EAX",
                    [
                        local_key_layer("RSA_OAEP"),
                        local_key_layer("ML_KEM_768"),
                        shared_secret_layer(
                            2,
                            [
                                [DAVE.key_layer("ML_KEM_768")],
                                [ERIN.key_layer("ECIES_X25519"), ERIN.key_layer("ML_KEM_768")],
                                [FRANK.key_layer("ML_KEM_768")],
                            ],
                        ),
                    ],
                    [local_signature("ML_DSA_65", "SHA512")],
                ),
                plaintext_signatures=[local_signature("ML_DSA_65", "SHA3_512", LOCAL_KEYCHAIN_UID2)],
            ),
            authenticators=authenticators,
        ),
    }
    cryptainers = {
        "07_pq_hybrid_shamir_authenticators": dict(
            cryptoconf="07_pq_hybrid", plaintext_size=4099,
            cryptainer_metadata={"compat_device": "compat-pq-camera"},
            scenarios=_shamir_scenarios(authenticators, threshold=2),
            description="Hybrid RSA_OAEP + ML_KEM_768 cryptainer with a Shamir shared secret over post-quantum "
            "authenticators, ML_DSA_65 signatures, inline",
        ),
        "07_pq_hybrid_offloaded": dict(
            cryptoconf="07_pq_hybrid", plaintext_size=65539, offloaded=True,
            scenarios=_shamir_scenarios(authenticators, threshold=2)[:1],
            description="Same hybrid stack with a 64 KiB offloaded payload",
        ),
    }
    return dict(
        pool_name="pq_pool",
        pool_description="Local keyfactory (RSA_OAEP, ECIES_X25519, ML_KEM_768, ML_DSA_65 keys of three keychains, "
        "unprotected) and three imported authenticators with passphrase-protected ML_KEM_768, ECIES_X25519 and "
        "ML_DSA_65 keys",
        local_key_algos=("RSA_OAEP", "ECIES_X25519", "ML_KEM_768", "ML_DSA_65"),
        authenticators=authenticators,
        cipher_algos=("ML_KEM_768",),
        signature_algos=("ML_DSA_65",),
        digest_list_vector=False,
        tampered_signature_algo="ML_DSA_65",
        cryptoconfs=cryptoconfs,
        invalid_cryptoconfs={},
        cryptainers=cryptainers,
    )


GRACE = AuthenticatorSpec(
    "grace", "62ace000-0000-4000-8000-000000000007", ("RSA_OAEP", "RSA_PSS", "DSA_DSS", "ECC_DSS"),
    legacy_pem_protection=True,
)


def build_edge_cases_profile():
    authenticators = [GRACE]
    success_scenario = dict(
        name="all_passphrases",
        description="The authenticator passphrase is provided",
        passphrase_mapper={GRACE.trustee_id: [GRACE.passphrase]},
        expected="success",
    )
    no_passphrase_scenario = dict(
        name="no_passphrase",
        description="The authenticator passphrase is missing",
        passphrase_mapper={},
        expected="failure",
        expected_errors=["ASYMMETRIC_DECRYPTION_ERROR"],
    )
    cryptoconfs = {
        "08_legacy_protected_authenticator": dict(
            level=6,
            description="AES_EAX payload layer whose key is wrapped by a local RSA_OAEP key, then by the RSA_OAEP "
            "key of an authenticator with legacy-protected private keys, with a DSA_DSS ciphertext signature and "
            "an ECC_DSS plaintext signature",
            cryptoconf=cryptoconf(
                payload_layer(
                    "AES_EAX",
                    [local_key_layer("RSA_OAEP"), GRACE.key_layer("RSA_OAEP")],
                    [local_signature("DSA_DSS", "SHA256")],
                ),
                plaintext_signatures=[local_signature("ECC_DSS", "SHA512")],
            ),
            authenticators=authenticators,
        ),
    }
    cryptainers = {
        "08_canonical_extjson": dict(
            cryptoconf="08_legacy_protected_authenticator", plaintext_size=257, canonical=True,
            cryptainer_metadata={"compat_device": "compat-edge-camera"},
            scenarios=[success_scenario, no_passphrase_scenario],
            description="CANONICAL extended JSON combined with the current 'payload_ciphertext_signatures' naming, "
            "inline, with cryptainer metadata",
        ),
        "08_legacy_signature_field_corrupted": dict(
            cryptoconf="08_legacy_protected_authenticator", plaintext_size=61, canonical=True,
            legacy_signature_field=True, corrupt_ciphertext_signature=True,
            scenarios=[
                dict(
                    success_scenario,
                    description="Decryption succeeds, but the corrupted signature of the legacy field is reported",
                    expected_warnings=["SIGNATURE_ERROR"],
                )
            ],
            description="Inline cryptainer using the legacy 'payload_signatures' field, whose ciphertext signature "
            "value was corrupted after encryption",
        ),
        "08_corrupted_payload_tag": dict(
            cryptoconf="08_legacy_protected_authenticator", plaintext_size=61, corrupt_payload_tag=True,
            scenarios=[
                dict(
                    success_scenario,
                    description="All keys are available, but the payload MAC tag check fails",
                    expected="failure",
                    expected_errors=["SYMMETRIC_DECRYPTION_ERROR"],
                )
            ],
            description="Inline cryptainer whose AES_EAX payload MAC tag was corrupted after encryption",
        ),
        "08_digest_list_key_ciphertexts_offloaded": dict(
            cryptoconf="08_legacy_protected_authenticator", plaintext_size=4099, offloaded=True,
            digest_list_key_ciphertexts=True,
            scenarios=[success_scenario, no_passphrase_scenario],
            description="Offloaded cryptainer whose RSA_OAEP key ciphertexts (nested ones included) use the legacy "
            "'digest_list' field name",
        ),
    }
    return dict(
        pool_name="edge_cases_pool",
        pool_description="Local keyfactory (RSA_OAEP, DSA_DSS, ECC_DSS, ECIES_X25519 keys of three keychains, "
        "unprotected) and one imported authenticator whose RSA_OAEP, RSA_PSS, DSA_DSS and ECC_DSS private keys are "
        "protected like wacryptolib <= 0.12 did (DES3 for DSA_DSS)",
        local_key_algos=("RSA_OAEP", "DSA_DSS", "ECC_DSS", "ECIES_X25519"),
        authenticators=authenticators,
        cipher_algos=(),
        signature_algos=(),
        digest_list_vector=False,
        tampered_signature_algo=None,
        tampered_cipherdicts=(("AES_EAX", 61), ("CHACHA20_POLY1305", 61), ("RSA_OAEP", 61), ("ECIES_X25519", 61)),
        cryptoconfs=cryptoconfs,
        invalid_cryptoconfs={},
        cryptainers=cryptainers,
    )


PROFILES = dict(
    classic=build_classic_profile, post_quantum=build_post_quantum_profile, edge_cases=build_edge_cases_profile
)


def _corrupt_bytes(value: bytes) -> bytes:
    corrupted = bytearray(value)
    corrupted[len(corrupted) // 2] ^= 0xFF
    return bytes(corrupted)


@contextlib.contextmanager
def _legacy_digest_list_rsa_oaep():
    """Make RSA_OAEP encryption output the legacy 'digest_list' field name, like old wacryptolib versions did."""
    from wacryptolib.cipher import CIPHER_ALGOS_REGISTRY

    registry_entry = CIPHER_ALGOS_REGISTRY["RSA_OAEP"]
    encryption_function = registry_entry["encryption_function"]

    def _encrypt_with_digest_list(*args, **kwargs):
        cipherdict = encryption_function(*args, **kwargs)
        return {("digest_list" if key == "ciphertext_chunks" else key): value for key, value in cipherdict.items()}

    with mock.patch.dict(registry_entry, encryption_function=_encrypt_with_digest_list):
        yield


# GENERATION #


class CurrentGenerationBuilder:
    def __init__(self, writer: _corpus.GenerationWriter, profile: dict, work_dir: Path):
        self.writer = writer
        self.profile = profile
        self.work_dir = work_dir
        self.plaintext_writer = _corpus.PlaintextWriter(writer.generation, corpus_dir=writer.corpus_dir)
        self.provenance = _corpus.build_provenance("genuine")
        self.pool_path = writer.get_final_path("keystores", profile["pool_name"])
        self.pool_staging_dir = None
        self.pool_keypairs = {}  # (keystore, keychain_uid, key_algo) -> keypair identifier dict

    def build(self):
        for size in PLAINTEXT_SIZES:
            self.plaintext_writer.ensure_plaintext(size)
        self.build_keystore_pool()
        self.build_cipherdicts()
        self.build_signatures()
        cryptoconf_paths = self.build_cryptoconfs()
        self.build_cryptainers(cryptoconf_paths)
        self.check_pool_untouched()

    # Keystore pool

    def build_keystore_pool(self):
        profile = self.profile
        self.pool_staging_dir = self.writer.get_staging_dir(self.pool_path)
        keystore_pool = FilesystemKeystorePool(self.pool_staging_dir)

        local_keystore = keystore_pool.get_local_keyfactory()
        for keychain_uid in LOCAL_KEYCHAIN_UIDS:
            for key_algo in profile["local_key_algos"]:
                generate_keypair_for_storage(key_algo, keystore=local_keystore, keychain_uid=keychain_uid)

        authenticators_dir = Path(tempfile.mkdtemp(dir=self.work_dir, prefix="authenticators-"))
        for authenticator in profile["authenticators"]:
            authenticator_dir = authenticators_dir / authenticator.keystore_owner
            with mock.patch("wacryptolib.authenticator.generate_uuid0", return_value=authenticator.keystore_uid):
                initialize_authenticator(
                    authenticator_dir,
                    keystore_owner=authenticator.keystore_owner,
                    keystore_passphrase_hint=KEYSTORE_PASSPHRASE_HINT,
                )
            authenticator_keystore = FilesystemKeystore(authenticator_dir)
            keypair_generator = (
                generate_legacy_protected_keypair_for_storage
                if authenticator.legacy_pem_protection
                else generate_keypair_for_storage
            )
            for key_algo in authenticator.key_algos:
                keypair_generator(
                    key_algo,
                    keystore=authenticator_keystore,
                    keychain_uid=authenticator.keychain_uid,
                    passphrase=authenticator.passphrase,
                )
            import_keystore_from_path(keystore_pool, authenticator_dir, include_private_keys=True)

        local_keypairs = corpus.list_keystore_keypairs(self.pool_staging_dir / "local_keyfactory")
        authenticator_entries = []
        for authenticator in profile["authenticators"]:
            keystore_dir = corpus.get_pool_keystore_dir(self.pool_staging_dir, str(authenticator.keystore_uid))
            authenticator_entries.append(
                dict(
                    keystore_uid=str(authenticator.keystore_uid),
                    keystore_owner=authenticator.keystore_owner,
                    keystore_passphrase_hint=KEYSTORE_PASSPHRASE_HINT,
                    passphrase=authenticator.passphrase,
                    keypairs=corpus.list_keystore_keypairs(keystore_dir),
                )
            )
        all_keypairs = local_keypairs + [kp for entry in authenticator_entries for kp in entry["keypairs"]]
        self.pool_requirements = _corpus.build_requirements(
            [kp["key_algo"] for kp in all_keypairs], [kp["pem_protection"] for kp in all_keypairs]
        )
        self.authenticator_pem_protections = {
            (entry["keystore_uid"], kp["keychain_uid"], kp["key_algo"]): kp["pem_protection"]
            for entry in authenticator_entries
            for kp in entry["keypairs"]
        }
        pool_provenance = self.provenance
        if any(authenticator.legacy_pem_protection for authenticator in profile["authenticators"]):
            pool_provenance = _corpus.build_provenance(
                "synthesized",
                legacy_forms=["des3_protected_private_key"],
                notes="Authenticator private keys exported with the PEM protections of wacryptolib <= 0.12 "
                "(PBKDF2-HMAC-SHA1, with AES-CBC, or DES-EDE3-CBC for DSA_DSS keys)",
            )
        self.writer.write_sidecar(
            self.pool_path,
            fixture_kind="keystore_pool",
            description=profile["pool_description"],
            provenance=pool_provenance,
            requirements=self.pool_requirements,
            local_keyfactory=dict(keypairs=local_keypairs),
            authenticators=authenticator_entries,
        )

    def _load_local_key(self, key_algo: str, private: bool, keychain_uid=LOCAL_KEYCHAIN_UID1):
        keystore = FilesystemKeystore(self.pool_staging_dir / "local_keyfactory")
        getter = keystore.get_private_key if private else keystore.get_public_key
        return load_asymmetric_key_from_pem_bytestring(
            getter(keychain_uid=keychain_uid, key_algo=key_algo), key_algo=key_algo
        )

    def _local_key_ref(self, sidecar_path: Path, key_algo: str, private: bool) -> dict:
        key_ref = dict(
            keystore_pool=_corpus.to_relpath(self.pool_path, sidecar_path),
            keystore="local_keyfactory",
            keychain_uid=str(LOCAL_KEYCHAIN_UID1),
            key_algo=key_algo,
        )
        if private:
            key_ref["passphrase"] = None
        return key_ref

    # Cipherdicts and signatures

    def _plaintext_path(self, size: int) -> Path:
        return self.plaintext_writer.get_plaintext_path(size)

    def build_cipherdicts(self):
        from wacryptolib.cipher import SUPPORTED_SYMMETRIC_CIPHER_ALGOS

        for cipher_algo in self.profile["cipher_algos"]:
            is_symmetric = cipher_algo in SUPPORTED_SYMMETRIC_CIPHER_ALGOS
            sizes = [size for size in PLAINTEXT_SIZES if is_symmetric or size <= MAX_ASYMMETRIC_PLAINTEXT_SIZE]
            for size in sizes:
                plaintext_path = self._plaintext_path(size)
                plaintext = plaintext_path.read_bytes()
                asset_path = self.writer.get_final_path(
                    "cipherdicts", cipher_algo, plaintext_path.stem + ".cipherdict"
                )
                fields = dict(cipher_algo=cipher_algo, plaintext=_corpus.to_relpath(plaintext_path, asset_path))
                if is_symmetric:
                    symkey = generate_symkey(cipher_algo)
                    cipherdict = encrypt_bytestring(plaintext, cipher_algo=cipher_algo, key_dict=symkey)
                    fields.update(direction="bidirectional", symkey={k: v.hex() for k, v in symkey.items()})
                    description = "%s encryption of a %d-byte plaintext, with its symmetric key" % (cipher_algo, size)
                else:
                    public_key = self._load_local_key(cipher_algo, private=False)
                    cipherdict = encrypt_bytestring(plaintext, cipher_algo=cipher_algo, key_dict={"key": public_key})
                    fields.update(
                        direction="decrypt_only",
                        private_key=self._local_key_ref(corpus.get_sidecar_path(asset_path), cipher_algo, True),
                    )
                    description = "%s encryption of a %d-byte plaintext, decryptable with a pool key" % (
                        cipher_algo,
                        size,
                    )
                self.writer.write_extjson_asset(asset_path, cipherdict)
                self.writer.write_sidecar(
                    asset_path,
                    fixture_kind="cipherdict",
                    description=description,
                    provenance=self.provenance,
                    requirements=_corpus.build_requirements([cipher_algo]),
                    **fields
                )

        if self.profile["digest_list_vector"]:
            self._build_digest_list_cipherdict(size=257)
        for cipher_algo, size in self.profile.get("tampered_cipherdicts", ()):
            self._build_tampered_cipherdict(cipher_algo, size)

    def _build_tampered_cipherdict(self, cipher_algo: str, size: int):
        from wacryptolib.cipher import SUPPORTED_SYMMETRIC_CIPHER_ALGOS

        plaintext_path = self._plaintext_path(size)
        plaintext = plaintext_path.read_bytes()
        asset_path = self.writer.get_final_path("cipherdicts", cipher_algo, plaintext_path.stem + "_tampered.cipherdict")
        fields = dict(cipher_algo=cipher_algo, plaintext=_corpus.to_relpath(plaintext_path, asset_path))
        if cipher_algo in SUPPORTED_SYMMETRIC_CIPHER_ALGOS:
            symkey = generate_symkey(cipher_algo)
            cipherdict = encrypt_bytestring(plaintext, cipher_algo=cipher_algo, key_dict=symkey)
            fields.update(symkey={k: v.hex() for k, v in symkey.items()})
        else:
            public_key = self._load_local_key(cipher_algo, private=False)
            cipherdict = encrypt_bytestring(plaintext, cipher_algo=cipher_algo, key_dict={"key": public_key})
            fields.update(private_key=self._local_key_ref(corpus.get_sidecar_path(asset_path), cipher_algo, True))
        if "tag" in cipherdict:
            corrupted_field = "MAC tag"
            cipherdict["tag"] = _corrupt_bytes(cipherdict["tag"])
        elif "ciphertext_chunks" in cipherdict:
            corrupted_field = "first ciphertext chunk"
            cipherdict["ciphertext_chunks"][0] = _corrupt_bytes(cipherdict["ciphertext_chunks"][0])
        else:
            corrupted_field = "ciphertext"
            cipherdict["ciphertext"] = _corrupt_bytes(cipherdict["ciphertext"])
        self.writer.write_extjson_asset(asset_path, cipherdict)
        self.writer.write_sidecar(
            asset_path,
            fixture_kind="cipherdict",
            description="%s encryption of a %d-byte plaintext, whose %s was corrupted (decryption must be rejected)"
            % (cipher_algo, size, corrupted_field),
            provenance=dict(self.provenance, notes="Cipherdict deliberately corrupted after encryption"),
            requirements=_corpus.build_requirements([cipher_algo]),
            direction="decrypt_only",
            expected_valid=False,
            **fields
        )

    def _build_digest_list_cipherdict(self, size: int):
        cipher_algo = "RSA_OAEP"
        plaintext_path = self._plaintext_path(size)
        public_key = self._load_local_key(cipher_algo, private=False)
        cipherdict = encrypt_bytestring(plaintext_path.read_bytes(), cipher_algo=cipher_algo, key_dict={"key": public_key})
        cipherdict = {("digest_list" if key == "ciphertext_chunks" else key): value for key, value in cipherdict.items()}
        assert "digest_list" in cipherdict, cipherdict.keys()
        asset_path = self.writer.get_final_path("cipherdicts", cipher_algo, plaintext_path.stem + "_digest_list.cipherdict")
        self.writer.write_extjson_asset(asset_path, cipherdict)
        self.writer.write_sidecar(
            asset_path,
            fixture_kind="cipherdict",
            description="RSA_OAEP encryption of a %d-byte plaintext, using the legacy 'digest_list' field name" % size,
            provenance=_corpus.build_provenance(
                "synthesized",
                legacy_forms=["rsa_oaep_digest_list_field"],
                notes="RSA_OAEP cipherdict of the in-tree library, with 'ciphertext_chunks' renamed to 'digest_list'",
            ),
            requirements=_corpus.build_requirements([cipher_algo]),
            cipher_algo=cipher_algo,
            plaintext=_corpus.to_relpath(plaintext_path, asset_path),
            direction="decrypt_only",
            private_key=self._local_key_ref(corpus.get_sidecar_path(asset_path), cipher_algo, True),
        )

    def build_signatures(self):
        plaintext_path = self._plaintext_path(SIGNED_PLAINTEXT_SIZE)
        inline_message = b"Witness Angel compatibility message"
        for signature_algo in self.profile["signature_algos"]:
            private_key = self._load_local_key(signature_algo, private=True)
            cases = [
                (plaintext_path.stem, plaintext_path.read_bytes(), dict(message=plaintext_path), True),
                ("inline_message", inline_message, dict(message_hex=inline_message.hex()), True),
            ]
            if signature_algo == self.profile["tampered_signature_algo"]:
                tampered_message = b"Witness Angel compatibility messagE"
                cases.append(("tampered_message", inline_message, dict(message_hex=tampered_message.hex()), False))
            for name, signed_message, message_fields, expected_valid in cases:
                asset_path = self.writer.get_final_path("signatures", signature_algo, name + ".signature")
                if "message" in message_fields:
                    message_fields = dict(message=_corpus.to_relpath(message_fields["message"], asset_path))
                signature = sign_message(signed_message, signature_algo=signature_algo, private_key=private_key)
                self.writer.write_extjson_asset(asset_path, signature)
                self.writer.write_sidecar(
                    asset_path,
                    fixture_kind="signature",
                    description="%s signature of %s%s"
                    % (
                        signature_algo,
                        "a %d-byte plaintext" % SIGNED_PLAINTEXT_SIZE if "message" in message_fields else "a short message",
                        "" if expected_valid else ", checked against an altered message (must NOT verify)",
                    ),
                    provenance=self.provenance,
                    requirements=_corpus.build_requirements([signature_algo]),
                    signature_algo=signature_algo,
                    public_key=self._local_key_ref(corpus.get_sidecar_path(asset_path), signature_algo, False),
                    expected_valid=expected_valid,
                    **message_fields
                )

    # Cryptoconfs and cryptainers

    def _structure_requirements(self, structure, authenticators) -> dict:
        """Requirements of a cryptoconf or cryptainer, with the PEM protections of the private keys it involves."""
        pem_protections = set()
        authenticator_uids = {str(authenticator.keystore_uid) for authenticator in authenticators or ()}
        for node in corpus._walk_data_tree(structure):
            if node.get("trustee_type") == "authenticator":
                assert str(node["keystore_uid"]) in authenticator_uids, node
            trustee = node.get("key_cipher_trustee")
            if isinstance(trustee, dict) and trustee.get("trustee_type") == "authenticator":
                keypair_key = (str(trustee["keystore_uid"]), str(node["keychain_uid"]), node["key_cipher_algo"])
                pem_protections.add(self.authenticator_pem_protections[keypair_key])
        return _corpus.build_requirements(corpus.collect_structure_algorithms(structure), pem_protections)

    @staticmethod
    def _full_passphrase_mapper(authenticators) -> dict:
        return {authenticator.trustee_id: [authenticator.passphrase] for authenticator in authenticators or ()}

    def build_cryptoconfs(self) -> dict:
        from wacryptolib.cryptainer import check_cryptoconf_sanity

        cryptoconf_paths = {}
        for name, spec in self.profile["cryptoconfs"].items():
            check_cryptoconf_sanity(spec["cryptoconf"])
            asset_path = self.writer.get_final_path("cryptoconfs", name + ".cryptoconf")
            self.writer.write_extjson_asset(asset_path, spec["cryptoconf"])
            self.writer.write_sidecar(
                asset_path,
                fixture_kind="cryptoconf",
                description=spec["description"],
                provenance=self.provenance,
                requirements=self._structure_requirements(spec["cryptoconf"], spec.get("authenticators")),
                expected_valid=True,
                sophistication_level=spec["level"],
                keystore_pool=_corpus.to_relpath(self.pool_path, corpus.get_sidecar_path(asset_path)),
                passphrase_mapper=self._full_passphrase_mapper(spec.get("authenticators")),
                min_library_version="0.12",
            )
            cryptoconf_paths[name] = asset_path

        for name, spec in self.profile["invalid_cryptoconfs"].items():
            asset_path = self.writer.get_final_path("cryptoconfs", "invalid", name + ".cryptoconf")
            self.writer.write_extjson_asset(asset_path, spec["cryptoconf"])
            self.writer.write_sidecar(
                asset_path,
                fixture_kind="cryptoconf",
                description=spec["description"] + " (must be rejected)",
                provenance=self.provenance,
                requirements=_corpus.build_requirements(),
                expected_valid=False,
                sophistication_level=0,
                min_library_version="0.12",
            )
        return cryptoconf_paths

    def _get_pool_copy(self) -> FilesystemKeystorePool:
        copy_dir = Path(tempfile.mkdtemp(dir=self.work_dir, prefix="pool-"))
        shutil.rmtree(copy_dir)
        shutil.copytree(self.pool_staging_dir, copy_dir)
        self._pool_copies = getattr(self, "_pool_copies", []) + [copy_dir]
        return FilesystemKeystorePool(copy_dir)

    def check_pool_untouched(self):
        """Encryptions must not have auto-generated keys, else committed cryptainers would need missing keys."""
        for copy_dir in getattr(self, "_pool_copies", []):
            comparison = filecmp.dircmp(self.pool_staging_dir, copy_dir)
            pending = [comparison]
            while pending:
                current = pending.pop()
                assert not (current.left_only or current.right_only or current.diff_files), (
                    "Keystore pool modified by an encryption: %s %s %s"
                    % (current.left_only, current.right_only, current.diff_files)
                )
                pending.extend(current.subdirs.values())

    def build_cryptainers(self, cryptoconf_paths: dict):
        from wacryptolib.cryptainer import load_cryptainer_from_filesystem

        for name, spec in self.profile["cryptainers"].items():
            cryptoconf_spec = self.profile["cryptoconfs"][spec["cryptoconf"]]
            conf = cryptoconf_spec["cryptoconf"]
            plaintext_path = self._plaintext_path(spec["plaintext_size"])
            plaintext = plaintext_path.read_bytes()
            cryptainer_metadata = spec.get("cryptainer_metadata")
            asset_path = self.writer.get_final_path("cryptainers", name + ".crypt")
            staging_path = self.writer.get_staging_path(asset_path)
            staging_path.parent.mkdir(parents=True, exist_ok=True)
            offloaded = spec.get("offloaded", False) or spec.get("streamed", False)

            if spec.get("streamed"):
                encrypt_payload_and_stream_cryptainer_to_filesystem(
                    plaintext,
                    cryptainer_filepath=staging_path,
                    cryptoconf=conf,
                    cryptainer_metadata=cryptainer_metadata,
                    keystore_pool=self._get_pool_copy(),
                )
                leftovers = sorted(
                    p.name for p in staging_path.parent.iterdir() if p.name.startswith(staging_path.name)
                )
                assert leftovers == [staging_path.name, staging_path.name + ".payload"], leftovers
            else:
                digest_list_context = (
                    _legacy_digest_list_rsa_oaep() if spec.get("digest_list_key_ciphertexts") else contextlib.nullcontext()
                )
                with digest_list_context:
                    cryptainer = encrypt_payload_into_cryptainer(
                        plaintext,
                        cryptoconf=conf,
                        cryptainer_metadata=cryptainer_metadata,
                        keystore_pool=self._get_pool_copy(),
                    )
                cryptainer = copy.deepcopy(cryptainer)
                if spec.get("digest_list_key_ciphertexts"):
                    assert b'"digest_list"' in cryptainer["payload_cipher_layers"][0]["key_ciphertext"]
                if spec.get("corrupt_ciphertext_signature"):
                    signature_struct = cryptainer["payload_cipher_layers"][0]["payload_ciphertext_signatures"][0][
                        "payload_signature_struct"
                    ]
                    signature_struct["signature_value"] = _corrupt_bytes(signature_struct["signature_value"])
                if spec.get("corrupt_payload_tag"):
                    payload_macs = cryptainer["payload_cipher_layers"][0]["payload_macs"]
                    payload_macs["tag"] = _corrupt_bytes(payload_macs["tag"])
                if spec.get("legacy_signature_field"):
                    for payload_cipher_layer in cryptainer["payload_cipher_layers"]:
                        payload_cipher_layer["payload_signatures"] = payload_cipher_layer.pop(
                            "payload_ciphertext_signatures"
                        )
                if spec.get("canonical"):
                    assert not offloaded, "Canonical cryptainers are written inline"
                    self.writer.write_extjson_asset(asset_path, cryptainer, canonical=True)
                else:
                    dump_cryptainer_to_filesystem(staging_path, cryptainer, offload_payload_ciphertext=offloaded)

            load_cryptainer_from_filesystem(staging_path)  # Sanity check of the dumped files
            legacy_forms = [
                legacy_form
                for option, legacy_form in [
                    ("canonical", "canonical_extjson"),
                    ("legacy_signature_field", "payload_signatures_field"),
                    ("digest_list_key_ciphertexts", "rsa_oaep_digest_list_field"),
                ]
                if spec.get(option)
            ]
            corruptions = [
                corruption
                for option, corruption in [
                    ("corrupt_ciphertext_signature", "Ciphertext signature value"),
                    ("corrupt_payload_tag", "Payload MAC tag"),
                ]
                if spec.get(option)
            ]
            notes = ("%s deliberately corrupted after encryption" % " and ".join(corruptions)) if corruptions else None
            if legacy_forms:
                provenance = _corpus.build_provenance("synthesized", legacy_forms=legacy_forms, notes=notes)
            else:
                provenance = dict(self.provenance, notes=notes) if notes else self.provenance
            fields = dict(
                plaintext=_corpus.to_relpath(plaintext_path, asset_path),
                keystore_pool=_corpus.to_relpath(self.pool_path, asset_path),
                cryptoconf=_corpus.to_relpath(cryptoconf_paths[spec["cryptoconf"]], asset_path),
                cryptainer_metadata=cryptainer_metadata,
                extjson_flavor="canonical" if spec.get("canonical") else "relaxed",
                payload_offloaded=offloaded,
                decryption_scenarios=spec["scenarios"],
            )
            self.writer.write_sidecar(
                asset_path,
                fixture_kind="cryptainer",
                description=spec["description"],
                provenance=provenance,
                requirements=self._structure_requirements(conf, cryptoconf_spec.get("authenticators")),
                **fields
            )


def generate_current_generation(profile_name: str, generation: str, corpus_dir: Path = _corpus.CORPUS_DIR) -> list:
    """Generate, commit and check a new generation; return the list of its directories."""
    profile = PROFILES[profile_name]()
    with tempfile.TemporaryDirectory(prefix="wacryptolib-compat-") as work_dir:
        work_dir = Path(work_dir)
        with _corpus.GenerationWriter(generation, corpus_dir=corpus_dir) as writer:
            CurrentGenerationBuilder(writer, profile, work_dir=work_dir).build()
            committed_dirs = writer.commit()
            try:
                sidecar_paths = list(writer.iter_committed_sidecar_paths())
                plaintext_sidecar_paths = sorted((Path(corpus_dir) / _corpus.PLAINTEXTS_DIRNAME).glob("*.json"))
                skipped = _corpus.check_generation_fixtures(plaintext_sidecar_paths + sidecar_paths, work_dir)
            except BaseException:
                writer.discard()
                raise
    for sidecar_path, reason in skipped.items():
        print("WARNING: fixture %s could not be checked: %s" % (sidecar_path, reason))
    print("Generation %s written and checked (%d sidecars) in:" % (generation, len(sidecar_paths)))
    for committed_dir in committed_dirs:
        print("   ", committed_dir)
    return committed_dirs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("profile", choices=sorted(PROFILES))
    parser.add_argument("generation", help="Name of the NEW generation, e.g. 2026_current")
    args = parser.parse_args(argv)
    try:
        generate_current_generation(args.profile, args.generation)
    except _corpus.GenerationAlreadyExists as exc:
        sys.exit("ABORTED: %s" % exc)


if __name__ == "__main__":
    main()
