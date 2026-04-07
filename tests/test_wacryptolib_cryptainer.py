# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import copy
import os
import random
import tempfile
import textwrap
import time
import uuid
from datetime import timedelta
from itertools import product
from pathlib import Path
from pprint import pprint
from unittest import mock
from unittest.mock import patch
from uuid import UUID

import pytest
from jsonrpc_requests import TransportError

import wacryptolib.cryptainer
from _test_mockups import FakeTestCryptainerStorage, random_bool
from wacryptolib._crypto_backend import get_random_bytes
from wacryptolib.cipher import SUPPORTED_CIPHER_ALGOS, AUTHENTICATED_CIPHER_ALGOS, encrypt_bytestring
from wacryptolib.cryptainer import (
    LOCAL_KEYFACTORY_TRUSTEE_MARKER,
    encrypt_payload_into_cryptainer,
    decrypt_payload_from_cryptainer,
    CryptainerStorage,
    extract_metadata_from_cryptainer,
    CryptainerBase,
    get_cryptoconf_summary,
    dump_cryptainer_to_filesystem,
    load_cryptainer_from_filesystem,
    SHARED_SECRET_ALGO_MARKER,
    get_trustee_id,
    gather_trustee_dependencies,
    get_trustee_proxy,
    request_decryption_authorizations,
    delete_cryptainer_from_filesystem,
    CRYPTAINER_DATETIME_FORMAT,
    get_cryptainer_size_on_filesystem,
    CryptainerEncryptor,
    encrypt_payload_and_stream_cryptainer_to_filesystem,
    is_cryptainer_cryptoconf_streamable,
    check_cryptoconf_sanity,
    check_cryptainer_sanity,
    CRYPTAINER_TEMP_SUFFIX,
    OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER,
    ReadonlyCryptainerStorage,
    CryptainerEncryptionPipeline,
    gather_decryptable_symkeys,
    DecryptionErrorType,
    DecryptionErrorCriticity,
    CRYPTAINER_SUFFIX,
    SIGNATURE_POLICIES,
    CRYPTAINER_TRUSTEE_TYPES,
    _do_get_message_signature,
)
from wacryptolib.exceptions import (
    DecryptionError,
    DecryptionIntegrityError,
    ValidationError,
    SchemaValidationError,
    SignatureVerificationError,
    KeyDoesNotExist,
    KeystoreDoesNotExist,
    KeyLoadingError,
    CryptographyError,
)
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.keygen import generate_keypair, load_asymmetric_key_from_pem_bytestring
from wacryptolib.keystore import (
    InMemoryKeystore,
    FilesystemKeystore,
    FilesystemKeystorePool,
    InMemoryKeystorePool,
    generate_keypair_for_storage,
)
from wacryptolib.trustee import TrusteeApi
from wacryptolib.utilities import (
    load_from_json_bytes,
    dump_to_json_bytes,
    generate_uuid0,
    get_utc_now_date,
    convert_to_extjson,
)
from wacryptolib.utilities import load_from_json_file


def _get_enriched_cryptoconf(cryptoconf, keychain_uid):
    cryptoconf = cryptoconf.copy()
    if keychain_uid:
        cryptoconf["keychain_uid"] = keychain_uid
    return cryptoconf


ENFORCED_UID1 = UUID("0e8e861e-f0f7-e54b-18ea-34798d5daaaa")
ENFORCED_UID2 = UUID("65dbbe4f-0bd5-4083-a274-3c76efeebbbb")
ENFORCED_UID3 = UUID("65dbbe4f-0bd5-4083-a274-3c76efeecccc")

DUMMY_GATEWAY_URLS = ["http://unexisting.example.com:9898/jsonrpc"]

VOID_CRYPTOCONF_REGARDING_PAYLOAD_CIPHER_LAYERS = dict(payload_cipher_layers=[])  # Forbidden

VOID_CRYPTOCONF_REGARDING_KEY_CIPHER_LAYERS = dict(  # Forbidden
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[],
            payload_ciphertext_signatures=[
                dict(
                    payload_digest_algo="SHA256",
                    payload_signature_algo="DSA_DSS",
                    payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                )
            ],
        )
    ]
)


MISCONFIGURED_SHAMIR_CRYPTOCONF = dict(
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[
                dict(
                    key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
                    key_shared_secret_threshold=random.choice([0, 2]),  # WRONG THERSHOLD
                    key_shared_secret_shards=[
                        dict(
                            key_cipher_layers=[
                                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                            ]
                        ),
                    ],
                ),
            ],
            payload_ciphertext_signatures=[],
        )
    ]
)


SIGNATURELESS_CRYPTOCONF = dict(
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_EAX",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_ciphertext_signatures=[],
        )
    ]
)

SIGNATURELESS_CRYPTAINER_TRUSTEE_DEPENDENCIES = lambda keychain_uid: {
    "encryption": {
        "local_keyfactory": (
            {"trustee_type": "local_keyfactory"},
            [{"key_algo": "RSA_OAEP", "keychain_uid": keychain_uid}],
        )
    },
    "signature": {},
}

SIMPLE_CRYPTOCONF = dict(
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_ciphertext_signatures=[
                dict(
                    payload_digest_algo="SHA256",
                    payload_signature_algo="DSA_DSS",
                    payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                )
            ],
        )
    ]
)

# Generating signing keys can be loooong, so we need this cryptoconf too for some tests
SIMPLE_CRYPTOCONF_NO_SIGNING = dict(
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_ciphertext_signatures=[],
        )
    ]
)

SIMPLE_CRYPTAINER_TRUSTEE_DEPENDENCIES = lambda keychain_uid: {
    "encryption": {
        "local_keyfactory": (
            {"trustee_type": "local_keyfactory"},
            [{"key_algo": "RSA_OAEP", "keychain_uid": keychain_uid}],
        )
    },
    "signature": {
        "local_keyfactory": (
            {"trustee_type": "local_keyfactory"},
            [{"key_algo": "DSA_DSS", "keychain_uid": keychain_uid}],
        )
    },
}

COMPLEX_CRYPTOCONF = dict(
    payload_plaintext_signatures=[
        dict(
            payload_digest_algo="SHA256",
            payload_signature_algo="RSA_PSS",
            payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
        )
    ],
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_EAX",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_ciphertext_signatures=[],
        ),
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[
                dict(
                    key_cipher_algo="RSA_OAEP",
                    key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                    keychain_uid=ENFORCED_UID1,
                ),
                dict(
                    key_cipher_algo="AES_EAX",
                    key_cipher_layers=[
                        dict(
                            key_cipher_algo="RSA_OAEP",
                            key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                            keychain_uid=ENFORCED_UID3,
                        ),
                        dict(
                            key_cipher_algo="RSA_OAEP",
                            key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                            # Default keychain_uid
                        ),
                    ],
                ),
            ],
            payload_ciphertext_signatures=[
                dict(
                    payload_digest_algo="SHA3_512",
                    payload_signature_algo="DSA_DSS",
                    payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                )
            ],
        ),
        dict(
            payload_cipher_algo="CHACHA20_POLY1305",
            key_cipher_layers=[
                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER),
                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER),
            ],
            payload_ciphertext_signatures=[
                dict(
                    payload_digest_algo="SHA3_256",
                    payload_signature_algo="RSA_PSS",
                    payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                ),
                dict(
                    payload_digest_algo="SHA512",
                    payload_signature_algo="ECC_DSS",
                    payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                    keychain_uid=ENFORCED_UID2,
                ),
            ],
        ),
    ],
)

COMPLEX_CRYPTAINER_TRUSTEE_DEPENDENCIES = lambda keychain_uid: {
    "encryption": {
        "local_keyfactory": (
            {"trustee_type": "local_keyfactory"},
            [
                {"key_algo": "RSA_OAEP", "keychain_uid": keychain_uid},  # Trustee used as several places
                {"key_algo": "RSA_OAEP", "keychain_uid": ENFORCED_UID1},
                {"key_algo": "RSA_OAEP", "keychain_uid": ENFORCED_UID3},
            ],
        )
    },
    "signature": {
        "local_keyfactory": (
            {"trustee_type": "local_keyfactory"},
            [
                {"key_algo": "DSA_DSS", "keychain_uid": keychain_uid},
                {"key_algo": "RSA_PSS", "keychain_uid": keychain_uid},
                {"key_algo": "ECC_DSS", "keychain_uid": ENFORCED_UID2},
            ],
        )
    },
}

SIMPLE_SHAMIR_CRYPTOCONF = dict(
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[
                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER),
                dict(
                    key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
                    key_shared_secret_threshold=3,
                    key_shared_secret_shards=[
                        dict(
                            key_cipher_layers=[
                                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                            ]
                        ),
                        dict(
                            key_cipher_layers=[
                                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                            ]
                        ),
                        dict(
                            key_cipher_layers=[
                                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                            ]
                        ),
                        dict(
                            key_cipher_layers=[
                                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                            ]
                        ),
                        dict(
                            key_cipher_layers=[
                                dict(
                                    key_cipher_algo="RSA_OAEP",
                                    key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                                    keychain_uid=ENFORCED_UID1,
                                )
                            ]
                        ),
                    ],
                ),
            ],
            payload_ciphertext_signatures=[
                dict(
                    payload_digest_algo="SHA256",
                    payload_signature_algo="DSA_DSS",
                    payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                )
            ],
        )
    ]
)


def SIMPLE_SHAMIR_CRYPTAINER_TRUSTEE_DEPENDENCIES(keychain_uid):
    return {
        "encryption": {
            "local_keyfactory": (
                {"trustee_type": "local_keyfactory"},
                [
                    {"key_algo": "RSA_OAEP", "keychain_uid": keychain_uid},
                    {"key_algo": "RSA_OAEP", "keychain_uid": ENFORCED_UID1},
                ],
            )
        },
        "signature": {
            "local_keyfactory": (
                {"trustee_type": "local_keyfactory"},
                [{"key_algo": "DSA_DSS", "keychain_uid": keychain_uid}],
            )
        },
    }


COMPLEX_SHAMIR_CRYPTOCONF = dict(
    payload_plaintext_signatures=[
        dict(
            payload_digest_algo="SHA512",
            payload_signature_algo="DSA_DSS",
            payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
        )
    ],
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_EAX",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_ciphertext_signatures=[],
        ),
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_ciphertext_signatures=[
                dict(
                    payload_digest_algo="SHA3_512",
                    payload_signature_algo="DSA_DSS",
                    payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                )
            ],
        ),
        dict(
            payload_cipher_algo="CHACHA20_POLY1305",
            key_cipher_layers=[
                dict(
                    key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
                    key_shared_secret_threshold=2,
                    key_shared_secret_shards=[
                        dict(
                            key_cipher_layers=[
                                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER),
                                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER),
                            ]
                        ),
                        dict(
                            key_cipher_layers=[
                                dict(
                                    key_cipher_algo="AES_CBC",
                                    key_cipher_layers=[
                                        dict(
                                            key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
                                            key_shared_secret_threshold=1,
                                            key_shared_secret_shards=[
                                                dict(
                                                    key_cipher_layers=[
                                                        dict(
                                                            key_cipher_algo="RSA_OAEP",
                                                            key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                                                            keychain_uid=ENFORCED_UID3,
                                                        )
                                                    ]
                                                )
                                            ],
                                        ),
                                        dict(
                                            key_cipher_algo="RSA_OAEP",
                                            key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                                            # Default keychain_uid
                                        ),
                                    ],
                                )
                            ]
                        ),
                        dict(
                            key_cipher_layers=[
                                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                            ]
                        ),
                        dict(
                            key_cipher_layers=[
                                dict(
                                    key_cipher_algo="RSA_OAEP",
                                    key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                                    keychain_uid=ENFORCED_UID2,
                                )
                            ]
                        ),
                    ],
                )
            ],
            payload_ciphertext_signatures=[
                dict(
                    payload_digest_algo="SHA3_256",
                    payload_signature_algo="RSA_PSS",
                    payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                    keychain_uid=ENFORCED_UID1,
                ),
                dict(
                    payload_digest_algo="SHA512",
                    payload_signature_algo="ECC_DSS",
                    payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                ),
            ],
        ),
    ],
)


def COMPLEX_SHAMIR_CRYPTAINER_TRUSTEE_DEPENDENCIES(keychain_uid):
    return {
        "encryption": {
            "local_keyfactory": (
                {"trustee_type": "local_keyfactory"},
                [
                    {"key_algo": "RSA_OAEP", "keychain_uid": keychain_uid},
                    {"key_algo": "RSA_OAEP", "keychain_uid": ENFORCED_UID3},
                    {"key_algo": "RSA_OAEP", "keychain_uid": ENFORCED_UID2},
                ],
            )
        },
        "signature": {
            "local_keyfactory": (
                {"trustee_type": "local_keyfactory"},
                [
                    {"key_algo": "DSA_DSS", "keychain_uid": keychain_uid},
                    {"key_algo": "RSA_PSS", "keychain_uid": ENFORCED_UID1},
                    {"key_algo": "ECC_DSS", "keychain_uid": keychain_uid},
                ],
            )
        },
    }


SIMPLE_CRYPTOCONF_WITH_BAD_PLAINTEXT_SIGNING = dict(
    payload_plaintext_signatures=[
        dict(
            payload_digest_algo="SHA256",
            payload_signature_algo="DSA_DSS",
            payload_signature_trustee=dict(
                trustee_type=CRYPTAINER_TRUSTEE_TYPES.AUTHENTICATOR_TRUSTEE,
                keystore_uid=ENFORCED_UID1,
            ),
        )
    ],
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_ciphertext_signatures=[],
        )
    ],
)


SIMPLE_CRYPTOCONF_WITH_BAD_CIPHERTEXT_SIGNING = dict(
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_EAX",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_ciphertext_signatures=[
                dict(
                    payload_digest_algo="SHA512",
                    payload_signature_algo="RSA_PSS",
                    payload_signature_trustee=dict(
                        trustee_type=CRYPTAINER_TRUSTEE_TYPES.AUTHENTICATOR_TRUSTEE,
                        keystore_uid=ENFORCED_UID1,
                    ),
                )
            ],
        )
    ]
)


def _get_binary_or_empty_content():
    if random_bool():
        bytes_length = random.randint(1, 1000)
        return get_random_bytes(bytes_length)
    return b""


def _get_random_cryptainer_storage_class():
    return random.choice([CryptainerStorage, ReadonlyCryptainerStorage])


def _intialize_real_cryptainer_with_single_file(tmp_path, allow_readonly_storage=False):
    storage = CryptainerStorage(default_cryptoconf=COMPLEX_CRYPTOCONF, cryptainer_dir=tmp_path)

    storage.enqueue_file_for_encryption("animals.dat", b"dogs\ncats\n", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    (cryptainer_name,) = storage.list_cryptainer_names()

    if allow_readonly_storage:
        StorageClass = _get_random_cryptainer_storage_class()
        storage = StorageClass(cryptainer_dir=tmp_path)  # We assume no default cryptoconf, then

    return storage, cryptainer_name


def _add_unfinished_cryptainer_to_folder(folder_path):
    cryptainer_filepath = folder_path / ("unfinished_cryptainer.dat" + CRYPTAINER_SUFFIX)

    pipeline = CryptainerEncryptionPipeline(
        cryptainer_filepath=cryptainer_filepath,
        cryptoconf=SIMPLE_CRYPTOCONF,
        cryptainer_metadata=None,
        signature_policy=SIGNATURE_POLICIES.SKIP_SIGNING,
        dump_initial_cryptainer=True,
    )
    del pipeline

    cryptainer_filepath_pending = cryptainer_filepath.with_suffix(cryptainer_filepath.suffix + CRYPTAINER_TEMP_SUFFIX)
    assert cryptainer_filepath_pending.exists()

    return cryptainer_filepath_pending


def _corrupt_cryptainer_tree(storage, cryptainer_name, corruptor_callback):
    cryptainer = storage.load_cryptainer_from_storage(cryptainer_name)
    corruptor_callback(cryptainer)  # Modifies the cryptainer in-place
    cryptainer_filepath = storage._make_absolute(cryptainer_name)
    dump_cryptainer_to_filesystem(
        cryptainer_filepath, cryptainer=cryptainer, offload_payload_ciphertext=False
    )  # Don't touch existing offloaded payload


def test_get_trustee_id():
    assert get_trustee_id(LOCAL_KEYFACTORY_TRUSTEE_MARKER) == "local_keyfactory"
    assert (
        get_trustee_id({"trustee_type": "authenticator", "keystore_uid": UUID("b6c576e1-ae1e-4154-ad71-4d564b4673de")})
        == "authenticator@b6c576e1-ae1e-4154-ad71-4d564b4673de"
    )
    assert (
        get_trustee_id({"trustee_type": "jsonrpc_api", "jsonrpc_url": "https://my.api.com/jsonrpc/"})
        == "jsonrpc_api@https://my.api.com/jsonrpc/"
    )
    with pytest.raises(ValueError):
        get_trustee_id({"trustee_type": "whatever"})
    with pytest.raises(ValueError):
        get_trustee_id({"aaa": "bbb"})


@pytest.mark.parametrize(
    "cryptoconf",
    [
        VOID_CRYPTOCONF_REGARDING_PAYLOAD_CIPHER_LAYERS,
        VOID_CRYPTOCONF_REGARDING_KEY_CIPHER_LAYERS,
        MISCONFIGURED_SHAMIR_CRYPTOCONF,
    ],
)
def test_misconfigured_cryptoconfs(cryptoconf):
    keystore_pool = InMemoryKeystorePool()

    with pytest.raises(SchemaValidationError, match="Empty .* list|threshold"):
        encrypt_payload_into_cryptainer(
            payload=b"stuffs",
            cryptoconf=cryptoconf,
            cryptainer_metadata=None,
            keystore_pool=keystore_pool,
        )


def test_encrypt_payload_into_cryptainer_from_file_object(tmp_path):
    source = tmp_path / "source.media"
    source.write_bytes(b"12345")
    assert source.exists()

    file_handle = open(source, "rb")

    cryptainer = encrypt_payload_into_cryptainer(
        payload=file_handle,
        cryptoconf=SIMPLE_CRYPTOCONF,
        cryptainer_metadata=None,
        keystore_pool=InMemoryKeystorePool(),
    )
    assert cryptainer

    assert not file_handle.closed
    assert source.exists()  # Source is NOT autodeleted!


def test_cryptainer_encryption_pipeline_autocleanup(tmp_path):
    pipeline = CryptainerEncryptionPipeline(
        cryptainer_filepath=tmp_path.joinpath("destination.crypt"),
        cryptoconf=SIMPLE_CRYPTOCONF,
        cryptainer_metadata=None,
        signature_policy=SIGNATURE_POLICIES.REQUIRE_SIGNING,
    )
    assert not pipeline._output_data_stream.closed
    pipeline.encrypt_chunk(b"abc")
    pipeline.encrypt_chunk(b"123")
    pipeline.finalize()
    assert pipeline._output_data_stream.closed

    pipeline2 = CryptainerEncryptionPipeline(
        cryptainer_filepath=tmp_path.joinpath("destination.crypt"),
        cryptoconf=SIMPLE_CRYPTOCONF,
        cryptainer_metadata=None,
        signature_policy=SIGNATURE_POLICIES.SKIP_SIGNING,
    )
    output_data_stream2 = pipeline2._output_data_stream
    assert not output_data_stream2.closed
    del pipeline2
    assert output_data_stream2.closed  # Autoclosed in __del__()


def test_is_cryptainer_cryptoconf_streamable():
    assert is_cryptainer_cryptoconf_streamable(SIMPLE_CRYPTOCONF)
    assert is_cryptainer_cryptoconf_streamable(COMPLEX_SHAMIR_CRYPTOCONF)

    WRONG_CRYPTOCONF = dict(
        payload_cipher_layers=[
            dict(
                payload_cipher_algo="RSA_OAEP",
                key_cipher_layers=[
                    dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                ],
            )
        ]
    )
    assert not is_cryptainer_cryptoconf_streamable(WRONG_CRYPTOCONF)


@pytest.mark.parametrize(
    "cryptoconf,trustee_dependencies_builder",
    [
        (SIGNATURELESS_CRYPTOCONF, SIGNATURELESS_CRYPTAINER_TRUSTEE_DEPENDENCIES),
        (SIMPLE_CRYPTOCONF, SIMPLE_CRYPTAINER_TRUSTEE_DEPENDENCIES),
        (COMPLEX_CRYPTOCONF, COMPLEX_CRYPTAINER_TRUSTEE_DEPENDENCIES),
    ],
)
# with local keyfactory
def test_standard_cryptainer_encryption_and_decryption(tmp_path, cryptoconf, trustee_dependencies_builder):
    payload = _get_binary_or_empty_content()

    keychain_uid = random.choice([None, uuid.UUID("450fc293-b702-42d3-ae65-e9cc58e5a62a")])
    cryptoconf = _get_enriched_cryptoconf(cryptoconf, keychain_uid=keychain_uid)

    use_streaming_encryption = random_bool()

    keystore_pool = InMemoryKeystorePool()
    metadata = random.choice([None, dict(a=[123])])

    if use_streaming_encryption and is_cryptainer_cryptoconf_streamable(cryptoconf):
        cryptainer_filepath = tmp_path / "mygoodcryptainer.crypt"
        encrypt_payload_and_stream_cryptainer_to_filesystem(
            payload=payload,
            cryptainer_filepath=cryptainer_filepath,
            cryptoconf=cryptoconf,
            cryptainer_metadata=metadata,
            keystore_pool=keystore_pool,
        )
        cryptainer = load_cryptainer_from_filesystem(cryptainer_filepath, include_payload_ciphertext=True)
    else:
        cryptainer = encrypt_payload_into_cryptainer(
            payload=payload,
            cryptoconf=cryptoconf,
            cryptainer_metadata=metadata,
            keystore_pool=keystore_pool,
        )

    assert cryptainer["keychain_uid"]
    if keychain_uid:
        assert cryptainer["keychain_uid"] == keychain_uid

    local_keypair_identifiers = keystore_pool.get_local_keyfactory()._cached_keypairs
    print(">>> Test local_keypair_identifiers ->", list(local_keypair_identifiers.keys()))

    trustee_dependencies = gather_trustee_dependencies(cryptainers=[cryptainer])
    print("GOTTEN DEPENDENCIES:")
    pprint(trustee_dependencies)
    print("THEORETICAL DEPENDENCIES:")
    pprint(trustee_dependencies_builder(cryptainer["keychain_uid"]))

    assert trustee_dependencies == trustee_dependencies_builder(cryptainer["keychain_uid"])

    # Check that all referenced keys were really created during encryption (so keychain_uid overriding works fine)
    for trustee_dependency_structs in trustee_dependencies.values():
        for trustee_dependency_struct in trustee_dependency_structs.values():
            trustee_conf, keypairs_identifiers = trustee_dependency_struct
            trustee = get_trustee_proxy(trustee_conf, keystore_pool=keystore_pool)
            for keypairs_identifier in keypairs_identifiers:
                assert trustee.fetch_public_key(**keypairs_identifier, must_exist=True)

    all_authorization_results = request_decryption_authorizations(
        trustee_dependencies=trustee_dependencies, request_message="Decryption needed", keystore_pool=keystore_pool
    )

    # Generic check of data structure
    for authorization_results in all_authorization_results.values():
        assert not authorization_results["has_errors"]
        assert "accepted" in authorization_results["response_message"]
        keypair_statuses = authorization_results["keypair_statuses"]
        assert keypair_statuses["accepted"]
        for keypair_identifiers in keypair_statuses["accepted"]:
            assert keypair_identifiers["key_algo"] in SUPPORTED_CIPHER_ALGOS
            assert isinstance(keypair_identifiers["keychain_uid"], UUID)
        assert not keypair_statuses["authorization_missing"]
        assert not keypair_statuses["missing_passphrase"]
        assert not keypair_statuses["missing_private_key"]

    verify_integrity_tags = random_bool()
    result_payload, operation_report = decrypt_payload_from_cryptainer(
        cryptainer=cryptainer, keystore_pool=keystore_pool, verify_integrity_tags=verify_integrity_tags
    )
    assert not operation_report.get_error_entries()
    assert not operation_report.get_error_count()
    assert not operation_report.has_errors()
    # pprint.pprint(result, width=120)
    assert result_payload == payload

    result_metadata = extract_metadata_from_cryptainer(cryptainer=cryptainer)
    assert result_metadata == metadata

    # Invalid Cryptainer Format
    cryptainer["cryptainer_format"] = "OAJKB"
    with pytest.raises(ValueError, match="Unknown cryptainer format"):
        decrypt_payload_from_cryptainer(cryptainer=cryptainer)


def _decrypt_cipherdict_with_trustee_then_encryt_with_response_key(
    foreign_keystore, cipherdict, keychain_uid, cipher_algo, response_key_algo, response_public_key, passphrases
):
    trustee_api = TrusteeApi(keystore=foreign_keystore)

    key_struct_bytes = trustee_api.decrypt_with_private_key(
        keychain_uid=keychain_uid, cipher_algo=cipher_algo, cipherdict=cipherdict, passphrases=passphrases
    )

    public_key = load_asymmetric_key_from_pem_bytestring(key_pem=response_public_key, key_algo=cipher_algo)

    response_data_dict = encrypt_bytestring(
        plaintext=key_struct_bytes, cipher_algo=response_key_algo, key_dict=dict(key=public_key)
    )
    response_data = dump_to_json_bytes(response_data_dict)

    return response_data


def _build_fake_gateway_revelation_request_list(revelation_requests_info):
    revelation_requests_successful = []

    for revelation_request_info in revelation_requests_info:
        cipherdict = load_from_json_bytes(revelation_request_info["symkey_ciphertext"])
        foreign_keystore = revelation_request_info["foreign_keystore"]

        # Authenticator has a single key pair that was used for data encryption
        keychain_uid = revelation_request_info["public_keys"][0]["keychain_uid"]
        cipher_algo = revelation_request_info["public_keys"][0]["key_algo"]
        key_value = revelation_request_info["public_keys"][0]["key_value"]

        response_key_algo = revelation_request_info["response_key_algo"]
        response_public_key = revelation_request_info["response_public_key"]

        passphrase = revelation_request_info["passphrase"]

        symkey_decryption_response_data = _decrypt_cipherdict_with_trustee_then_encryt_with_response_key(
            foreign_keystore, cipherdict, keychain_uid, cipher_algo, response_key_algo, response_public_key, passphrase
        )

        revelation_request_successful = {
            "target_public_authenticator": [
                {
                    "keystore_owner": revelation_request_info["keystore_owner"],
                    "keystore_uid": revelation_request_info["keystore_uid"],
                    "public_keys": revelation_request_info["public_keys"],
                }
            ],
            "revelation_request_uid": generate_uuid0(),
            "revelation_requestor_uid": revelation_request_info["revelation_requestor_uid"],
            "revelation_request_description": "Description",
            "revelation_response_public_key": revelation_request_info["response_public_key"],
            "revelation_response_keychain_uid": revelation_request_info["response_keychain_uid"],
            "revelation_response_key_algo": revelation_request_info["response_key_algo"],
            "revelation_request_status": "ACCEPTED",
            "symkey_decryption_requests": [
                {
                    "target_public_authenticator_key": [
                        {"keychain_uid": keychain_uid, "key_algo": cipher_algo, "key_value": key_value}
                    ],
                    "cryptainer_uid": revelation_request_info["cryptainer_uid"],
                    "cryptainer_metadata": revelation_request_info["cryptainer_metadata"],
                    "symkey_decryption_request_data": revelation_request_info["symkey_ciphertext"],
                    "symkey_decryption_response_data": symkey_decryption_response_data,
                    "symkey_decryption_status": "DECRYPTED",
                }
            ],
        }

        revelation_requests_successful.append(revelation_request_successful)

    return revelation_requests_successful


def _patched_gateway_revelation_request_list(return_value=None):
    return mock.patch(
        "wacryptolib.jsonrpc_client.JsonRpcProxy.list_requestor_revelation_requests",
        create=True,
        return_value=return_value,
    )


def _create_keystore_and_keypair_protected_by_passphrase_in_foreign_keystore(keystore_uid, keychain_uid, passphrase):
    # Create fake keystore in foreign key
    keystore_pool = InMemoryKeystorePool()
    keystore_pool._register_fake_imported_storage_uids(storage_uids=[keystore_uid])

    foreign_keystore = keystore_pool.get_foreign_keystore(keystore_uid)
    generate_keypair_for_storage(
        key_algo="RSA_OAEP", keystore=foreign_keystore, keychain_uid=keychain_uid, passphrase=passphrase
    )

    # Get Trustee id
    key_cipher_trustee = dict(trustee_type="authenticator", keystore_uid=keystore_uid, keystore_owner="owner")

    return keystore_pool, foreign_keystore, key_cipher_trustee


# Create a response keypair in localkeyfactory to encrypt the decrypted symkeys and for each crypatiner trustee create
# the information needed to generate a successful decryption request
def _create_response_keyair_in_local_keyfactory_and_build_fake_revelation_request_info(
    revelation_requestor_uid, cryptainers_with_names, keystore_pool, list_shard_trustee_id
):
    # Create response key pair in local key factory
    local_keystore = keystore_pool.get_local_keyfactory()
    response_keychain_uid = generate_uuid0()
    generate_keypair_for_storage(key_algo="RSA_OAEP", keystore=local_keystore, keychain_uid=response_keychain_uid)
    response_public_key = local_keystore.get_public_key(keychain_uid=response_keychain_uid, key_algo="RSA_OAEP")

    decryptable_symkeys_per_trustee = gather_decryptable_symkeys(cryptainers_with_names=cryptainers_with_names)

    revelation_requests_info = []
    for shard_trustee_id, passphrase in list_shard_trustee_id:
        trustee_data, symkey_revelation_requests = decryptable_symkeys_per_trustee[shard_trustee_id]
        keystore_uid = trustee_data["keystore_uid"]
        keychain_uid = symkey_revelation_requests[0]["keychain_uid"]

        foreign_keystore = keystore_pool.get_foreign_keystore(keystore_uid)

        # Get a key value of trustee public key
        key_value = foreign_keystore.get_public_key(keychain_uid=keychain_uid, key_algo="RSA_OAEP")

        revelation_request_info = {
            "revelation_requestor_uid": revelation_requestor_uid,
            "keystore_uid": keystore_uid,
            "keystore_owner": trustee_data["keystore_uid"],
            "public_keys": [
                {
                    "keychain_uid": symkey_revelation_requests[0]["keychain_uid"],
                    "key_algo": symkey_revelation_requests[0]["key_algo"],
                    "key_value": key_value,
                }
            ],
            "response_public_key": response_public_key,
            "response_keychain_uid": response_keychain_uid,
            "response_key_algo": "RSA_OAEP",
            "cryptainer_uid": symkey_revelation_requests[0]["cryptainer_uid"],
            "cryptainer_metadata": symkey_revelation_requests[0]["cryptainer_metadata"],
            "symkey_ciphertext": symkey_revelation_requests[0]["symkey_decryption_request_data"],
            "foreign_keystore": foreign_keystore,
            "passphrase": [passphrase],
        }
        revelation_requests_info.append(revelation_request_info)

    return revelation_requests_info


def _check_operation_report_entry(
    operation_report, entry_type, entry_criticity, entry_msg_match, exception_class=None, occurrence_count=1
):
    real_occurrence_count = 0

    print("REPORT LIST:")
    print(operation_report.format_entries())

    for entry in operation_report.get_all_entries():
        try:
            assert entry["entry_type"] == entry_type
            assert entry["entry_criticity"] == entry_criticity
            assert entry_msg_match.lower() in entry["entry_message"].lower()

            if exception_class is not None:
                real__exception_class = entry["entry_exception"].__class__  # EXACT match, not "issubclass"!
                assert real__exception_class == exception_class
            else:
                assert entry["entry_exception"] is None

            real_occurrence_count += 1
        except AssertionError:
            pass  # It was not the entry we searched for

    assert real_occurrence_count == occurrence_count


def test_cryptainer_decryption_rare_cipher_errors(tmp_path):
    keychain_uid = generate_uuid0()

    cryptoconf = dict(
        keychain_uid=keychain_uid,
        payload_cipher_layers=[
            dict(
                payload_cipher_algo="AES_CBC",
                key_cipher_layers=[
                    dict(
                        key_cipher_algo="AES_EAX",
                        key_cipher_layers=[
                            dict(
                                key_cipher_algo="RSA_OAEP",
                                keychain_uid=keychain_uid,
                                key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                            )
                        ],
                    )
                ],
                payload_ciphertext_signatures=[],
            )
        ],
    )

    check_cryptoconf_sanity(cryptoconf=cryptoconf, jsonschema_mode=False)

    # Encrypt payload into cryptainer
    payload = b"sdfsfsdfsdf"

    cryptainer_original = encrypt_payload_into_cryptainer(
        payload=payload, cryptoconf=cryptoconf, cryptainer_metadata=None
    )
    pprint(cryptainer_original)

    cryptainer = copy.deepcopy(cryptainer_original)

    result_payload, operation_report = decrypt_payload_from_cryptainer(cryptainer)
    assert result_payload == payload  # SUCCESS

    # Corrupt the integrity tag of the ciphertext
    key_ciphertext = cryptainer["payload_cipher_layers"][0]["key_ciphertext"]
    key_cipherdict = load_from_json_bytes(key_ciphertext)
    key_cipherdict["tag"] += b"xxx"
    cryptainer["payload_cipher_layers"][0]["key_ciphertext"] = dump_to_json_bytes(key_cipherdict)

    result_payload, operation_report = decrypt_payload_from_cryptainer(cryptainer)
    assert not result_payload

    _check_operation_report_entry(
        operation_report=operation_report,
        entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
        entry_criticity=DecryptionErrorCriticity.ERROR,
        entry_msg_match="decrypting key with symmetric algorithm AES_EAX",
        exception_class=DecryptionIntegrityError,
    )
    assert operation_report.get_error_count() == 2
    assert operation_report.has_errors()

    # ---

    cryptainer = copy.deepcopy(cryptainer_original)
    key_ciphertext = cryptainer["payload_cipher_layers"][0]["key_cipher_layers"][0]["key_ciphertext"]
    key_cipherdict = load_from_json_bytes(key_ciphertext)
    key_cipherdict["ciphertext_chunks"][0] += b"xxx"
    cryptainer["payload_cipher_layers"][0]["key_cipher_layers"][0]["key_ciphertext"] = dump_to_json_bytes(
        key_cipherdict
    )

    result_payload, operation_report = decrypt_payload_from_cryptainer(cryptainer)
    assert not result_payload

    _check_operation_report_entry(
        operation_report=operation_report,
        entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        entry_criticity=DecryptionErrorCriticity.ERROR,
        entry_msg_match="decrypting key with asymmetric algorithm",
        exception_class=DecryptionError,
    )
    assert operation_report.get_error_count() == 2


# Cryptoconf with 1 payload_cipher_layer containing 1 key_cipher_layer managed by an authenticator
def test_cryptainer_decryption_with_passphrases_and_mock_authenticator_from_simplecryptoconf(tmp_path):

    keychain_uid_trustee = generate_uuid0()
    keystore_uid = generate_uuid0()
    passphrase = "tata"

    # Create fake keystore and keypair trustee in foreign key
    (
        keystore_pool,
        foreign_keystore,
        key_cipher_trustee,
    ) = _create_keystore_and_keypair_protected_by_passphrase_in_foreign_keystore(
        keystore_uid=keystore_uid, keychain_uid=keychain_uid_trustee, passphrase=passphrase
    )

    # Get shard trustee id
    list_shard_trustee_id = []
    shard_trustee_id = get_trustee_id(key_cipher_trustee)
    trustee_info = (shard_trustee_id, passphrase)
    list_shard_trustee_id.append(trustee_info)

    # Cryptoconf
    cryptoconf = dict(
        payload_cipher_layers=[
            dict(
                payload_cipher_algo="AES_CBC",
                key_cipher_layers=[
                    dict(
                        key_cipher_algo="RSA_OAEP",
                        keychain_uid=keychain_uid_trustee,
                        key_cipher_trustee=key_cipher_trustee,
                    )
                ],
                payload_ciphertext_signatures=[],
            )
        ]
    )
    check_cryptoconf_sanity(cryptoconf=cryptoconf, jsonschema_mode=False)

    # Ecrypt payload into cryptainer
    keychain_uid = random.choice([None, uuid.UUID("450fc293-b702-42d3-ae65-e9cc58e5a62a")])
    cryptoconf = _get_enriched_cryptoconf(cryptoconf, keychain_uid=keychain_uid)
    payload = b"sjzgzj"

    cryptainer = encrypt_payload_into_cryptainer(
        payload=payload,
        cryptoconf=cryptoconf,
        keystore_pool=keystore_pool,
        cryptainer_metadata=None,
    )
    passphrase_mapper = {shard_trustee_id: [passphrase]}

    # Decrypt cryptainer with passphrase
    result_payload, operation_report = decrypt_payload_from_cryptainer(
        cryptainer, keystore_pool=keystore_pool, passphrase_mapper={shard_trustee_id: [passphrase]}
    )
    assert result_payload == payload

    # Wrong passphrase
    result_payload, operation_report = decrypt_payload_from_cryptainer(
        cryptainer, keystore_pool=keystore_pool, passphrase_mapper={shard_trustee_id: ["fakepassphrase"]}
    )
    assert result_payload is None
    _check_operation_report_entry(
        operation_report=operation_report,
        entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        entry_criticity=DecryptionErrorCriticity.WARNING,
        entry_msg_match="Could not load private key",
        exception_class=KeyLoadingError,
    )
    # DecryptionError is present whenever decryption fails (will not always be tested)
    _check_operation_report_entry(
        operation_report=operation_report,
        entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
        entry_criticity=DecryptionErrorCriticity.ERROR,
        entry_msg_match="Failed symmetric decryption",
    )

    assert operation_report.get_error_count() == 2

    revelation_requestor_uid = generate_uuid0()

    cryptainers_with_names = [("cryptainer_name.mp4.crypt", cryptainer)]

    revelation_requests_info = _create_response_keyair_in_local_keyfactory_and_build_fake_revelation_request_info(
        revelation_requestor_uid, cryptainers_with_names, keystore_pool, list_shard_trustee_id
    )

    gateway_urls = DUMMY_GATEWAY_URLS

    # Network warning when no JSONRPC mockups provided
    result_payload, operation_report = decrypt_payload_from_cryptainer(
        cryptainer=cryptainer,
        keystore_pool=keystore_pool,
        passphrase_mapper=passphrase_mapper,
        gateway_urls=gateway_urls,
        revelation_requestor_uid=revelation_requestor_uid,
    )
    assert result_payload == payload
    _check_operation_report_entry(
        operation_report=operation_report,
        entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        entry_criticity=DecryptionErrorCriticity.WARNING,
        entry_msg_match="reach remote server",
        exception_class=TransportError,
    )
    assert operation_report.get_error_count() == 1

    # Remote revelation request return right symkey_revelation_response_data
    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(revelation_requests_info)
    ):
        result_payload, operation_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper=passphrase_mapper,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload == payload
        assert not operation_report.get_error_entries()

    # Response keypair in not local key factory
    fake_revelation_request_info = copy.deepcopy(revelation_requests_info)
    wrong_response_keychain_uid = generate_uuid0()
    fake_revelation_request_info[0]["response_keychain_uid"] = wrong_response_keychain_uid

    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(fake_revelation_request_info)
    ):
        result_payload, operation_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper=passphrase_mapper,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert (
            result_payload == payload
        )  # Using imported trustee because can't decrypt the symkey_decryption_response_data with response key
        _check_operation_report_entry(
            operation_report=operation_report,
            entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            entry_criticity=DecryptionErrorCriticity.ERROR,
            entry_msg_match="Private key of revelation response not found",
            exception_class=KeyDoesNotExist,
        )
        assert operation_report.get_error_count() == 1
        assert operation_report.has_errors()

    # Wrong symkey revelation response data
    gateway_revelation_request_list = _build_fake_gateway_revelation_request_list(revelation_requests_info)
    # Corrupted symkey
    gateway_revelation_request_list[0]["symkey_decryption_requests"][0][
        "symkey_decryption_response_data"
    ] = b'{"ciphertext_chunks": [{"$binary": {"base64": "FImgSTpvmdIGPjml5YzI1qtOrN/I34DkG1PTNWqnqg==", "subType": "00"}}]}'

    with _patched_gateway_revelation_request_list(return_value=gateway_revelation_request_list):
        result_payload, operation_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper=passphrase_mapper,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload == payload  # Using asymmetric algorithm because response_data corrupted
        _check_operation_report_entry(
            operation_report=operation_report,
            entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            entry_criticity=DecryptionErrorCriticity.ERROR,
            entry_msg_match="Failed decryption of remote symkey/shard",
            exception_class=DecryptionError,
        )
        assert operation_report.get_error_count() == 1

    # keystore pool without trustee and response keypair
    keystore_pool1 = InMemoryKeystorePool()
    response_keychain_uid = revelation_requests_info[0]["response_keychain_uid"]
    keystore_pool1._register_fake_imported_storage_uids(storage_uids=[keystore_uid])

    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(revelation_requests_info)
    ):
        result_payload, operation_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool1,
            passphrase_mapper=passphrase_mapper,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload is None
        _check_operation_report_entry(
            operation_report=operation_report,
            entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            entry_criticity=DecryptionErrorCriticity.WARNING,
            entry_msg_match="Private key not found",
            exception_class=KeyDoesNotExist,
        )  # TRUSTEE KEYPAIR
        _check_operation_report_entry(
            operation_report=operation_report,
            entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            entry_criticity=DecryptionErrorCriticity.ERROR,
            entry_msg_match="Private key of revelation response not found",
            exception_class=KeyDoesNotExist,
        )  # RESPONSE KEYPAIR

        assert operation_report.get_error_count() == 3  # with Symmetric decryption error

    # Keystore pool empty( without trustee keystore in imported keystore and response key in local keystore)
    keystore_pool2 = InMemoryKeystorePool()
    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(revelation_requests_info)
    ):
        result_payload, operation_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool2,
            passphrase_mapper=passphrase_mapper,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload is None
        _check_operation_report_entry(
            operation_report=operation_report,
            entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            entry_criticity=DecryptionErrorCriticity.ERROR,
            entry_msg_match="Private key of revelation response not found",
            exception_class=KeyDoesNotExist,
        )  # RESPONSE KEYPAIR
        _check_operation_report_entry(
            operation_report=operation_report,
            entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            entry_criticity=DecryptionErrorCriticity.WARNING,
            entry_msg_match="Trustee key storage not found",
            exception_class=KeystoreDoesNotExist,
        )  # TRUSTEE KEYSTORE
        assert operation_report.get_error_count() == 3  # with Symmetric decryption error


def test_get_proxy_for_trustee(tmp_path):
    cryptainer_base1 = CryptainerBase()
    proxy1 = get_trustee_proxy(LOCAL_KEYFACTORY_TRUSTEE_MARKER, cryptainer_base1._keystore_pool)
    assert isinstance(proxy1, TrusteeApi)  # Local Trustee
    assert isinstance(proxy1._keystore, InMemoryKeystore)  # Default type

    cryptainer_base1_bis = CryptainerBase()
    proxy1_bis = get_trustee_proxy(LOCAL_KEYFACTORY_TRUSTEE_MARKER, cryptainer_base1_bis._keystore_pool)
    assert proxy1_bis._keystore is proxy1_bis._keystore  # process-local storage is SINGLETON!

    cryptainer_base2 = CryptainerBase(keystore_pool=FilesystemKeystorePool(str(tmp_path)))
    proxy2 = get_trustee_proxy(LOCAL_KEYFACTORY_TRUSTEE_MARKER, cryptainer_base2._keystore_pool)
    assert isinstance(proxy2, TrusteeApi)  # Local Trustee
    assert isinstance(proxy2._keystore, FilesystemKeystore)

    for cryptainer_base in (cryptainer_base1, cryptainer_base2):
        proxy = get_trustee_proxy(
            dict(trustee_type="jsonrpc_api", jsonrpc_url="http://example.com/jsonrpc"), cryptainer_base._keystore_pool
        )
        assert isinstance(proxy, JsonRpcProxy)  # It should expose identical methods to TrusteeApi

        assert proxy._url == "http://example.com/jsonrpc"
        assert proxy._response_error_handler == status_slugs_response_error_handler

        with pytest.raises(ValueError):
            get_trustee_proxy(dict(trustee_type="something-wrong"), cryptainer_base._keystore_pool)

        with pytest.raises(ValueError):
            get_trustee_proxy(dict(urn="athena"), cryptainer_base._keystore_pool)


def test_cryptainer_list_cryptainer_properties(tmp_path):
    storage, cryptainer_name = _intialize_real_cryptainer_with_single_file(tmp_path, allow_readonly_storage=True)

    assert not storage.list_cryptainer_properties(finished=False)

    properties = storage.list_cryptainer_properties()
    assert properties == [dict(name=cryptainer_name)]

    properties = storage.list_cryptainer_properties(with_size=True, finished=True)
    (first_properties,) = properties
    assert isinstance(first_properties["size"], int) and first_properties["size"] > 0
    del first_properties["size"]
    assert properties == [dict(name=cryptainer_name)]

    properties = storage.list_cryptainer_properties(with_age=True, finished=None)
    (first_properties,) = properties
    assert isinstance(first_properties["age"], timedelta)
    del first_properties["age"]
    assert first_properties == dict(name=cryptainer_name)

    properties = storage.list_cryptainer_properties(with_size=True, with_age=True)
    (first_properties,) = properties
    assert sorted(first_properties.keys()) == ["age", "name", "size"]

    cryptainer_filepath_pending = _add_unfinished_cryptainer_to_folder(tmp_path)

    properties = storage.list_cryptainer_properties(finished=False)
    (first_properties,) = properties
    assert first_properties["name"] == Path(cryptainer_filepath_pending.name)

    properties = storage.list_cryptainer_properties(finished=True)
    (first_properties,) = properties
    assert first_properties["name"] == cryptainer_name

    properties = storage.list_cryptainer_properties(as_sorted_list=random_bool(), finished=None)
    (first_properties, second_properties) = properties
    assert first_properties["name"] == cryptainer_name
    assert second_properties["name"] == Path(cryptainer_filepath_pending.name)


def test_cryptainer_storage_and_executor(tmp_path, capsys):
    side_tmp = tmp_path / "side_tmp"
    side_tmp.mkdir()

    cryptainer_dir = tmp_path / "cryptainers_dir"
    cryptainer_dir.mkdir()

    cryptainer_filepath_unfinished = _add_unfinished_cryptainer_to_folder(cryptainer_dir)

    animals_file_path = side_tmp / "animals"
    animals_file_path.write_bytes(b"dogs\ncats\n")
    assert animals_file_path.is_file()

    animals_file_handle = animals_file_path.open("rb")

    already_deleted_file_input = random_bool()
    if already_deleted_file_input:
        try:
            animals_file_path.unlink()
        except PermissionError:
            pass  # Win32 doesn't allow that

    # Beware, here we use the REAL CryptainerStorage, not FakeTestCryptainerStorage!
    storage = CryptainerStorage(default_cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_dir=cryptainer_dir)
    assert storage._max_cryptainer_count is None
    assert storage.get_cryptainer_count() == 0
    assert storage.list_cryptainer_names() == []

    storage.enqueue_file_for_encryption("animals.dat", animals_file_handle, cryptainer_metadata=None)
    storage.enqueue_file_for_encryption("empty.txt", b"", cryptainer_metadata=dict(somevalue=True))
    assert storage.get_cryptainer_count() == 0  # Cryptainer threads are just beginning to work!

    storage.wait_for_idle_state()

    assert animals_file_path.is_file()  # NOT AUTO-DELETED after encryption!

    assert storage.get_cryptainer_count() == 2
    assert storage.list_cryptainer_names(as_sorted_list=True) == [Path("animals.dat.crypt"), Path("empty.txt.crypt")]
    assert storage._cryptainer_dir.joinpath(
        "animals.dat.crypt.payload"
    ).is_file()  # By default, DATA OFFLOADING is activated
    assert storage._cryptainer_dir.joinpath("empty.txt.crypt.payload").is_file()
    assert len(list(storage._cryptainer_dir.iterdir())) == 6  # 2 files per cryptainer, including the pending cryptainer

    storage = CryptainerStorage(
        default_cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_dir=cryptainer_dir, offload_payload_ciphertext=False
    )
    storage.enqueue_file_for_encryption("newfile.bmp", b"stuffs", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.get_cryptainer_count() == 3
    expected_cryptainer_names = [Path("animals.dat.crypt"), Path("empty.txt.crypt"), Path("newfile.bmp.crypt")]
    assert storage.list_cryptainer_names(as_sorted_list=True) == expected_cryptainer_names
    assert sorted(storage.list_cryptainer_names(as_sorted_list=False)) == expected_cryptainer_names

    assert not list(storage._cryptainer_dir.glob("newfile*data"))  # Offloading is well disabled now
    assert len(list(storage._cryptainer_dir.iterdir())) == 7  # Still the pending cryptainer is here

    _cryptainer_for_txt = storage.load_cryptainer_from_storage("empty.txt.crypt")
    assert storage.load_cryptainer_from_storage(1) == _cryptainer_for_txt
    assert _cryptainer_for_txt["payload_ciphertext_struct"]  # Padding occurs for AES_CBC

    _cryptainer_for_txt2 = storage.load_cryptainer_from_storage("empty.txt.crypt", include_payload_ciphertext=False)
    assert storage.load_cryptainer_from_storage(1, include_payload_ciphertext=False) == _cryptainer_for_txt2
    assert not hasattr(_cryptainer_for_txt2, "payload_ciphertext_struct")

    # We continue test with a randomly configured storage
    offload_payload_ciphertext = random_bool()
    storage = CryptainerStorage(
        default_cryptoconf=SIMPLE_CRYPTOCONF,
        cryptainer_dir=cryptainer_dir,
        offload_payload_ciphertext=offload_payload_ciphertext,
    )

    # Test proper logging of errors occurring in thread pool executor
    assert storage._make_absolute  # Instance method
    storage._make_absolute = None  # Corruption!
    captured = capsys.readouterr()
    assert "Abnormal exception" not in captured.err, captured.err
    storage.enqueue_file_for_encryption("something.mpg", b"#########", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.get_cryptainer_count() == 3  # Unchanged
    captured = capsys.readouterr()
    assert "Abnormal exception" in captured.err, captured.err
    del storage._make_absolute
    assert storage._make_absolute  # Back to the method

    abs_entries = storage.list_cryptainer_names(as_absolute_paths=True)
    assert len(abs_entries) == 3  # Unchanged
    assert all(entry.is_absolute() for entry in abs_entries)

    animals_content, _operation_report = storage.decrypt_cryptainer_from_storage("animals.dat.crypt")
    assert animals_content == b"dogs\ncats\n"

    empty_content, _operation_report = storage.decrypt_cryptainer_from_storage("empty.txt.crypt")
    assert empty_content == b""

    assert storage.get_cryptainer_count() == 3
    os.remove(os.path.join(cryptainer_dir, "animals.dat.crypt"))
    os.remove(os.path.join(cryptainer_dir, "newfile.bmp.crypt"))
    assert storage.list_cryptainer_names(as_sorted_list=True) == [Path("empty.txt.crypt")]
    assert storage.get_cryptainer_count() == 1  # Remaining offloaded data file is ignored

    offload_payload_ciphertext1 = random_bool()
    storage = FakeTestCryptainerStorage(
        default_cryptoconf={"smth": True},
        cryptainer_dir=cryptainer_dir,
        max_cryptainer_count=3,
        offload_payload_ciphertext=offload_payload_ciphertext1,
    )
    assert storage.get_cryptainer_count() == 0

    for i in range(10):
        storage.enqueue_file_for_encryption("file.dat", b"dogs\ncats\n", cryptainer_metadata=None)
    assert storage.get_cryptainer_count() < 11  # In progress
    storage.wait_for_idle_state()
    assert storage.get_cryptainer_count() == 11  # Still the older file remains

    assert storage.get_cryptainer_count(finished=False) == 1
    assert storage.get_cryptainer_count(finished=None) == 12
    assert storage.list_cryptainer_names(as_sorted_list=random_bool(), finished=False) == [
        Path(cryptainer_filepath_unfinished.name)
    ]
    assert storage.list_cryptainer_names(as_sorted_list=random_bool(), as_absolute_paths=True, finished=False) == [
        cryptainer_filepath_unfinished
    ]
    assert (
        len(storage.list_cryptainer_names(as_sorted_list=random_bool(), as_absolute_paths=random_bool(), finished=None))
        == 12
    )


def test_cryptainer_storage_purge_by_max_count(tmp_path):
    cryptainer_dir = tmp_path

    offload_payload_ciphertext = random_bool()
    storage = FakeTestCryptainerStorage(
        default_cryptoconf={"stuffs": True},
        cryptainer_dir=cryptainer_dir,
        max_cryptainer_count=3,
        offload_payload_ciphertext=offload_payload_ciphertext,
    )
    for i in range(3):
        storage.enqueue_file_for_encryption("xyz.dat", b"abc", cryptainer_metadata=None)

    storage.wait_for_idle_state()
    assert storage.get_cryptainer_count() == 3  # Purged
    assert storage.list_cryptainer_names(as_sorted_list=True, finished=None) == [
        Path("xyz.dat.000.crypt"),
        Path("xyz.dat.001.crypt"),
        Path("xyz.dat.002.crypt"),
    ]

    storage.enqueue_file_for_encryption("xyz.dat", b"abc", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.get_cryptainer_count() == 3  # Purged
    assert storage.list_cryptainer_names(as_sorted_list=True, finished=None) == [
        Path("xyz.dat.001.crypt"),
        Path("xyz.dat.002.crypt"),
        Path("xyz.dat.003.crypt"),
    ]

    time.sleep(0.2)  # Leave delay, else if files have exactly same timestamp, it's the filename that matters

    offload_payload_ciphertext2 = random_bool()
    storage = FakeTestCryptainerStorage(
        default_cryptoconf={"randomthings": True},
        cryptainer_dir=cryptainer_dir,
        max_cryptainer_count=4,
        offload_payload_ciphertext=offload_payload_ciphertext2,
    )
    assert storage.get_cryptainer_count() == 3  # Retrieves existing cryptainers
    storage.enqueue_file_for_encryption("aaa.dat", b"000", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.get_cryptainer_count() == 4  # Unchanged
    storage.enqueue_file_for_encryption("zzz.dat", b"000", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.get_cryptainer_count() == 4  # Purge occurred
    assert storage.list_cryptainer_names(as_sorted_list=True, finished=None) == [
        Path("aaa.dat.000.crypt"),  # It's the file timestamps that counts, not the name!
        Path("xyz.dat.002.crypt"),
        Path("xyz.dat.003.crypt"),
        Path("zzz.dat.001.crypt"),
    ]

    cryptainer_path = storage._make_absolute("aaa.dat.000.crypt")
    cryptainer_path.rename(cryptainer_path.with_suffix(cryptainer_path.suffix + CRYPTAINER_TEMP_SUFFIX))

    storage.delete_cryptainer(Path("xyz.dat.002.crypt"))

    assert storage.list_cryptainer_names(as_sorted_list=True, finished=None) == [
        Path("aaa.dat.000.crypt~"),
        Path("xyz.dat.003.crypt"),
        Path("zzz.dat.001.crypt"),
    ]

    storage.enqueue_file_for_encryption("20201121_222727_whatever.dat", b"000", cryptainer_metadata=None)
    storage.wait_for_idle_state()

    assert storage.list_cryptainer_names(as_sorted_list=True, finished=None) == [
        Path("20201121_222727_whatever.dat.002.crypt"),
        Path("aaa.dat.000.crypt~"),
        Path("xyz.dat.003.crypt"),
        Path("zzz.dat.001.crypt"),
    ]

    storage.enqueue_file_for_encryption("21201121_222729_smth.dat", b"000", cryptainer_metadata=None)
    storage.enqueue_file_for_encryption("lmn.dat", b"000", cryptainer_metadata=None)
    storage.wait_for_idle_state()

    # print(">>>>>>>", storage.list_cryptainer_names(as_sorted_list=True))
    assert storage.list_cryptainer_names(as_sorted_list=True, finished=None) == [
        Path("21201121_222729_smth.dat.003.crypt"),
        Path("aaa.dat.000.crypt~"),  # It's the file timestamps that counts, not the name!
        Path("lmn.dat.004.crypt"),
        Path("zzz.dat.001.crypt"),
    ]

    assert storage._max_cryptainer_count
    storage._max_cryptainer_count = 0

    storage.enqueue_file_for_encryption("abc.dat", b"000", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.list_cryptainer_names(as_sorted_list=True, finished=None) == []  # ALL PURGED


def test_cryptainer_storage_purge_by_age(tmp_path):
    cryptainer_dir = tmp_path
    now = get_utc_now_date()

    (cryptainer_dir / "20201021_222700_oldfile.dat.crypt~").touch()
    (cryptainer_dir / "20301021_222711_oldfile.dat.crypt").touch()

    offload_payload_ciphertext = random_bool()
    storage = FakeTestCryptainerStorage(
        default_cryptoconf={"stuffs": True},
        cryptainer_dir=cryptainer_dir,
        max_cryptainer_age=timedelta(days=2),
        offload_payload_ciphertext=offload_payload_ciphertext,
    )

    assert storage.list_cryptainer_names(as_sorted_list=True, finished=None) == [
        Path("20201021_222700_oldfile.dat.crypt~"),
        Path("20301021_222711_oldfile.dat.crypt"),
    ]

    dt = now - timedelta(seconds=1)
    for i in range(5):
        storage.enqueue_file_for_encryption(
            "%s_stuff.dat" % dt.strftime(CRYPTAINER_DATETIME_FORMAT), b"abc", cryptainer_metadata=None
        )
        dt -= timedelta(days=1)
    storage.enqueue_file_for_encryption(
        "whatever_stuff.dat", b"xxx", cryptainer_metadata=None
    )  # File timestamp with be used instead
    storage.wait_for_idle_state()

    cryptainer_names = storage.list_cryptainer_names(as_sorted_list=True, finished=None)

    assert Path("20201021_222700_oldfile.dat.crypt~") not in cryptainer_names

    assert Path("20301021_222711_oldfile.dat.crypt") in cryptainer_names
    assert Path("whatever_stuff.dat.005.crypt") in cryptainer_names

    assert storage.get_cryptainer_count() == 4  # 2 listed just above + 2 recent "<date>_stuff.dat" from loop

    # Change mtime to VERY old!
    os.utime(storage._make_absolute(Path("whatever_stuff.dat.005.crypt")), (1000, 1000))

    storage.enqueue_file_for_encryption("abcde.dat", b"xxx", cryptainer_metadata=None)
    storage.wait_for_idle_state()

    cryptainer_names = storage.list_cryptainer_names(as_sorted_list=True, finished=None)
    assert Path("whatever_stuff.dat.005.crypt") not in cryptainer_names
    assert Path("abcde.dat.006.crypt") in cryptainer_names

    assert storage.get_cryptainer_count() == 4

    assert storage._max_cryptainer_age
    storage._max_cryptainer_age = timedelta(days=-1)

    storage.enqueue_file_for_encryption("abc.dat", b"000", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.list_cryptainer_names(as_sorted_list=True, finished=None) == [
        Path("20301021_222711_oldfile.dat.crypt")
    ]  # ALL PURGED


def test_cryptainer_storage_purge_by_quota(tmp_path):
    cryptainer_dir = tmp_path

    offload_payload_ciphertext = random_bool()
    storage = FakeTestCryptainerStorage(
        default_cryptoconf={"stuffs": True},
        cryptainer_dir=cryptainer_dir,
        max_cryptainer_quota=8000,  # Beware of overhead of encryption and json structs!
        offload_payload_ciphertext=offload_payload_ciphertext,
    )
    assert not storage.get_cryptainer_count()

    storage.enqueue_file_for_encryption("20101021_222711_stuff.dat", b"a" * 2000, cryptainer_metadata=None)
    storage.enqueue_file_for_encryption("20301021_222711_stuff.dat", b"z" * 2000, cryptainer_metadata=None)

    for i in range(10):
        storage.enqueue_file_for_encryption("some_stuff.dat", b"m" * 1000, cryptainer_metadata=None)
    storage.wait_for_idle_state()

    cryptainer_names = storage.list_cryptainer_names(as_sorted_list=True, finished=None)

    if offload_payload_ciphertext:  # Offloaded cryptainers are smaller due to skipping of base64 encoding of ciphertext
        assert cryptainer_names == [
            Path("20301021_222711_stuff.dat.001.crypt"),
            Path("some_stuff.dat.007.crypt"),
            Path("some_stuff.dat.008.crypt"),
            Path("some_stuff.dat.009.crypt"),
            Path("some_stuff.dat.010.crypt"),
            Path("some_stuff.dat.011.crypt"),
        ]
    else:
        assert cryptainer_names == [
            Path("20301021_222711_stuff.dat.001.crypt"),
            Path("some_stuff.dat.009.crypt"),
            Path("some_stuff.dat.010.crypt"),
            Path("some_stuff.dat.011.crypt"),
        ]

    cryptainer_path = storage._make_absolute("20301021_222711_stuff.dat.001.crypt")
    cryptainer_path.rename(cryptainer_path.with_suffix(cryptainer_path.suffix + CRYPTAINER_TEMP_SUFFIX))

    storage.delete_cryptainer(Path("some_stuff.dat.009.crypt"))

    assert storage.list_cryptainer_names(as_sorted_list=True, finished=None) == [
        Path("20301021_222711_stuff.dat.001.crypt~"),
        Path("some_stuff.dat.010.crypt"),
        Path("some_stuff.dat.011.crypt"),
    ]

    storage.enqueue_file_for_encryption("abc.dat", b"000", cryptainer_metadata=None)
    storage.wait_for_idle_state()

    assert storage.list_cryptainer_names(as_sorted_list=True, finished=None) == [
        Path("20301021_222711_stuff.dat.001.crypt~"),
        Path("abc.dat.002.crypt"),
        Path("some_stuff.dat.010.crypt"),
        Path("some_stuff.dat.011.crypt"),
    ]

    assert storage._max_cryptainer_quota
    storage._max_cryptainer_quota = 0

    storage.enqueue_file_for_encryption("abc.dat", b"000", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.list_cryptainer_names(as_sorted_list=True, finished=None) == []  # ALL PURGED


def test_cryptainer_storage_purge_parameter_combinations(tmp_path):
    cryptainer_dir = tmp_path
    now = get_utc_now_date() - timedelta(seconds=1)

    recent_big_file_name = "%s_recent_big_stuff.dat" % now.strftime(CRYPTAINER_DATETIME_FORMAT)

    params_sets = product([None, 2], [None, 1000], [None, timedelta(days=3)])

    for max_cryptainer_count, max_cryptainer_quota, max_cryptainer_age in params_sets:
        offload_payload_ciphertext = random_bool()

        storage = FakeTestCryptainerStorage(
            default_cryptoconf={"stuffs": True},
            cryptainer_dir=cryptainer_dir,
            max_cryptainer_count=max_cryptainer_count,
            max_cryptainer_quota=max_cryptainer_quota,
            max_cryptainer_age=max_cryptainer_age,
            offload_payload_ciphertext=offload_payload_ciphertext,
        )

        storage.enqueue_file_for_encryption("20001121_222729_smth.dat", b"000", cryptainer_metadata=None)
        storage.enqueue_file_for_encryption(recent_big_file_name, b"0" * 2000, cryptainer_metadata=None)
        storage.enqueue_file_for_encryption("recent_small_file.dat", b"0" * 50, cryptainer_metadata=None)

        storage.wait_for_idle_state()

        first_file_purged = max_cryptainer_count or max_cryptainer_quota or max_cryptainer_age

        if not first_file_purged:
            cryptainer_path = storage._make_absolute("20001121_222729_smth.dat.000.crypt")
            cryptainer_path.rename(cryptainer_path.with_suffix(cryptainer_path.suffix + CRYPTAINER_TEMP_SUFFIX))

        cryptainer_names = storage.list_cryptainer_names(as_sorted_list=True, finished=None)

        assert (Path("20001121_222729_smth.dat.000.crypt~") in cryptainer_names) == (not first_file_purged)
        assert (Path(recent_big_file_name + ".001.crypt") in cryptainer_names) == (not max_cryptainer_quota)
        assert (Path("recent_small_file.dat.002.crypt") in cryptainer_names) == True

    # Special case of "everything restricted"

    storage = FakeTestCryptainerStorage(
        default_cryptoconf={"stuffs": True},
        cryptainer_dir=cryptainer_dir,
        max_cryptainer_count=0,
        max_cryptainer_quota=0,
        max_cryptainer_age=timedelta(days=0),
        offload_payload_ciphertext=False,
    )
    storage.enqueue_file_for_encryption("some_small_file.dat", b"0" * 50, cryptainer_metadata=None)
    storage.wait_for_idle_state()

    cryptainer_names = storage.list_cryptainer_names(as_sorted_list=True, finished=None)
    assert cryptainer_names == []


def test_cryptainer_storage_cryptoconf_precedence(tmp_path):
    # Beware, here we use the REAL CryptainerStorage, not FakeTestCryptainerStorage!
    storage = CryptainerStorage(default_cryptoconf=None, cryptainer_dir=tmp_path)

    assert storage.list_cryptainer_names() == []

    with pytest.raises(RuntimeError, match="cryptoconf"):
        storage.enqueue_file_for_encryption("animals.dat", b"dogs\ncats\n", cryptainer_metadata=None)

    storage.enqueue_file_for_encryption(
        "animals.dat", b"dogs\ncats\n", cryptainer_metadata=None, cryptoconf=SIMPLE_CRYPTOCONF
    )

    storage.wait_for_idle_state()
    assert storage.list_cryptainer_names() == [Path("animals.dat.crypt")]

    # ---

    storage = CryptainerStorage(default_cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_dir=tmp_path)
    storage.enqueue_file_for_encryption("stuff_simple.txt", b"aaa", cryptainer_metadata=None)
    storage.enqueue_file_for_encryption(
        "stuff_complex.txt", b"xxx", cryptainer_metadata=None, cryptoconf=COMPLEX_CRYPTOCONF
    )
    storage.wait_for_idle_state()

    StorageClass = _get_random_cryptainer_storage_class()  # Test READONLY mode too!
    storage = StorageClass(tmp_path)

    cryptainer_simple = storage.load_cryptainer_from_storage("stuff_simple.txt.crypt")
    assert len(cryptainer_simple["payload_cipher_layers"]) == 1
    cryptainer_complex = storage.load_cryptainer_from_storage("stuff_complex.txt.crypt")
    assert len(cryptainer_complex["payload_cipher_layers"]) == 3


def test_cryptainer_storage_decryption_with_authenticated_algo_and_verify_failure(tmp_path):
    # Beware, here we use the REAL CryptainerStorage, not FakeTestCryptainerStorage!
    storage, cryptainer_name = _intialize_real_cryptainer_with_single_file(tmp_path, allow_readonly_storage=True)

    def corrupt_eax_tag(cryptainer):
        cryptainer["payload_cipher_layers"][0]["payload_macs"]["tag"] += b"hi"  # CORRUPTION of EAX

    _corrupt_cryptainer_tree(storage, cryptainer_name=cryptainer_name, corruptor_callback=corrupt_eax_tag)

    result, _operation_report = storage.decrypt_cryptainer_from_storage(cryptainer_name, verify_integrity_tags=False)
    assert result == b"dogs\ncats\n"

    result, operation_report = storage.decrypt_cryptainer_from_storage(cryptainer_name, verify_integrity_tags=True)

    assert result is None
    _check_operation_report_entry(
        operation_report=operation_report,
        entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
        entry_criticity=DecryptionErrorCriticity.ERROR,
        entry_msg_match="Failed decryption authentication",
        exception_class=DecryptionIntegrityError,
    )
    assert operation_report.get_error_count() == 1


def test_cryptainer_storage_check_cryptainer_sanity(tmp_path):
    storage, cryptainer_name = _intialize_real_cryptainer_with_single_file(tmp_path, allow_readonly_storage=True)

    storage.check_cryptainer_sanity(cryptainer_name_or_idx=cryptainer_name)

    def add_wrong_attribute(cryptainer):
        cryptainer["payload_cipher_layers"][0]["bad_name_of_attribute"] = 42

    _corrupt_cryptainer_tree(storage, cryptainer_name=cryptainer_name, corruptor_callback=add_wrong_attribute)

    with pytest.raises(ValidationError):
        storage.check_cryptainer_sanity(cryptainer_name_or_idx=cryptainer_name)


def test_readonly_cryptainer_storage_limitations(tmp_path):
    """For now we just test that the base ReadonlyCryptainerStorage class doesn't have dangerous fields."""

    normal_storage = CryptainerStorage(default_cryptoconf=COMPLEX_CRYPTOCONF, cryptainer_dir=tmp_path)
    readonly_storage = ReadonlyCryptainerStorage(cryptainer_dir=tmp_path)

    forbidden_fields = [
        # Methods
        "delete_cryptainer",
        "create_cryptainer_encryption_stream",
        "enqueue_file_for_encryption",
        "_offloaded_encrypt_payload_and_dump_cryptainer",
        "wait_for_idle_state",
        # Attributes
        "_thread_pool_executor",
        "_default_cryptoconf",
    ]

    for forbidden_field in forbidden_fields:
        assert hasattr(normal_storage, forbidden_field)
        assert not hasattr(readonly_storage, forbidden_field)


def test_get_cryptoconf_summary():
    payload = b"some data whatever"

    summary = get_cryptoconf_summary(SIMPLE_CRYPTOCONF)

    assert summary == textwrap.dedent(
        """\
        Plaintext signatures: None
        Data encryption layer 1: AES_CBC
          Key encryption layers:
            RSA_OAEP via trustee 'local device'
          Ciphertext signatures:
            SHA256/DSA_DSS via trustee 'local device'
            """
    )  # Ending by newline!

    cryptainer = encrypt_payload_into_cryptainer(
        payload=payload, cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_metadata=None
    )
    summary2 = get_cryptoconf_summary(cryptainer)
    assert summary2 == summary  # Identical summary for cryptoconf and generated cryptainers!

    # Simulate a cryptoconf with remote trustee webservices

    CONF_WITH_TRUSTEE = copy.deepcopy(COMPLEX_SHAMIR_CRYPTOCONF)
    CONF_WITH_TRUSTEE["payload_cipher_layers"][0]["key_cipher_layers"][0]["key_cipher_trustee"] = dict(
        trustee_type="jsonrpc_api", jsonrpc_url="http://www.mydomain.com/json"
    )
    CONF_WITH_TRUSTEE["payload_cipher_layers"][1]["key_cipher_layers"][0]["key_cipher_trustee"] = dict(
        trustee_type="authenticator", keystore_uid=UUID("320b35bb-e735-4f6a-a4b2-ada124e30190")
    )
    check_cryptoconf_sanity(CONF_WITH_TRUSTEE)
    print("'-----------------------")
    pprint(CONF_WITH_TRUSTEE)
    print("'-----------------------")

    summary = get_cryptoconf_summary(CONF_WITH_TRUSTEE)
    print("SUMMARY OBTAINED\n" + summary)

    assert summary == textwrap.dedent(
        """\
        Plaintext signatures:
          SHA512/DSA_DSS via trustee 'local device'
        Data encryption layer 1: AES_EAX
          Key encryption layers:
            RSA_OAEP via trustee 'server www.mydomain.com'
          Ciphertext signatures: None
        Data encryption layer 2: AES_CBC
          Key encryption layers:
            RSA_OAEP via trustee 'authenticator 320b35bb-e735-4f6a-a4b2-ada124e30190'
          Ciphertext signatures:
            SHA3_512/DSA_DSS via trustee 'local device'
        Data encryption layer 3: CHACHA20_POLY1305
          Key encryption layers:
            Shared secret with threshold 2:
              Shard 1 encryption layers:
                RSA_OAEP via trustee 'local device'
                RSA_OAEP via trustee 'local device'
              Shard 2 encryption layers:
                AES_CBC with subkey encryption layers:
                  Shared secret with threshold 1:
                    Shard 1 encryption layers:
                      RSA_OAEP via trustee 'local device'
                  RSA_OAEP via trustee 'local device'
              Shard 3 encryption layers:
                RSA_OAEP via trustee 'local device'
              Shard 4 encryption layers:
                RSA_OAEP via trustee 'local device'
          Ciphertext signatures:
            SHA3_256/RSA_PSS via trustee 'local device'
            SHA512/ECC_DSS via trustee 'local device'
            """
    )  # Ending with newline!

    _public_key = generate_keypair(key_algo="RSA_OAEP", serialize=True)["public_key"]
    # We mockup the call to remote trustees
    with patch("wacryptolib.cryptainer._encryptor.FlightboxUtilitiesImpl._fetch_asymmetric_key_pem_from_trustee",
        return_value=_public_key
    ) as mock_method:
        cryptainer = encrypt_payload_into_cryptainer(
            payload=payload, cryptoconf=CONF_WITH_TRUSTEE, cryptainer_metadata=None
        )
        summary2 = get_cryptoconf_summary(cryptainer)
        assert summary2 == summary  # Identical summary for cryptoconf and generated cryptainers!

    # Test unknown trustee structure

    CONF_WITH_BROKEN_TRUSTEE = copy.deepcopy(SIMPLE_CRYPTOCONF)
    CONF_WITH_BROKEN_TRUSTEE["payload_cipher_layers"][0]["key_cipher_layers"][0]["key_cipher_trustee"] = dict(abc=33)

    with pytest.raises(ValueError, match="Unrecognized key trustee"):
        get_cryptoconf_summary(CONF_WITH_BROKEN_TRUSTEE)


@pytest.mark.parametrize("cryptoconf", [SIMPLE_CRYPTOCONF, COMPLEX_CRYPTOCONF])
def test_filesystem_cryptainer_loading_and_dumping(tmp_path, cryptoconf):
    payload = b"jhf" * 200

    keychain_uid = random.choice([None, uuid.UUID("450fc293-b702-42d3-ae65-e9cc58e5a62a")])
    cryptoconf = _get_enriched_cryptoconf(cryptoconf, keychain_uid=keychain_uid)

    metadata = random.choice([None, dict(a=[123])])

    cryptainer = encrypt_payload_into_cryptainer(payload=payload, cryptoconf=cryptoconf, cryptainer_metadata=metadata)
    cryptainer_ciphertext_struct_before_dump = cryptainer["payload_ciphertext_struct"]
    cryptainer_ciphertext_value_before_dump = cryptainer_ciphertext_struct_before_dump["ciphertext_value"]

    cryptainer_without_ciphertext = copy.deepcopy(cryptainer)
    del cryptainer_without_ciphertext["payload_ciphertext_struct"]

    # CASE 1 - MONOLITHIC JSON FILE

    cryptainer_filepath = tmp_path / "mycryptainer_monolithic.crypt"
    dump_cryptainer_to_filesystem(cryptainer_filepath, cryptainer=cryptainer, offload_payload_ciphertext=False)
    cryptainer_reloaded = load_from_json_file(cryptainer_filepath)
    assert cryptainer_reloaded["payload_ciphertext_struct"] == cryptainer_ciphertext_struct_before_dump  # NO OFFLOADING
    assert load_cryptainer_from_filesystem(cryptainer_filepath) == cryptainer  # UNCHANGED from original

    cryptainer_truncated = load_cryptainer_from_filesystem(cryptainer_filepath, include_payload_ciphertext=False)
    assert "payload_ciphertext_struct" not in cryptainer_truncated
    assert cryptainer_truncated == cryptainer_without_ciphertext

    assert (
        cryptainer["payload_ciphertext_struct"] == cryptainer_ciphertext_struct_before_dump
    )  # Original dict unchanged

    size1 = get_cryptainer_size_on_filesystem(cryptainer_filepath)
    assert size1

    assert cryptainer_filepath.exists()
    # delete_cryptainer_from_filesystem(cryptainer_filepath)
    # assert not cryptainer_filepath.exists()

    # CASE 2 - OFFLOADED CIPHERTEXT FILE

    cryptainer_filepath = tmp_path / "mycryptainer_offloaded.crypt"

    dump_cryptainer_to_filesystem(cryptainer_filepath, cryptainer=cryptainer)  # OVERWRITE, with offloading by default
    cryptainer_reloaded = load_from_json_file(cryptainer_filepath)
    assert cryptainer_reloaded["payload_ciphertext_struct"] == OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER

    cryptainer_offloaded_filepath = Path(str(cryptainer_filepath) + ".payload")
    offloaded_data_reloaded = cryptainer_offloaded_filepath.read_bytes()
    assert offloaded_data_reloaded == cryptainer_ciphertext_value_before_dump  # WELL OFFLOADED as DIRECT BYTES
    assert load_cryptainer_from_filesystem(cryptainer_filepath) == cryptainer  # UNCHANGED from original

    cryptainer_truncated = load_cryptainer_from_filesystem(cryptainer_filepath, include_payload_ciphertext=False)
    assert "payload_ciphertext_struct" not in cryptainer_truncated
    assert cryptainer_truncated == cryptainer_without_ciphertext

    assert (
        cryptainer["payload_ciphertext_struct"] == cryptainer_ciphertext_struct_before_dump
    )  # Original dict unchanged

    size2 = get_cryptainer_size_on_filesystem(cryptainer_filepath)
    assert size2 < size1  # Overhead of base64 encoding in monolithic file!
    assert size1 < size2 + 1000  # Overhead remaings limited though

    assert cryptainer_filepath.exists()
    assert cryptainer_offloaded_filepath.exists()
    delete_cryptainer_from_filesystem(cryptainer_filepath)
    assert not cryptainer_filepath.exists()
    assert not cryptainer_offloaded_filepath.exists()


def test_generate_cryptainer_base_and_symmetric_keys():
    cryptainer_decryptor = CryptainerEncryptor(signature_policy=SIGNATURE_POLICIES.REQUIRE_SIGNING)
    cryptainer, secrets = cryptainer_decryptor._generate_cryptainer_base_and_secrets(COMPLEX_CRYPTOCONF)

    payload_plaintext_hash_algos = secrets["payload_plaintext_hash_algos"]
    assert payload_plaintext_hash_algos == ["SHA256"]

    payload_cipher_layer_extracts = secrets["payload_cipher_layer_extracts"]

    for payload_cipher_layer in payload_cipher_layer_extracts:
        symkey = payload_cipher_layer["symkey"]
        assert isinstance(symkey, dict)
        assert symkey["key"]  # actual main key
        del payload_cipher_layer["symkey"]

    assert payload_cipher_layer_extracts == [
        {"cipher_algo": "AES_EAX", "hash_algos": []},
        {"cipher_algo": "AES_CBC", "hash_algos": ["SHA3_512"]},
        {"cipher_algo": "CHACHA20_POLY1305", "hash_algos": ["SHA3_256", "SHA512"]},
    ]


def test_create_cryptainer_encryption_stream(tmp_path):
    cryptainer_dir = tmp_path / "cryptainers_dir"
    cryptainer_dir.mkdir()

    filename_base = "20200101_cryptainer_example"

    # Beware, here we use the REAL CryptainerStorage, not FakeTestCryptainerStorage!
    storage = CryptainerStorage(default_cryptoconf=None, cryptainer_dir=cryptainer_dir)

    cryptainer_encryption_stream = storage.create_cryptainer_encryption_stream(
        filename_base,
        cryptainer_metadata={"mymetadata": True},
        signature_policy=None,
        cryptoconf=SIMPLE_CRYPTOCONF,
        dump_initial_cryptainer=True,
    )

    cryptainer_started = storage.load_cryptainer_from_storage(
        "20200101_cryptainer_example.crypt" + CRYPTAINER_TEMP_SUFFIX
    )
    assert cryptainer_started["cryptainer_state"] == "STARTED"

    cryptainer_encryption_stream.encrypt_chunk(b"bonjour")
    cryptainer_encryption_stream.encrypt_chunk(b"everyone")
    cryptainer_encryption_stream.finalize()

    StorageClass = _get_random_cryptainer_storage_class()  # Test READONLY mode too!
    storage = StorageClass(cryptainer_dir)

    cryptainer = storage.load_cryptainer_from_storage("20200101_cryptainer_example.crypt")
    assert cryptainer["cryptainer_metadata"] == {"mymetadata": True}
    assert cryptainer["cryptainer_state"] == "FINISHED"

    plaintext, _operation_report = storage.decrypt_cryptainer_from_storage("20200101_cryptainer_example.crypt")
    assert plaintext == b"bonjoureveryone"


@pytest.mark.parametrize(
    "cryptoconf", [SIMPLE_CRYPTOCONF, COMPLEX_CRYPTOCONF, SIMPLE_SHAMIR_CRYPTOCONF, COMPLEX_SHAMIR_CRYPTOCONF]
)
def test_cryptoconf_validation_success(cryptoconf):
    check_cryptoconf_sanity(cryptoconf=cryptoconf, jsonschema_mode=False)

    conf_json = convert_to_extjson(cryptoconf)
    check_cryptoconf_sanity(cryptoconf=conf_json, jsonschema_mode=True)


def _generate_corrupted_cryptoconfs(cryptoconf, is_complex_conf, include_extended_checks):
    corrupted_confs = []

    # Add a false information to config
    corrupted_conf1 = copy.deepcopy(cryptoconf)
    corrupted_conf1["payload_cipher_layers"][0]["keychain_uid"] = ENFORCED_UID2
    corrupted_confs.append(corrupted_conf1)

    # Delete a "key_cipher_layers" at top level
    corrupted_conf2 = copy.deepcopy(cryptoconf)
    del corrupted_conf2["payload_cipher_layers"][0]["key_cipher_layers"]
    corrupted_confs.append(corrupted_conf2)

    # Update payload_cipher_algo with a value algo that does not exist
    corrupted_conf3 = copy.deepcopy(cryptoconf)
    corrupted_conf3["payload_cipher_layers"][0]["payload_cipher_algo"] = "AES_AES"
    corrupted_confs.append(corrupted_conf3)

    # Update a "key_cipher_layers" with a string instead of list
    corrupted_conf4 = copy.deepcopy(cryptoconf)
    corrupted_conf4["payload_cipher_layers"][0]["key_cipher_layers"] = " "
    corrupted_confs.append(corrupted_conf4)

    if include_extended_checks:
        # Empty the ciphers of payload
        corrupted_conf5 = copy.deepcopy(cryptoconf)
        del corrupted_conf5["payload_cipher_layers"][:]
        corrupted_confs.append(corrupted_conf5)

        # Empty the ciphers of payload key
        corrupted_conf6 = copy.deepcopy(cryptoconf)
        del corrupted_conf6["payload_cipher_layers"][0]["key_cipher_layers"][:]
        corrupted_confs.append(corrupted_conf6)

        if is_complex_conf:
            # Empty the ciphers of shared secret key
            corrupted_conf6_bis = copy.deepcopy(cryptoconf)
            del corrupted_conf6_bis["payload_cipher_layers"][2]["key_cipher_layers"][0]["key_shared_secret_shards"][0][
                "key_cipher_layers"
            ]
            corrupted_confs.append(corrupted_conf6_bis)

            # Empty the ciphers of first key
            corrupted_conf6_ter = copy.deepcopy(cryptoconf)
            del corrupted_conf6_ter["payload_cipher_layers"][2]["key_cipher_layers"][0]["key_shared_secret_shards"][1][
                "key_cipher_layers"
            ][0]["key_cipher_layers"]
            corrupted_confs.append(corrupted_conf6_ter)

            # Corrupt the threshold of shared secret
            corrupted_conf7 = copy.deepcopy(cryptoconf)
            shared_secret = corrupted_conf7["payload_cipher_layers"][2]["key_cipher_layers"][0]
            assert shared_secret["key_cipher_algo"] == SHARED_SECRET_ALGO_MARKER
            shared_secret["key_shared_secret_threshold"] = random.choice([-1, 0, 5, 100])
            corrupted_confs.append(corrupted_conf7)

    return corrupted_confs


@pytest.mark.parametrize(
    "corrupted_conf",
    _generate_corrupted_cryptoconfs(COMPLEX_SHAMIR_CRYPTOCONF, is_complex_conf=True, include_extended_checks=True),
)
def test_cryptoconf_validation_error_via_python_schema(corrupted_conf):
    print("corrupted_conf>>>>>>>>>:")
    pprint(corrupted_conf)
    with pytest.raises(ValidationError):
        check_cryptoconf_sanity(cryptoconf=corrupted_conf, jsonschema_mode=False)


@pytest.mark.parametrize(
    "corrupted_conf",
    _generate_corrupted_cryptoconfs(COMPLEX_SHAMIR_CRYPTOCONF, is_complex_conf=True, include_extended_checks=False),
)
def test_cryptoconf_validation_error_via_json_schema(corrupted_conf):
    with pytest.raises(ValidationError):
        corrupted_conf_json = convert_to_extjson(corrupted_conf)
        check_cryptoconf_sanity(cryptoconf=corrupted_conf_json, jsonschema_mode=True)


@pytest.mark.parametrize(
    "cryptoconf", [SIMPLE_CRYPTOCONF, COMPLEX_CRYPTOCONF, SIMPLE_SHAMIR_CRYPTOCONF, COMPLEX_SHAMIR_CRYPTOCONF]
)
def test_cryptainer_validation_success(cryptoconf):
    cryptainer = encrypt_payload_into_cryptainer(payload=b"stuffs", cryptoconf=cryptoconf, cryptainer_metadata=None)
    check_cryptainer_sanity(cryptainer=cryptainer, jsonschema_mode=False)

    cryptainer_json = convert_to_extjson(cryptainer)
    check_cryptainer_sanity(cryptainer=cryptainer_json, jsonschema_mode=True)


def _generate_corrupted_cryptainers(cryptoconf, include_extended_checks):
    cryptainer = encrypt_payload_into_cryptainer(payload=b"stuffs", cryptoconf=cryptoconf, cryptainer_metadata=None)

    # We can treat cryptainer as a cryptoconf sructure too!
    corrupted_cryptainers = _generate_corrupted_cryptoconfs(
        cryptainer, is_complex_conf=False, include_extended_checks=include_extended_checks
    )

    corrupted_cryptainer1 = copy.deepcopy(cryptainer)
    corrupted_cryptainer1["payload_cipher_layers"][0]["keychain_uid"] = ENFORCED_UID1
    corrupted_cryptainers.append(corrupted_cryptainer1)

    corrupted_cryptainer2 = copy.deepcopy(cryptainer)
    del corrupted_cryptainer2["payload_cipher_layers"][0]["payload_macs"]
    corrupted_cryptainers.append(corrupted_cryptainer2)

    corrupted_cryptainer3 = copy.deepcopy(cryptainer)
    corrupted_cryptainer3["payload_cipher_layers"][0]["key_ciphertext"] = []
    corrupted_cryptainers.append(corrupted_cryptainer3)

    return corrupted_cryptainers


def test_cryptainer_validation_error_via_python_schema():
    corrupted_cryptainers = _generate_corrupted_cryptainers(SIMPLE_CRYPTOCONF, include_extended_checks=True)

    for corrupted_cryptainer in corrupted_cryptainers:
        with pytest.raises(ValidationError):
            check_cryptainer_sanity(cryptainer=corrupted_cryptainer, jsonschema_mode=False)


def test_cryptainer_validation_error_via_json_schema():
    corrupted_cryptainers = _generate_corrupted_cryptainers(SIMPLE_CRYPTOCONF, include_extended_checks=False)

    for corrupted_cryptainer in corrupted_cryptainers:
        with pytest.raises(ValidationError):
            # Use RELAXED format (the default) for extjson representation
            corrupted_cryptainer_json = convert_to_extjson(corrupted_cryptainer, canonical=False)
            check_cryptainer_sanity(cryptainer=corrupted_cryptainer_json, jsonschema_mode=True)


def test_retrocompatibility_for_payload_ciphertext_signatures_field():
    cryptoconf = copy.deepcopy(SIMPLE_CRYPTOCONF)
    layer_dict = cryptoconf["payload_cipher_layers"][0]
    layer_dict["payload_signatures"] = _temp = layer_dict.pop("payload_ciphertext_signatures")  # OLD naming

    check_cryptoconf_sanity(cryptoconf)

    assert layer_dict["payload_ciphertext_signatures"] == _temp
    assert "payload_signatures" not in layer_dict

    # ---

    cryptainer = encrypt_payload_into_cryptainer(payload=b"stuffs", cryptoconf=cryptoconf, cryptainer_metadata=None)

    layer_dict = cryptainer["payload_cipher_layers"][0]
    layer_dict["payload_signatures"] = _temp = layer_dict.pop("payload_ciphertext_signatures")  # OLD naming

    check_cryptainer_sanity(cryptainer)

    assert layer_dict["payload_ciphertext_signatures"] == _temp
    assert "payload_signatures" not in layer_dict


@pytest.mark.parametrize(
    "cryptoconf",
    [SIMPLE_CRYPTOCONF_WITH_BAD_PLAINTEXT_SIGNING, SIMPLE_CRYPTOCONF_WITH_BAD_CIPHERTEXT_SIGNING],
)
def test_encryption_signature_policy_with_error_cases(cryptoconf):
    keystore_pool = InMemoryKeystorePool()

    def _build_normal_cryptainer_with_signature_policy(signature_policy):
        return encrypt_payload_into_cryptainer(
            payload=b"stuffs",
            cryptoconf=cryptoconf,
            cryptainer_metadata=None,
            keystore_pool=keystore_pool,
            signature_policy=signature_policy,
        )

    def _build_streamed_cryptainer_with_signature_policy(signature_policy):
        _cryptainer_filepath = Path(tempfile.mktemp() + ".crypt")
        encrypt_payload_and_stream_cryptainer_to_filesystem(
            payload=b"stuffs",
            cryptoconf=cryptoconf,
            cryptainer_metadata=None,
            keystore_pool=keystore_pool,
            signature_policy=signature_policy,
            cryptainer_filepath=_cryptainer_filepath
        )
        cryptainer = load_cryptainer_from_filesystem(_cryptainer_filepath)
        return cryptainer

    for _build_cryptainer_with_signature_policy in [
        _build_normal_cryptainer_with_signature_policy, _build_streamed_cryptainer_with_signature_policy
    ]:
        with mock.patch(
            "wacryptolib.cryptainer._do_get_message_signature",
            wraps=_do_get_message_signature,
        ) as patched_do_get_message_signature:
            cryptainer = _build_cryptainer_with_signature_policy(signature_policy=SIGNATURE_POLICIES.SKIP_SIGNING)
            check_cryptainer_sanity(cryptainer)
            assert patched_do_get_message_signature.call_count == 0

        with mock.patch(
            "wacryptolib.cryptainer._do_get_message_signature", wraps=_do_get_message_signature
        ) as patched_do_get_message_signature:
            cryptainer = _build_cryptainer_with_signature_policy(signature_policy=SIGNATURE_POLICIES.ATTEMPT_SIGNING)
            check_cryptainer_sanity(cryptainer)
            assert patched_do_get_message_signature.call_count == 1

        with pytest.raises(KeystoreDoesNotExist):
            _build_cryptainer_with_signature_policy(signature_policy=SIGNATURE_POLICIES.REQUIRE_SIGNING)


def test_encryption_signature_policy_with_success_cases():
    keystore_pool = InMemoryKeystorePool()

    cryptoconf = None  # Placeholder

    def _build_cryptainer_with_signature_policy(signature_policy):
        return encrypt_payload_into_cryptainer(
            payload=b"stuffs",
            cryptoconf=cryptoconf,
            cryptainer_metadata=None,
            keystore_pool=keystore_pool,
            signature_policy=signature_policy,
        )

    for cryptoconf, signature_conf_cb in [
        (SIMPLE_CRYPTOCONF, lambda _cryptainer: _cryptainer["payload_cipher_layers"][0]["payload_ciphertext_signatures"][0]),
        (COMPLEX_CRYPTOCONF, lambda _cryptainer: _cryptainer["payload_plaintext_signatures"][0]),
    ]:

        for signature_policy in [SIGNATURE_POLICIES.REQUIRE_SIGNING, SIGNATURE_POLICIES.ATTEMPT_SIGNING]:
            cryptainer = _build_cryptainer_with_signature_policy(signature_policy=signature_policy)
            check_cryptainer_sanity(cryptainer)
            signature_conf = signature_conf_cb(cryptainer)
            assert signature_conf["payload_digest_value"]  # Properly updated
            assert signature_conf["payload_signature_struct"]  # SUCCESS

        cryptainer = _build_cryptainer_with_signature_policy(signature_policy=SIGNATURE_POLICIES.SKIP_SIGNING)
        check_cryptainer_sanity(cryptainer)
        signature_conf = signature_conf_cb(cryptainer)
        assert signature_conf["payload_digest_value"]  # Properly updated
        assert "payload_signature_struct" not in signature_conf  # SKIPPED


def test_load_legacy_canonical_extjson_cryptainer(tmp_path):
    """Test that cryptainers saved in canonical extjson format can still be loaded."""
    from wacryptolib.utilities import convert_to_extjson, convert_from_extjson, dump_to_json_file, load_from_json_file
    
    # Create a cryptainer
    cryptainer = encrypt_payload_into_cryptainer(
        payload=b"test data", 
        cryptoconf=SIMPLE_CRYPTOCONF, 
        cryptainer_metadata=None
    )
    
    # Convert to canonical extjson format (legacy format with $binary for UUIDs)
    cryptainer_canonical = convert_to_extjson(cryptainer, canonical=True)
    
    # Save to file
    temp_file = tmp_path / "legacy_cryptainer.json"
    dump_to_json_file(temp_file, cryptainer_canonical, canonical=True)
    
    # Load back from file (should work with relaxed mode by default, but handle both formats)
    loaded_cryptainer_json = load_from_json_file(temp_file)
    
    # Convert from extjson to Python objects
    loaded_cryptainer = convert_from_extjson(loaded_cryptainer_json)
    
    # Verify it's valid
    check_cryptainer_sanity(loaded_cryptainer, jsonschema_mode=False)
    
    # Decrypt to verify it works
    decrypted, operation_report = decrypt_payload_from_cryptainer(loaded_cryptainer)
    assert decrypted == b"test data"
    assert not operation_report.has_errors()


def test_save_and_load_relaxed_extjson_cryptainer(tmp_path):
    """Test that cryptainers can be saved and loaded in RELAXED extjson format (the default)."""
    from wacryptolib.utilities import convert_to_extjson, convert_from_extjson, dump_to_json_file, load_from_json_file
    
    # Create a cryptainer
    cryptainer = encrypt_payload_into_cryptainer(
        payload=b"test data", 
        cryptoconf=SIMPLE_CRYPTOCONF, 
        cryptainer_metadata=None
    )
    
    # Convert to RELAXED extjson format (default format with $uuid for UUIDs and plain ints)
    cryptainer_relaxed = convert_to_extjson(cryptainer, canonical=False)
    
    # Save to file (RELAXED is the default)
    temp_file = tmp_path / "relaxed_cryptainer.json"
    dump_to_json_file(temp_file, cryptainer_relaxed)
    
    # Load back from file
    loaded_cryptainer_json = load_from_json_file(temp_file)
    
    # Convert from extjson to Python objects
    loaded_cryptainer = convert_from_extjson(loaded_cryptainer_json)
    
    # Verify it's valid
    check_cryptainer_sanity(loaded_cryptainer, jsonschema_mode=False)
    
    # Decrypt to verify it works
    decrypted, operation_report = decrypt_payload_from_cryptainer(loaded_cryptainer)
    assert decrypted == b"test data"
    assert not operation_report.has_errors()


