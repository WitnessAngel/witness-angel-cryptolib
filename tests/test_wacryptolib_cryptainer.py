import copy
import os
import random
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
    convert_native_tree_to_extended_json_tree,
)
from wacryptolib.utilities import load_from_json_file

ENFORCED_UID1 = UUID("0e8e861e-f0f7-e54b-18ea-34798d5daaaa")
ENFORCED_UID2 = UUID("65dbbe4f-0bd5-4083-a274-3c76efeebbbb")
ENFORCED_UID3 = UUID("65dbbe4f-0bd5-4083-a274-3c76efeecccc")

VOID_CRYPTOCONF_REGARDING_PAYLOAD_CIPHER_LAYERS = dict(payload_cipher_layers=[])  # Forbidden

VOID_CRYPTOCONF_REGARDING_KEY_CIPHER_LAYERS = dict(  # Forbidden
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[],
            payload_signatures=[
                dict(
                    payload_digest_algo="SHA256",
                    payload_signature_algo="DSA_DSS",
                    payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                )
            ],
        )
    ]
)

SIGNATURELESS_CRYPTOCONF = dict(
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_EAX",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_signatures=[],
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
            payload_signatures=[
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
            payload_signatures=[],
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
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_EAX",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_signatures=[],
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
            payload_signatures=[
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
            payload_signatures=[
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
    ]
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
            payload_signatures=[
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
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_EAX",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_signatures=[],
        ),
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_signatures=[
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
            payload_signatures=[
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
    ]
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
    "cryptoconf", [VOID_CRYPTOCONF_REGARDING_PAYLOAD_CIPHER_LAYERS, VOID_CRYPTOCONF_REGARDING_KEY_CIPHER_LAYERS]
)
def test_void_cryptoconfs(cryptoconf):
    keystore_pool = InMemoryKeystorePool()

    with pytest.raises(SchemaValidationError, match="Empty .* list"):
        encrypt_payload_into_cryptainer(
            payload=b"stuffs",
            cryptoconf=cryptoconf,
            keychain_uid=None,
            cryptainer_metadata=None,
            keystore_pool=keystore_pool,
        )


def test_encrypt_payload_into_cryptainer_from_file_object(tmp_path):
    source = tmp_path / "source.media"
    source.write_bytes(b"12345")
    assert source.exists()

    open_fileobj = open(source, "rb")

    cryptainer = encrypt_payload_into_cryptainer(
        payload=open_fileobj,
        cryptoconf=SIMPLE_CRYPTOCONF,
        cryptainer_metadata=None,
        keystore_pool=InMemoryKeystorePool(),
    )
    assert cryptainer

    assert open_fileobj.closed
    assert not source.exists()  # Source is autodeleted!


def test_cryptainer_encryption_pipeline_autocleanup(tmp_path):
    pipeline = CryptainerEncryptionPipeline(
        cryptainer_filepath=tmp_path.joinpath("destination.crypt"),
        cryptoconf=SIMPLE_CRYPTOCONF,
        cryptainer_metadata=None,
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
    use_streaming_encryption = random_bool()

    keystore_pool = InMemoryKeystorePool()
    metadata = random.choice([None, dict(a=[123])])

    if use_streaming_encryption and is_cryptainer_cryptoconf_streamable(cryptoconf):
        cryptainer_filepath = tmp_path / "mygoodcryptainer.crypt"
        encrypt_payload_and_stream_cryptainer_to_filesystem(
            payload=payload,
            cryptainer_filepath=cryptainer_filepath,
            cryptoconf=cryptoconf,
            keychain_uid=keychain_uid,
            cryptainer_metadata=metadata,
            keystore_pool=keystore_pool,
        )
        cryptainer = load_cryptainer_from_filesystem(cryptainer_filepath, include_payload_ciphertext=True)
    else:
        cryptainer = encrypt_payload_into_cryptainer(
            payload=payload,
            cryptoconf=cryptoconf,
            keychain_uid=keychain_uid,
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
    result_payload, error_report = decrypt_payload_from_cryptainer(
        cryptainer=cryptainer, keystore_pool=keystore_pool, verify_integrity_tags=verify_integrity_tags
    )
    assert error_report == []
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
    for (shard_trustee_id, passphrase) in list_shard_trustee_id:
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


def _check_error_entry(
    error_list, error_type, error_criticity, error_msg_match, exception_class=None, occurrence_count=1
):
    real_occurrence_count = 0

    print("ERROR LIST:")
    pprint(error_list)

    for error_entry in error_list:
        try:
            assert error_entry["error_type"] == error_type
            assert error_entry["error_criticity"] == error_criticity
            assert error_msg_match.lower() in error_entry["error_message"].lower()

            if exception_class is not None:
                entry_exception_class = error_entry["error_exception"].__class__  # EXACT match, not "issubclass"!
                assert entry_exception_class == exception_class
            else:
                assert error_entry["error_exception"] is None

            real_occurrence_count += 1
        except AssertionError:
            pass  # It was not the entry we searched for

    assert real_occurrence_count == occurrence_count


def test_cryptainer_decryption_rare_cipher_errors(tmp_path):
    keychain_uid = generate_uuid0()

    cryptoconf = dict(
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
                payload_signatures=[],
            )
        ]
    )

    check_cryptoconf_sanity(cryptoconf=cryptoconf, jsonschema_mode=False)

    # Encrypt payload into cryptainer
    payload = b"sdfsfsdfsdf"

    cryptainer_original = encrypt_payload_into_cryptainer(
        payload=payload, cryptoconf=cryptoconf, keychain_uid=keychain_uid, cryptainer_metadata=None
    )
    pprint(cryptainer_original)

    cryptainer = copy.deepcopy(cryptainer_original)

    decrypted, error_report = decrypt_payload_from_cryptainer(cryptainer)
    assert decrypted == payload  # SUCCESS

    # Corrupt the integrity tag of the ciphertext
    key_ciphertext = cryptainer["payload_cipher_layers"][0]["key_ciphertext"]
    key_cipherdict = load_from_json_bytes(key_ciphertext)
    key_cipherdict["tag"] += b"xxx"
    cryptainer["payload_cipher_layers"][0]["key_ciphertext"] = dump_to_json_bytes(key_cipherdict)

    decrypted, error_report = decrypt_payload_from_cryptainer(cryptainer)
    assert not decrypted

    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.ERROR,
        error_msg_match="decrypting key with symmetric algorithm AES_EAX",
        exception_class=DecryptionIntegrityError,
    )
    assert len(error_report) == 2

    # ---

    cryptainer = copy.deepcopy(cryptainer_original)
    key_ciphertext = cryptainer["payload_cipher_layers"][0]["key_cipher_layers"][0]["key_ciphertext"]
    key_cipherdict = load_from_json_bytes(key_ciphertext)
    key_cipherdict["ciphertext_chunks"][0] += b"xxx"
    cryptainer["payload_cipher_layers"][0]["key_cipher_layers"][0]["key_ciphertext"] = dump_to_json_bytes(
        key_cipherdict
    )

    decrypted, error_report = decrypt_payload_from_cryptainer(cryptainer)
    assert not decrypted

    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.ERROR,
        error_msg_match="decrypting key with asymmetric algorithm",
        exception_class=DecryptionError,
    )
    assert len(error_report) == 2


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
                payload_signatures=[],
            )
        ]
    )
    check_cryptoconf_sanity(cryptoconf=cryptoconf, jsonschema_mode=False)

    # Ecrypt payload into cryptainer
    keychain_uid = random.choice([None, uuid.UUID("450fc293-b702-42d3-ae65-e9cc58e5a62a")])
    payload = b"sjzgzj"

    cryptainer = encrypt_payload_into_cryptainer(
        payload=payload,
        cryptoconf=cryptoconf,
        keychain_uid=keychain_uid,
        keystore_pool=keystore_pool,
        cryptainer_metadata=None,
    )
    passphrase_mapper = {shard_trustee_id: [passphrase]}

    # Decrypt cryptainer with passphrase
    decrypted, error_report = decrypt_payload_from_cryptainer(
        cryptainer, keystore_pool=keystore_pool, passphrase_mapper={shard_trustee_id: [passphrase]}
    )
    assert decrypted == payload

    # Wrong passphrase
    decrypted, error_report = decrypt_payload_from_cryptainer(
        cryptainer, keystore_pool=keystore_pool, passphrase_mapper={shard_trustee_id: ["fakepassphrase"]}
    )
    assert decrypted is None
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="Could not load private key",
        exception_class=KeyLoadingError,
    )
    # DecryptionError is present whenever decryption fails (will not always be tested)
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.ERROR,
        error_msg_match="Failed symmetric decryption",
    )

    assert len(error_report) == 2

    revelation_requestor_uid = generate_uuid0()

    cryptainers_with_names = [("cryptainer_name.mp4.crypt", cryptainer)]

    revelation_requests_info = _create_response_keyair_in_local_keyfactory_and_build_fake_revelation_request_info(
        revelation_requestor_uid, cryptainers_with_names, keystore_pool, list_shard_trustee_id
    )

    gateway_urls = ["http://127.0.0.1:9898/jsonrpc"]  # FIXME what's this url ? CHANGE THEM ALL

    # Network warning when no JSONRPC mockup s provided
    result_payload, error_report = decrypt_payload_from_cryptainer(
        cryptainer=cryptainer,
        keystore_pool=keystore_pool,
        passphrase_mapper=passphrase_mapper,
        gateway_urls=gateway_urls,
        revelation_requestor_uid=revelation_requestor_uid,
    )
    assert result_payload == payload
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="reach remote server",
        exception_class=TransportError,
    )
    assert len(error_report) == 1

    # Remote revelation request return right symkey_revelation_response_data
    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(revelation_requests_info)
    ):
        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper=passphrase_mapper,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload == payload
        assert error_report == []

    # Response keypair in not local key factory
    fake_revelation_request_info = copy.deepcopy(revelation_requests_info)
    wrong_response_keychain_uid = generate_uuid0()
    fake_revelation_request_info[0]["response_keychain_uid"] = wrong_response_keychain_uid

    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(fake_revelation_request_info)
    ):

        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper=passphrase_mapper,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert (
            result_payload == payload
        )  # Using imported trustee because can't decrypt the symkey_decryption_response_data with response key
        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.ERROR,
            error_msg_match="Private key of revelation response not found",
            exception_class=KeyDoesNotExist,
        )
        assert len(error_report) == 1

    # Wrong symkey revelation response data
    gateway_revelation_request_list = _build_fake_gateway_revelation_request_list(revelation_requests_info)
    # Corrupted symkey
    gateway_revelation_request_list[0]["symkey_decryption_requests"][0][
        "symkey_decryption_response_data"
    ] = b'{"ciphertext_chunks": [{"$binary": {"base64": "FImgSTpvmdIGPjml5YzI1qtOrN/I34DkG1PTNWqnqg==", "subType": "00"}}]}'

    with _patched_gateway_revelation_request_list(return_value=gateway_revelation_request_list):

        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper=passphrase_mapper,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload == payload  # Using asymmetric algorithm because response_data corrupted
        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.ERROR,
            error_msg_match="Failed decryption of remote symkey/shard",
            exception_class=DecryptionError,
        )
        assert len(error_report) == 1

    # keystore pool without trustee and response keypair
    keystore_pool1 = InMemoryKeystorePool()
    response_keychain_uid = revelation_requests_info[0]["response_keychain_uid"]
    keystore_pool1._register_fake_imported_storage_uids(storage_uids=[keystore_uid])

    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(revelation_requests_info)
    ):
        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool1,
            passphrase_mapper=passphrase_mapper,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload is None
        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.WARNING,
            error_msg_match="Private key not found",
            exception_class=KeyDoesNotExist,
        )  # TRUSTEE KEYPAIR
        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.ERROR,
            error_msg_match="Private key of revelation response not found",
            exception_class=KeyDoesNotExist,
        )  # RESPONSE KEYPAIR

        assert len(error_report) == 3  # with Symmetric decryption error

    # Keystore pool empty( without trustee keystore in imported keystore and response key in local keystore)
    keystore_pool2 = InMemoryKeystorePool()
    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(revelation_requests_info)
    ):
        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool2,
            passphrase_mapper=passphrase_mapper,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload is None
        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.ERROR,
            error_msg_match="Private key of revelation response not found",
            exception_class=KeyDoesNotExist,
        )  # RESPONSE KEYPAIR
        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.WARNING,
            error_msg_match="Trustee key storage not found",
            exception_class=KeystoreDoesNotExist,
        )  # TRUSTEE KEYSTORE
        assert len(error_report) == 3  # with Symmetric decryption error


# Cryptoconf with 1 shared secret with threshold of 1 and only one trustee
def test_cryptainer_decryption_with_one_authenticator_in_shared_secret(tmp_path):
    keychain_uid_trustee = generate_uuid0()
    keystore_uid = generate_uuid0()
    passphrase = "xyz"

    # Create fake trustee keystore and keypair in foreign key
    (
        keystore_pool,
        foreign_keystore,
        shard_trustee,
    ) = _create_keystore_and_keypair_protected_by_passphrase_in_foreign_keystore(
        keystore_uid=keystore_uid, keychain_uid=keychain_uid_trustee, passphrase=passphrase
    )

    # Get shard trustee id
    list_shard_trustee_id = []
    shard_trustee_id = get_trustee_id(shard_trustee)
    trustee_info = (shard_trustee_id, passphrase)
    list_shard_trustee_id.append(trustee_info)

    # creer un crypconf qui crypte avec authentifieur
    cryptoconf = dict(
        payload_cipher_layers=[
            dict(
                payload_cipher_algo="AES_CBC",
                key_cipher_layers=[
                    dict(
                        key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
                        key_shared_secret_threshold=1,
                        key_shared_secret_shards=[
                            dict(
                                key_cipher_layers=[
                                    dict(
                                        key_cipher_algo="CHACHA20_POLY1305",  # Nested symmetric cipher
                                        key_cipher_layers=[
                                            dict(
                                                key_cipher_algo="RSA_OAEP",
                                                keychain_uid=keychain_uid_trustee,
                                                key_cipher_trustee=shard_trustee,
                                            )
                                        ],
                                    )
                                ]
                            )
                        ],
                    )
                ],
                payload_signatures=[],
            )
        ]
    )

    check_cryptoconf_sanity(cryptoconf=cryptoconf, jsonschema_mode=False)

    # Encrypt data into cryptainer
    payload = _get_binary_or_empty_content()
    keychain_uid = random.choice([None, uuid.UUID("450fc293-b702-42d3-ae65-e9cc58e5a62a")])
    metadata = random.choice([None, dict(a=[123])])

    cryptainer = encrypt_payload_into_cryptainer(
        payload=payload,
        cryptoconf=cryptoconf,
        keychain_uid=keychain_uid,
        cryptainer_metadata=metadata,
        keystore_pool=keystore_pool,
    )

    assert cryptainer["keychain_uid"]
    if keychain_uid:
        assert cryptainer["keychain_uid"] == keychain_uid

    verify_integrity_tags = random_bool()

    passphrase_mapper = {shard_trustee_id: [passphrase]}

    # Decrypt data with passphrase mapper
    result_payload, error_report = decrypt_payload_from_cryptainer(
        cryptainer=cryptainer,
        keystore_pool=keystore_pool,
        passphrase_mapper=passphrase_mapper,
        verify_integrity_tags=verify_integrity_tags,
    )
    assert error_report == []
    assert result_payload == payload
    result_metadata = extract_metadata_from_cryptainer(cryptainer=cryptainer)
    assert result_metadata == metadata

    # Decrypt with remote revelation request
    revelation_requestor_uid = generate_uuid0()

    cryptainers_with_names = [("cryptainer_name.mp4.crypt", cryptainer)]

    # Create a response keypair in localkeyfactory to encrypt the decrypted symkeys and for each crypatiner trustee
    # create the information needed to generate a successful decryption request
    revelation_requests_info = _create_response_keyair_in_local_keyfactory_and_build_fake_revelation_request_info(
        revelation_requestor_uid, cryptainers_with_names, keystore_pool, list_shard_trustee_id
    )

    gateway_urls = ["http://127.0.0.1:9898/jsonrpc"]

    # Remote revelation request return right symkey_revelation_response_data
    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(revelation_requests_info)
    ):
        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload == payload
        assert error_report == []

    # Trustee keypair does not exist in storage
    # Create new keystore pool with response keypair in localkeyfactory without trustee keystore
    keystore_pool1 = InMemoryKeystorePool()
    local_keystore1 = keystore_pool1.get_local_keyfactory()
    response_keychain_uid = revelation_requests_info[0]["response_keychain_uid"]
    generate_keypair_for_storage(key_algo="RSA_OAEP", keystore=local_keystore1, keychain_uid=response_keychain_uid)

    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(revelation_requests_info)
    ):

        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool1,
            passphrase_mapper=passphrase_mapper,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload == payload
        assert error_report == []  # Using remote_revelation_request so no trustee needed

    # Trustee and response keypair does not exist in storage
    gateway_revelation_request_list = _build_fake_gateway_revelation_request_list(revelation_requests_info)
    # Corrupted response keychain uid
    gateway_revelation_request_list[0]["revelation_response_keychain_uid"] = generate_uuid0()

    with _patched_gateway_revelation_request_list(return_value=gateway_revelation_request_list):

        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool1,
            gateway_urls=gateway_urls,
            passphrase_mapper=passphrase_mapper,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload is None

        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.ERROR,
            error_msg_match="Private key of revelation response not found",
            exception_class=KeyDoesNotExist,
        )  # RESPONSE KEYPAIR

        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.WARNING,
            error_msg_match="Trustee key storage not found",
            exception_class=KeystoreDoesNotExist,
        )  # TRUSTEE KEYSTORE

        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.WARNING,
            error_msg_match="error prevented decrypting shard",
        )

        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.WARNING,
            error_msg_match="1 valid shard(s) missing for reconstitution of symmetric key",
        )  # 1 SHARD MISSING

        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.ERROR,
            error_msg_match="Failed symmetric decryption",  # FAILED DECRYPTION
        )
        assert len(error_report) == 5


def test_cryptainer_decryption_from_complex_cryptoconf(tmp_path):
    keychain_uid = generate_uuid0()
    local_passphrase = "b^yep&ts"

    # Trustee 1(with mockuup)
    keystore_uid1 = generate_uuid0()
    passphrase1 = "tata"

    # Trustee 2(without mockup)
    keystore_uid2 = generate_uuid0()
    passphrase2 = "2çès"

    # Trustee 3(with mockup)
    keystore_uid3 = generate_uuid0()
    passphrase3 = "zaizoadsxsnd123"

    all_passphrases = [local_passphrase, passphrase1, passphrase2, passphrase3]

    keystore_pool = InMemoryKeystorePool()
    keystore_pool._register_fake_imported_storage_uids(storage_uids=[keystore_uid1, keystore_uid2, keystore_uid3])

    local_keystore = keystore_pool.get_local_keyfactory()
    generate_keypair_for_storage(
        key_algo="RSA_OAEP", keystore=local_keystore, keychain_uid=keychain_uid, passphrase=local_passphrase
    )
    keystore1 = keystore_pool.get_foreign_keystore(keystore_uid1)
    generate_keypair_for_storage(
        key_algo="RSA_OAEP", keystore=keystore1, keychain_uid=keychain_uid, passphrase=passphrase1
    )
    keystore2 = keystore_pool.get_foreign_keystore(keystore_uid2)
    generate_keypair_for_storage(
        key_algo="RSA_OAEP", keystore=keystore2, keychain_uid=keychain_uid, passphrase=passphrase2
    )
    keystore3 = keystore_pool.get_foreign_keystore(keystore_uid3)
    generate_keypair_for_storage(
        key_algo="RSA_OAEP", keystore=keystore3, keychain_uid=keychain_uid, passphrase=passphrase3
    )

    local_keyfactory_trustee_id = get_trustee_id(LOCAL_KEYFACTORY_TRUSTEE_MARKER)
    list_shard_trustee_id = []

    shard_trustee1 = dict(trustee_type="authenticator", keystore_uid=keystore_uid1)
    shard_trustee1_id = get_trustee_id(shard_trustee1)
    trustee_info1 = (shard_trustee1_id, passphrase1)
    list_shard_trustee_id.append(trustee_info1)

    shard_trustee2 = dict(trustee_type="authenticator", keystore_uid=keystore_uid2)
    shard_trustee2_id = get_trustee_id(shard_trustee2)

    shard_trustee3 = dict(trustee_type="authenticator", keystore_uid=keystore_uid3)
    shard_trustee3_id = get_trustee_id(shard_trustee3)
    trustee_info3 = (shard_trustee3_id, passphrase3)
    list_shard_trustee_id.append(trustee_info3)

    cryptoconf = dict(
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
                                    dict(
                                        key_cipher_algo="RSA_OAEP",
                                        key_cipher_trustee=shard_trustee1,
                                        keychain_uid=keychain_uid,
                                    )
                                ]
                            ),
                            dict(
                                key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=shard_trustee2)]
                            ),
                            dict(
                                key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=shard_trustee3)]
                            ),
                            dict(
                                key_cipher_layers=[
                                    dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                                ]
                            ),
                        ],
                    ),
                ],
                payload_signatures=[
                    dict(
                        payload_digest_algo="SHA256",
                        payload_signature_algo="DSA_DSS",
                        payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                        # Uses separate keypair, no passphrase here
                    )
                ],
            )
        ]
    )
    check_cryptoconf_sanity(cryptoconf=cryptoconf, jsonschema_mode=False)

    payload = b"azertyuiop"

    cryptainer = encrypt_payload_into_cryptainer(
        payload=payload,
        cryptoconf=cryptoconf,
        keychain_uid=keychain_uid,
        keystore_pool=keystore_pool,
        cryptainer_metadata=None,
    )

    passphrase_mapper = {
        local_keyfactory_trustee_id: [local_passphrase],
        shard_trustee1_id: all_passphrases,
        shard_trustee3_id: [passphrase3],
    }

    # Missing trustee2 passphrase
    decrypted, error_report = decrypt_payload_from_cryptainer(
        cryptainer, keystore_pool=keystore_pool, passphrase_mapper=passphrase_mapper
    )
    assert decrypted == payload
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="Could not load private key",
        exception_class=KeyLoadingError,
    )
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="error prevented decrypting shard",
    )

    assert len(error_report) == 2

    # Decrypt with passphrase and mockup
    revelation_requestor_uid = generate_uuid0()

    cryptainers_with_names = [("cryptainer_name.mp4.crypt", cryptainer)]

    # Create the information needed to generate a successful decryption request
    revelation_requests_info = _create_response_keyair_in_local_keyfactory_and_build_fake_revelation_request_info(
        revelation_requestor_uid, cryptainers_with_names, keystore_pool, list_shard_trustee_id
    )

    gateway_urls = ["http://127.0.0.1:9898/jsonrpc"]  # FIXME what's this url ?

    # No remote decryption request for this container and requestor
    with _patched_gateway_revelation_request_list(return_value=[]):
        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper={None: all_passphrases},
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload == payload
        assert error_report == []  # All passphrases are provided

    # Remote decryption request for this container and requestor is rejected
    gateway_revelation_request_list = _build_fake_gateway_revelation_request_list(revelation_requests_info)
    gateway_revelation_request_list[0]["revelation_request_status"] = "REJECTED"

    with _patched_gateway_revelation_request_list(return_value=gateway_revelation_request_list):

        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper={None: all_passphrases},
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload == payload
        assert error_report == []  # All passphrases are provided

    # No remote decryption request exists for this container and requestor
    gateway_revelation_request_list = _build_fake_gateway_revelation_request_list(revelation_requests_info)
    gateway_revelation_request_list[0]["symkey_decryption_requests"][0]["cryptainer_uid"] = generate_uuid0()

    with _patched_gateway_revelation_request_list(return_value=gateway_revelation_request_list):

        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper={None: all_passphrases},
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload == payload
        assert error_report == []  # All passphrases are provided

    # Remote revelation request with two trustee (1,3) and local trustee
    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(revelation_requests_info)
    ):

        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper={local_keyfactory_trustee_id: [local_passphrase], shard_trustee2_id: [passphrase2]},
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload == payload
        assert error_report == []  # Trustee 1, 3 decrypted from server, trustee2 and localkey have passphrases

    # Remote revelation request with two trustee (1,3) and without any passphrase(decrypted_shards below threshold)
    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(revelation_requests_info)
    ):

        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload is None
        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.WARNING,
            error_msg_match="Could not load private key",
            exception_class=KeyLoadingError,
            occurrence_count=2,
        )  # 2 for Trustee2 and LOCAL_KEYFACTORY_TRUSTEE_MARKER
        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.WARNING,
            error_msg_match="error prevented decrypting shard",
            occurrence_count=2,
        )  # 2 for Trustee2 and LOCAL_KEYFACTORY_TRUSTEE_MARKER

        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.WARNING,
            error_msg_match="1 valid shard(s) missing for reconstitution of symmetric key",
        )  # 1 SHARD MISSING
        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.ERROR,
            error_msg_match="Failed symmetric decryption",
        )
        assert len(error_report) == 6


def test_key_loading_local_decryption_and_payload_signature(tmp_path):  # TODO CHANGE THIS NAME
    # TODO NOT FINISH
    keychain_uid = generate_uuid0()

    keystore_uid = generate_uuid0()
    keychain_uid_trustee = generate_uuid0()

    passphrase = "passphrase"

    # Create fake keystore and keypair in foreign key

    (
        keystore_pool,
        foreign_keystore,
        shard_trustee,
    ) = _create_keystore_and_keypair_protected_by_passphrase_in_foreign_keystore(
        keystore_uid=keystore_uid, keychain_uid=keychain_uid_trustee, passphrase=passphrase
    )

    # Local Keyfactory
    local_keystore = keystore_pool.get_local_keyfactory()

    # Get shard trustee id
    list_shard_trustee_id = []
    shard_trustee_id = get_trustee_id(shard_trustee)
    trustee_info = (shard_trustee_id, passphrase)
    list_shard_trustee_id.append(trustee_info)

    cryptoconf = dict(
        payload_cipher_layers=[
            dict(
                payload_cipher_algo="AES_CBC",
                key_cipher_layers=[
                    dict(
                        key_cipher_algo="RSA_OAEP", key_cipher_trustee=shard_trustee, keychain_uid=keychain_uid_trustee
                    )
                ],
                payload_signatures=[
                    dict(
                        payload_digest_algo="SHA256",
                        payload_signature_algo="DSA_DSS",
                        payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                    )
                ],
            )
        ]
    )

    payload = b"azertyuiop"

    cryptainer = encrypt_payload_into_cryptainer(
        payload=payload,
        cryptoconf=cryptoconf,
        keychain_uid=keychain_uid,
        keystore_pool=keystore_pool,
        cryptainer_metadata=None,
    )

    cryptainers_with_names = [("cryptainer_name.mp4.crypt", cryptainer)]

    # Generate revelation requests info
    revelation_requestor_uid = generate_uuid0()
    revelation_requests_info = _create_response_keyair_in_local_keyfactory_and_build_fake_revelation_request_info(  # FIXME TYPO KEYAIR
        revelation_requestor_uid, cryptainers_with_names, keystore_pool, list_shard_trustee_id
    )

    # Corrupt response privatekey
    response_keychain_uid = revelation_requests_info[0]["response_keychain_uid"]
    response_key = (response_keychain_uid, "RSA_OAEP")
    response_keypair = local_keystore._cached_keypairs[response_key]
    response_keypair["private_key"] = b"wrongresponseprivatekey"

    # Corrupt signature public key
    response_key = (keychain_uid, "DSA_DSS")
    response_keypair = local_keystore._cached_keypairs[response_key]
    response_keypair["public_key"] = b"wrongsignaturepublickey"

    gateway_urls = ["http://127.0.0.1:9898/jsonrpc"]
    with _patched_gateway_revelation_request_list(
        return_value=_build_fake_gateway_revelation_request_list(revelation_requests_info)
    ):

        result_payload, error_report = decrypt_payload_from_cryptainer(
            cryptainer=cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper={shard_trustee_id: [passphrase]},
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        assert result_payload == payload
        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.SIGNATURE_ERROR,
            error_criticity=DecryptionErrorCriticity.WARNING,
            error_msg_match="Failed loading signature key from pem bytestring",
            exception_class=KeyLoadingError,
        )  # SIGNATURE KEY LOADING ERROR
        _check_error_entry(
            error_list=error_report,
            error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            error_criticity=DecryptionErrorCriticity.ERROR,
            error_msg_match="Failed loading revelation response key of from pem bytestring",
            exception_class=KeyLoadingError,
        )  # RESPONSE KEY LOADING ERROR
        assert len(error_report) == 2


@pytest.mark.parametrize(
    "shamir_cryptoconf, trustee_dependencies_builder",
    [
        (SIMPLE_SHAMIR_CRYPTOCONF, SIMPLE_SHAMIR_CRYPTAINER_TRUSTEE_DEPENDENCIES),
        (COMPLEX_SHAMIR_CRYPTOCONF, COMPLEX_SHAMIR_CRYPTAINER_TRUSTEE_DEPENDENCIES),
    ],
)
def test_shamir_cryptainer_encryption_and_decryption(shamir_cryptoconf, trustee_dependencies_builder):
    payload = _get_binary_or_empty_content()

    keychain_uid = random.choice([None, uuid.UUID("450fc293-b702-42d3-ae65-e9cc58e5a62a")])

    metadata = random.choice([None, dict(a=[123])])

    cryptainer = encrypt_payload_into_cryptainer(
        payload=payload, cryptoconf=shamir_cryptoconf, keychain_uid=keychain_uid, cryptainer_metadata=metadata
    )

    assert cryptainer["keychain_uid"]
    if keychain_uid:
        assert cryptainer["keychain_uid"] == keychain_uid

    trustee_dependencies = gather_trustee_dependencies(cryptainers=[cryptainer])
    assert trustee_dependencies == trustee_dependencies_builder(cryptainer["keychain_uid"])

    assert isinstance(cryptainer["payload_ciphertext_struct"], dict)

    result_payload, error_report = decrypt_payload_from_cryptainer(cryptainer=cryptainer)

    assert result_payload == payload
    assert error_report == []

    payload_encryption_shamir = {}
    # Delete 1, 2 and too many share(s) from cipherdict key
    for payload_encryption in cryptainer["payload_cipher_layers"]:
        for key_encryption in payload_encryption["key_cipher_layers"]:
            if key_encryption["key_cipher_algo"] == SHARED_SECRET_ALGO_MARKER:
                payload_encryption_shamir = payload_encryption

    key_ciphertext_shards = load_from_json_bytes(payload_encryption_shamir["key_ciphertext"])

    # 1 share is deleted

    del key_ciphertext_shards["shard_ciphertexts"][-1]

    payload_encryption_shamir["key_ciphertext"] = dump_to_json_bytes(key_ciphertext_shards)

    verify_integrity_tags = random_bool()
    result_payload, error_report = decrypt_payload_from_cryptainer(
        cryptainer=cryptainer, verify_integrity_tags=verify_integrity_tags
    )
    assert result_payload == payload
    assert error_report == []

    # Another share is deleted

    del key_ciphertext_shards["shard_ciphertexts"][-1]

    payload_encryption_shamir["key_ciphertext"] = dump_to_json_bytes(key_ciphertext_shards)

    result_payload, error_report = decrypt_payload_from_cryptainer(cryptainer=cryptainer)
    assert result_payload == payload
    assert error_report == []

    # Another share is deleted and now there aren't enough valid ones to decipher data

    del key_ciphertext_shards["shard_ciphertexts"][-1]

    payload_encryption_shamir["key_ciphertext"] = dump_to_json_bytes(key_ciphertext_shards)

    result_payload, error_report = decrypt_payload_from_cryptainer(cryptainer=cryptainer)
    assert result_payload is None
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="1 valid shard(s) missing for reconstitution of symmetric key",
    )

    result_metadata = extract_metadata_from_cryptainer(cryptainer=cryptainer)
    assert result_metadata == metadata

    cryptainer["cryptainer_format"] = "OAJKB"
    with pytest.raises(ValueError, match="Unknown cryptainer format"):
        decrypt_payload_from_cryptainer(cryptainer=cryptainer)


def test_decrypt_payload_from_cryptainer_with_authenticated_algo_and_verify_failures():
    payload_cipher_algo = random.choice(AUTHENTICATED_CIPHER_ALGOS)
    cryptoconf = copy.deepcopy(SIMPLE_CRYPTOCONF)
    cryptoconf["payload_cipher_layers"][0]["payload_cipher_algo"] = payload_cipher_algo

    cryptainer = encrypt_payload_into_cryptainer(payload=b"1234", cryptoconf=cryptoconf, cryptainer_metadata=None)

    result, error_report = decrypt_payload_from_cryptainer(cryptainer, verify_integrity_tags=True)
    assert result == b"1234"

    cryptainer["payload_cipher_layers"][0]["payload_macs"]["tag"] += b"hi"  # CORRUPTION

    result, error_report = decrypt_payload_from_cryptainer(cryptainer, verify_integrity_tags=False)
    assert result == b"1234"

    # DecryptionIntegrityError
    result, error_report = decrypt_payload_from_cryptainer(cryptainer, verify_integrity_tags=True)
    assert result is None
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.ERROR,
        error_msg_match="Failed decryption authentication",
        exception_class=DecryptionIntegrityError,
    )
    assert len(error_report) == 1


def test_decrypt_payload_from_cryptainer_with_signature_troubles():
    verify_integrity_tags = random_bool()

    cryptainer_original = encrypt_payload_into_cryptainer(
        payload=b"1234abc", cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_metadata=None
    )

    result, error_report = decrypt_payload_from_cryptainer(
        cryptainer_original, verify_integrity_tags=verify_integrity_tags
    )
    assert result == b"1234abc"

    cryptainer_corrupted = copy.deepcopy(cryptainer_original)
    # pprint(cryptainer_corrupted)
    del cryptainer_corrupted["payload_cipher_layers"][0]["payload_signatures"][0]["payload_digest_value"]

    result, error_report = decrypt_payload_from_cryptainer(
        cryptainer_corrupted, verify_integrity_tags=verify_integrity_tags
    )
    assert result == b"1234abc"  # Missing the payload_digest_value is OK

    cryptainer_corrupted = copy.deepcopy(cryptainer_original)
    cryptainer_corrupted["payload_cipher_layers"][0]["payload_signatures"][0]["payload_digest_value"] = b"000"

    # RuntimeError, match="Mismatch"
    result, error_report = decrypt_payload_from_cryptainer(
        cryptainer_corrupted, verify_integrity_tags=verify_integrity_tags
    )
    assert result == b"1234abc"
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.SIGNATURE_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="Mismatch between actual and expected payload digests during signature verification",
    )
    assert len(error_report) == 1

    cryptainer_corrupted = copy.deepcopy(cryptainer_original)
    del cryptainer_corrupted["payload_cipher_layers"][0]["payload_signatures"][0]["payload_signature_struct"]

    # RuntimeError, match="Missing signature structure"
    result, error_report = decrypt_payload_from_cryptainer(
        cryptainer_corrupted, verify_integrity_tags=verify_integrity_tags
    )

    assert result == b"1234abc"
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.SIGNATURE_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="Missing signature structure",
    )
    assert len(error_report) == 1

    cryptainer_corrupted = copy.deepcopy(cryptainer_original)
    cryptainer_corrupted["payload_cipher_layers"][0]["payload_signatures"][0]["payload_signature_struct"] = {
        "signature_timestamp_utc": 1645905017,
        "signature_value": b"abcd",
    }
    payload_signature_algo = cryptainer_corrupted["payload_cipher_layers"][0]["payload_signatures"][0][
        "payload_signature_algo"
    ]

    # SignatureVerificationError, match="signature verification"
    result, error_report = decrypt_payload_from_cryptainer(
        cryptainer_corrupted, verify_integrity_tags=verify_integrity_tags
    )

    assert result == b"1234abc"
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.SIGNATURE_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="Failed signature verification",
        exception_class=SignatureVerificationError,
    )
    assert len(error_report) == 1


def test_passphrase_mapping_during_decryption(tmp_path):
    keychain_uid = generate_uuid0()

    keychain_uid_trustee = generate_uuid0()

    local_passphrase = "b^yep&ts"

    keystore_uid1 = keychain_uid_trustee  # FIXME why mix key and storage uids ?
    passphrase1 = "tata"

    keystore_uid2 = generate_uuid0()
    passphrase2 = "2çès"

    keystore_uid3 = generate_uuid0()
    passphrase3 = "zaizoadsxsnd123"

    all_passphrases = [local_passphrase, passphrase1, passphrase2, passphrase3]

    keystore_pool = InMemoryKeystorePool()
    keystore_pool._register_fake_imported_storage_uids(storage_uids=[keystore_uid1, keystore_uid2, keystore_uid3])

    local_keystore = keystore_pool.get_local_keyfactory()
    generate_keypair_for_storage(
        key_algo="RSA_OAEP", keystore=local_keystore, keychain_uid=keychain_uid, passphrase=local_passphrase
    )
    keystore1 = keystore_pool.get_foreign_keystore(keystore_uid1)
    generate_keypair_for_storage(
        key_algo="RSA_OAEP", keystore=keystore1, keychain_uid=keychain_uid_trustee, passphrase=passphrase1
    )
    keystore2 = keystore_pool.get_foreign_keystore(keystore_uid2)
    generate_keypair_for_storage(
        key_algo="RSA_OAEP", keystore=keystore2, keychain_uid=keychain_uid, passphrase=passphrase2
    )
    keystore3 = keystore_pool.get_foreign_keystore(keystore_uid3)
    generate_keypair_for_storage(
        key_algo="RSA_OAEP", keystore=keystore3, keychain_uid=keychain_uid, passphrase=passphrase3
    )

    local_keyfactory_trustee_id = get_trustee_id(LOCAL_KEYFACTORY_TRUSTEE_MARKER)

    shard_trustee1 = dict(trustee_type="authenticator", keystore_uid=keystore_uid1)
    shard_trustee1_id = get_trustee_id(shard_trustee1)

    shard_trustee2 = dict(trustee_type="authenticator", keystore_uid=keystore_uid2)
    shard_trustee2_id = get_trustee_id(shard_trustee2)

    shard_trustee3 = dict(trustee_type="authenticator", keystore_uid=keystore_uid3)
    shard_trustee3_id = get_trustee_id(shard_trustee3)

    cryptoconf = dict(
        payload_cipher_layers=[
            dict(
                payload_cipher_algo="AES_CBC",
                key_cipher_layers=[
                    dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER),
                    dict(
                        key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
                        key_shared_secret_threshold=2,
                        key_shared_secret_shards=[
                            dict(
                                key_cipher_layers=[
                                    dict(
                                        key_cipher_algo="RSA_OAEP",
                                        key_cipher_trustee=shard_trustee1,
                                        keychain_uid=keychain_uid_trustee,
                                    )
                                ]
                            ),
                            dict(
                                key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=shard_trustee2)]
                            ),
                            dict(
                                key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=shard_trustee3)]
                            ),
                        ],
                    ),
                ],
                payload_signatures=[
                    dict(
                        payload_digest_algo="SHA256",
                        payload_signature_algo="DSA_DSS",
                        payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                        # Uses separate keypair, no passphrase here
                    )
                ],
            )
        ]
    )

    payload = b"sjzgzj"

    cryptainer = encrypt_payload_into_cryptainer(
        payload=payload,
        cryptoconf=cryptoconf,
        keychain_uid=keychain_uid,
        keystore_pool=keystore_pool,
        cryptainer_metadata=None,
    )

    # FIXME we must TEST that keychain_uid_trustee is necessary for decryption, for example by deleting it before a decrypt()

    # DecryptionError, match="2 valid .* missing for reconstitution"
    decrypted, error_report = decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)
    assert decrypted is None

    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="Could not load private key",
        exception_class=KeyLoadingError,
        occurrence_count=3,
    )  # Missing passphrase for 3 Trustee
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="error prevented decrypting shard",
        occurrence_count=3,
    )

    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="2 valid shard(s) missing for reconstitution of symmetric key",
    )
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.ERROR,
        error_msg_match="Failed symmetric decryption",  # FAILED DECRYPTION
    )
    assert len(error_report) == 8

    # DecryptionError, match="2 valid .* missing for reconstitution"
    decrypted, error_report = decrypt_payload_from_cryptainer(
        cryptainer, keystore_pool=keystore_pool, passphrase_mapper={local_keyfactory_trustee_id: all_passphrases}
    )  # Doesn't help share trustees
    assert decrypted is None
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="2 valid shard(s) missing for reconstitution of symmetric key",
    )

    assert len(error_report) == 8

    # DecryptionError, match="1 valid .* missing for reconstitution"
    decrypted, error_report = decrypt_payload_from_cryptainer(
        cryptainer, keystore_pool=keystore_pool, passphrase_mapper={shard_trustee1_id: all_passphrases}
    )  # Unblocks 1 share trustee
    assert decrypted is None

    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="1 valid shard(s) missing for reconstitution of symmetric key",
    )
    assert len(error_report) == 6

    # DecryptionError, match="1 valid .* missing for reconstitution"
    decrypted, error_report = decrypt_payload_from_cryptainer(
        cryptainer,
        keystore_pool=keystore_pool,
        passphrase_mapper={shard_trustee1_id: all_passphrases, shard_trustee2_id: [passphrase3]},
    )  # No changes(fake trustee2 passphrase)
    assert decrypted is None
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="1 valid shard(s) missing for reconstitution of symmetric key",
    )
    assert len(error_report) == 6

    # DecryptionError, match="Could not decrypt private key"):
    decrypted, error_report = decrypt_payload_from_cryptainer(
        cryptainer,
        keystore_pool=keystore_pool,
        passphrase_mapper={shard_trustee1_id: all_passphrases, shard_trustee3_id: [passphrase3]},
    )
    assert decrypted is None
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="Could not load private key",
        exception_class=KeyLoadingError,
        occurrence_count=2,
    )  # Trustee 2 and Local keyfactory missing passphrases

    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="error prevented decrypting shard",
    )  # For Trustee 2

    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.ERROR,
        error_msg_match="Failed symmetric decryption",  # FAILED SYMMETRIC DECRYPTION
    )
    assert len(error_report) == 4

    # DecryptionError, match="Could not decrypt private key":
    decrypted, error_report = decrypt_payload_from_cryptainer(
        cryptainer,
        keystore_pool=keystore_pool,
        passphrase_mapper={
            local_keyfactory_trustee_id: ["qsdqsd"],
            shard_trustee1_id: all_passphrases,
            shard_trustee3_id: [passphrase3],
        },
    )
    assert decrypted is None
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="error prevented decrypting shard",
    )  # For Trustee 2
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="Could not load private key",
        exception_class=KeyLoadingError,
        occurrence_count=2,
    )  # For LocalKeyFactory and Trustee 2

    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.ERROR,
        error_msg_match="Failed symmetric decryption",  # FAILED SYMMETRIC DECRYPTION
    )
    assert len(error_report) == 4

    decrypted, error_report = decrypt_payload_from_cryptainer(
        cryptainer,
        keystore_pool=keystore_pool,
        passphrase_mapper={
            local_keyfactory_trustee_id: [local_passphrase],
            shard_trustee1_id: all_passphrases,
            shard_trustee3_id: [passphrase3],
        },
    )
    assert decrypted == payload
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="Could not load private key",
        exception_class=KeyLoadingError,
    )
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="error prevented decrypting shard",
    )  # For Trustee 2
    assert len(error_report) == 2

    # Passphrases of `None` key are always used
    decrypted, error_report = decrypt_payload_from_cryptainer(
        cryptainer,
        keystore_pool=keystore_pool,
        passphrase_mapper={
            local_keyfactory_trustee_id: [local_passphrase],
            shard_trustee1_id: ["dummy-passphrase"],
            shard_trustee3_id: [passphrase3],
            None: all_passphrases,
        },
    )
    assert decrypted == payload
    assert error_report == []

    # Proper forwarding of parameters in cryptainer storage class

    storage = CryptainerStorage(tmp_path, keystore_pool=keystore_pool)
    storage.enqueue_file_for_encryption(
        "beauty.txt", payload=payload, cryptainer_metadata=None, keychain_uid=keychain_uid, cryptoconf=cryptoconf
    )
    storage.wait_for_idle_state()

    StorageClass = _get_random_cryptainer_storage_class()  # Test READONLY mode too!
    storage = StorageClass(tmp_path, keystore_pool=keystore_pool)

    cryptainer_names = storage.list_cryptainer_names(as_sorted_list=True)
    print(">> cryptainer_names", cryptainer_names)

    # DecryptionError
    decrypted, error_report = storage.decrypt_cryptainer_from_storage("beauty.txt.crypt")
    assert decrypted is None
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.WARNING,
        error_msg_match="2 valid shard(s) missing for reconstitution of symmetric key",
    )
    assert len(error_report) == 8

    verify_integrity_tags = random_bool()
    decrypted, error_report = storage.decrypt_cryptainer_from_storage(
        "beauty.txt.crypt", passphrase_mapper={None: all_passphrases}, verify_integrity_tags=verify_integrity_tags
    )
    assert decrypted == payload
    assert error_report == []

    # Decryption Error with wrong payload
    cryptainer_paylod_path = tmp_path / "beauty.txt.crypt.payload"

    cryptainer_paylod_path.write_bytes(b"wrongpayload")
    decrypted, error_report = storage.decrypt_cryptainer_from_storage(
        "beauty.txt.crypt", passphrase_mapper={None: all_passphrases}
    )

    assert decrypted is None
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.ERROR,
        error_msg_match="Failed symmetric decryption",
        exception_class=DecryptionError,
    )
    assert len(error_report) == 3  # with SignatureError


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

    properties = storage.list_cryptainer_properties()
    assert properties == [dict(name=Path(cryptainer_name))]

    properties = storage.list_cryptainer_properties(with_size=True)
    (first_properties,) = properties
    assert isinstance(first_properties["size"], int) and first_properties["size"] > 0
    del first_properties["size"]
    assert properties == [dict(name=cryptainer_name)]

    properties = storage.list_cryptainer_properties(with_age=True)
    (first_properties,) = properties
    assert isinstance(first_properties["age"], timedelta)
    del first_properties["age"]
    assert first_properties == dict(name=cryptainer_name)

    properties = storage.list_cryptainer_properties(with_size=True, with_age=True)
    (first_properties,) = properties
    assert sorted(first_properties.keys()) == ["age", "name", "size"]


def test_cryptainer_storage_and_executor(tmp_path, caplog):
    side_tmp = tmp_path / "side_tmp"
    side_tmp.mkdir()

    cryptainer_dir = tmp_path / "cryptainers_dir"
    cryptainer_dir.mkdir()

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

    assert not animals_file_path.is_file()  # AUTO-DELETED after encryption!

    assert storage.get_cryptainer_count() == 2
    assert storage.list_cryptainer_names(as_sorted_list=True) == [Path("animals.dat.crypt"), Path("empty.txt.crypt")]
    assert storage._cryptainer_dir.joinpath(
        "animals.dat.crypt.payload"
    ).is_file()  # By default, DATA OFFLOADING is activated
    assert storage._cryptainer_dir.joinpath("empty.txt.crypt.payload").is_file()
    assert len(list(storage._cryptainer_dir.iterdir())) == 4  # 2 files per cryptainer

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
    assert len(list(storage._cryptainer_dir.iterdir())) == 5

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
    assert "Abnormal exception" not in caplog.text, caplog.text
    storage.enqueue_file_for_encryption("something.mpg", b"#########", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.get_cryptainer_count() == 3  # Unchanged
    assert "Abnormal exception" in caplog.text, caplog.text
    del storage._make_absolute
    assert storage._make_absolute  # Back to the method

    abs_entries = storage.list_cryptainer_names(as_absolute_paths=True)
    assert len(abs_entries) == 3  # Unchanged
    assert all(entry.is_absolute() for entry in abs_entries)

    animals_content, error_report = storage.decrypt_cryptainer_from_storage("animals.dat.crypt")
    assert animals_content == b"dogs\ncats\n"

    empty_content, error_report = storage.decrypt_cryptainer_from_storage("empty.txt.crypt")
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
        offload_payload_ciphertext=offload_payload_ciphertext1,
    )
    assert storage._max_cryptainer_count is None
    for i in range(10):
        storage.enqueue_file_for_encryption("file.dat", b"dogs\ncats\n", cryptainer_metadata=None)
    assert storage.get_cryptainer_count() < 11  # In progress
    storage.wait_for_idle_state()
    assert storage.get_cryptainer_count() == 11  # Still the older file remains


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
    assert storage.list_cryptainer_names(as_sorted_list=True) == [
        Path("xyz.dat.000.crypt"),
        Path("xyz.dat.001.crypt"),
        Path("xyz.dat.002.crypt"),
    ]

    storage.enqueue_file_for_encryption("xyz.dat", b"abc", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.get_cryptainer_count() == 3  # Purged
    assert storage.list_cryptainer_names(as_sorted_list=True) == [
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
    assert storage.list_cryptainer_names(as_sorted_list=True) == [
        Path("aaa.dat.000.crypt"),  # It's the file timestamps that counts, not the name!
        Path("xyz.dat.002.crypt"),
        Path("xyz.dat.003.crypt"),
        Path("zzz.dat.001.crypt"),
    ]

    storage.delete_cryptainer(Path("xyz.dat.002.crypt"))

    assert storage.list_cryptainer_names(as_sorted_list=True) == [
        Path("aaa.dat.000.crypt"),
        Path("xyz.dat.003.crypt"),
        Path("zzz.dat.001.crypt"),
    ]

    storage.enqueue_file_for_encryption("20201121_222727_whatever.dat", b"000", cryptainer_metadata=None)
    storage.wait_for_idle_state()

    assert storage.list_cryptainer_names(as_sorted_list=True) == [
        Path("20201121_222727_whatever.dat.002.crypt"),
        Path("aaa.dat.000.crypt"),
        Path("xyz.dat.003.crypt"),
        Path("zzz.dat.001.crypt"),
    ]

    storage.enqueue_file_for_encryption("21201121_222729_smth.dat", b"000", cryptainer_metadata=None)
    storage.enqueue_file_for_encryption("lmn.dat", b"000", cryptainer_metadata=None)
    storage.wait_for_idle_state()

    print(">>>>>>>", storage.list_cryptainer_names(as_sorted_list=True))
    assert storage.list_cryptainer_names(as_sorted_list=True) == [
        Path("21201121_222729_smth.dat.003.crypt"),
        Path("aaa.dat.000.crypt"),  # It's the file timestamps that counts, not the name!
        Path("lmn.dat.004.crypt"),
        Path("zzz.dat.001.crypt"),
    ]

    assert storage._max_cryptainer_count
    storage._max_cryptainer_count = 0

    storage.enqueue_file_for_encryption("abc.dat", b"000", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.list_cryptainer_names(as_sorted_list=True) == []  # ALL PURGED


def test_cryptainer_storage_purge_by_age(tmp_path):
    cryptainer_dir = tmp_path
    now = get_utc_now_date()

    (cryptainer_dir / "20201021_222700_oldfile.dat.crypt").touch()
    (cryptainer_dir / "20301021_222711_oldfile.dat.crypt").touch()

    offload_payload_ciphertext = random_bool()
    storage = FakeTestCryptainerStorage(
        default_cryptoconf={"stuffs": True},
        cryptainer_dir=cryptainer_dir,
        max_cryptainer_age=timedelta(days=2),
        offload_payload_ciphertext=offload_payload_ciphertext,
    )

    assert storage.list_cryptainer_names(as_sorted_list=True) == [
        Path("20201021_222700_oldfile.dat.crypt"),
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

    cryptainer_names = storage.list_cryptainer_names(as_sorted_list=True)

    assert Path("20201021_222700_oldfile.dat.crypt") not in cryptainer_names

    assert Path("20301021_222711_oldfile.dat.crypt") in cryptainer_names
    assert Path("whatever_stuff.dat.005.crypt") in cryptainer_names

    assert storage.get_cryptainer_count() == 4  # 2 listed just above + 2 recent "<date>_stuff.dat" from loop

    # Change mtime to VERY old!
    os.utime(storage._make_absolute(Path("whatever_stuff.dat.005.crypt")), (1000, 1000))

    storage.enqueue_file_for_encryption("abcde.dat", b"xxx", cryptainer_metadata=None)
    storage.wait_for_idle_state()

    cryptainer_names = storage.list_cryptainer_names(as_sorted_list=True)
    assert Path("whatever_stuff.dat.005.crypt") not in cryptainer_names
    assert Path("abcde.dat.006.crypt") in cryptainer_names

    assert storage.get_cryptainer_count() == 4

    assert storage._max_cryptainer_age
    storage._max_cryptainer_age = timedelta(days=-1)

    storage.enqueue_file_for_encryption("abc.dat", b"000", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.list_cryptainer_names(as_sorted_list=True) == [
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

    cryptainer_names = storage.list_cryptainer_names(as_sorted_list=True)

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

    assert storage._max_cryptainer_quota
    storage._max_cryptainer_quota = 0

    storage.enqueue_file_for_encryption("abc.dat", b"000", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.list_cryptainer_names(as_sorted_list=True) == []  # ALL PURGED


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

        cryptainer_names = storage.list_cryptainer_names(as_sorted_list=True)

        assert (Path("20001121_222729_smth.dat.000.crypt") in cryptainer_names) == (
            not (max_cryptainer_count or max_cryptainer_quota or max_cryptainer_age)
        )
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

    cryptainer_names = storage.list_cryptainer_names(as_sorted_list=True)
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

    result, error_report = storage.decrypt_cryptainer_from_storage(cryptainer_name, verify_integrity_tags=False)
    assert result == b"dogs\ncats\n"

    result, error_report = storage.decrypt_cryptainer_from_storage(cryptainer_name, verify_integrity_tags=True)

    assert result is None
    _check_error_entry(
        error_list=error_report,
        error_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
        error_criticity=DecryptionErrorCriticity.ERROR,
        error_msg_match="Failed decryption authentication",
        exception_class=DecryptionIntegrityError,
    )
    assert len(error_report) == 1


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
        Data encryption layer 1: AES_CBC
          Key encryption layers:
            RSA_OAEP via trustee 'local device'
          Signatures:
            SHA256/DSA_DSS via trustee 'local device'
            """
    )  # Ending by newline!

    cryptainer = encrypt_payload_into_cryptainer(
        payload=payload, cryptoconf=SIMPLE_CRYPTOCONF, keychain_uid=None, cryptainer_metadata=None
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
        Data encryption layer 1: AES_EAX
          Key encryption layers:
            RSA_OAEP via trustee 'server www.mydomain.com'
          Signatures: None
        Data encryption layer 2: AES_CBC
          Key encryption layers:
            RSA_OAEP via trustee 'authenticator 320b35bb-e735-4f6a-a4b2-ada124e30190'
          Signatures:
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
          Signatures:
            SHA3_256/RSA_PSS via trustee 'local device'
            SHA512/ECC_DSS via trustee 'local device'
            """
    )  # Ending with newline!

    _public_key = generate_keypair(key_algo="RSA_OAEP", serialize=True)["public_key"]
    # We mockup the call to remote trustees
    with patch.object(
        CryptainerEncryptor, "_fetch_asymmetric_key_pem_from_trustee", return_value=_public_key, create=True
    ) as mock_method:
        cryptainer = encrypt_payload_into_cryptainer(
            payload=payload, cryptoconf=CONF_WITH_TRUSTEE, keychain_uid=None, cryptainer_metadata=None
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

    metadata = random.choice([None, dict(a=[123])])

    cryptainer = encrypt_payload_into_cryptainer(
        payload=payload, cryptoconf=cryptoconf, keychain_uid=keychain_uid, cryptainer_metadata=metadata
    )
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
    cryptainer_decryptor = CryptainerEncryptor()
    cryptainer, extracts = cryptainer_decryptor._generate_cryptainer_base_and_secrets(COMPLEX_CRYPTOCONF)

    for payload_cipher_layer in extracts:
        symkey = payload_cipher_layer["symkey"]
        assert isinstance(symkey, dict)
        assert symkey["key"]  # actual main key
        del payload_cipher_layer["symkey"]

    assert extracts == [
        {"cipher_algo": "AES_EAX", "payload_digest_algos": []},
        {"cipher_algo": "AES_CBC", "payload_digest_algos": ["SHA3_512"]},
        {"cipher_algo": "CHACHA20_POLY1305", "payload_digest_algos": ["SHA3_256", "SHA512"]},
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

    plaintext, error_report = storage.decrypt_cryptainer_from_storage("20200101_cryptainer_example.crypt")
    assert plaintext == b"bonjoureveryone"


@pytest.mark.parametrize(
    "cryptoconf", [SIMPLE_CRYPTOCONF, COMPLEX_CRYPTOCONF, SIMPLE_SHAMIR_CRYPTOCONF, COMPLEX_SHAMIR_CRYPTOCONF]
)
def test_conf_validation_success(cryptoconf):
    check_cryptoconf_sanity(cryptoconf=cryptoconf, jsonschema_mode=False)

    conf_json = convert_native_tree_to_extended_json_tree(cryptoconf)
    check_cryptoconf_sanity(cryptoconf=conf_json, jsonschema_mode=True)


def _generate_corrupted_confs(cryptoconf):
    corrupted_confs = []

    # Add a false information to config
    corrupted_conf1 = copy.deepcopy(cryptoconf)
    corrupted_conf1["payload_cipher_layers"][0]["keychain_uid"] = ENFORCED_UID2
    corrupted_confs.append(corrupted_conf1)

    # Delete a "key_cipher_layers" in an element of cryptoconf
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

    return corrupted_confs


@pytest.mark.parametrize("corrupted_conf", _generate_corrupted_confs(COMPLEX_SHAMIR_CRYPTOCONF))
def test_conf_validation_error(corrupted_conf):
    with pytest.raises(ValidationError):
        check_cryptoconf_sanity(cryptoconf=corrupted_conf, jsonschema_mode=False)

    with pytest.raises(ValidationError):
        corrupted_conf_json = convert_native_tree_to_extended_json_tree(corrupted_conf)
        check_cryptoconf_sanity(cryptoconf=corrupted_conf_json, jsonschema_mode=True)


@pytest.mark.parametrize(
    "cryptoconf", [SIMPLE_CRYPTOCONF, COMPLEX_CRYPTOCONF, SIMPLE_SHAMIR_CRYPTOCONF, COMPLEX_SHAMIR_CRYPTOCONF]
)
def test_cryptainer_validation_success(cryptoconf):
    cryptainer = encrypt_payload_into_cryptainer(
        payload=b"stuffs", cryptoconf=cryptoconf, keychain_uid=None, cryptainer_metadata=None
    )
    check_cryptainer_sanity(cryptainer=cryptainer, jsonschema_mode=False)

    cryptainer_json = convert_native_tree_to_extended_json_tree(cryptainer)
    check_cryptainer_sanity(cryptainer=cryptainer_json, jsonschema_mode=True)


def _generate_corrupted_cryptainers(cryptoconf):
    cryptainer = encrypt_payload_into_cryptainer(
        payload=b"stuffs", cryptoconf=cryptoconf, keychain_uid=None, cryptainer_metadata=None
    )
    corrupted_cryptainers = []

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


def test_cryptainer_validation_error():
    corrupted_cryptainers = _generate_corrupted_cryptainers(SIMPLE_CRYPTOCONF)

    for corrupted_cryptainer in corrupted_cryptainers:
        with pytest.raises(ValidationError):
            check_cryptainer_sanity(cryptainer=corrupted_cryptainer, jsonschema_mode=True)

        with pytest.raises(ValidationError):
            corrupted_cryptainer_json = convert_native_tree_to_extended_json_tree(corrupted_cryptainer)
            check_cryptainer_sanity(cryptainer=corrupted_cryptainer_json, jsonschema_mode=False)
