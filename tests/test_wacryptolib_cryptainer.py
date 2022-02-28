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
from unittest.mock import patch
from uuid import UUID

import pytest
from Crypto.Random import get_random_bytes

from _test_mockups import FakeTestCryptainerStorage, random_bool
from wacryptolib.cipher import SUPPORTED_CIPHER_ALGOS, AUTHENTICATED_CIPHER_ALGOS
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
    _get_trustee_id,
    gather_trustee_dependencies,
    get_trustee_proxy,
    request_decryption_authorizations,
    delete_cryptainer_from_filesystem,
    CRYPTAINER_DATETIME_FORMAT,
    get_cryptainer_size_on_filesystem,
    CryptainerEncryptor,
    encrypt_payload_and_stream_cryptainer_to_filesystem,
    is_cryptainer_cryptoconf_streamable,
    check_conf_sanity,
    check_cryptainer_sanity,
    CRYPTAINER_TEMP_SUFFIX,
    OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER,
    ReadonlyCryptainerStorage,
    CryptainerEncryptionPipeline,
)
from wacryptolib.exceptions import (
    DecryptionError,
    DecryptionIntegrityError,
    ValidationError,
    SchemaValidationError,
    SignatureVerificationError,
)
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.keygen import generate_keypair
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
        "[('trustee_type', 'local_keyfactory')]": (
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

SIMPLE_CRYPTAINER_TRUSTEE_DEPENDENCIES = lambda keychain_uid: {
    "encryption": {
        "[('trustee_type', 'local_keyfactory')]": (
            {"trustee_type": "local_keyfactory"},
            [{"key_algo": "RSA_OAEP", "keychain_uid": keychain_uid}],
        )
    },
    "signature": {
        "[('trustee_type', 'local_keyfactory')]": (
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
                )
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
        "[('trustee_type', 'local_keyfactory')]": (
            {"trustee_type": "local_keyfactory"},
            [
                {"key_algo": "RSA_OAEP", "keychain_uid": keychain_uid},
                {"key_algo": "RSA_OAEP", "keychain_uid": ENFORCED_UID1},
            ],
        )
    },
    "signature": {
        "[('trustee_type', 'local_keyfactory')]": (
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
            "[('trustee_type', 'local_keyfactory')]": (
                {"trustee_type": "local_keyfactory"},
                [
                    {"key_algo": "RSA_OAEP", "keychain_uid": keychain_uid},
                    {"key_algo": "RSA_OAEP", "keychain_uid": ENFORCED_UID1},
                ],
            )
        },
        "signature": {
            "[('trustee_type', 'local_keyfactory')]": (
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
            "[('trustee_type', 'local_keyfactory')]": (
                {"trustee_type": "local_keyfactory"},
                [
                    {"key_algo": "RSA_OAEP", "keychain_uid": keychain_uid},
                    {"key_algo": "RSA_OAEP", "keychain_uid": ENFORCED_UID2},
                ],
            )
        },
        "signature": {
            "[('trustee_type', 'local_keyfactory')]": (
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
    result_payload = decrypt_payload_from_cryptainer(
        cryptainer=cryptainer, keystore_pool=keystore_pool, verify_integrity_tags=verify_integrity_tags
    )
    # pprint.pprint(result, width=120)
    assert result_payload == payload

    result_metadata = extract_metadata_from_cryptainer(cryptainer=cryptainer)
    assert result_metadata == metadata

    cryptainer["cryptainer_format"] = "OAJKB"
    with pytest.raises(ValueError, match="Unknown cryptainer format"):
        decrypt_payload_from_cryptainer(cryptainer=cryptainer)


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

    result_payload = decrypt_payload_from_cryptainer(cryptainer=cryptainer)

    assert result_payload == payload

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
    result_payload = decrypt_payload_from_cryptainer(cryptainer=cryptainer, verify_integrity_tags=verify_integrity_tags)
    assert result_payload == payload

    # Another share is deleted

    del key_ciphertext_shards["shard_ciphertexts"][-1]

    payload_encryption_shamir["key_ciphertext"] = dump_to_json_bytes(key_ciphertext_shards)

    result_payload = decrypt_payload_from_cryptainer(cryptainer=cryptainer)
    assert result_payload == payload

    # Another share is deleted and now there aren't enough valid ones to decipher data

    del key_ciphertext_shards["shard_ciphertexts"][-1]

    payload_encryption_shamir["key_ciphertext"] = dump_to_json_bytes(key_ciphertext_shards)

    with pytest.raises(DecryptionError, match="shard.*missing"):
        decrypt_payload_from_cryptainer(cryptainer=cryptainer)

    result_metadata = extract_metadata_from_cryptainer(cryptainer=cryptainer)
    assert result_metadata == metadata

    cryptainer["cryptainer_format"] = "OAJKB"
    with pytest.raises(ValueError, match="Unknown cryptainer format"):
        decrypt_payload_from_cryptainer(cryptainer=cryptainer)


def test_decrypt_payload_from_cryptainer_with_authenticated_algo_and_verify():
    payload_cipher_algo = random.choice(AUTHENTICATED_CIPHER_ALGOS)
    cryptoconf = copy.deepcopy(SIMPLE_CRYPTOCONF)
    cryptoconf["payload_cipher_layers"][0]["payload_cipher_algo"] = payload_cipher_algo

    cryptainer = encrypt_payload_into_cryptainer(payload=b"1234", cryptoconf=cryptoconf, cryptainer_metadata=None)

    result = decrypt_payload_from_cryptainer(cryptainer, verify_integrity_tags=True)
    assert result == b"1234"

    cryptainer["payload_cipher_layers"][0]["payload_macs"]["tag"] += b"hi"  # CORRUPTION

    result = decrypt_payload_from_cryptainer(cryptainer, verify_integrity_tags=False)
    assert result == b"1234"

    with pytest.raises(DecryptionIntegrityError):
        decrypt_payload_from_cryptainer(cryptainer, verify_integrity_tags=True)


def test_decrypt_payload_from_cryptainer_signature_troubles():

    verify_integrity_tags = random_bool()

    cryptainer_original = encrypt_payload_into_cryptainer(
        payload=b"1234abc", cryptoconf=SIMPLE_CRYPTOCONF, cryptainer_metadata=None
    )

    result = decrypt_payload_from_cryptainer(cryptainer_original, verify_integrity_tags=verify_integrity_tags)
    assert result == b"1234abc"

    cryptainer_corrupted = copy.deepcopy(cryptainer_original)
    # pprint(cryptainer_corrupted)
    del cryptainer_corrupted["payload_cipher_layers"][0]["payload_signatures"][0]["payload_digest_value"]

    result = decrypt_payload_from_cryptainer(cryptainer_corrupted, verify_integrity_tags=verify_integrity_tags)
    assert result == b"1234abc"  # Missing the payload_digest_value is OK

    cryptainer_corrupted = copy.deepcopy(cryptainer_original)
    # pprint(cryptainer_corrupted)
    cryptainer_corrupted["payload_cipher_layers"][0]["payload_signatures"][0]["payload_digest_value"] = b"000"

    with pytest.raises(RuntimeError, match="Mismatch"):
        decrypt_payload_from_cryptainer(cryptainer_corrupted, verify_integrity_tags=verify_integrity_tags)

    cryptainer_corrupted = copy.deepcopy(cryptainer_original)
    del cryptainer_corrupted["payload_cipher_layers"][0]["payload_signatures"][0]["payload_signature_struct"]

    with pytest.raises(RuntimeError, match="Missing signature structure"):
        decrypt_payload_from_cryptainer(cryptainer_corrupted, verify_integrity_tags=verify_integrity_tags)

    cryptainer_corrupted = copy.deepcopy(cryptainer_original)
    cryptainer_corrupted["payload_cipher_layers"][0]["payload_signatures"][0]["payload_signature_struct"] = {
        "signature_timestamp_utc": 1645905017,
        "signature_value": b"abc",
    }

    with pytest.raises(SignatureVerificationError, match="signature verification"):
        decrypt_payload_from_cryptainer(cryptainer_corrupted, verify_integrity_tags=verify_integrity_tags)


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

    local_keyfactory_trustee_id = _get_trustee_id(LOCAL_KEYFACTORY_TRUSTEE_MARKER)

    shard_trustee1 = dict(trustee_type="authenticator", keystore_uid=keystore_uid1)
    shard_trustee1_id = _get_trustee_id(shard_trustee1)

    shard_trustee2 = dict(trustee_type="authenticator", keystore_uid=keystore_uid2)
    shard_trustee2_id = _get_trustee_id(shard_trustee2)

    shard_trustee3 = dict(trustee_type="authenticator", keystore_uid=keystore_uid3)
    shard_trustee3_id = _get_trustee_id(shard_trustee3)

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
                        payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,  # Uses separate keypair, no passphrase here
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

    with pytest.raises(DecryptionError, match="2 valid .* missing for reconstitution"):
        decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)

    with pytest.raises(DecryptionError, match="2 valid .* missing for reconstitution"):
        decrypt_payload_from_cryptainer(
            cryptainer, keystore_pool=keystore_pool, passphrase_mapper={local_keyfactory_trustee_id: all_passphrases}
        )  # Doesn't help share trustees

    with pytest.raises(DecryptionError, match="1 valid .* missing for reconstitution"):
        decrypt_payload_from_cryptainer(
            cryptainer, keystore_pool=keystore_pool, passphrase_mapper={shard_trustee1_id: all_passphrases}
        )  # Unblocks 1 share trustee

    with pytest.raises(DecryptionError, match="1 valid .* missing for reconstitution"):
        decrypt_payload_from_cryptainer(
            cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper={shard_trustee1_id: all_passphrases, shard_trustee2_id: [passphrase3]},
        )  # No changes

    with pytest.raises(DecryptionError, match="Could not decrypt private key"):
        decrypt_payload_from_cryptainer(
            cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper={shard_trustee1_id: all_passphrases, shard_trustee3_id: [passphrase3]},
        )

    with pytest.raises(DecryptionError, match="Could not decrypt private key"):
        decrypt_payload_from_cryptainer(
            cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper={
                local_keyfactory_trustee_id: ["qsdqsd"],
                shard_trustee1_id: all_passphrases,
                shard_trustee3_id: [passphrase3],
            },
        )

    decrypted = decrypt_payload_from_cryptainer(
        cryptainer,
        keystore_pool=keystore_pool,
        passphrase_mapper={
            local_keyfactory_trustee_id: [local_passphrase],
            shard_trustee1_id: all_passphrases,
            shard_trustee3_id: [passphrase3],
        },
    )
    assert decrypted == payload

    # Passphrases of `None` key are always used
    decrypted = decrypt_payload_from_cryptainer(
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

    with pytest.raises(DecryptionError):
        storage.decrypt_cryptainer_from_storage("beauty.txt.crypt")

    verify_integrity_tags = random_bool()
    decrypted = storage.decrypt_cryptainer_from_storage(
        "beauty.txt.crypt", passphrase_mapper={None: all_passphrases}, verify_integrity_tags=verify_integrity_tags
    )
    assert decrypted == payload


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
            dict(trustee_type="jsonrpc_api", url="http://example.com/jsonrpc"), cryptainer_base._keystore_pool
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
    assert "Caught exception" not in caplog.text, caplog.text
    storage.enqueue_file_for_encryption("something.mpg", b"#########", cryptainer_metadata=None)
    storage.wait_for_idle_state()
    assert storage.get_cryptainer_count() == 3  # Unchanged
    assert "Caught exception" in caplog.text, caplog.text
    del storage._make_absolute
    assert storage._make_absolute  # Back to the method

    abs_entries = storage.list_cryptainer_names(as_absolute_paths=True)
    assert len(abs_entries) == 3  # Unchanged
    assert all(entry.is_absolute() for entry in abs_entries)

    animals_content = storage.decrypt_cryptainer_from_storage("animals.dat.crypt")
    assert animals_content == b"dogs\ncats\n"

    empty_content = storage.decrypt_cryptainer_from_storage("empty.txt.crypt")
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

    print(cryptainer_names)

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


def test_cryptainer_storage_decryption_authenticated_algo_verify(tmp_path):

    # Beware, here we use the REAL CryptainerStorage, not FakeTestCryptainerStorage!
    storage, cryptainer_name = _intialize_real_cryptainer_with_single_file(tmp_path, allow_readonly_storage=True)

    def corrupt_eax_tag(cryptainer):
        cryptainer["payload_cipher_layers"][0]["payload_macs"]["tag"] += b"hi"  # CORRUPTION of EAX

    _corrupt_cryptainer_tree(storage, cryptainer_name=cryptainer_name, corruptor_callback=corrupt_eax_tag)

    result = storage.decrypt_cryptainer_from_storage(cryptainer_name, verify_integrity_tags=False)
    assert result == b"dogs\ncats\n"

    with pytest.raises(DecryptionIntegrityError):
        storage.decrypt_cryptainer_from_storage(cryptainer_name, verify_integrity_tags=True)


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
            RSA_OAEP (by local device)
          Signatures:
            SHA256/DSA_DSS (by local device)
            """
    )  # Ending by newline!

    cryptainer = encrypt_payload_into_cryptainer(
        payload=payload, cryptoconf=SIMPLE_CRYPTOCONF, keychain_uid=None, cryptainer_metadata=None
    )
    summary2 = get_cryptoconf_summary(cryptainer)
    assert summary2 == summary  # Identical summary for cryptoconf and generated cryptainers!

    # Simulate a cryptoconf with remote trustee webservices

    CONF_WITH_TRUSTEE = copy.deepcopy(COMPLEX_CRYPTOCONF)
    CONF_WITH_TRUSTEE["payload_cipher_layers"][0]["key_cipher_layers"][0]["key_cipher_trustee"] = dict(
        trustee_type="jsonrpc_api", url="http://www.mydomain.com/json"
    )

    summary = get_cryptoconf_summary(CONF_WITH_TRUSTEE)
    assert summary == textwrap.dedent(
        """\
        Data encryption layer 1: AES_EAX
          Key encryption layers:
            RSA_OAEP (by www.mydomain.com)
          Signatures:
        Data encryption layer 2: AES_CBC
          Key encryption layers:
            RSA_OAEP (by local device)
          Signatures:
            SHA3_512/DSA_DSS (by local device)
        Data encryption layer 3: CHACHA20_POLY1305
          Key encryption layers:
            RSA_OAEP (by local device)
            RSA_OAEP (by local device)
          Signatures:
            SHA3_256/RSA_PSS (by local device)
            SHA512/ECC_DSS (by local device)
            """
    )  # Ending by newline!

    _public_key = generate_keypair(key_algo="RSA_OAEP")["public_key"]
    with patch.object(JsonRpcProxy, "fetch_public_key", return_value=_public_key, create=True) as mock_method:
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

    plaintext = storage.decrypt_cryptainer_from_storage("20200101_cryptainer_example.crypt")
    assert plaintext == b"bonjoureveryone"


@pytest.mark.parametrize(
    "cryptoconf", [SIMPLE_CRYPTOCONF, COMPLEX_CRYPTOCONF, SIMPLE_SHAMIR_CRYPTOCONF, COMPLEX_SHAMIR_CRYPTOCONF]
)
def test_conf_validation_success(cryptoconf):
    check_conf_sanity(cryptoconf=cryptoconf, jsonschema_mode=False)

    conf_json = convert_native_tree_to_extended_json_tree(cryptoconf)
    check_conf_sanity(cryptoconf=conf_json, jsonschema_mode=True)


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
        check_conf_sanity(cryptoconf=corrupted_conf, jsonschema_mode=False)

    with pytest.raises(ValidationError):
        corrupted_conf_json = convert_native_tree_to_extended_json_tree(corrupted_conf)
        check_conf_sanity(cryptoconf=corrupted_conf_json, jsonschema_mode=True)


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


@pytest.mark.parametrize("corrupted_cryptainer", _generate_corrupted_cryptainers(SIMPLE_CRYPTOCONF))
def test_cryptainer_validation_error(corrupted_cryptainer):

    with pytest.raises(ValidationError):
        check_cryptainer_sanity(cryptainer=corrupted_cryptainer, jsonschema_mode=True)

    with pytest.raises(ValidationError):
        corrupted_cryptainer_json = convert_native_tree_to_extended_json_tree(corrupted_cryptainer)
        check_cryptainer_sanity(cryptainer=corrupted_cryptainer_json, jsonschema_mode=False)
