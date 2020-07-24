import copy
import os
import random
import textwrap
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from _test_mockups import FakeTestContainerStorage
from wacryptolib.container import (
    LOCAL_ESCROW_PLACEHOLDER,
    encrypt_data_into_container,
    decrypt_data_from_container,
    ContainerStorage,
    extract_metadata_from_container,
    ContainerBase,
    get_encryption_configuration_summary,
)
from wacryptolib.escrow import EscrowApi
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.key_generation import generate_asymmetric_keypair
from wacryptolib.key_storage import DummyKeyStorage, FilesystemKeyStorage
from wacryptolib.utilities import load_from_json_bytes

SIMPLE_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[
                dict(
                    key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_PLACEHOLDER
                )
            ],
            data_signatures=[
                dict(
                    message_prehash_algo="SHA256",
                    signature_algo="DSA_DSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
        )
    ]
)

COMPLEX_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_EAX",
            key_encryption_strata=[
                dict(
                    key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_PLACEHOLDER
                )
            ],
            data_signatures=[],
        ),
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[
                dict(
                    key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_PLACEHOLDER
                )
            ],
            data_signatures=[
                dict(
                    message_prehash_algo="SHA3_512",
                    signature_algo="DSA_DSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
        ),
        dict(
            data_encryption_algo="CHACHA20_POLY1305",
            key_encryption_strata=[
                dict(
                    key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_PLACEHOLDER
                ),
                dict(
                    key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_PLACEHOLDER
                ),
            ],
            data_signatures=[
                dict(
                    message_prehash_algo="SHA3_256",
                    signature_algo="RSA_PSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                ),
                dict(
                    message_prehash_algo="SHA512",
                    signature_algo="ECC_DSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                ),
            ],
        ),
    ]
)

SHAMIR_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[
                dict(
                    key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_PLACEHOLDER
                ),
                dict(
                    key_encryption_algo="SHARED_SECRET",
                    key_shared_secret_threshold=3,
                    key_shared_secret_escrow=[
                        dict(
                            shared_encryption_algo="RSA_OAEP",
                            # shared_escrow=dict(url="http://example.com/jsonrpc"),
                            shared_escrow=LOCAL_ESCROW_PLACEHOLDER,
                        ),
                        dict(
                            shared_encryption_algo="RSA_OAEP",
                            # shared_escrow=dict(url="http://example.com/jsonrpc"),
                            shared_escrow=LOCAL_ESCROW_PLACEHOLDER,
                        ),
                        dict(
                            shared_encryption_algo="RSA_OAEP",
                            # shared_escrow=dict(url="http://example.com/jsonrpc"),
                            shared_escrow=LOCAL_ESCROW_PLACEHOLDER,
                        ),
                        dict(
                            shared_encryption_algo="RSA_OAEP",
                            # shared_escrow=dict(url="http://example.com/jsonrpc"),
                            shared_escrow=LOCAL_ESCROW_PLACEHOLDER,
                        ),
                        dict(
                            shared_encryption_algo="RSA_OAEP",
                            # shared_escrow=dict(url="http://example.com/jsonrpc"),
                            shared_escrow=LOCAL_ESCROW_PLACEHOLDER,
                        ),
                    ],
                ),
            ],
            data_signatures=[
                dict(
                    message_prehash_algo="SHA256",
                    signature_algo="DSA_DSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
        )
    ]
)

OTHER_SHAMIR_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_EAX",
            key_encryption_strata=[
                dict(
                    key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_PLACEHOLDER
                )
            ],
            data_signatures=[],
        ),
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[
                dict(
                    key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_PLACEHOLDER
                )
            ],
            data_signatures=[
                dict(
                    message_prehash_algo="SHA3_512",
                    signature_algo="DSA_DSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
        ),
        dict(
            data_encryption_algo="CHACHA20_POLY1305",
            key_encryption_strata=[
                dict(
                    key_encryption_algo="SHARED_SECRET",
                    key_shared_secret_threshold=2,
                    key_shared_secret_escrow=[
                        dict(
                            shared_encryption_algo="RSA_OAEP",
                            # shared_escrow=dict(url="http://example.com/jsonrpc"),
                            shared_escrow=LOCAL_ESCROW_PLACEHOLDER,
                        ),
                        dict(
                            shared_encryption_algo="RSA_OAEP",
                            # shared_escrow=dict(url="http://example.com/jsonrpc"),
                            shared_escrow=LOCAL_ESCROW_PLACEHOLDER,
                        ),
                        dict(
                            shared_encryption_algo="RSA_OAEP",
                            # shared_escrow=dict(url="http://example.com/jsonrpc"),
                            shared_escrow=LOCAL_ESCROW_PLACEHOLDER,
                        ),
                        dict(
                            shared_encryption_algo="RSA_OAEP",
                            # shared_escrow=dict(url="http://example.com/jsonrpc"),
                            shared_escrow=LOCAL_ESCROW_PLACEHOLDER,
                        )
                    ]
                ),
                dict(
                    key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_PLACEHOLDER
                ),
            ],
            data_signatures=[
                dict(
                    message_prehash_algo="SHA3_256",
                    signature_algo="RSA_PSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                ),
                dict(
                    message_prehash_algo="SHA512",
                    signature_algo="ECC_DSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                ),
            ],
        ),
    ]
)


@pytest.mark.parametrize(
    "container_conf",
    [SIMPLE_CONTAINER_CONF, COMPLEX_CONTAINER_CONF, SHAMIR_CONTAINER_CONF, OTHER_SHAMIR_CONTAINER_CONF],
)
def test_container_encryption_and_decryption(container_conf):
    data = b"abc"  # get_random_bytes(random.randint(1, 1000))

    keychain_uid = random.choice(
        [None, uuid.UUID("450fc293-b702-42d3-ae65-e9cc58e5a62a")]
    )

    metadata = random.choice([None, dict(a=[123])])

    container = encrypt_data_into_container(
        data=data, conf=container_conf, keychain_uid=keychain_uid, metadata=metadata
    )
    # pprint.pprint(container, width=120)

    assert container["keychain_uid"]
    if keychain_uid:
        assert container["keychain_uid"] == keychain_uid

    result_data = decrypt_data_from_container(container=container)
    # pprint.pprint(result, width=120)
    assert result_data == data

    result_metadata = extract_metadata_from_container(container=container)
    assert result_metadata == metadata

    container["container_format"] = "OAJKB"
    with pytest.raises(ValueError, match="Unknown container format"):
        decrypt_data_from_container(container=container)


def test_get_proxy_for_escrow(tmp_path):
    container_base1 = ContainerBase()
    proxy1 = container_base1._get_proxy_for_escrow(LOCAL_ESCROW_PLACEHOLDER)
    assert isinstance(proxy1, EscrowApi)  # Local Escrow
    assert isinstance(proxy1._key_storage, DummyKeyStorage)  # Default type

    container_base1_bis = ContainerBase()
    proxy1_bis = container_base1_bis._get_proxy_for_escrow(LOCAL_ESCROW_PLACEHOLDER)
    assert (
        proxy1_bis._key_storage is proxy1_bis._key_storage
    )  # process-local storage is SINGLETON!

    container_base2 = ContainerBase(
        local_key_storage=FilesystemKeyStorage(keys_dir=str(tmp_path))
    )
    proxy2 = container_base2._get_proxy_for_escrow(LOCAL_ESCROW_PLACEHOLDER)
    assert isinstance(proxy2, EscrowApi)  # Local Escrow
    assert isinstance(proxy2._key_storage, FilesystemKeyStorage)

    for container_base in (container_base1, container_base2):
        proxy = container_base._get_proxy_for_escrow(
            dict(url="http://example.com/jsonrpc")
        )
        assert isinstance(
            proxy, JsonRpcProxy
        )  # It should expose identical methods to EscrowApi

        assert proxy._url == "http://example.com/jsonrpc"
        assert proxy._response_error_handler == status_slugs_response_error_handler

        with pytest.raises(ValueError):
            container_base._get_proxy_for_escrow(dict(urn="athena"))

        with pytest.raises(ValueError):
            container_base._get_proxy_for_escrow("weird-value")


def test_container_storage_and_executor(tmp_path, caplog):
    # Beware, here we use the REAL ContainerStorage, not FakeTestContainerStorage!
    storage = ContainerStorage(
        encryption_conf=SIMPLE_CONTAINER_CONF, containers_dir=tmp_path
    )
    assert storage._max_containers_count is None
    assert len(storage) == 0
    assert storage.list_container_names() == []

    storage.enqueue_file_for_encryption("animals.dat", b"dogs\ncats\n", metadata=None)
    storage.enqueue_file_for_encryption("empty.txt", b"", metadata=dict(somevalue=True))
    assert len(storage) == 0  # Container threads are just beginning to work!

    storage.wait_for_idle_state()

    assert len(storage) == 2
    assert storage.list_container_names(as_sorted=True) == [
        Path("animals.dat.crypt"),
        Path("empty.txt.crypt"),
    ]

    # Test proper logging of errors occurring in thread pool executor
    assert storage._make_absolute  # Instance method
    storage._make_absolute = None  # Corruption!
    assert "Caught exception" not in caplog.text, caplog.text
    storage.enqueue_file_for_encryption("something.mpg", b"#########", metadata=None)
    storage.wait_for_idle_state()
    assert len(storage) == 2  # Unchanged
    assert "Caught exception" in caplog.text, caplog.text
    del storage._make_absolute
    assert storage._make_absolute  # Back to the method

    abs_entries = storage.list_container_names(as_absolute=True)
    assert len(abs_entries) == 2  # Unchanged
    assert all(entry.is_absolute() for entry in abs_entries)

    animals_content = storage.decrypt_container_from_storage("animals.dat.crypt")
    assert animals_content == b"dogs\ncats\n"

    empty_content = storage.decrypt_container_from_storage("empty.txt.crypt")
    assert empty_content == b""

    assert len(storage) == 2
    os.remove(os.path.join(tmp_path, "animals.dat.crypt"))
    assert storage.list_container_names(as_sorted=True) == [Path("empty.txt.crypt")]
    assert len(storage) == 1

    # Test purge system

    storage = FakeTestContainerStorage(encryption_conf=None, containers_dir=tmp_path)
    assert storage._max_containers_count is None
    for i in range(10):
        storage.enqueue_file_for_encryption("file.dat", b"dogs\ncats\n", metadata=None)
    assert len(storage) < 11  # In progress
    storage.wait_for_idle_state()
    assert len(storage) == 11  # Still the older file remains

    storage = FakeTestContainerStorage(
        encryption_conf=None, containers_dir=tmp_path, max_containers_count=3
    )
    for i in range(3):
        storage.enqueue_file_for_encryption("xyz.dat", b"abc", metadata=None)
    storage.wait_for_idle_state()
    assert len(storage) == 3  # Purged
    assert storage.list_container_names(as_sorted=True) == [
        Path("xyz.dat.000.crypt"),
        Path("xyz.dat.001.crypt"),
        Path("xyz.dat.002.crypt"),
    ]

    storage.enqueue_file_for_encryption("xyz.dat", b"abc", metadata=None)
    storage.wait_for_idle_state()
    assert len(storage) == 3  # Purged
    assert storage.list_container_names(as_sorted=True) == [
        Path("xyz.dat.001.crypt"),
        Path("xyz.dat.002.crypt"),
        Path("xyz.dat.003.crypt"),
    ]

    storage = FakeTestContainerStorage(
        encryption_conf=None, containers_dir=tmp_path, max_containers_count=4
    )
    assert len(storage) == 3  # Retrieves existing containers
    storage.enqueue_file_for_encryption("aaa.dat", b"000", metadata=None)
    storage.wait_for_idle_state()
    assert len(storage) == 4  # Unchanged
    storage.enqueue_file_for_encryption("zzz.dat", b"000", metadata=None)
    storage.wait_for_idle_state()
    assert len(storage) == 4  # Purge occurred
    # Entry "aaa.dat.000.crypt" was ejected because it's a sorting by NAMES for now!
    assert storage.list_container_names(as_sorted=True) == [
        Path("xyz.dat.001.crypt"),
        Path("xyz.dat.002.crypt"),
        Path("xyz.dat.003.crypt"),
        Path("zzz.dat.001.crypt"),
    ]


def test_get_encryption_configuration_summary():
    data = b"some data whatever"

    summary = get_encryption_configuration_summary(SIMPLE_CONTAINER_CONF)

    assert summary == textwrap.dedent(
        """\
        Data encryption layer 1: AES_CBC
          Key encryption layers:
            RSA_OAEP (by local device)
          Signatures:
            SHA256/DSA_DSS (by local device)
            """
    )  # Ending by newline!

    container = encrypt_data_into_container(
        data=data, conf=SIMPLE_CONTAINER_CONF, keychain_uid=None, metadata=None
    )
    summary2 = get_encryption_configuration_summary(container)
    assert summary2 == summary  # Identical summary for conf and generated containers!

    # Simulate a conf with remote escrow webservices

    CONF_WITH_ESCROW = copy.deepcopy(COMPLEX_CONTAINER_CONF)
    CONF_WITH_ESCROW["data_encryption_strata"][0]["key_encryption_strata"][0][
        "key_escrow"
    ] = dict(url="http://www.mydomain.com/json")

    summary = get_encryption_configuration_summary(CONF_WITH_ESCROW)
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

    _public_key = generate_asymmetric_keypair(key_type="RSA_OAEP")["public_key"]
    with patch.object(
        JsonRpcProxy, "get_public_key", return_value=_public_key, create=True
    ) as mock_method:
        container = encrypt_data_into_container(
            data=data, conf=CONF_WITH_ESCROW, keychain_uid=None, metadata=None
        )
        summary2 = get_encryption_configuration_summary(container)
        assert (
            summary2 == summary
        )  # Identical summary for conf and generated containers!

    # Test unknown escrow structure

    CONF_WITH_BROKEN_ESCROW = copy.deepcopy(SIMPLE_CONTAINER_CONF)
    CONF_WITH_BROKEN_ESCROW["data_encryption_strata"][0]["key_encryption_strata"][0][
        "key_escrow"
    ] = dict(abc=33)

    with pytest.raises(ValueError, match="Unrecognized key escrow"):
        get_encryption_configuration_summary(CONF_WITH_BROKEN_ESCROW)
