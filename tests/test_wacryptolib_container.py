import os
import random
import uuid
from pathlib import Path

import pytest

from _test_mockups import FakeTestContainerStorage
from wacryptolib.container import (
    LOCAL_ESCROW_PLACEHOLDER,
    encrypt_data_into_container,
    decrypt_data_from_container,
    ContainerStorage,
    extract_metadata_from_container,
    ContainerBase,
)
from wacryptolib.escrow import EscrowApi
from wacryptolib.jsonrpc_client import JsonRpcProxy
from wacryptolib.key_storage import DummyKeyStorage, FilesystemKeyStorage

SIMPLE_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[
                dict(
                    escrow_key_type="RSA",
                    key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
            data_signatures=[
                dict(
                    signature_key_type="DSA",
                    signature_algo="DSS",
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
                    escrow_key_type="RSA",
                    key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
            data_signatures=[],
        ),
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[
                dict(
                    escrow_key_type="RSA",
                    key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
            data_signatures=[
                dict(
                    signature_key_type="DSA",
                    signature_algo="DSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
        ),
        dict(
            data_encryption_algo="CHACHA20_POLY1305",
            key_encryption_strata=[
                dict(
                    escrow_key_type="RSA",
                    key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                ),
                dict(
                    escrow_key_type="RSA",
                    key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                ),
            ],
            data_signatures=[
                dict(
                    signature_key_type="RSA",
                    signature_algo="PSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                ),
                dict(
                    signature_key_type="ECC",
                    signature_algo="DSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                ),
            ],
        ),
    ]
)


@pytest.mark.parametrize(
    "container_conf", [SIMPLE_CONTAINER_CONF, COMPLEX_CONTAINER_CONF]
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

        with pytest.raises(ValueError):
            container_base._get_proxy_for_escrow(dict(urn="athena"))

        with pytest.raises(ValueError):
            container_base._get_proxy_for_escrow("weird-value")


def test_container_storage(tmp_path):

    # Beware, here we use the REAL ContainerStorage, not FakeTestContainerStorage!
    storage = ContainerStorage(
        encryption_conf=SIMPLE_CONTAINER_CONF, containers_dir=tmp_path
    )
    assert storage._max_containers_count is None
    assert len(storage) == 0
    assert storage.list_container_names() == []

    storage.enqueue_file_for_encryption("animals.dat", b"dogs\ncats\n", metadata=None)
    storage.enqueue_file_for_encryption("empty.txt", b"", metadata=dict(somevalue=True))

    assert len(storage) == 2
    assert storage.list_container_names(as_sorted=True) == [
        Path("animals.dat.crypt"),
        Path("empty.txt.crypt"),
    ]

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
    assert len(storage) == 11  # Still the older file remains

    storage = FakeTestContainerStorage(
        encryption_conf=None, containers_dir=tmp_path, max_containers_count=3
    )
    for i in range(3):
        storage.enqueue_file_for_encryption("xyz.dat", b"abc", metadata=None)
    assert len(storage) == 3  # Purged
    assert storage.list_container_names(as_sorted=True) == [
        Path("xyz.dat.000.crypt"),
        Path("xyz.dat.001.crypt"),
        Path("xyz.dat.002.crypt"),
    ]

    storage.enqueue_file_for_encryption("xyz.dat", b"abc", metadata=None)
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
    assert len(storage) == 4  # Unchanged
    storage.enqueue_file_for_encryption("zzz.dat", b"000", metadata=None)
    assert len(storage) == 4  # Purge occurred
    # Entry "aaa.dat.000.crypt" was ejected because it's a sorting by NAMES for now!
    assert storage.list_container_names(as_sorted=True) == [
        Path("xyz.dat.001.crypt"),
        Path("xyz.dat.002.crypt"),
        Path("xyz.dat.003.crypt"),
        Path("zzz.dat.001.crypt"),
    ]
