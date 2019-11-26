import os
import random
import time
import uuid
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta

import pytest
from freezegun import freeze_time

from _test_mockups import FakeTestContainerStorage
from wacryptolib.container import (
    LOCAL_ESCROW_PLACEHOLDER,
    encrypt_data_into_container,
    decrypt_data_from_container,
    _get_proxy_for_escrow,
    ContainerStorage,
)
from wacryptolib.escrow import EscrowApi
from wacryptolib.jsonrpc_client import JsonRpcProxy
from wacryptolib.sensor import TarfileAggregator, JsonAggregator, PeriodicValuePoller
from wacryptolib.utilities import load_from_json_bytes

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

    container = encrypt_data_into_container(
        data=data, conf=container_conf, keychain_uid=keychain_uid
    )
    # pprint.pprint(container, width=120)

    assert container["keychain_uid"]
    if keychain_uid:
        assert container["keychain_uid"] == keychain_uid

    result = decrypt_data_from_container(container=container)
    # pprint.pprint(result, width=120)

    assert result == data

    container["container_format"] = "OAJKB"
    with pytest.raises(ValueError, match="Unknown container format"):
        decrypt_data_from_container(container=container)


def test_get_proxy_for_escrow():

    proxy = _get_proxy_for_escrow(LOCAL_ESCROW_PLACEHOLDER)
    assert isinstance(proxy, EscrowApi)  # Local proxy

    proxy = _get_proxy_for_escrow(dict(url="http://example.com/jsonrpc"))
    assert isinstance(
        proxy, JsonRpcProxy
    )  # It should expose identical methods to EscrowApi

    with pytest.raises(ValueError):
        _get_proxy_for_escrow(dict(urn="athena"))

    with pytest.raises(ValueError):
        _get_proxy_for_escrow("weird-value")


def test_container_storage(tmp_path):

    # Beware, here we use the REAL ContainerStorage, not FakeTestContainerStorage!
    storage = ContainerStorage(
        encryption_conf=SIMPLE_CONTAINER_CONF, output_dir=tmp_path
    )
    assert storage._max_containers_count is None
    assert len(storage) == 0
    assert storage.list_container_names() == []

    storage.enqueue_file_for_encryption("animals.dat", b"dogs\ncats\n")
    storage.enqueue_file_for_encryption("empty.txt", b"")

    assert len(storage) == 2
    assert storage.list_container_names(as_sorted_relative_paths=True) == [
        "animals.dat.crypt",
        "empty.txt.crypt",
    ]

    animals_content = storage.decrypt_container_from_storage("animals.dat.crypt")
    assert animals_content == b"dogs\ncats\n"

    empty_content = storage.decrypt_container_from_storage("empty.txt.crypt")
    assert empty_content == b""

    assert len(storage) == 2
    os.remove(os.path.join(tmp_path, "animals.dat.crypt"))
    assert storage.list_container_names(as_sorted_relative_paths=True) == [
        "empty.txt.crypt"
    ]
    assert len(storage) == 1

    # Test purge system

    storage = FakeTestContainerStorage(encryption_conf=None, output_dir=tmp_path)
    assert storage._max_containers_count is None
    for i in range(10):
        storage.enqueue_file_for_encryption("file.dat", b"dogs\ncats\n")
    assert len(storage) == 11  # Still the older file remains

    storage = FakeTestContainerStorage(
        encryption_conf=None, output_dir=tmp_path, max_containers_count=3
    )
    for i in range(3):
        storage.enqueue_file_for_encryption("xyz.dat", b"abc")
    assert len(storage) == 3  # Purged
    assert storage.list_container_names(as_sorted_relative_paths=True) == [
        "xyz.dat.000.crypt",
        "xyz.dat.001.crypt",
        "xyz.dat.002.crypt",
    ]

    storage.enqueue_file_for_encryption("xyz.dat", b"abc")
    assert len(storage) == 3  # Purged
    assert storage.list_container_names(as_sorted_relative_paths=True) == [
        "xyz.dat.001.crypt",
        "xyz.dat.002.crypt",
        "xyz.dat.003.crypt",
    ]

    storage = FakeTestContainerStorage(
        encryption_conf=None, output_dir=tmp_path, max_containers_count=4
    )
    assert len(storage) == 3  # Retrieves existing containers
    storage.enqueue_file_for_encryption("aaa.dat", b"000")
    assert len(storage) == 4  # Unchanged
    storage.enqueue_file_for_encryption("zzz.dat", b"000")
    assert len(storage) == 4  # Purge occurred
    # Entry "aaa.dat.000.crypt" was ejected because it's a sorting by NAMES for now!
    assert storage.list_container_names(as_sorted_relative_paths=True) == [
        "xyz.dat.001.crypt",
        "xyz.dat.002.crypt",
        "xyz.dat.003.crypt",
        "zzz.dat.001.crypt",
    ]
