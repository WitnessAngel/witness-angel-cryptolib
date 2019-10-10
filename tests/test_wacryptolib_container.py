import os
import random
import time
import uuid
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta

import pytest
from freezegun import freeze_time

from wacryptolib.container import (
    LOCAL_ESCROW_PLACEHOLDER,
    encrypt_data_into_container,
    decrypt_data_from_container,
    TarfileAggregator,
    JsonAggregator,
    _get_proxy_for_escrow, ContainerStorage)
from wacryptolib.escrow import EscrowApi
from wacryptolib.jsonrpc_client import JsonRpcProxy
from wacryptolib.utilities import load_from_json_bytes


class FakeTestContainerStorage(ContainerStorage):
    """Fake class which bypasses encryption and forces filename unicity regardless fo datetime, to speed up tests..."""
    increment = 0
    def enqueue_file_for_encryption(self, filename_base, data):
        super().enqueue_file_for_encryption(filename_base + (".%03d" % self.increment), data)
        self.increment += 1
    def _encrypt_data_into_container(self, data):
        return data
    def _decrypt_data_from_container(self, container):
        return container


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
    assert isinstance(proxy, JsonRpcProxy)  # It should expose identical methods to EscrowApi

    with pytest.raises(ValueError):
        _get_proxy_for_escrow(dict(urn="athena"))

    with pytest.raises(ValueError):
        _get_proxy_for_escrow("weird-value")


def test_container_storage(tmp_path):

    # Beware, here we use the REAL ContainerStorage, not FakeTestContainerStorage!
    storage = ContainerStorage(encryption_conf=SIMPLE_CONTAINER_CONF, output_dir=tmp_path)
    assert storage._max_containers_count is None
    assert len(storage) == 0
    assert storage.list_container_names() == []

    storage.enqueue_file_for_encryption("animals.dat", b"dogs\ncats\n")
    storage.enqueue_file_for_encryption("empty.txt", b"")

    assert len(storage) == 2
    assert storage.list_container_names(as_sorted_relative_paths=True) == ['animals.dat.crypt', 'empty.txt.crypt']

    animals_content = storage.decrypt_container_from_storage('animals.dat.crypt')
    assert animals_content == b"dogs\ncats\n"

    empty_content = storage.decrypt_container_from_storage('empty.txt.crypt')
    assert empty_content == b""

    assert len(storage) == 2
    os.remove(os.path.join(tmp_path, 'animals.dat.crypt'))
    assert storage.list_container_names(as_sorted_relative_paths=True) == ['empty.txt.crypt']
    assert len(storage) == 1

    # Test purge system

    storage = FakeTestContainerStorage(encryption_conf=None, output_dir=tmp_path)
    assert storage._max_containers_count is None
    for i in range(10):
        storage.enqueue_file_for_encryption("file.dat", b"dogs\ncats\n")
    assert len(storage) == 11  # Still the older file remains

    storage = FakeTestContainerStorage(encryption_conf=None, output_dir=tmp_path, max_containers_count=3)
    for i in range(3):
        storage.enqueue_file_for_encryption("xyz.dat", b"abc")
    assert len(storage) == 3  # Purged
    assert storage.list_container_names(as_sorted_relative_paths=True) == ['xyz.dat.000.crypt', 'xyz.dat.001.crypt', 'xyz.dat.002.crypt']

    storage.enqueue_file_for_encryption("xyz.dat", b"abc")
    assert len(storage) == 3  # Purged
    assert storage.list_container_names(as_sorted_relative_paths=True) == ['xyz.dat.001.crypt', 'xyz.dat.002.crypt', 'xyz.dat.003.crypt']

    storage = FakeTestContainerStorage(encryption_conf=None, output_dir=tmp_path, max_containers_count=4)
    assert len(storage) == 3  # Retrieves existing containers
    storage.enqueue_file_for_encryption("aaa.dat", b"000")
    assert len(storage) == 4  # Unchanged
    storage.enqueue_file_for_encryption("zzz.dat", b"000")
    assert len(storage) == 4  # Purge occurred
    # Entry "aaa.dat.000.crypt" was ejected because it's a sorting by NAMES for now!
    assert storage.list_container_names(as_sorted_relative_paths=True) == ['xyz.dat.001.crypt', 'xyz.dat.002.crypt', 'xyz.dat.003.crypt', "zzz.dat.001.crypt"]


def test_tarfile_aggregator(tmp_path):

    container_storage = FakeTestContainerStorage(encryption_conf=None, output_dir=tmp_path)

    tarfile_aggregator = TarfileAggregator(container_storage=container_storage, max_duration_s=10)
    assert len(tarfile_aggregator) == 0
    assert not tarfile_aggregator._current_start_time
    assert len(container_storage) == 0

    with freeze_time() as frozen_datetime:

        tarfile_aggregator.finalize_tarfile()
        assert len(tarfile_aggregator) == 0
        assert not tarfile_aggregator._current_start_time
        assert len(container_storage) == 0

        data1 = "hêllö".encode("utf8")
        tarfile_aggregator.add_record(
            sensor_name="smartphone_front_camera",
            from_datetime=datetime(
                year=2014,
                month=1,
                day=2,
                hour=22,
                minute=11,
                second=55,
                tzinfo=timezone.utc,
            ),
            to_datetime=datetime(year=2015, month=2, day=3, tzinfo=timezone.utc),
            extension=".txt",
            data=data1,
        )
        assert len(tarfile_aggregator) == 1
        assert tarfile_aggregator._current_start_time

        data2 = b"123xyz"
        tarfile_aggregator.add_record(
            sensor_name="smartphone_recorder",
            from_datetime=datetime(year=2017, month=10, day=11, tzinfo=timezone.utc),
            to_datetime=datetime(year=2017, month=12, day=1, tzinfo=timezone.utc),
            extension=".mp3",
            data=data2,
        )
        assert len(tarfile_aggregator) == 2

        frozen_datetime.tick(delta=timedelta(seconds=1))

        tarfile_aggregator.finalize_tarfile()
        assert len(container_storage) == 1
        tarfile_bytestring = container_storage.decrypt_container_from_storage(container_name_or_idx=-1)
        tar_file = TarfileAggregator.read_tarfile_from_bytestring(tarfile_bytestring)
        assert len(tarfile_aggregator) == 0
        assert not tarfile_aggregator._current_start_time

        filenames = sorted(tar_file.getnames())
        assert filenames == [
            "20140102221155_20150203000000_smartphone_front_camera.txt",
            "20171011000000_20171201000000_smartphone_recorder.mp3",
        ]
        assert tar_file.extractfile(filenames[0]).read() == data1
        assert tar_file.extractfile(filenames[1]).read() == data2

        for i in range(2):
            frozen_datetime.tick(delta=timedelta(seconds=1))
            tarfile_aggregator.finalize_tarfile()
            assert len(tarfile_aggregator) == 0
            assert not tarfile_aggregator._current_start_time
            assert len(container_storage) == 1  # Unchanged

        data3 = b""
        tarfile_aggregator.add_record(
            sensor_name="abc",
            from_datetime=datetime(year=2017, month=10, day=11, tzinfo=timezone.utc),
            to_datetime=datetime(year=2017, month=12, day=1, tzinfo=timezone.utc),
            extension=".avi",
            data=data3,
        )
        assert len(tarfile_aggregator) == 1
        assert tarfile_aggregator._current_start_time

        frozen_datetime.tick(delta=timedelta(seconds=1))
        tarfile_aggregator.finalize_tarfile()
        assert len(container_storage) == 2
        tarfile_bytestring = container_storage.decrypt_container_from_storage(container_name_or_idx=-1)
        tar_file = TarfileAggregator.read_tarfile_from_bytestring(tarfile_bytestring)
        assert len(tarfile_aggregator) == 0
        assert not tarfile_aggregator._current_start_time

        filenames = sorted(tar_file.getnames())
        assert filenames == ["20171011000000_20171201000000_abc.avi"]
        assert tar_file.extractfile(filenames[0]).read() == b""

        for i in range(2):
            frozen_datetime.tick(delta=timedelta(seconds=1))
            tarfile_aggregator.finalize_tarfile()
            assert len(tarfile_aggregator) == 0
            assert not tarfile_aggregator._current_start_time
            assert len(container_storage) == 2  # Unchanged

        # We test time-limited aggregation
        simple_add_record = lambda: tarfile_aggregator.add_record(
            sensor_name="somedata",
            from_datetime=datetime(year=2017, month=10, day=11, tzinfo=timezone.utc),
            to_datetime=datetime(year=2017, month=12, day=1, tzinfo=timezone.utc),
            extension=".dat",
            data=b"hiiii",
        )
        simple_add_record()
        assert len(tarfile_aggregator) == 1
        assert tarfile_aggregator._current_start_time
        current_start_time_saved = tarfile_aggregator._current_start_time

        frozen_datetime.tick(delta=timedelta(seconds=9))
        assert datetime.now(tz=timezone.utc) - tarfile_aggregator._current_start_time == timedelta(seconds=9)

        simple_add_record()
        assert len(tarfile_aggregator) == 2
        assert tarfile_aggregator._current_start_time == current_start_time_saved

        frozen_datetime.tick(delta=timedelta(seconds=2))

        simple_add_record()
        assert len(tarfile_aggregator) == 1
        assert tarfile_aggregator._current_start_time
        assert tarfile_aggregator._current_start_time != current_start_time_saved  # AUTO FLUSH occurred

        assert len(container_storage) == 3

        tarfile_aggregator.finalize_tarfile()  # CLEANUP

        assert len(container_storage) == 4

        # We tests conflicts between identifical tar record names
        for i in range(3):  # Three times the same file name!
            tarfile_aggregator.add_record(
                sensor_name="smartphone_recorder",
                from_datetime=datetime(year=2017, month=10, day=11, tzinfo=timezone.utc),
                to_datetime=datetime(year=2017, month=12, day=1, tzinfo=timezone.utc),
                extension=".mp3",
                data=bytes([i] * 500))

        frozen_datetime.tick(delta=timedelta(seconds=1))
        tarfile_aggregator.finalize_tarfile()
        assert len(container_storage) == 5
        tarfile_bytestring = container_storage.decrypt_container_from_storage(container_name_or_idx=-1)
        tar_file = TarfileAggregator.read_tarfile_from_bytestring(tarfile_bytestring)
        assert len(tar_file.getmembers()) == 3
        assert len(tar_file.getnames()) == 3
        # The LAST record has priority over others with the same name
        assert tar_file.extractfile(tar_file.getnames()[0]).read() == bytes([2] * 500)


def test_json_aggregator(tmp_path):

    container_storage = FakeTestContainerStorage(encryption_conf=None, output_dir=tmp_path)

    tarfile_aggregator = TarfileAggregator(container_storage=container_storage, max_duration_s=100)

    assert len(tarfile_aggregator) == 0

    json_aggregator = JsonAggregator(
        max_duration_s=2,
        tarfile_aggregator=tarfile_aggregator,
        sensor_name="some_sensors",
    )
    assert len(json_aggregator) == 0

    json_aggregator.flush_dataset()  # Does nothing
    assert len(tarfile_aggregator) == 0
    assert len(json_aggregator) == 0
    assert not json_aggregator._current_start_time

    with freeze_time() as frozen_datetime:

        json_aggregator.add_data(dict(pulse=42))
        json_aggregator.add_data(dict(timing=True))

        assert len(tarfile_aggregator) == 0
        assert len(json_aggregator) == 2
        assert json_aggregator._current_start_time

        frozen_datetime.tick(delta=timedelta(seconds=1))

        json_aggregator.add_data(dict(abc=2.2))

        assert len(tarfile_aggregator) == 0
        assert len(json_aggregator) == 3

        frozen_datetime.tick(delta=timedelta(seconds=1))

        json_aggregator.add_data(dict(x="abc"))

        assert len(tarfile_aggregator) == 1  # Single json file
        assert len(json_aggregator) == 1
        assert json_aggregator._current_start_time

        json_aggregator.flush_dataset()
        assert not json_aggregator._current_start_time

        assert len(tarfile_aggregator) == 2  # 2 json files
        assert len(json_aggregator) == 0

        frozen_datetime.tick(delta=timedelta(seconds=10))

        json_aggregator.flush_dataset()

        # Unchanged
        assert len(tarfile_aggregator) == 2
        assert len(json_aggregator) == 0

        tarfile_aggregator.finalize_tarfile()
        assert len(container_storage) == 1
        tarfile_bytestring = container_storage.decrypt_container_from_storage(container_name_or_idx=-1)
        tar_file = TarfileAggregator.read_tarfile_from_bytestring(tarfile_bytestring)
        assert len(tarfile_aggregator) == 0

        filenames = sorted(tar_file.getnames())
        assert len(filenames) == 2

        for filename in filenames:
            assert "some_sensors" in filename
            assert filename.endswith(".json")

        data = tar_file.extractfile(filenames[0]).read()
        assert (
            data == b'[{"pulse": {"$numberInt": "42"}}, {"timing": true}, {"abc": {"$numberDouble": "2.2"}}]'
        )

        data = tar_file.extractfile(filenames[1]).read()
        assert data == b'[{"x": "abc"}]'

        tarfile_aggregator.finalize_tarfile()
        assert len(container_storage) == 1  # Unchanged
        assert not json_aggregator._current_start_time


def test_aggregators_thread_safety(tmp_path):

    container_storage = FakeTestContainerStorage(encryption_conf=None, output_dir=tmp_path)

    tarfile_aggregator = TarfileAggregator(container_storage=container_storage, max_duration_s=100)
    json_aggregator = JsonAggregator(
        max_duration_s=1,
        tarfile_aggregator=tarfile_aggregator,
        sensor_name="some_sensors",
    )

    misc_futures = []

    record_data = "hêllo".encode("utf8")

    with ThreadPoolExecutor(max_workers=30) as executor:
        for burst in range(10):
            for idx in range(100):
                misc_futures.append(
                    executor.submit(json_aggregator.add_data, dict(res=idx))
                )
                misc_futures.append(executor.submit(json_aggregator.flush_dataset))
                misc_futures.append(
                    executor.submit(
                        tarfile_aggregator.add_record,
                        sensor_name="some_recorder_%s_%s" % (burst, idx),
                        from_datetime=datetime(
                            year=2017, month=10, day=11, tzinfo=timezone.utc
                        ),
                        to_datetime=datetime(
                            year=2017, month=12, day=1, tzinfo=timezone.utc
                        ),
                        extension=".txt",
                        data=record_data,
                    )
                )
                misc_futures.append(
                    executor.submit(tarfile_aggregator.finalize_tarfile)
                )
            time.sleep(0.2)

    json_aggregator.flush_dataset()
    tarfile_aggregator.finalize_tarfile()

    misc_results = set(future.result() for future in misc_futures)
    assert misc_results == set([None])  # No results expected from any of these methods

    container_names = container_storage.list_container_names(as_sorted_relative_paths=True)

    tarfiles_bytes = [container_storage.decrypt_container_from_storage(container_name)
                      for container_name in container_names]

    tarfiles = [
        TarfileAggregator.read_tarfile_from_bytestring(bytestring)
        for bytestring in tarfiles_bytes
        if bytestring
    ]

    tarfiles_count = len(tarfiles)
    print("Tarfiles count:", tarfiles_count)

    total_idx = 0
    txt_count = 0

    for tarfile in tarfiles:
        print("NEW TARFILE")
        members = tarfile.getmembers()
        for member in members:
            print(">>>>", member.name)
            ext = os.path.splitext(member.name)[1]
            record_bytes = tarfile.extractfile(member).read()
            if ext == ".json":
                data_array = load_from_json_bytes(record_bytes)
                total_idx += sum(data["res"] for data in data_array)
            elif ext == ".txt":
                assert record_bytes == record_data
                txt_count += 1
            else:
                raise RuntimeError(ext)

    assert txt_count == 1000
    assert total_idx == 1000 * 99 / 2 == 49500  # Sum of idx sequences
