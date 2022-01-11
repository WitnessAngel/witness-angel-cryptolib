import os
import time
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime, timezone
from datetime import timedelta

from freezegun import freeze_time

from _test_mockups import FakeTestCryptainerStorage, random_bool
from wacryptolib.scaffolding import check_sensor_state_machine
from wacryptolib.sensor import TarfileRecordAggregator, JsonDataAggregator, PeriodicValuePoller, SensorManager
from wacryptolib.sensor import TimeLimitedAggregatorMixin
from wacryptolib.utilities import load_from_json_bytes, TaskRunnerStateMachineBase, get_utc_now_date


def test_time_limited_aggregator_mixin():

    for max_duration_s in (0.5, 20, 1000000):

        delta_seconds = max_duration_s / 3

        with freeze_time() as frozen_datetime:

            obj = TimeLimitedAggregatorMixin(max_duration_s=max_duration_s)
            assert obj._current_start_time is None

            obj._notify_aggregation_operation()
            assert obj._current_start_time

            start_time_copy = obj._current_start_time

            frozen_datetime.tick(delta=timedelta(seconds=delta_seconds))
            obj._notify_aggregation_operation()
            assert obj._current_start_time == start_time_copy

            frozen_datetime.tick(delta=timedelta(seconds=delta_seconds))
            obj._notify_aggregation_operation()
            assert obj._current_start_time == start_time_copy

            frozen_datetime.tick(delta=timedelta(seconds=1.3 * delta_seconds))
            obj._notify_aggregation_operation()
            assert obj._current_start_time > start_time_copy  # Renewed

            obj._flush_aggregated_data()
            assert obj._current_start_time is None


def test_tarfile_aggregator(tmp_path):

    offload_payload_ciphertext = random_bool()
    cryptainer_storage = FakeTestCryptainerStorage(
        default_cryptoconf={"whatever": True},
        cryptainer_dir=tmp_path,
        offload_payload_ciphertext=offload_payload_ciphertext,
    )

    tarfile_aggregator = TarfileRecordAggregator(cryptainer_storage=cryptainer_storage, max_duration_s=10)
    assert tarfile_aggregator.get_record_count() == 0
    assert not tarfile_aggregator._current_start_time
    assert cryptainer_storage.get_cryptainer_count() == 0

    with freeze_time() as frozen_datetime:

        tarfile_aggregator.finalize_tarfile()
        cryptainer_storage.wait_for_idle_state()
        assert tarfile_aggregator.get_record_count() == 0
        assert not tarfile_aggregator._current_start_time
        assert cryptainer_storage.get_cryptainer_count() == 0

        data1 = "hêllö".encode("utf8")
        tarfile_aggregator.add_record(
            sensor_name="smartphone_front_camera",
            from_datetime=datetime(year=2014, month=1, day=2, hour=22, minute=11, second=55, tzinfo=timezone.utc),
            to_datetime=datetime(year=2015, month=2, day=3, tzinfo=timezone.utc),
            extension=".txt",
            payload=data1,
        )
        assert tarfile_aggregator.get_record_count() == 1
        assert tarfile_aggregator._current_start_time

        data2 = b"123xyz"
        tarfile_aggregator.add_record(
            sensor_name="smartphone_recorder",
            from_datetime=datetime(year=2017, month=10, day=11, tzinfo=timezone.utc),
            to_datetime=datetime(year=2017, month=12, day=1, tzinfo=timezone.utc),
            extension=".mp3",
            payload=data2,
        )
        assert tarfile_aggregator.get_record_count() == 2

        frozen_datetime.tick(delta=timedelta(seconds=1))

        tarfile_aggregator.finalize_tarfile()
        cryptainer_storage.wait_for_idle_state()
        assert cryptainer_storage.get_cryptainer_count() == 1
        tarfile_bytestring = cryptainer_storage.decrypt_cryptainer_from_storage(cryptainer_name_or_idx=-1)
        tar_file = TarfileRecordAggregator.read_tarfile_from_bytestring(tarfile_bytestring)
        assert tarfile_aggregator.get_record_count() == 0
        assert not tarfile_aggregator._current_start_time

        filenames = sorted(tar_file.getnames())
        assert filenames == [
            "20140102_221155_to_20150203_000000_smartphone_front_camera.txt",
            "20171011_000000_to_20171201_000000_smartphone_recorder.mp3",
        ]
        assert tar_file.extractfile(filenames[0]).read() == data1
        assert tar_file.extractfile(filenames[1]).read() == data2

        for i in range(2):
            frozen_datetime.tick(delta=timedelta(seconds=1))
            tarfile_aggregator.finalize_tarfile()
            cryptainer_storage.wait_for_idle_state()
            assert tarfile_aggregator.get_record_count() == 0
            assert not tarfile_aggregator._current_start_time
            assert cryptainer_storage.get_cryptainer_count() == 1  # Unchanged

        data3 = b""
        tarfile_aggregator.add_record(
            sensor_name="abc",
            from_datetime=datetime(year=2017, month=10, day=11, tzinfo=timezone.utc),
            to_datetime=datetime(year=2017, month=12, day=1, tzinfo=timezone.utc),
            extension=".avi",
            payload=data3,
        )
        assert tarfile_aggregator.get_record_count() == 1
        assert tarfile_aggregator._current_start_time

        frozen_datetime.tick(delta=timedelta(seconds=1))
        tarfile_aggregator.finalize_tarfile()
        cryptainer_storage.wait_for_idle_state()
        assert cryptainer_storage.get_cryptainer_count() == 2
        tarfile_bytestring = cryptainer_storage.decrypt_cryptainer_from_storage(cryptainer_name_or_idx=-1)
        tar_file = TarfileRecordAggregator.read_tarfile_from_bytestring(tarfile_bytestring)
        assert tarfile_aggregator.get_record_count() == 0
        assert not tarfile_aggregator._current_start_time

        filenames = sorted(tar_file.getnames())
        assert filenames == ["20171011_000000_to_20171201_000000_abc.avi"]
        assert tar_file.extractfile(filenames[0]).read() == b""

        for i in range(2):
            frozen_datetime.tick(delta=timedelta(seconds=1))
            tarfile_aggregator.finalize_tarfile()
            cryptainer_storage.wait_for_idle_state()
            assert tarfile_aggregator.get_record_count() == 0
            assert not tarfile_aggregator._current_start_time
            assert cryptainer_storage.get_cryptainer_count() == 2  # Unchanged

        # We test time-limited aggregation
        simple_add_record = lambda: tarfile_aggregator.add_record(
            sensor_name="somedata",
            from_datetime=datetime(year=2017, month=10, day=11, tzinfo=timezone.utc),
            to_datetime=datetime(year=2017, month=12, day=1, tzinfo=timezone.utc),
            extension=".dat",
            payload=b"hiiii",
        )
        simple_add_record()
        assert tarfile_aggregator.get_record_count() == 1
        assert tarfile_aggregator._current_start_time
        current_start_time_saved = tarfile_aggregator._current_start_time

        frozen_datetime.tick(delta=timedelta(seconds=9))
        assert get_utc_now_date() - tarfile_aggregator._current_start_time == timedelta(seconds=9)

        simple_add_record()
        assert tarfile_aggregator.get_record_count() == 2
        assert tarfile_aggregator._current_start_time == current_start_time_saved

        frozen_datetime.tick(delta=timedelta(seconds=2))

        simple_add_record()
        assert tarfile_aggregator.get_record_count() == 1
        assert tarfile_aggregator._current_start_time
        assert tarfile_aggregator._current_start_time != current_start_time_saved  # AUTO FLUSH occurred
        cryptainer_storage.wait_for_idle_state()

        assert cryptainer_storage.get_cryptainer_count() == 3

        tarfile_aggregator.finalize_tarfile()  # CLEANUP
        cryptainer_storage.wait_for_idle_state()

        assert cryptainer_storage.get_cryptainer_count() == 4

        # We tests conflicts between identifical tar record names
        for i in range(3):  # Three times the same file name!
            tarfile_aggregator.add_record(
                sensor_name="smartphone_recorder",
                from_datetime=datetime(year=2017, month=10, day=11, tzinfo=timezone.utc),
                to_datetime=datetime(year=2017, month=12, day=1, tzinfo=timezone.utc),
                extension=".mp3",
                payload=bytes([i] * 500),
            )

        frozen_datetime.tick(delta=timedelta(seconds=1))
        tarfile_aggregator.finalize_tarfile()
        cryptainer_storage.wait_for_idle_state()
        assert cryptainer_storage.get_cryptainer_count() == 5
        tarfile_bytestring = cryptainer_storage.decrypt_cryptainer_from_storage(cryptainer_name_or_idx=-1)
        tar_file = TarfileRecordAggregator.read_tarfile_from_bytestring(tarfile_bytestring)
        assert len(tar_file.getmembers()) == 3
        assert len(tar_file.getnames()) == 3
        # The LAST record has priority over others with the same name
        assert tar_file.extractfile(tar_file.getnames()[0]).read() == bytes([2] * 500)


def test_json_aggregator(tmp_path):

    offload_payload_ciphertext = random_bool()
    cryptainer_storage = FakeTestCryptainerStorage(
        default_cryptoconf={"qsdqsdsd": True},
        cryptainer_dir=tmp_path,
        offload_payload_ciphertext=offload_payload_ciphertext,
    )

    tarfile_aggregator = TarfileRecordAggregator(cryptainer_storage=cryptainer_storage, max_duration_s=100)

    assert tarfile_aggregator.get_record_count() == 0

    json_aggregator = JsonDataAggregator(
        max_duration_s=2, tarfile_aggregator=tarfile_aggregator, sensor_name="some_sensors"
    )
    assert json_aggregator.get_data_count() == 0
    assert json_aggregator.sensor_name == "some_sensors"

    json_aggregator.flush_dataset()  # Does nothing
    assert tarfile_aggregator.get_record_count() == 0
    assert json_aggregator.get_data_count() == 0
    assert not json_aggregator._current_start_time

    with freeze_time() as frozen_datetime:

        json_aggregator.add_data(dict(pulse=42))
        json_aggregator.add_data(dict(timing=True))

        assert tarfile_aggregator.get_record_count() == 0
        assert json_aggregator.get_data_count() == 2
        assert json_aggregator._current_start_time

        frozen_datetime.tick(delta=timedelta(seconds=1))

        json_aggregator.add_data(dict(abc=2.2))

        assert tarfile_aggregator.get_record_count() == 0
        assert json_aggregator.get_data_count() == 3

        frozen_datetime.tick(delta=timedelta(seconds=1))

        json_aggregator.add_data(dict(x="abc"))

        assert tarfile_aggregator.get_record_count() == 1  # Single json file
        assert json_aggregator.get_data_count() == 1
        assert json_aggregator._current_start_time

        json_aggregator.flush_dataset()
        assert not json_aggregator._current_start_time

        assert tarfile_aggregator.get_record_count() == 2  # 2 json files
        assert json_aggregator.get_data_count() == 0

        frozen_datetime.tick(delta=timedelta(seconds=10))

        json_aggregator.flush_dataset()

        # Unchanged
        assert tarfile_aggregator.get_record_count() == 2
        assert json_aggregator.get_data_count() == 0

        tarfile_aggregator.finalize_tarfile()
        cryptainer_storage.wait_for_idle_state()
        assert cryptainer_storage.get_cryptainer_count() == 1
        tarfile_bytestring = cryptainer_storage.decrypt_cryptainer_from_storage(cryptainer_name_or_idx=-1)
        tar_file = TarfileRecordAggregator.read_tarfile_from_bytestring(tarfile_bytestring)
        assert tarfile_aggregator.get_record_count() == 0

        filenames = sorted(tar_file.getnames())
        assert len(filenames) == 2

        for filename in filenames:
            assert "some_sensors" in filename
            assert filename.endswith(".json")

        data = tar_file.extractfile(filenames[0]).read()
        assert data == b'[{"pulse": {"$numberInt": "42"}}, {"timing": true}, {"abc": {"$numberDouble": "2.2"}}]'

        data = tar_file.extractfile(filenames[1]).read()
        assert data == b'[{"x": "abc"}]'

        tarfile_aggregator.finalize_tarfile()
        cryptainer_storage.wait_for_idle_state()
        assert cryptainer_storage.get_cryptainer_count() == 1  # Unchanged
        assert not json_aggregator._current_start_time


def test_aggregators_thread_safety(tmp_path):

    offload_payload_ciphertext = random_bool()
    cryptainer_storage = FakeTestCryptainerStorage(
        default_cryptoconf={"zesvscc": True},
        cryptainer_dir=tmp_path,
        offload_payload_ciphertext=offload_payload_ciphertext,
    )

    tarfile_aggregator = TarfileRecordAggregator(cryptainer_storage=cryptainer_storage, max_duration_s=100)
    json_aggregator = JsonDataAggregator(
        max_duration_s=1, tarfile_aggregator=tarfile_aggregator, sensor_name="some_sensors"
    )

    misc_futures = []

    record_data = "hêllo".encode("utf8")

    with ThreadPoolExecutor(max_workers=30) as executor:
        for burst in range(10):
            for idx in range(100):
                misc_futures.append(executor.submit(json_aggregator.add_data, dict(res=idx)))
                misc_futures.append(executor.submit(json_aggregator.flush_dataset))
                misc_futures.append(
                    executor.submit(
                        tarfile_aggregator.add_record,
                        sensor_name="some_recorder_%s_%s" % (burst, idx),
                        from_datetime=datetime(year=2017, month=10, day=11, tzinfo=timezone.utc),
                        to_datetime=datetime(year=2017, month=12, day=1, tzinfo=timezone.utc),
                        extension=".txt",
                        payload=record_data,
                    )
                )
                misc_futures.append(executor.submit(tarfile_aggregator.finalize_tarfile))
            time.sleep(0.2)

    json_aggregator.flush_dataset()
    tarfile_aggregator.finalize_tarfile()
    cryptainer_storage.wait_for_idle_state()

    misc_results = set(future.result() for future in misc_futures)
    assert misc_results == set([None])  # No results expected from any of these methods

    cryptainer_names = cryptainer_storage.list_cryptainer_names(as_sorted_list=True)

    tarfiles_bytes = [
        cryptainer_storage.decrypt_cryptainer_from_storage(cryptainer_name) for cryptainer_name in cryptainer_names
    ]

    tarfiles = [
        TarfileRecordAggregator.read_tarfile_from_bytestring(bytestring) for bytestring in tarfiles_bytes if bytestring
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


def test_periodic_value_poller(tmp_path):

    offload_payload_ciphertext = random_bool()
    cryptainer_storage = FakeTestCryptainerStorage(
        default_cryptoconf={"zexcsc": True},
        cryptainer_dir=tmp_path,
        offload_payload_ciphertext=offload_payload_ciphertext,
    )

    tarfile_aggregator = TarfileRecordAggregator(cryptainer_storage=cryptainer_storage, max_duration_s=100)

    assert tarfile_aggregator.get_record_count() == 0

    json_aggregator = JsonDataAggregator(
        max_duration_s=100, tarfile_aggregator=tarfile_aggregator, sensor_name="some_sensors"
    )

    def task_func():
        return dict(time=int(time.time()), type="current time")

    poller = PeriodicValuePoller(interval_s=0.1, task_func=task_func, json_aggregator=json_aggregator)

    check_sensor_state_machine(poller, run_duration=0.45)

    # We have variations due to machine load (but data was fetched immediately on start)
    assert 5 <= json_aggregator.get_data_count() <= 6
    data_sets = json_aggregator._current_dataset
    assert all(rec["type"] == "current time" for rec in data_sets), data_sets

    json_aggregator.flush_dataset()  # From here one, everything is just standard
    assert json_aggregator.get_data_count() == 0

    # CASE OF SLOW FETCHER #

    def task_func_slow():
        time.sleep(0.2)
        return dict(time=int(time.time()), type="current time 2")

    poller = PeriodicValuePoller(interval_s=0.05, task_func=task_func_slow, json_aggregator=json_aggregator)
    poller.start()
    time.sleep(0.3)
    poller.stop()
    poller.join()

    assert json_aggregator.get_data_count() == 2  # Second fetching could complete
    data_sets = json_aggregator._current_dataset
    assert all(rec["type"] == "current time 2" for rec in data_sets), data_sets

    json_aggregator.flush_dataset()  # From here one, everything is just standard
    assert json_aggregator.get_data_count() == 0

    # CASE OF BROKEN TASK #

    broken_iterations = 0

    def task_func_broken():
        nonlocal broken_iterations
        broken_iterations += 1
        ABCDE

    poller = PeriodicValuePoller(interval_s=0.05, task_func=task_func_broken, json_aggregator=json_aggregator)

    check_sensor_state_machine(poller, run_duration=0.5)
    assert broken_iterations > 5


def test_sensor_manager():
    class DummyUnstableSensor(TaskRunnerStateMachineBase):
        def __init__(self, is_broken):
            super().__init__()
            self._is_broken = is_broken

        def start(self):
            super().start()
            if self._is_broken:
                raise OSError("dummy sensor failure on start")

        def stop(self):
            super().stop()
            if self._is_broken:
                raise OSError("dummy sensor failure on stop")

        def join(self):
            super().join()
            if self._is_broken:
                raise OSError("dummy sensor failure on join")

    # First with EMPTY manager

    manager = SensorManager(sensors=[])
    check_sensor_state_machine(manager)

    # Now with FILLED manager

    sensors = [
        DummyUnstableSensor(is_broken=False),
        DummyUnstableSensor(is_broken=False),
        DummyUnstableSensor(is_broken=True),
        DummyUnstableSensor(is_broken=False),
    ]

    manager = SensorManager(sensors=sensors)
    check_sensor_state_machine(manager)

    success_count = manager.start()
    assert success_count == 3
    assert all(sensor.is_running for sensor in manager._sensors)

    success_count = manager.stop()
    assert success_count == 3
    assert not any(sensor.is_running for sensor in manager._sensors)

    success_count = manager.join()
    assert success_count == 3
    assert not any(sensor.is_running for sensor in manager._sensors)
