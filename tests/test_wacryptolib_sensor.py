import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from datetime import timedelta

import pytest
import sys
import time
from freezegun import freeze_time

from _test_mockups import FakeTestCryptainerStorage, random_bool, longrun_command_line, oneshot_command_line
from wacryptolib.cryptainer import CryptainerStorage, CryptainerEncryptionPipeline
from wacryptolib.scaffolding import check_sensor_state_machine
from wacryptolib.sensor import (
    TarfileRecordAggregator,
    JsonDataAggregator,
    PeriodicValuePoller,
    SensorManager,
    PeriodicSubprocessStreamRecorder,
)
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
        tarfile_bytestring, error_report = cryptainer_storage.decrypt_cryptainer_from_storage(cryptainer_name_or_idx=-1)
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
        tarfile_bytestring, error_report = cryptainer_storage.decrypt_cryptainer_from_storage(cryptainer_name_or_idx=-1)
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
        tarfile_bytestring, error_report = cryptainer_storage.decrypt_cryptainer_from_storage(cryptainer_name_or_idx=-1)
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
        tarfile_bytestring, error_report = cryptainer_storage.decrypt_cryptainer_from_storage(cryptainer_name_or_idx=-1)
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

    tarfiles_bytes = []
    for cryptainer_name in cryptainer_names:
        tarfiles_byte, error_report = cryptainer_storage.decrypt_cryptainer_from_storage(cryptainer_name)
        tarfiles_bytes.append(tarfiles_byte)

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


class TestStreamRecorderForTesting(PeriodicSubprocessStreamRecorder):
    sensor_name = "test_sensor"
    record_extension = ".testext"

    subprocess_data_chunk_size = 100

    def __init__(
        self,
        executable_command_line,
        transmit_post_stop_data=False,
        skip_quit_operation=False,
        skip_kill_operation=False,
        **kwargs
    ):
        self._executable_command_line = executable_command_line
        self._transmit_post_stop_data = transmit_post_stop_data
        self._skip_quit_operation = skip_quit_operation
        self._skip_kill_operation = skip_kill_operation
        super().__init__(**kwargs)

    def _build_subprocess_command_line(self):
        return self._executable_command_line

    def _do_stop_recording(self):
        super()._do_stop_recording()
        if self._transmit_post_stop_data:
            return "post-stop-data__" * 3
        return None

    def _handle_post_stop_data(self, payload, from_datetime, to_datetime):
        print("POST STOP DATA RECEIVED IN TEST IS", payload, from_datetime, to_datetime)

    def _quit_subprocess(self, subprocess):
        if not self._skip_quit_operation:
            super()._quit_subprocess(subprocess)

    def _kill_subprocess(self, subprocess):
        if not self._skip_kill_operation:
            super()._kill_subprocess(subprocess)


class TestStreamRecorderForTestingWithCustomEncryptionStream(TestStreamRecorderForTesting):
    class TestCryptainerEncryptionPipelineWithFinalizationNotification(CryptainerEncryptionPipeline):
        def __init__(self, *args, finalization_callback=None, **kwargs):
            super().__init__(*args, **kwargs)
            assert finalization_callback is not None
            self._finalization_callback = finalization_callback

        def finalize(self):
            self._finalization_callback()
            return super().finalize()

    def __init__(self, *args, finalization_callback, **kwargs):
        super().__init__(*args, **kwargs)
        self._finalization_callback = finalization_callback

    def _get_cryptainer_encryption_stream_creation_kwargs(self) -> dict:
        return dict(
            cryptainer_encryption_stream_class=self.__class__.TestCryptainerEncryptionPipelineWithFinalizationNotification,
            cryptainer_encryption_stream_extra_kwargs=dict(finalization_callback=self._finalization_callback),
        )


def _check_stream_recorder_cryptainer_name(cryptainer_name):
    assert "test_sensor" in str(cryptainer_name)
    assert str(cryptainer_name).endswith(".testext.crypt")


def _build_real_cryptainer_storage_for_stream_recorder_testing(tmp_path, skip_signing=False):
    from test_wacryptolib_cryptainer import SIMPLE_CRYPTOCONF, SIMPLE_CRYPTOCONF_NO_SIGNING

    cryptoconf = SIMPLE_CRYPTOCONF_NO_SIGNING if skip_signing else SIMPLE_CRYPTOCONF
    offload_payload_ciphertext = random_bool()

    cryptainer_storage = CryptainerStorage(  # We need a REAL CrytpainerStorage to handle Pipelining!
        default_cryptoconf=cryptoconf, cryptainer_dir=tmp_path, offload_payload_ciphertext=offload_payload_ciphertext
    )
    return cryptainer_storage


@pytest.mark.parametrize("transmit_post_stop_data", [True, False])
def test_periodic_subprocess_stream_recorder_simple_cases(tmp_path, transmit_post_stop_data):
    cryptainer_storage = _build_real_cryptainer_storage_for_stream_recorder_testing(tmp_path)

    def _purge_cryptainer_storage(cryptainer_storage, _cryptainer_names):
        for cryptainer_name in _cryptainer_names:
            cryptainer_storage.delete_cryptainer(cryptainer_name)
        assert not cryptainer_storage.list_cryptainer_names()

    recorder = TestStreamRecorderForTesting(
        executable_command_line=longrun_command_line,
        transmit_post_stop_data=transmit_post_stop_data,
        interval_s=5,
        cryptainer_storage=cryptainer_storage,
    )
    recorder.start()
    print("BEFORE SLEEP")
    time.sleep(7)  # Beware of python launch time...
    print("AFTER SLEEP")
    recorder.stop()
    recorder.join()
    cryptainer_names = cryptainer_storage.list_cryptainer_names()
    assert len(cryptainer_names) == 2  # Last recording was aborted early though
    _check_stream_recorder_cryptainer_name(cryptainer_names[0])


def test_periodic_subprocess_stream_recorder_broken_executable(tmp_path):
    # Signing was too slow and broke the "2 cryptainers only" rule
    cryptainer_storage = _build_real_cryptainer_storage_for_stream_recorder_testing(tmp_path, skip_signing=True)

    recorder = TestStreamRecorderForTesting(
        executable_command_line=["ABCDE"], interval_s=5, cryptainer_storage=cryptainer_storage  # WRONG executable
    )
    recorder.start()
    time.sleep(6)
    recorder.stop()
    recorder.join()
    cryptainer_names = cryptainer_storage.list_cryptainer_names()
    assert len(cryptainer_names) == 2  # Cryptainers are EMPTY but still exist
    _check_stream_recorder_cryptainer_name(cryptainer_names[0])


def test_periodic_subprocess_stream_recorder_autoexiting_executable(tmp_path):
    cryptainer_storage = _build_real_cryptainer_storage_for_stream_recorder_testing(tmp_path)

    recorder = TestStreamRecorderForTesting(
        executable_command_line=oneshot_command_line,  # This program quits immediately
        interval_s=5,
        cryptainer_storage=cryptainer_storage,
    )
    recorder.start()
    time.sleep(6)
    recorder.stop()  # Retcode will already have been set
    recorder.join()  # Necessary for files to be output to disk
    cryptainer_names = cryptainer_storage.list_cryptainer_names()
    assert len(cryptainer_names) == 2  # Cryptainers contain only the initially output data
    _check_stream_recorder_cryptainer_name(cryptainer_names[0])


def test_periodic_subprocess_stream_recorder_non_quittable_executable(tmp_path):
    cryptainer_storage = _build_real_cryptainer_storage_for_stream_recorder_testing(tmp_path)

    recorder = TestStreamRecorderForTesting(
        executable_command_line=longrun_command_line,
        skip_quit_operation=True,
        interval_s=5,
        cryptainer_storage=cryptainer_storage,
    )
    recorder.start()
    time.sleep(12)  # Beware of python launch time...
    recorder.stop()
    recorder.join()
    cryptainer_names = cryptainer_storage.list_cryptainer_names()
    assert len(cryptainer_names) == 2  # Waiting for sigquit effect prevented more than that
    _check_stream_recorder_cryptainer_name(cryptainer_names[0])


def test_periodic_subprocess_stream_recorder_non_killable_executable(tmp_path):
    cryptainer_storage = _build_real_cryptainer_storage_for_stream_recorder_testing(tmp_path)

    recorder = TestStreamRecorderForTesting(
        executable_command_line=longrun_command_line,
        skip_quit_operation=True,
        skip_kill_operation=True,
        interval_s=5,
        cryptainer_storage=cryptainer_storage,
    )
    recorder.start()
    subprocess = recorder._subprocess
    try:
        time.sleep(12)  # Beware of python launch time...
        recorder.stop()  # Will wait for still in-process stop+start anyway...
        recorder.join()  # Will give up even before stdout stream ended...
        stdout_thread = recorder._previous_stdout_threads[0]
        assert stdout_thread.is_alive()
        cryptainer_names = cryptainer_storage.list_cryptainer_names()
        assert len(cryptainer_names) == 0  # Not ready yet
        subprocess.kill()
        stdout_thread.join(timeout=15)
        assert not stdout_thread.is_alive()  # Join() was a success
        cryptainer_names = cryptainer_storage.list_cryptainer_names()
        assert len(cryptainer_names) == 1  # First record was at last finished
        _check_stream_recorder_cryptainer_name(cryptainer_names[0])
    finally:
        if subprocess.poll() is None:
            subprocess.kill()  # Kill abnormally remaining subprocess, even if it'd end soon


def test_periodic_subprocess_stream_recorder_with_custom_encryption_stream(tmp_path):
    cryptainer_storage = _build_real_cryptainer_storage_for_stream_recorder_testing(tmp_path)

    finalization_result_holder = []

    def finalization_callback():
        finalization_result_holder.append("FINALIZED")

    recorder = TestStreamRecorderForTestingWithCustomEncryptionStream(
        finalization_callback=finalization_callback,
        executable_command_line=longrun_command_line,
        interval_s=6,
        cryptainer_storage=cryptainer_storage,
    )
    recorder.start()
    print("BEFORE SLEEP")
    time.sleep(1)
    print("AFTER SLEEP")
    recorder.stop()
    recorder.join()

    assert finalization_result_holder == ["FINALIZED"]

    cryptainer_names = cryptainer_storage.list_cryptainer_names()
    assert len(cryptainer_names) == 1  # Only one was recorded
    _check_stream_recorder_cryptainer_name(cryptainer_names[0])


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
