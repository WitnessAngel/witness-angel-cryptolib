import io
import logging
import subprocess
import tarfile
import threading
from datetime import datetime
from subprocess import TimeoutExpired

from wacryptolib.cryptainer import CryptainerStorage, CRYPTAINER_DATETIME_FORMAT
from wacryptolib.utilities import (
    dump_to_json_bytes,
    synchronized,
    check_datetime_is_tz_aware,
    PeriodicTaskHandler,
    TaskRunnerStateMachineBase,
    get_utc_now_date,
    catch_and_log_exception,
)

logger = logging.getLogger(__name__)


class TimeLimitedAggregatorMixin:
    """
    This class provides utilities to flush underlying data after a defined `max_duration_s`
    delay has been exceeded.

    The timer starts when the first record is added.
    """

    _max_duration_s = None

    _current_start_time = None

    def __init__(self, max_duration_s: float):
        assert max_duration_s > 0, max_duration_s
        self._max_duration_s = max_duration_s
        self._lock = threading.Lock()

    def _notify_aggregation_operation(self):
        """Call this before every "data append" operation, to flush AND renew inner aggregator if needed."""
        if self._current_start_time is not None:
            delay_s = get_utc_now_date() - self._current_start_time
            if delay_s.total_seconds() >= self._max_duration_s:
                self._flush_aggregated_data()
        if self._current_start_time is None:
            self._current_start_time = get_utc_now_date()

    def _flush_aggregated_data(self):
        """Call this AFTER really flushing data to the next step of the pipeline"""
        self._current_start_time = None


class TarfileRecordAggregator(TimeLimitedAggregatorMixin):
    """
    This class allows sensors to aggregate file-like records of data in memory.

    It is in charge of building the filenames of tar records, as well as of completed tarfiles.

    Public methods of this class are thread-safe.
    """

    _lock = None

    # Keep these in sync if you add bz/gz compression later
    tarfile_writing_mode = "w"
    tarfile_extension = ".tar"

    _current_tarfile = None
    _current_bytesio = None
    _current_records_count = 0
    _current_metadata = None

    def __init__(self, cryptainer_storage: CryptainerStorage, max_duration_s: float):
        super().__init__(max_duration_s=max_duration_s)
        assert cryptainer_storage is not None, cryptainer_storage
        self._cryptainer_storage = cryptainer_storage
        self._lock = threading.Lock()

    def get_record_count(self):
        return self._current_records_count

    def _notify_aggregation_operation(self):
        super()._notify_aggregation_operation()
        if not self._current_tarfile:
            assert not self._current_bytesio, repr(self._current_bytesio)
            assert not self._current_metadata, repr(self._current_metadata)
            assert not self._current_records_count, self._current_bytesio
            self._current_bytesio = io.BytesIO()
            self._current_tarfile = tarfile.open(
                mode=self.tarfile_writing_mode, fileobj=self._current_bytesio  # TODO - add tarfile compression?
            )
            self._current_metadata = {"members": {}}

    def _build_tarfile_filename(self, from_datetime, to_datetime):
        extension = self.tarfile_extension
        assert extension.startswith("."), extension
        from_ts = from_datetime.strftime(CRYPTAINER_DATETIME_FORMAT)
        to_ts = to_datetime.strftime(CRYPTAINER_DATETIME_FORMAT)
        filename = "{from_ts}_to_{to_ts}_cryptainer{extension}".format(**locals())
        assert " " not in filename, repr(filename)
        return filename

    def _flush_aggregated_data(self):
        if not self._current_start_time:
            assert not self._current_records_count
            return

        assert self._current_tarfile  # Since start time is only set on new aggregation...
        self._current_tarfile.close()
        result_bytestring = self._current_bytesio.getvalue()
        end_time = get_utc_now_date()
        filename_base = self._build_tarfile_filename(from_datetime=self._current_start_time, to_datetime=end_time)
        self._cryptainer_storage.enqueue_file_for_encryption(
            filename_base=filename_base, payload=result_bytestring, cryptainer_metadata=self._current_metadata
        )

        self._current_tarfile = None
        self._current_bytesio = None
        self._current_metadata = None
        self._current_records_count = 0

        super()._flush_aggregated_data()

    def _build_record_filename(self, sensor_name, from_datetime, to_datetime, extension):
        assert extension.startswith("."), extension
        from_ts = from_datetime.strftime(CRYPTAINER_DATETIME_FORMAT)
        to_ts = to_datetime.strftime(CRYPTAINER_DATETIME_FORMAT)
        filename = "{from_ts}_to_{to_ts}_{sensor_name}{extension}".format(**locals())
        assert " " not in filename, repr(filename)
        return filename

    @synchronized
    def add_record(
        self, sensor_name: str, from_datetime: datetime, to_datetime: datetime, extension: str, payload: bytes
    ):
        """Add the provided data to the tarfile, using associated metadata.

        If, despite included timestamps, several records end up having the exact same name, the last one will have
        priority when extracting the tarfile, but all of them will be stored in it anyway.

        :param sensor_name: slug label for the sensor
        :param from_datetime: start time of the recording
        :param to_datetime: end time of the recording
        :param extension: file extension, starting with a dot
        :param payload: bytestring of audio/video/other data
        """
        assert self._current_records_count or not self._current_start_time  # INVARIANT of our system!
        assert isinstance(payload, bytes), repr(payload)  # For now, only format supported
        assert extension.startswith("."), extension
        assert from_datetime <= to_datetime, (from_datetime, to_datetime)
        check_datetime_is_tz_aware(from_datetime)
        check_datetime_is_tz_aware(to_datetime)

        self._notify_aggregation_operation()

        filename = self._build_record_filename(
            sensor_name=sensor_name, from_datetime=from_datetime, to_datetime=to_datetime, extension=extension
        )
        logger.info("Adding record %r to tarfile builder", filename)

        mtime = to_datetime.timestamp()

        member_metadata = dict(size=len(payload), mtime=to_datetime)
        self._current_metadata["members"][filename] = member_metadata  # Overridden if existing

        tarinfo = tarfile.TarInfo(filename)
        tarinfo.size = len(payload)  # this is crucial
        tarinfo.mtime = mtime

        fileobj = io.BytesIO(payload)  # Does NOT copy data until write, since Python3.5

        # Memory warning : duplicates data to bytesio tarfile
        self._current_tarfile.addfile(tarinfo, fileobj=fileobj)

        self._current_records_count += 1

    @synchronized
    def finalize_tarfile(self):
        """
        Return the content of current tarfile as a bytestring, possibly empty, and reset the current tarfile.
        """
        assert self._current_records_count or not self._current_start_time  # INVARIANT of our system!
        self._flush_aggregated_data()

    @staticmethod
    def read_tarfile_from_bytestring(payload: bytes):
        """
        Create a readonly TarFile instance from the provided bytestring.
        """
        assert payload, payload  # Empty bytestrings must already have been filtered out
        return tarfile.open(mode="r", fileobj=io.BytesIO(payload))


class JsonDataAggregator(TimeLimitedAggregatorMixin):
    """
    This class allows sensors to aggregate dicts of data, which are periodically pushed as a json bytestring
    to the underlying TarfileRecordAggregator.

    Public methods of this class are thread-safe.
    """

    _tarfile_aggregator = None
    _current_dataset = None
    _lock = None

    def __init__(self, tarfile_aggregator: TarfileRecordAggregator, sensor_name: str, max_duration_s: float):
        super().__init__(max_duration_s=max_duration_s)
        assert isinstance(tarfile_aggregator, TarfileRecordAggregator), tarfile_aggregator
        self._tarfile_aggregator = tarfile_aggregator
        self._sensor_name = sensor_name
        self._lock = threading.Lock()

    def get_data_count(self):
        return len(self._current_dataset) if self._current_dataset else 0

    @property
    def sensor_name(self):
        return self._sensor_name

    def _notify_aggregation_operation(self):
        super()._notify_aggregation_operation()
        if self._current_dataset is None:
            self._current_dataset = []

    def _flush_aggregated_data(self):
        if not self._current_start_time:
            assert not self._current_dataset
            return
        end_time = get_utc_now_date()
        payload = dump_to_json_bytes(self._current_dataset)
        self._tarfile_aggregator.add_record(
            payload=payload,
            sensor_name=self._sensor_name,
            from_datetime=self._current_start_time,
            to_datetime=end_time,
            extension=".json",
        )
        self._current_dataset = None
        super()._flush_aggregated_data()

    @synchronized
    def add_data(self, data_dict: dict):
        """
        Flush current data to the tarfile if needed, and append `data_dict` to the queue.
        """
        assert self._current_dataset or not self._current_start_time  # INVARIANT of our system!
        assert isinstance(data_dict, dict), data_dict
        logger.debug("New data added to %s json builder: %s", self._sensor_name, data_dict)
        self._notify_aggregation_operation()
        self._current_dataset.append(data_dict)

    @synchronized
    def flush_dataset(self):
        """
        Force the flushing of current data to the tarfile (e.g. when terminating the service).
        """
        assert self._current_dataset or not self._current_start_time  # INVARIANT of our system!
        self._flush_aggregated_data()


class PeriodicValueMixin:
    """
    Mixin for sensors polling or pushing data to a json aggregator at regular intervals.
    """

    def __init__(self, json_aggregator, **kwargs):
        super().__init__(**kwargs)
        self._json_aggregator = json_aggregator

    def _offloaded_add_data(self, data_dict):
        """This function is meant to be called by secondary thread, to push data into the json aggregator."""
        self._json_aggregator.add_data(data_dict)


class PeriodicValuePoller(PeriodicValueMixin, PeriodicTaskHandler):
    """
    This class runs a function at a specified interval, and pushes its result to a json aggregator.
    """

    @catch_and_log_exception("PeriodicValuePoller._offloaded_run_task")
    def _offloaded_run_task(self):
        """This function is meant to be called by secondary thread, to fetch and store data."""
        assert self.is_running
        assert self._task_func  # Sanity check, else _offloaded_run_task() should have been overridden
        result = self._task_func()
        self._offloaded_add_data(result)


class PeriodicSensorRestarter(PeriodicTaskHandler):
    """THIS IS PRIVATE API"""

    sensor_name = None

    _current_start_time = None

    def __init__(self, interval_s: float):
        super().__init__(interval_s=interval_s, runonstart=False)
        assert self.sensor_name, self.sensor_name
        assert not hasattr(self, "_lock")
        self._lock = threading.Lock()

    @synchronized
    def start(self):
        super().start()

        logger.debug("Starting sensor %s", self.sensor_name)

        self._current_start_time = get_utc_now_date()

        self._do_start_recording()

        logger.debug("Finished starting sensor %s", self.sensor_name)

    def _do_start_recording(self):  # pragma: no cover
        raise NotImplementedError("%s -> _do_start_recording" % self.sensor_name)

    @synchronized
    def stop(self):
        super().stop()

        logger.debug("Stopping sensor %s", self.sensor_name)

        from_datetime = self._current_start_time
        to_datetime = get_utc_now_date()

        payload = self._do_stop_recording()

        if payload is not None:
            self._handle_post_stop_data(payload=payload, from_datetime=from_datetime, to_datetime=to_datetime)

        logger.debug("Finished stopping sensor %s", self.sensor_name)

    def _do_stop_recording(self):  # pragma: no cover
        raise NotImplementedError("%s -> _do_stop_recording" % self.sensor_name)

    def _handle_post_stop_data(self, payload, from_datetime, to_datetime):  # pragma: no cover
        raise NotImplementedError("%s -> _handle_post_stop_data" % self.sensor_name)

    def _do_restart_recording(self):
        """Default implementation does a stop and then start, some sensors have better ways"""
        try:
            payload = self._do_stop_recording()  # Renames target files
        except Exception as es:
            logger.critical("Unrecoverable error when stopping sensor %s for restart - aborting sensor operation" % self.sensor_name)
            super().stop()  # Stops state and multitimer thread (we don't want to overflow the device with e.g. processes)
            raise  # Will propagate up to catch_and_log_exception()
        self._do_start_recording()  # Recording must be restarted immediately
        return payload

    @synchronized
    @catch_and_log_exception("PeriodicSensorRestarter._offloaded_run_task")
    def _offloaded_run_task(self):
        assert self.is_running
        from_datetime = self._current_start_time
        to_datetime = get_utc_now_date()
        self._current_start_time = get_utc_now_date()  # RESET

        payload = self._do_restart_recording()

        if payload is not None:
            self._handle_post_stop_data(payload=payload, from_datetime=from_datetime, to_datetime=to_datetime)


class PeriodicEncryptionStreamMixin:
    """THIS IS PRIVATE API"""

    # Class fields to be overridden
    record_extension = None

    def __init__(self, cryptainer_storage, **kwargs):
        super().__init__(**kwargs)
        self._cryptainer_storage = cryptainer_storage

    def _build_cryptainer_filename_base(self, from_datetime):
        # FIXME use same format as build_record_filename, less verbose!!!!
        extension = self.record_extension
        assert extension.startswith("."), extension
        from_ts = from_datetime.strftime(CRYPTAINER_DATETIME_FORMAT)
        sensor_name = self.sensor_name
        filename = "{from_ts}_{sensor_name}_cryptainer{extension}".format(**locals())
        assert " " not in filename, repr(filename)
        return filename

    def _get_cryptainer_encryption_stream_creation_kwargs(self) -> dict:
        """Good hook to provide e.g. cryptainer_encryption_stream_class and/or cryptainer_encryption_stream_extra_kwargs parameters"""
        return {}

    def _build_cryptainer_encryption_stream(self):  # FIXME rename to encryption-pipeline ???
        cryptainer_filename_base = self._build_cryptainer_filename_base(self._current_start_time)
        encryption_stream_extra_kwargs = self._get_cryptainer_encryption_stream_creation_kwargs()
        cryptainer_encryption_stream = self._cryptainer_storage.create_cryptainer_encryption_stream(
            cryptainer_filename_base,
            cryptainer_metadata=None,
            dump_initial_cryptainer=True,
            **encryption_stream_extra_kwargs,
        )
        return cryptainer_encryption_stream


class PeriodicSubprocessStreamRecorder(PeriodicEncryptionStreamMixin, PeriodicSensorRestarter):
    """THIS IS PRIVATE API"""

    # How much data to push to encryption stream at the same time
    subprocess_data_chunk_size = 2 * 1024**2

    _subprocess = None
    _stdout_thread = None
    _stderr_thread = None

    @property
    def suprocess_buffer_size(self):
        # This buffer must be big enough to avoid any overflow while encrypting+dumping data
        return self.subprocess_data_chunk_size * 6

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._previous_stdio_threads = []  # To allow a proper join() at the end (for stdout+stderr streams)

    def _build_subprocess_command_line(self) -> list:  # pragma: no cover
        raise NotImplementedError("%s -> _handle_post_stop_data" % self.sensor_name)

    def _launch_and_consume_subprocess(self, command_line, cryptainer_encryption_stream):
        logger.info("Calling {} sensor subprocess command: {}".format(self.sensor_name, " ".join(command_line)))

        try:
            self._subprocess = subprocess.Popen(
                command_line,
                bufsize=self.suprocess_buffer_size,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:  # E.g. program binary not found
            logger.error("Failure when calling {} sensor subprocess command: {!r}".format(self.sensor_name, exc))
            # FIXME here add deletion of empty self._cryptainer_encryption_stream instead of finalizing it?
            cryptainer_encryption_stream.finalize()
            return  # Skip the setup of threads below, and let self._subprocess be None

        # Do some cleanup to save memory
        self._previous_stdio_threads = [thread for thread in self._previous_stdio_threads if thread.is_alive()]

        @catch_and_log_exception("Subprocess stdout_reader_thread of sensor %s" % self.sensor_name)
        def _stdout_reader_thread(fh):
            # Backported from Popen._readerthread of Python3.8
            while True:
                chunk = fh.read(self.subprocess_data_chunk_size)
                assert chunk is not None  # We're NOT in non-blocking mode!
                if chunk:
                    logger.debug("Encrypting %s chunk of length %s", self.sensor_name, len(chunk))
                    cryptainer_encryption_stream.encrypt_chunk(chunk)
                else:
                    break  # End of subprocess
            logger.debug(
                "Finalizing %s cryptainer encryption stream", cryptainer_encryption_stream._cryptainer_filepath.name
            )
            cryptainer_encryption_stream.finalize()
            fh.close()
            logger.debug(
                "Finished finalizing %s cryptainer encryption stream",
                cryptainer_encryption_stream._cryptainer_filepath.name,
            )

        self._stdout_thread = threading.Thread(target=_stdout_reader_thread, args=(self._subprocess.stdout,))
        self._stdout_thread.start()
        self._previous_stdio_threads.append(self._stdout_thread)

        @catch_and_log_exception("Subprocess stderr_reader_thread of sensor %s" % self.sensor_name)
        def _sytderr_reader_thread(fh):
            for line in fh:
                line_str = line.decode("ascii", "ignore")
                logger.info("Subprocess stderr: %s" % line_str.rstrip("\n"))
                ##print(">>>>>>>>>>>>>_sytderr_reader_thread output done")
            fh.close()

        self._stderr_thread = threading.Thread(target=_sytderr_reader_thread, args=(self._subprocess.stderr,))
        self._stderr_thread.start()
        self._previous_stdio_threads.append(self._stderr_thread)

    def _do_start_recording(self):
        ##print(">>>>>>>>>> DO START RECORDING CALLED")
        command_line = self._build_subprocess_command_line()
        cryptainer_encryption_stream = self._build_cryptainer_encryption_stream()
        self._launch_and_consume_subprocess(
            command_line=command_line, cryptainer_encryption_stream=cryptainer_encryption_stream
        )

    @classmethod
    def _quit_subprocess(cls, subprocess):
        subprocess.terminate()

    @classmethod
    def _kill_subprocess(cls, subprocess):
        # Subclass might use terminate() instead, if signals/ctdin are used for normal quit
        subprocess.kill()

    def _do_stop_recording(self):
        if self._subprocess is None:
            logger.warning("No subprocess to be terminated in %s stop-recording", self.sensor_name)
            assert self._stdout_thread is None
            assert self._stderr_thread is None
            return  # Start of recording failed previously, most probably

        try:
            retcode = self._subprocess.poll()
            if retcode is not None:
                logger.warning(
                    "Subprocess had already terminated with return code %s in %s stop-recording",
                    retcode,
                    self.sensor_name,
                )
                return  # Stream must have crashed
            try:
                logger.warning("Attempting normal termination of %s subprocess", self.sensor_name)
                self._quit_subprocess(self._subprocess)
                self._subprocess.wait(timeout=10)  # Will raise on timeout!
                # Note : stdout reader thread might still be running now to complete data encryption and cryptainer finalization!
            except Exception as exc:  # E.g. TimeoutExpired if wait() expired
                logger.warning("Failed normal termination of %s subprocess: %r", self.sensor_name, exc)
                logger.warning("Force-terminating dangling %s subprocess" % self.sensor_name)
                self._kill_subprocess(self._subprocess)
                try:
                    self._subprocess.wait(timeout=5)
                except TimeoutExpired:  # Should never happen IRL...
                    raise RuntimeError("Force-termination of dangling %s subprocess failed!" % self.sensor_name)

        finally:
            # Cleanup recording attributes
            self._subprocess = self._stdout_thread = self._stderr_thread = None

    def join(self):
        ##print(">>>>>>>>>> PREPARING JOIN ON", len(self._previous_stdio_threads), "STDIO THREADS")
        super().join()
        for thread in self._previous_stdio_threads:
            thread.join(timeout=15)
            if thread.is_alive():  # Might happen in very slow system, or if subprocess actually never exited...
                logger.critical("An stdio reader thread for previous %s subprocess didn't exit" % self.sensor_name)
        ##print(">>>>>>>>>>>>>PeriodicSubprocessStreamRecorder join done")

class SensorManager(TaskRunnerStateMachineBase):
    """
    Manage a group of sensors for simultaneous starts/stops.

    The underlying aggregators are not supposed to be directly impacted
    by these operations - they must be flushed separately.
    """

    def __init__(self, sensors):
        super().__init__()
        self._sensors = sensors

    def start(self):
        logger.info("Starting all %d managed sensors", len(self._sensors))
        super().start()
        success_count = 0
        for sensor in self._sensors:
            with catch_and_log_exception(f"start of sensor {sensor.__class__.__name__}"):
                sensor.start()
                success_count += 1
        return success_count

    def stop(self):
        logger.info("Stopping all %d managed sensors", len(self._sensors))
        super().stop()
        success_count = 0
        for sensor in self._sensors:
            with catch_and_log_exception(f"stop of sensor {sensor.__class__.__name__}"):
                sensor.stop()
                success_count += 1
        return success_count

    def join(self):
        logger.info("Waiting for all %d managed sensors termination", len(self._sensors))
        super().join()
        success_count = 0
        for sensor in self._sensors:
            with catch_and_log_exception(f"join of sensor {sensor.__class__.__name__}"):
                sensor.join()
                success_count += 1
        return success_count
