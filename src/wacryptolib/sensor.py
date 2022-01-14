import io
import logging
import tarfile
import threading
from datetime import datetime

from wacryptolib.cryptainer import CryptainerStorage, CRYPTAINER_DATETIME_FORMAT
from wacryptolib.utilities import (
    dump_to_json_bytes,
    synchronized,
    check_datetime_is_tz_aware,
    PeriodicTaskHandler,
    TaskRunnerStateMachineBase,
    get_utc_now_date,
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
        logger.info("Adding record %r to tarfile builder" % filename)

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

    def _offloaded_run_task(self):
        """This function is meant to be called by secondary thread, to fetch and store data."""
        try:
            assert self._task_func  # Sanity check, else _offloaded_run_task() should have been overridden
            result = self._task_func()
            self._offloaded_add_data(result)
        except Exception as exc:
            logger.error("Error in PeriodicValuePoller offloaded task: %r" % exc, exc_info=True)


class SensorManager(
    TaskRunnerStateMachineBase
):  # FIXME deprecate this in favor of class handling the whole recording toolchain, with aggregators etc.?
    """
    Manage a group of sensors for simultaneous starts/stops.

    The underlying aggregators are not supposed to be directly impacted
    by these operations - they must be flushed separately.
    """

    def __init__(self, sensors):
        super().__init__()
        self._sensors = sensors

    def start(self):
        logger.info("Starting all managed sensors")
        super().start()
        success_count = 0
        for sensor in self._sensors:
            try:
                sensor.start()
            except Exception as exc:
                logger.error(f"Failed starting sensor {sensor.__class__.__name__} ({exc!r})")
            else:
                success_count += 1
        return success_count

    def stop(self):
        logger.info("Stopping all managed sensors")
        super().stop()
        success_count = 0
        for sensor in self._sensors:
            try:
                sensor.stop()
            except Exception as exc:
                logger.error(f"Failed stopping sensor {sensor.__class__.__name__} ({exc!r})")
            else:
                success_count += 1
        return success_count

    def join(self):
        logger.info("Waiting for all managed sensors termination")
        super().join()
        success_count = 0
        for sensor in self._sensors:
            try:
                sensor.join()
            except Exception as exc:
                logger.error(f"Failed joining sensor {sensor.__class__.__name__} ({exc!r})")
            else:
                success_count += 1
        return success_count
