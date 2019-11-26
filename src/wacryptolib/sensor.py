import abc
import io
import tarfile
import threading
from datetime import datetime, timezone

import multitimer

from wacryptolib.container import ContainerStorage
from wacryptolib.utilities import (
    dump_to_json_bytes,
    synchronized,
    check_datetime_is_tz_aware,
)


class TimeLimitedAggregatorMixin:
    """
    This class provides utilities to flush underlying data after a defined `max_duration_s`
    delay has been exceeded.
    """

    _max_duration_s = None

    _current_start_time = None

    def __init__(self, max_duration_s: int):
        assert max_duration_s > 0, max_duration_s
        self._max_duration_s = max_duration_s
        self._lock = threading.Lock()

    def _notify_aggregation_operation(self):
        """Call this before every "data append" operation, to flush AND renew inner aggregator if needed."""
        if self._current_start_time is not None:
            delay_s = datetime.now(tz=timezone.utc) - self._current_start_time
            if delay_s.total_seconds() >= self._max_duration_s:
                self._flush_aggregated_data()
        if self._current_start_time is None:
            self._current_start_time = datetime.now(
                tz=timezone.utc  # TODO make datetime utility with TZ
            )

    def _flush_aggregated_data(self):
        """Call this AFTER really flushing data to the next step of the pipeline"""
        self._current_start_time = None


class TarfileAggregator(TimeLimitedAggregatorMixin):
    """
    This class allows sensors to aggregate file-like records of data in memory.

    It is in charge of building the filenames of tar records, as well as of completed tarfiles.

    Public methods of this class are thread-safe.
    """

    DATETIME_FORMAT = "%Y%m%d%H%M%S"

    _lock = None

    # Keep these in sync if you add bz/gz compression later
    tarfile_writing_mode = "w"
    tarfile_extension = ".tar"

    _current_tarfile = None
    _current_bytesio = None
    _current_records_count = 0

    def __init__(self, container_storage: ContainerStorage, max_duration_s: int):
        super().__init__(max_duration_s=max_duration_s)
        self._container_storage = container_storage
        self._lock = threading.Lock()

    def __len__(self):
        return self._current_records_count

    def _notify_aggregation_operation(self):
        super()._notify_aggregation_operation()
        if not self._current_tarfile:
            assert not self._current_bytesio, repr(self._current_bytesio)
            self._current_bytesio = io.BytesIO()
            self._current_tarfile = tarfile.open(
                mode=self.tarfile_writing_mode,
                fileobj=self._current_bytesio,  # TODO - add compression?
            )
            assert self._current_records_count == 0, self._current_bytesio

    def _build_tarfile_filename(self, from_datetime, to_datetime):
        extension = self.tarfile_extension
        assert extension.startswith("."), extension
        from_ts = from_datetime.strftime(self.DATETIME_FORMAT)
        to_ts = to_datetime.strftime(self.DATETIME_FORMAT)
        filename = "{from_ts}_{to_ts}_container{extension}".format(**locals())
        assert " " not in filename, repr(filename)
        return filename

    def _flush_aggregated_data(self):

        if not self._current_start_time:
            assert not self._current_records_count
            return

        assert (
            self._current_tarfile
        )  # Since start time is only set on new aggregation...
        self._current_tarfile.close()
        result_bytestring = self._current_bytesio.getvalue()
        end_time = datetime.now(tz=timezone.utc)
        filename_base = self._build_tarfile_filename(
            from_datetime=self._current_start_time, to_datetime=end_time
        )
        self._container_storage.enqueue_file_for_encryption(
            filename_base=filename_base, data=result_bytestring
        )

        self._current_tarfile = None
        self._current_bytesio = None
        self._current_records_count = 0

        super()._flush_aggregated_data()

    def _build_record_filename(
        self, sensor_name, from_datetime, to_datetime, extension
    ):
        assert extension.startswith("."), extension
        from_ts = from_datetime.strftime(self.DATETIME_FORMAT)
        to_ts = to_datetime.strftime(self.DATETIME_FORMAT)
        filename = "{from_ts}_{to_ts}_{sensor_name}{extension}".format(**locals())
        assert " " not in filename, repr(filename)
        return filename

    @synchronized
    def add_record(
        self,
        sensor_name: str,
        from_datetime: datetime,
        to_datetime: datetime,
        extension: str,
        data: bytes,
    ):
        """Add the provided data to the tarfile, using associated metadata.

        If, despite included timestamps, several records end up having the exact same name, the last one will have
        priority when extracting the tarfile, but all of them will be stored in it anyway.

        :param sensor_name: slug label for the sensor
        :param from_datetime: start time of the recording
        :param to_datetime: end time of the recording
        :param extension: file extension, starting with a dot
        :param data: bytestring of audio/video/other data
        """
        assert (
            self._current_records_count or not self._current_start_time
        )  # INVARIANT of our system!
        assert isinstance(data, bytes), repr(data)  # For now, only format supported
        assert extension.startswith("."), extension
        assert from_datetime <= to_datetime, (from_datetime, to_datetime)
        check_datetime_is_tz_aware(from_datetime)
        check_datetime_is_tz_aware(to_datetime)

        self._notify_aggregation_operation()

        filename = self._build_record_filename(
            sensor_name=sensor_name,
            from_datetime=from_datetime,
            to_datetime=to_datetime,
            extension=extension,
        )

        mtime = to_datetime.timestamp()

        tarinfo = tarfile.TarInfo(filename)
        tarinfo.size = len(data)  # this is crucial
        tarinfo.mtime = mtime
        self._current_tarfile.addfile(tarinfo, io.BytesIO(data))

        self._current_records_count += 1

    @synchronized
    def finalize_tarfile(self):
        """
        Return the content of current tarfile as a bytestring, possibly empty, and reset the current tarfile.
        """
        assert (
            self._current_records_count or not self._current_start_time
        )  # INVARIANT of our system!
        self._flush_aggregated_data()

    @staticmethod
    def read_tarfile_from_bytestring(data_bytestring):
        """
        Create a readonly TarFile instance from the provided bytestring.
        """
        assert (
            data_bytestring
        ), data_bytestring  # Empty bytestrings must already have been filtered out
        return tarfile.open(mode="r", fileobj=io.BytesIO(data_bytestring))


class JsonAggregator(TimeLimitedAggregatorMixin):  # TODO -> JsonAggregator
    """
    This class allows sensors to aggregate dicts of data, which are pushed to the underlying TarfileAggregator after a
    certain amount of seconds.

    Public methods of this class are thread-safe.
    """

    _tarfile_aggregator = None
    _current_dataset = None
    _lock = None

    def __init__(
        self,
        tarfile_aggregator: TarfileAggregator,
        sensor_name: str,
        max_duration_s: int,
    ):
        super().__init__(max_duration_s=max_duration_s)
        assert isinstance(tarfile_aggregator, TarfileAggregator), tarfile_aggregator
        self._tarfile_aggregator = tarfile_aggregator
        self._sensor_name = sensor_name
        self._lock = threading.Lock()

    def __len__(self):
        return len(self._current_dataset) if self._current_dataset else 0

    def _notify_aggregation_operation(self):
        super()._notify_aggregation_operation()
        if self._current_dataset is None:
            self._current_dataset = []

    def _flush_aggregated_data(self):
        if not self._current_start_time:
            assert not self._current_dataset
            return
        end_time = datetime.now(tz=timezone.utc)
        dataset_bytes = dump_to_json_bytes(self._current_dataset)
        self._tarfile_aggregator.add_record(
            data=dataset_bytes,
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
        assert (
            self._current_dataset or not self._current_start_time
        )  # INVARIANT of our system!
        assert isinstance(data_dict, dict), data_dict
        self._notify_aggregation_operation()
        self._current_dataset.append(data_dict)

    @synchronized
    def flush_dataset(self):
        """
        Force the flushing of current data to the tarfile (e.g. when terminating the service).
        """
        assert (
            self._current_dataset or not self._current_start_time
        )  # INVARIANT of our system!
        self._flush_aggregated_data()


class PeriodicValueProviderBase(abc.ABC):
    def __init__(self, interval_s, json_aggregator):
        self._provider_is_started = False
        self._interval_s = interval_s
        self._json_aggregator = json_aggregator

    def _offloaded_add_data(self, data_dict):
        """This function is meant to be called by secondary thread, to push data into the json aggregator."""
        self._json_aggregator.add_data(data_dict)

    def start(self):
        """Start the periodic system which will poll or push the value."""
        if self._provider_is_started:
            raise RuntimeError("Can't start an already started periodic value provider")
        self._provider_is_started = True

    def stop(self):
        """Request the periodic system to stop as soon as possible."""
        if not self._provider_is_started:
            raise RuntimeError("Can't stop an already stopped periodic value provider")
        self._provider_is_started = False

    def join(self):
        """Wait for the periodic system to really finish running."""
        if self._provider_is_started:
            raise RuntimeError("Can't join a running periodic value provider")


class PeriodicValuePoller(PeriodicValueProviderBase):
    """
    This class runs a function at a specified interval, and pushes its result to a json aggregator.

    Two-steps shutdown (`stop()`, and later `join()`) allows caller to efficiently and safely stop numerous pollers.
    """

    from multitimer import RepeatingTimer as _RepeatingTimer

    _RepeatingTimer.daemon = (
        True
    )  # Do not prevent process shutdown if we forgot to stop...

    def __init__(self, interval_s, task_func, json_aggregator):
        super().__init__(interval_s=interval_s, json_aggregator=json_aggregator)
        self._task_func = task_func
        self._multitimer = multitimer.MultiTimer(
            interval=interval_s,
            function=self._offloaded_run_task,
            count=-1,
            runonstart=True,
        )

    def _offloaded_run_task(self):
        """This function is meant to be called by secondary thread, to fetch and store data."""
        try:
            result = self._task_func()
            self._offloaded_add_data(result)
        except Exception:
            # TODO add logging/warnings
            import traceback

            traceback.print_exc()

    def start(self):
        """Launch the secondary thread for periodic polling."""
        super().start()
        self._multitimer.start()

    def stop(self):
        """Request the secondary thread to stop. If it's currently processing data,
        it will not stop immediately, and another data aggregation operation might happen."""
        super().stop()
        self._multitimer.stop()

    def join(self):
        """
        Wait for the secondary thread to really exit, after `stop()` was called.
        When this function returns, no more data will be sent to the json aggregator by this poller,
        until the next `start()`.

        This does NOT flush the underlying json aggregator!
        """
        super().join()
        timer_thread = self._multitimer._timer
        if timer_thread:
            assert timer_thread.stopevent.is_set()
            timer_thread.join()