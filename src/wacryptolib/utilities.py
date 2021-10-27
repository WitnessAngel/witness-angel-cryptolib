import abc
import importlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
import shutil
from typing import List, Optional, Sequence, Union, BinaryIO

import multitimer
import uuid0
from Crypto.Util.Padding import pad, unpad
from decorator import decorator

logger = logging.getLogger(__name__)

UTF8_ENCODING = "utf8"


### Private utilities ###


def get_utc_now_date():
    """Return current datetime with UTC timezone."""
    return datetime.now(tz=timezone.utc)


def check_datetime_is_tz_aware(dt):
    """Raise if datetime is naive regarding timezones."""
    is_aware = dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None
    if not is_aware:
        raise ValueError("Naive datetime was encountered: %s" % dt)


@decorator
def synchronized(func, self, *args, **kwargs):
    """
    Wraps the function call with a mutex locking on the expected "self._lock" mutex.
    """
    with self._lock:
        return func(self, *args, **kwargs)


@decorator
def catch_and_log_exception(f, *args, **kwargs):
    try:
        return f(*args, **kwargs)
    except Exception as exc:
        logger.error(f"Caught exception when calling {f!r}(): {exc!r}", exc_info=True)


def get_memory_rss_bytes():
    import psutil
    process = psutil.Process(os.getpid())
    rss = process.memory_info().rss  # in bytes
    return rss


def delete_filesystem_node_for_stream(stream: BinaryIO):
    """Deletes the corresponding filesystem node if it exists."""
    filename = getattr(stream, "name", None)
    if filename and os.path.exists(filename):  # Can't be false on Win32, since files are not deletable when open
        os.remove(filename)  # We let errors flow here!


def get_metadata_file_path(storage_folder: Path):  # FIXME move to AUTHENTICATOR and disambiguate wrt container's metadata!!
    """
    Return path of standard metadata file for key/container storage.
    """
    return storage_folder.joinpath(".metadata.json")


def safe_copy_directory(from_dir: Path, to_dir: Path, temp_prefix="__", **extra_params):
    """
    Copy a file tree to a destination directory (which must not exist) in a kinda-safe way,
    using a temporary directory and an atomic rename.

    `extra_params` are passed as keyword arguments to `shutil.copytree()`.
    """
    if to_dir.exists():
        raise FileExistsError("Target %s already exists" % to_dir)
    to_dir_tmp = to_dir.with_name(temp_prefix + to_dir.name)
    if to_dir_tmp.exists():
        shutil.rmtree(to_dir_tmp)
    try:
        shutil.copytree(from_dir, dst=to_dir_tmp, **extra_params)
    except Exception:
        if to_dir_tmp.exists():
            shutil.rmtree(to_dir_tmp)
        raise
    os.rename(to_dir_tmp, to_dir)



### Public utilities ###


#: Hash algorithms authorized for use with `hash_message()`
SUPPORTED_HASH_ALGOS = ["SHA256", "SHA512", "SHA3_256", "SHA3_512"]


def hash_message(message: bytes, hash_algo: str):
    """Hash a message with the selected hash algorithm, and return the hash as bytes."""
    if hash_algo not in SUPPORTED_HASH_ALGOS:
        raise ValueError("Unsupported hash algorithm %r" % hash_algo)
    module = importlib.import_module("Crypto.Hash.%s" % hash_algo)
    digest = module.new(message).digest()
    assert 32 <= len(digest) <= 64, len(digest)
    return digest


def consume_bytes_as_chunks(data: Union[bytes, BinaryIO], chunk_size: int):  # FIXME DOCUMENT AND TEST ME
    """Automatically deletes filesystem entry if it exists!"""
    if hasattr(data, "read"):  # File-like BinaryIO object
        while True:
            chunk = data.read(chunk_size)
            if not chunk:
                break;
            yield chunk
        data.close()
        delete_filesystem_node_for_stream(data)
    else:  # Object with a len()
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]  # TODO use memoryview to optimize?


def split_as_chunks(
        bytestring: bytes, *, chunk_size: int, must_pad: bool, accept_incomplete_chunk: bool = False
) -> List[bytes]:
    """Split a `bytestring` into chunks (or blocks)

        :param bytestring: element to be split into chunks
        :param chunk_size: size of a chunk in bytes
        :param must_pad: whether the bytestring must be padded first or not
        :param accept_incomplete_chunk: do not raise error if a chunk with a length != chunk_size is obtained

        :return: list of bytes chunks"""

    assert chunk_size > 0, chunk_size

    if must_pad:
        bytestring = pad(bytestring, block_size=chunk_size)
    if len(bytestring) % chunk_size and not accept_incomplete_chunk:
        raise ValueError("If no padding occurs, bytestring must have a size multiple of chunk_size")

    chunks_count = (len(bytestring) + chunk_size - 1) // chunk_size

    chunks = []

    for i in range(chunks_count):
        chunk = bytestring[i * chunk_size: (i + 1) * chunk_size]
        chunks.append(chunk)
    return chunks


def recombine_chunks(chunks: Sequence[bytes], *, chunk_size: int, must_unpad: bool) -> bytes:
    """Recombine chunks which were previously separated.

        :param chunks: sequence of bytestring parts
        :param chunk_size: size of a chunk in bytes (only used for error checking, when unpadding occurs)
        :param must_unpad: whether the bytestring must be unpadded after recombining, or not

        :return: initial bytestring"""
    bytestring = b"".join(chunks)
    if must_unpad:
        bytestring = unpad(bytestring, block_size=chunk_size)
    return bytestring


def dump_to_json_str(data, **extra_options):
    """
    Dump a data tree to a json representation as string.
    Supports advanced types like bytes, uuids, dates...
    """
    from bson.json_util import dumps, CANONICAL_JSON_OPTIONS

    sort_keys = extra_options.pop("sort_keys", True)

    json_str = dumps(data, sort_keys=sort_keys, json_options=CANONICAL_JSON_OPTIONS, **extra_options)
    return json_str


def load_from_json_str(data, **extra_options):
    """
    Load a data tree from a json representation as string.
    Supports advanced types like bytes, uuids, dates...
    """
    from bson.json_util import loads, CANONICAL_JSON_OPTIONS

    assert isinstance(data, str), data
    return loads(data, json_options=CANONICAL_JSON_OPTIONS, **extra_options)


def dump_to_json_bytes(data, **extra_options):
    """
    Same as `dump_to_json_str`, but returns UTF8-encoded bytes.
    """
    json_str = dump_to_json_str(data, **extra_options)
    return json_str.encode(UTF8_ENCODING)


def load_from_json_bytes(data, **extra_options):
    """
    Same as `load_from_json_str`, but takes UTF8-encoded bytes as input.
    """

    json_str = data.decode(UTF8_ENCODING)
    return load_from_json_str(data=json_str, **extra_options)


def dump_to_json_file(filepath, data, **extra_options):
    """
    Same as `dump_to_json_bytes`, but writes data to filesystem (and returns bytes too).
    """
    json_bytes = dump_to_json_bytes(data, **extra_options)
    with open(filepath, "wb") as f:
        f.write(json_bytes)
    return json_bytes


def load_from_json_file(filepath, **extra_options):
    """
    Same as `load_from_json_bytes`, but reads data from filesystem.
    """
    with open(filepath, "rb") as f:
        json_bytes = f.read()
    return load_from_json_bytes(json_bytes, **extra_options)


def generate_uuid0(ts: Optional[float] = None):
    """
    Generate a random UUID partly based on Unix timestamp (not part of official "variants").

    Uses 6 bytes to encode the time and does not encode any version bits, leaving 10 bytes (80 bits) of random data.

    :param ts: optional timestamp to use instead of current time (if not falsey)
    :return: uuid0 object (subclass of UUID)
    """
    return uuid0.generate(ts)


def split_as_formatted_data(first_data: bytes, second_data: bytes, block_size: int):
    """Split the sum of two data into formatted data (multiple of block size)

    :param block_size: size of which we want a multiple
    :param formatted_data: data whose length is a multiple of the block size

    :return: memory view of formatted data and remainder
    """
    assert block_size > 0, block_size
    full_data = first_data + second_data
    formatted_length = (len(full_data) // block_size) * block_size
    formatted_data = memoryview(full_data[0:formatted_length])
    remainder = full_data[formatted_length:]

    return formatted_data, remainder


class TaskRunnerStateMachineBase(abc.ABC):
    """
    State machine for all sensors/players, checking that the order of start/stop/join
    operations is correct.

    The two-steps shutdown (`stop()`, and later `join()`) allows caller to
    efficiently and safely stop numerous runners.
    """

    def __init__(self, **kwargs):  # Ignored exceeding kwargs here
        self._runner_is_started = False

    @property
    def is_running(self):
        return self._runner_is_started

    def start(self):
        """Start the periodic system which will poll or push the value."""
        if self._runner_is_started:
            raise RuntimeError("Can't start an already started runner")
        self._runner_is_started = True

    def stop(self):
        """Request the periodic system to stop as soon as possible."""
        if not self._runner_is_started:
            raise RuntimeError("Can't stop an already stopped runner")
        self._runner_is_started = False

    def join(self):
        """
        Wait for the periodic system to really finish running.
        Does nothing if periodic system is already stopped.
        """
        if self._runner_is_started:
            raise RuntimeError("Can't join an in-progress runner")


class PeriodicTaskHandler(TaskRunnerStateMachineBase):
    """
    This class runs a task at a specified interval, with start/stop/join controls.

    If `task_func` argument is not provided, then `_offloaded_run_task()` must be overridden by subclass.
    """

    from multitimer import RepeatingTimer as _RepeatingTimer

    # TODO make PR to ensure that multitimer is a DAEMON thread!
    assert hasattr(_RepeatingTimer, "daemon")
    _RepeatingTimer.daemon = True  # Do not prevent process shutdown if we forgot to stop...

    _task_func = None  # Might be overridden as a method too!

    def __init__(self, interval_s, count=-1, runonstart=True, task_func=None, **kwargs):
        super().__init__(**kwargs)
        self._interval_s = interval_s
        if task_func:  # Important
            self._task_func = task_func
        self._multitimer = multitimer.MultiTimer(
            interval=interval_s, function=self._offloaded_run_task, count=count, runonstart=runonstart
        )

    def _offloaded_run_task(self):
        """Method which will be run periodically by background thread,
           and which by default simply calls task_func() and returns the result.
        """
        return self._task_func()

    def start(self):
        """Launch the secondary thread for periodic task execution."""
        super().start()
        self._multitimer.start()

    def stop(self):
        """Request the secondary thread to stop. If it's currently processing data,
        it will not stop immediately, and another data aggregation operation might happen."""
        super().stop()
        self._multitimer.stop()

    def join(self):  # TODO - add a join timeout everywhere?
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
