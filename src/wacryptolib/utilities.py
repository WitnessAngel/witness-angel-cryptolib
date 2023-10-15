import abc
import logging
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from json import JSONDecodeError
from pathlib import Path
from typing import List, Optional, Sequence, Union, BinaryIO

import multitimer
import schema
import uuid0
from bson.binary import UuidRepresentation
from bson.json_util import dumps, loads, JSONOptions, JSONMode
from decorator import decorator
from schema import SchemaError, Schema

from wacryptolib import _crypto_backend
from wacryptolib.exceptions import SchemaValidationError

logger = logging.getLogger(__name__)

UTF8_ENCODING = "utf8"

WACRYPTOLIB_JSON_OPTIONS = JSONOptions(
    json_mode=JSONMode.CANONICAL,  # Preserve all type information
    uuid_representation=UuidRepresentation.STANDARD,  # Same as PythonLegacy
    tz_aware=True,  # All our serialized dates are UTC, not NAIVE
)


### Private utilities ###


def get_utc_now_date():
    """Return current datetime with UTC timezone."""
    return datetime.now(tz=timezone.utc)


def is_datetime_tz_aware(dt):
    return dt.utcoffset() is not None


def check_datetime_is_tz_aware(dt):
    """Raise if datetime is naive regarding timezones."""
    is_aware = is_datetime_tz_aware(dt)
    if not is_aware:
        raise ValueError("Naive datetime was encountered: %s" % dt)


@decorator
def synchronized(func, self, *args, **kwargs):
    """
    Wraps the function call with a mutex locking on the expected "self._lock" mutex.
    """
    with self._lock:
        return func(self, *args, **kwargs)


@contextmanager
def catch_and_log_exception(context_message):
    """Logs and stops any exception in the managed code block or the decorated function"""
    assert isinstance(context_message, str), context_message
    try:
        yield
    except Exception as exc:
        logger.critical("Abnormal exception caught in %s: %r", context_message, exc, exc_info=True)


def get_memory_rss_bytes():
    import psutil

    process = psutil.Process(os.getpid())
    rss = process.memory_info().rss  # in bytes
    return rss


def get_nice_size(size):  # FIXME TEST THIS
    """We're actually using KiB/MiB/... here"""
    filesize_units = ("B", "KB", "MB", "GB", "TB")
    for unit in filesize_units:
        if size < 1024.0:
            return "%1.0f %s" % (size, unit)
        size /= 1023.0
    return size


def is_file_basename(path):
    """Returns True iff path is a proper filename, without dots or path separators.

    Does not check for forbidden characters or reserved filenames."""
    return Path(path).resolve().name == str(path)


### Public utilities ###


#: Hash algorithms authorized for use with `hash_message()`
SUPPORTED_HASH_ALGOS = ["SHA256", "SHA512", "SHA3_256", "SHA3_512"]


def hash_message(message: bytes, hash_algo: str):
    """Hash a message with the selected hash algorithm, and return the hash as bytes."""
    if hash_algo not in SUPPORTED_HASH_ALGOS:
        raise ValueError("Unsupported hash algorithm %r" % hash_algo)
    hasher = _crypto_backend.get_hasher_instance(hash_algo)
    hasher.update(message)
    digest = hasher.digest()
    assert 32 <= len(digest) <= 64, len(digest)
    return digest


def consume_bytes_as_chunks(
    data: Union[bytes, BinaryIO], chunk_size: int
):  # FIXME RENAME (consume_io_bytes..), DOCUMENT AND TEST ME
    if hasattr(data, "read"):  # File-like BinaryIO object
        while True:
            # print("READING", chunk_size, "bytes of data")
            chunk = data.read(chunk_size)
            # print("READ", str(chunk))
            if not chunk:
                break
            yield chunk
        # DO NOT close/delete the file, e.g. it might come from CLI!
    else:  # Object with a len()
        for i in range(0, len(data), chunk_size):
            yield data[i : i + chunk_size]  # TODO use memoryview to optimize?


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
        bytestring = _crypto_backend.pad_bytes(bytestring, block_size=chunk_size)
    if len(bytestring) % chunk_size and not accept_incomplete_chunk:
        raise ValueError("If no padding occurs, bytestring must have a size multiple of chunk_size")

    chunks_count = (len(bytestring) + chunk_size - 1) // chunk_size

    chunks = []

    for i in range(chunks_count):
        chunk = bytestring[i * chunk_size : (i + 1) * chunk_size]
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
        bytestring = _crypto_backend.unpad_bytes(bytestring, block_size=chunk_size)
    return bytestring


def dump_to_json_str(data, **extra_options):
    """
    Dump a data tree to a json representation as string.
    Supports advanced types like bytes, uuids, dates...
    """
    sort_keys = extra_options.pop("sort_keys", True)
    json_str = dumps(data, sort_keys=sort_keys, json_options=WACRYPTOLIB_JSON_OPTIONS, **extra_options)
    return json_str


def load_from_json_str(data, **extra_options):
    """
    Load a data tree from a json representation as string.
    Supports advanced types like bytes, uuids, dates...

    Raises exceptions.ValidationError on loading error.
    """
    assert isinstance(data, str), data
    try:
        return loads(data, json_options=WACRYPTOLIB_JSON_OPTIONS, **extra_options)
    except JSONDecodeError as exc:
        raise SchemaValidationError("Invalid JSON string: %r" % exc) from exc


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

    When just transmitting these UUIDs around, the stdlib "uuid" module does the job fine, no need for uuid0 lib.

    :param ts: optional timestamp to use instead of current time (if not falsey)
    :return: uuid0 object (subclass of UUID)
    """
    return uuid0.generate(ts)


def gather_data_as_blocks(first_data: bytes, second_data: bytes, block_size: int):  # FIXME improve naming?
    """PRIVATE API

    Split the sum of two bytestrings between a data payload with a size multiple of block_size,
    and remainder.

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

    # TODO make PR upstream to ensure that multitimer is a DAEMON thread!
    assert hasattr(_RepeatingTimer, "daemon")
    _RepeatingTimer.daemon = True  # Do not prevent process shutdown if we forgot to stop...

    _task_func = None  # Might be overridden as a method too!

    def __init__(self, interval_s, count=-1, runonstart=True, task_func=None, **kwargs):
        super().__init__(**kwargs)
        self._interval_s = interval_s
        if task_func:  # Important
            self._task_func = task_func

        self._multitimer = multitimer.MultiTimer(
            interval=interval_s, function=self._private_launch_offloaded_run_task, count=count, runonstart=runonstart
        )

    def _private_launch_offloaded_run_task(self):
        """Wrapper to ensure that offloaded task will not be run if
        state machine has just been stopped concurrently"""
        if not self.is_running:  # pragma: no cover
            return  # In case of race condition (too hard to test)...
        return self._offloaded_run_task()

    def _offloaded_run_task(self):
        """Method which will be run periodically by background thread,
        and which by default simply calls task_func() and returns the result.

        MEANT TO BE OVERRIDDEN BY SUBCLASS
        """
        return self._task_func()

    def start(self):
        """Launch the secondary thread for periodic task execution."""
        super().start()
        self._multitimer.start()

    def stop(self):
        """Request the secondary thread to stop. If it's currently processing data,
        it will not stop immediately, and another offloaded operation might happen."""
        super().stop()
        self._multitimer.stop()

    def join(self):  # TODO - add a join timeout everywhere?
        """
        Wait for the secondary thread to really exit, after `stop()` was called.
        When this function returns, no more offloaded operation will happen,
        until the next `start()`.
        """
        super().join()
        timer_thread = self._multitimer._timer
        if timer_thread:
            assert timer_thread.stopevent.is_set()
            timer_thread.join()


# Validation-related utilities


def validate_data_against_schema(data_tree, schema: Schema):
    """
    Validate data against provided python-schema, and raise SchemaValidationError if problems occur.
    """
    try:
        schema.validate(data_tree)
    except SchemaError as exc:
        raise SchemaValidationError("Error validating data tree with python-schema: {}".format(exc)) from exc


def convert_native_tree_to_extended_json_tree(data):  # FIXME push to docs?
    """
    Turn a native python tree (including UUIDs, bytes etc.) into its representation
    as Pymongo extended json (with nested $binary, $numberInt etc.)
    """
    import json

    # Export to pymongo extended json format string
    json_str = dump_to_json_str(data)

    # Parse standard Json from string, without advanced type coercion
    data_tree = json.loads(json_str)

    return data_tree


def get_validation_micro_schemas(extended_json_format=False):  # FIXME push to docs?
    """
    Get python-schema compatible microschemas for basic types,
    for their python or extended-json representations.
    """
    import uuid

    micro_schema_uid = uuid.UUID  # BASE CLASS, not uuid0's subclass
    micro_schema_binary = bytes
    micro_schema_int = int

    if extended_json_format:
        _micro_schema_integer = schema.And(str, schema.Regex(r"^[+-]?\d+$"))

        _micro_schema_base64 = schema.And(
            str, schema.Regex(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$")
        )

        micro_schema_uid = {
            "$binary": {"base64": _micro_schema_base64, "subType": schema.Or("03", "04")}
        }  # Type 04 is the future!

        micro_schema_binary = {"$binary": {"base64": _micro_schema_base64, "subType": "00"}}

        micro_schema_int = schema.Or({"$numberInt": _micro_schema_integer}, {"$numberLong": _micro_schema_integer})

    class MicroSchemas:
        schema_uid = micro_schema_uid
        schema_binary = micro_schema_binary
        schema_int = micro_schema_int

    return MicroSchemas
