# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later
from typing import Sequence

from wacryptolib import _crypto_backend

# Expose these important utilities for the rest of the package:
from extjson import (UTF8_ENCODING, convert_to_extjson, convert_from_extjson, extjson_decoder_object_hook, load_from_json_bytes,
                     load_from_json_str, load_from_json_file, dump_to_json_str, dump_to_json_bytes, dump_to_json_file)

from .data_utils import split_as_chunks, recombine_chunks, do_split_secret_into_shards, do_recombine_secret_from_shards, pad_bytes_pkcs7, unpad_bytes_pkcs7
from .os_utils import is_file_basename, get_memory_rss_bytes, get_nice_size
from .time_utils import generate_uuid0, get_utc_now_date, is_datetime_tz_aware, check_datetime_is_tz_aware
from .validation_utils import validate_data_against_schema, get_validation_micro_schemas
from .workflow_utils import synchronized, catch_and_log_exception, TaskRunnerStateMachineBase, PeriodicTaskHandler

# We link generic data manipulation utilities to our crypto backend

''' OBSOLETED TODO REMOVE
def do_split_as_chunks(
    bytestring: bytes, *, chunk_size: int, must_pad: bool, accept_incomplete_chunk: bool = False, byte_pad_func
) -> list[bytes]:
    return do_split_as_chunks(
            bytestring, chunk_size=chunk_size, must_pad=must_pad, accept_incomplete_chunk=accept_incomplete_chunk,
            byte_pad_func=_crypto_backend.pad_bytes
    )

def recombine_chunks(chunks: Sequence[bytes], *, chunk_size: int, must_unpad: bool, byte_unpad_func) -> bytes:
    return recombine_chunks(chunks=chunks, chunk_size=chunk_size, must_unpad=must_unpad,
                            byte_unpad_func=_crypto_backend.unpad_bytes)
'''