# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import uuid
from datetime import datetime, timezone, timedelta
from threading import Lock

import pytest
import pytz

from wacryptolib._crypto_backend import get_random_bytes
from wacryptolib.utilities import (
    split_as_chunks,
    recombine_chunks,
    dump_to_json_bytes,
    dump_to_json_str,
    load_from_json_bytes,
    load_from_json_str,
    check_datetime_is_tz_aware,
    dump_to_json_file,
    load_from_json_file,
    generate_uuid0,
    get_utc_now_date,
    get_memory_rss_bytes,
    catch_and_log_exception,
    synchronized,
)
from wacryptolib.hash import SUPPORTED_HASH_ALGOS, hash_message


def test_hash_message():
    bytestring = get_random_bytes(1000)

    assert len(SUPPORTED_HASH_ALGOS) == 4  # For now

    for hash_algo in SUPPORTED_HASH_ALGOS:
        digest1 = hash_message(bytestring, hash_algo=hash_algo)
        assert 32 <= len(digest1) <= 64, len(digest1)
        digest2 = hash_message(bytestring, hash_algo=hash_algo)
        assert digest1 == digest2

    with pytest.raises(ValueError, match="Unsupported"):
        hash_message(bytestring, hash_algo="XYZ")
