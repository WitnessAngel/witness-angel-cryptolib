# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from datetime import datetime, timezone
from typing import Optional

import uuid0


def generate_uuid0(ts: Optional[float] = None):
    """
    Generate a random UUID partly based on Unix timestamp (not part of official "variants").

    Uses 6 bytes to encode the time and does not encode any version bits, leaving 10 bytes (80 bits) of random data.

    When just transmitting these UUIDs around, the stdlib "uuid" module does the job fine, no need for uuid0 lib.

    :param ts: optional timestamp to use instead of current time (if not falsey)
    :return: uuid0 object (subclass of UUID)
    """
    return uuid0.generate(ts)


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
