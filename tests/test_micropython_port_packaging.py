# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests of the packaging of the MicroPython flightbox port (reimplementations/micropython/): its vendored copies and
patches, its platform utilities, and a smoke run of the port whose cryptainers wacryptolib decrypts. The smoke run uses
CPython, plus the MicroPython interpreter of the WA_MICROPYTHON environment variable (or "micropython" in PATH) if any."""

import importlib
import importlib.util
import logging
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

REPOSITORY_DIR = Path(__file__).resolve().parents[1]
MICROPYTHON_DIR = REPOSITORY_DIR / "reimplementations" / "micropython"


def _load_module_from_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def port_utilities():
    """The port's platform utilities module, imported like its main.py does on CPython, lib/ after the stdlib."""
    added_paths = [str(MICROPYTHON_DIR / "src"), str(MICROPYTHON_DIR / "lib")]
    sys.path.extend(added_paths)
    try:
        yield importlib.import_module("cryptainer.flightbox_utilities_implementation")
    finally:
        for added_path in added_paths:
            sys.path.remove(added_path)


# UUID0


class _FakeTimeModule:
    def __init__(self, unix_time_ns, epoch_year=1970, has_time_ns=True, integer_time=False, clock_error=None):
        self._time_ns = unix_time_ns - (946684800 * 10**9 if epoch_year == 2000 else 0)  # Counted from the port's epoch
        self._epoch_year = epoch_year
        self._integer_time = integer_time
        self._clock_error = clock_error
        if has_time_ns:
            self.time_ns = self._get_time_ns

    def _get_time_ns(self):
        if self._clock_error:
            raise self._clock_error
        return self._time_ns

    def time(self):
        if self._clock_error:
            raise self._clock_error
        return self._time_ns // 10**9 if self._integer_time else self._time_ns / 10**9

    def gmtime(self, secs):
        assert secs == 0
        return (self._epoch_year, 1, 1, 0, 0, 0, 3, 1)


UNIX_TIME_NS = 1763600000123456789  # 2025-11-20, with sub-second digits


@pytest.mark.parametrize(
    "fake_time_kwargs, expected_tsi",
    [
        (dict(), UNIX_TIME_NS // 100000),  # Unix port, like CPython
        (dict(epoch_year=2000), UNIX_TIME_NS // 100000),  # Bare-metal port counting from 2000-01-01
        (dict(epoch_year=2000, has_time_ns=False, integer_time=True), UNIX_TIME_NS // 10**9 * 10000),
        (dict(has_time_ns=False), UNIX_TIME_NS // 100000),
        (dict(clock_error=OSError(19, "ENODEV")), 0),  # A zero time prefix without a usable clock
    ],
)
def test_micropython_uuid0_time_prefix_is_unix_time_on_every_port(port_utilities, monkeypatch, fake_time_kwargs,
                                                                   expected_tsi):
    monkeypatch.setattr(port_utilities, "time", _FakeTimeModule(UNIX_TIME_NS, **fake_time_kwargs))
    uid_bytes = port_utilities._generate_uuid0().bytes
    tsi = int.from_bytes(uid_bytes[:6], "big")
    assert abs(tsi - expected_tsi) <= 1  # Float rounding of time.time()
    assert uid_bytes[6:] != port_utilities._generate_uuid0().bytes[6:]  # 80 random bits
