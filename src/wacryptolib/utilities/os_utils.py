# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import os
from pathlib import PurePath



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
    """Returns True iff path is a proper filename: not empty, not "." or "..", and without path separators
    (nor drive, on Windows).

    This is a pure string check, which doesn't depend on the files existing on disk, nor on their letter case
    or symlinks. It doesn't check for forbidden characters or reserved filenames either."""
    path = os.fspath(path)
    if path in ("", ".", ".."):
        return False
    if any(separator in path for separator in ("/", os.sep, os.altsep) if separator):
        return False
    return PurePath(path).name == path  # E.g. rejects "C:" on Windows
