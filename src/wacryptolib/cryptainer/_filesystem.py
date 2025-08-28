# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import os
from pathlib import Path

from wacryptolib.cryptainer import CRYPTAINER_TEMP_SUFFIX, OFFLOADED_PAYLOAD_FILENAME_SUFFIX, \
    OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER, PAYLOAD_CIPHERTEXT_LOCATIONS, _get_cryptainer_inline_ciphertext_value
from wacryptolib.exceptions import SchemaValidationError
from wacryptolib.utilities import dump_to_json_file, load_from_json_file


def _get_offloaded_file_path(cryptainer_filepath: Path):
    """We also support, discreetly, TEMPORARY cryptainers"""
    return cryptainer_filepath.parent.joinpath(
        cryptainer_filepath.name.rstrip(CRYPTAINER_TEMP_SUFFIX) + OFFLOADED_PAYLOAD_FILENAME_SUFFIX
    )


# FIXME handle "overwrite" argument to prevent
def dump_cryptainer_to_filesystem(cryptainer_filepath: Path, cryptainer: dict, offload_payload_ciphertext=True) -> None:
    """Dump a cryptainer to a file path, overwriting it if existing.

    If `offload_payload_ciphertext`, actual encrypted payload is dumped to a separate bytes file nearby the json-formatted cryptainer.
    """
    if offload_payload_ciphertext:
        offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
        payload_ciphertext = _get_cryptainer_inline_ciphertext_value(cryptainer)
        offloaded_file_path.write_bytes(payload_ciphertext)
        cryptainer = cryptainer.copy()  # Shallow copy, since we DO NOT touch original dict here!
        cryptainer["payload_ciphertext_struct"] = OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER
    dump_to_json_file(cryptainer_filepath, cryptainer)


def load_cryptainer_from_filesystem(cryptainer_filepath: Path, include_payload_ciphertext=True) -> dict:
    """Load a json-formatted cryptainer from a file path, potentially loading its offloaded ciphertext from a separate nearby bytes file.

    Field `payload_ciphertext` is only present in result dict if `include_payload_ciphertext` is True.
    """

    cryptainer = load_from_json_file(cryptainer_filepath)

    if include_payload_ciphertext:
        if (
            "payload_ciphertext_struct" not in cryptainer
        ):  # Early error before we have a chance to validate the whole cryptainer...
            raise SchemaValidationError("Cryptainer has no root field 'payload_ciphertext_struct'")

        if cryptainer["payload_ciphertext_struct"] == OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER:
            offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
            ciphertext_value = offloaded_file_path.read_bytes()
            cryptainer["payload_ciphertext_struct"] = dict(
                ciphertext_location=PAYLOAD_CIPHERTEXT_LOCATIONS.INLINE, ciphertext_value=ciphertext_value
            )
    else:
        del cryptainer["payload_ciphertext_struct"]  # Ensure that a nasty error pops if we try to access it

    return cryptainer


def delete_cryptainer_from_filesystem(cryptainer_filepath):
    """Delete a cryptainer file and its potential offloaded payload file."""
    os.remove(cryptainer_filepath)  # TODO - additional retries if file access error?
    offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
    if offloaded_file_path.exists():
        # We don't care about OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER here, we go the quick way
        os.remove(offloaded_file_path)


def get_cryptainer_size_on_filesystem(cryptainer_filepath):
    """Return the total size in bytes occupied by a cryptainer and its potential offloaded payload file."""
    size = cryptainer_filepath.stat().st_size  # FIXME - Might fail if file got deleted concurrently
    offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
    if offloaded_file_path.exists():
        # We don't care about OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER here, we go the quick way
        size += offloaded_file_path.stat().st_size
    return size