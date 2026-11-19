# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from contextlib import suppress
import os
from pathlib import Path

from wacryptolib.cryptainer import CRYPTAINER_TEMP_SUFFIX, OFFLOADED_PAYLOAD_FILENAME_SUFFIX, \
    OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER, PAYLOAD_CIPHERTEXT_LOCATIONS, _get_cryptainer_inline_ciphertext_value
from wacryptolib.exceptions import SchemaValidationError
from wacryptolib.utilities import DocumentFormat, dump_to_document_bytes, get_recognized_extension,     load_from_document_bytes


def _get_offloaded_file_path(cryptainer_filepath: Path):
    """We also support, discreetly, TEMPORARY cryptainers"""
    return cryptainer_filepath.parent.joinpath(
        _get_final_cryptainer_filename(cryptainer_filepath) + OFFLOADED_PAYLOAD_FILENAME_SUFFIX
    )


def _get_final_cryptainer_filename(cryptainer_filepath) -> str:
    """Return the filename of a cryptainer, without its potential temporary suffix.

    A single temporary suffix is removed, so "x.crypt.json~~" is the temporary file of "x.crypt.json~"; but since
    such a final filename would itself be taken for a temporary one, it must not be used for cryptainers."""
    filename = Path(cryptainer_filepath).name
    if filename.endswith(CRYPTAINER_TEMP_SUFFIX):
        filename = filename[: -len(CRYPTAINER_TEMP_SUFFIX)]
    return filename


def _write_bytes_or_delete_file(filepath: Path, data: bytes) -> None:
    """Write a whole file, and delete it if this write fails, so that no partial file remains.

    A file which couldn't even be opened for writing (e.g. a read-only existing one) is left untouched."""
    output_stream = open(filepath, mode="wb")
    try:
        with output_stream:  # Its closing may fail too (e.g. disk full when flushing)
            output_stream.write(data)
    except BaseException:
        with suppress(OSError):  # A cleanup failure must not replace the original error
            filepath.unlink(missing_ok=True)
        raise


def _get_written_cryptainer_file_format(cryptainer_filepath) -> str:
    """WA-CBOR for a filename (without temporary suffix) ending with ".cbor" in any letter case, else Extended JSON
    (".crypt.json", legacy ".crypt", and ad-hoc names without these suffixes)."""
    extension = get_recognized_extension(_get_final_cryptainer_filename(cryptainer_filepath))
    if extension in (".cbor", ".crypt.cbor"):
        return DocumentFormat.CBOR
    return DocumentFormat.JSON


# FIXME handle "overwrite" argument to prevent
def dump_cryptainer_to_filesystem(cryptainer_filepath: Path, cryptainer: dict, offload_payload_ciphertext=True) -> None:
    """Dump a cryptainer to a file path, overwriting it if existing.

    The cryptainer is written in WA-CBOR if the filename, without its potential temporary suffix "~", ends with
    ".cbor" (in any letter case), else in Extended JSON; it is written at the exact path given.

    If `offload_payload_ciphertext`, actual encrypted payload is dumped to a separate bytes file nearby the cryptainer.

    The payload file is written first, so that a cryptainer file never points to a missing or partial payload.
    If a write fails, the partial file and the payload file just written are deleted; but this is not an atomic
    replacement, so cryptainer files overwritten until then are lost.
    """
    cryptainer_filepath = Path(cryptainer_filepath)
    cryptainer_file_format = _get_written_cryptainer_file_format(cryptainer_filepath)
    if offload_payload_ciphertext:
        payload_ciphertext = _get_cryptainer_inline_ciphertext_value(cryptainer)
        cryptainer = cryptainer.copy()  # Shallow copy, since we DO NOT touch original dict here!
        cryptainer["payload_ciphertext_struct"] = OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER
    cryptainer_bytes = dump_to_document_bytes(cryptainer, format=cryptainer_file_format)  # Fails before any write
    offloaded_file_path = None
    if offload_payload_ciphertext:
        offloaded_file_path = _get_offloaded_file_path(cryptainer_filepath)
        _write_bytes_or_delete_file(offloaded_file_path, payload_ciphertext)
    try:
        _write_bytes_or_delete_file(cryptainer_filepath, cryptainer_bytes)
    except BaseException:
        if offloaded_file_path:  # Else orphan, since storage only lists cryptainer files
            with suppress(OSError):
                offloaded_file_path.unlink(missing_ok=True)
        raise


def load_cryptainer_from_filesystem(cryptainer_filepath: Path, include_payload_ciphertext=True) -> dict:
    """Load a cryptainer from a file path, potentially loading its offloaded ciphertext from a separate nearby bytes file.

    The cryptainer is read in the format given by the extension of its filename, without its potential temporary
    suffix "~" (Extended JSON for ".crypt.json" and legacy ".crypt", WA-CBOR for ".crypt.cbor", in any letter case),
    else in the format detected from its content.

    Field `payload_ciphertext` is only present in result dict if `include_payload_ciphertext` is True.
    """
    cryptainer_filepath = Path(cryptainer_filepath)
    cryptainer_bytes = cryptainer_filepath.read_bytes()
    cryptainer = load_from_document_bytes(
        cryptainer_bytes, filename=_get_final_cryptainer_filename(cryptainer_filepath)
    )

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