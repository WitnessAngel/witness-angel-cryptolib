# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Dumping and loading of document files, in Extended JSON or in WA-CBOR, with recognition of their format.
"""

import os
from typing import Optional

from extjson import dump_to_json_bytes, load_from_json_bytes

from .wacbor import check_document_tree, dump_to_cbor_bytes, load_from_cbor_bytes


class DocumentFormat:
    JSON = "json"  # Extended JSON, in RELAXED form when written
    CBOR = "cbor"  # WA-CBOR


DOCUMENT_FORMATS = (DocumentFormat.JSON, DocumentFormat.CBOR)

# Extensions recognized in any letter case, longest first since some end with others
RECOGNIZED_EXTENSIONS = (".crypt.json", ".crypt.cbor", ".crypt", ".json", ".cbor")

_TEMPORARY_SUFFIX = "~"  # Same as CRYPTAINER_TEMP_SUFFIX

_READ_FORMATS_BY_EXTENSION = {
    ".crypt.json": DocumentFormat.JSON,
    ".crypt.cbor": DocumentFormat.CBOR,
    ".crypt": DocumentFormat.JSON,  # Legacy cryptainers are always Extended JSON
    ".json": DocumentFormat.JSON,
    ".cbor": DocumentFormat.CBOR,
}

_UTF8_BOM = b"\xef\xbb\xbf"
_JSON_WHITESPACE = b" \t\n\r"
_SELF_DESCRIBED_CBOR_PREFIX = b"\xd9\xd9\xf7"


class DocumentFormatError(ValueError):
    """The format of a document can't be determined, or contradicts its filename."""


def get_recognized_extension(filename: str) -> Optional[str]:
    """Return, in lowercase, the longest recognized extension that `filename` ends with, matched in any
    letter case (`.crypt.json`, `.crypt.cbor`, `.crypt`, `.json`, `.cbor`), or None.

    A trailing temporary suffix "~" is NOT skipped."""
    filename = os.fspath(filename)
    for extension in RECOGNIZED_EXTENSIONS:
        tail = filename[-len(extension) :]
        if tail.isascii() and tail.lower() == extension:  # ASCII check, since some letters lowercase to ASCII
            return extension
    return None


def normalize_recognized_extension(filename: str) -> str:
    """Lowercase the longest recognized extension that `filename` ends with, if any, and leave the rest of the
    name untouched, e.g. "Clip.MP4.CRYPT.JSON" becomes "Clip.MP4.crypt.json". A trailing temporary suffix "~" is
    kept aside, so "x.CRYPT~" becomes "x.crypt~"."""
    filename = os.fspath(filename)
    temporary_suffix = ""
    if filename.endswith(_TEMPORARY_SUFFIX):
        filename, temporary_suffix = filename[: -len(_TEMPORARY_SUFFIX)], _TEMPORARY_SUFFIX
    extension = get_recognized_extension(filename)
    if extension:
        filename = filename[: -len(extension)] + extension
    return filename + temporary_suffix


def get_document_format_from_filename(filename) -> Optional[str]:
    """Return the format that a document file must have when read, according to its name (`.json`, `.crypt.json`
    and `.crypt` mean Extended JSON, `.cbor` and `.crypt.cbor` mean WA-CBOR, in any letter case), or None."""
    extension = get_recognized_extension(os.path.basename(os.fspath(filename)))
    return _READ_FORMATS_BY_EXTENSION.get(extension)


def _get_written_document_format_from_filename(filename) -> Optional[str]:
    extension = get_recognized_extension(os.path.basename(os.fspath(filename)))
    if extension in (".json", ".crypt.json"):
        return DocumentFormat.JSON
    if extension in (".cbor", ".crypt.cbor"):
        return DocumentFormat.CBOR
    return None  # Legacy ".crypt" doesn't give a format to written files


def _sniff_document_format(data) -> Optional[str]:
    if not data:
        return None
    if 0x80 <= data[0] <= 0xBF or bytes(data[:3]) == _SELF_DESCRIBED_CBOR_PREFIX:
        return DocumentFormat.CBOR
    position = len(_UTF8_BOM) if bytes(data[: len(_UTF8_BOM)]) == _UTF8_BOM else 0
    while position < len(data) and data[position] in _JSON_WHITESPACE:
        position += 1
    if position < len(data) and data[position] in b"{[":
        return DocumentFormat.JSON
    return None


def detect_document_format(data, filename=None) -> str:
    """Return the format of document bytes, given by the `filename` extension if any, else detected from the
    first significant byte; a content contradicting the extension raises DocumentFormatError."""
    expected_format = get_document_format_from_filename(filename) if filename else None
    detected_format = _sniff_document_format(data)
    if expected_format:
        if detected_format and detected_format != expected_format:
            raise DocumentFormatError(
                "Document file '%s' should be %s from its name, but its content looks like %s"
                % (filename, _get_format_label(expected_format), _get_format_label(detected_format))
            )
        return expected_format  # The parser will complain if the content is malformed
    if not detected_format:
        raise DocumentFormatError(
            "Format of document%s couldn't be detected from its content"
            % (" file '%s'" % filename if filename else "")
        )
    return detected_format


def _get_format_label(format):
    return {DocumentFormat.JSON: "Extended JSON", DocumentFormat.CBOR: "WA-CBOR"}[format]


def _check_document_format(format):
    if format not in DOCUMENT_FORMATS:
        raise ValueError("Unknown document format %r" % (format,))


def load_from_document_bytes(data, filename=None, format: Optional[str] = None):
    """Load a document tree from Extended JSON or WA-CBOR bytes, in the `format` given, or else per
    `detect_document_format()`."""
    if format:
        _check_document_format(format)
    else:
        format = detect_document_format(data, filename=filename)
    if format == DocumentFormat.CBOR:
        return load_from_cbor_bytes(data)
    return load_from_json_bytes(bytes(data))


def load_from_document_file(filepath, format: Optional[str] = None):
    """Same as `load_from_document_bytes`, but reads data from filesystem, at the exact path given."""
    with open(filepath, "rb") as f:
        data = f.read()
    return load_from_document_bytes(data, filename=os.path.basename(os.fspath(filepath)), format=format)


def dump_to_document_bytes(data, format: str) -> bytes:
    """Dump a document tree to bytes in the given format (library default writer of that format)."""
    _check_document_format(format)
    if format == DocumentFormat.CBOR:
        return dump_to_cbor_bytes(data)
    return dump_to_json_bytes(data)


def dump_to_document_file(filepath, data, format: Optional[str] = None) -> bytes:
    """Dump a document tree to a file, at the exact path given, and return the written bytes.

    The format is the one explicitly requested, or else the one given by a `.json` or `.cbor` extension
    (in any letter case). A contradiction between both, or the absence of both, raises DocumentFormatError
    without writing anything."""
    extension_format = _get_written_document_format_from_filename(filepath)
    if format:
        _check_document_format(format)
        if extension_format and extension_format != format:
            raise DocumentFormatError(
                "Document file '%s' can't be written as %s, since its extension implies %s"
                % (filepath, _get_format_label(format), _get_format_label(extension_format))
            )
    elif extension_format:
        format = extension_format
    else:
        raise DocumentFormatError(
            "No format requested for document file '%s', and its name has no .json or .cbor extension" % filepath
        )
    document_bytes = dump_to_document_bytes(data, format=format)  # Fully encoded before the file gets created
    with open(filepath, "wb") as f:
        f.write(document_bytes)
    return document_bytes


def convert_document_tree_to_bytes(data, target_format: str) -> bytes:
    """Dump a document tree to the target format, as part of a conversion between Extended JSON and WA-CBOR.

    Unlike `dump_to_document_bytes`, values that one of the formats can't carry faithfully are rejected
    for both target formats, with WaCborEncodingError."""
    _check_document_format(target_format)
    check_document_tree(data)
    return dump_to_document_bytes(data, format=target_format)


def convert_document_bytes(data, target_format: str, filename=None) -> bytes:
    """Convert document bytes, whose format is recognized per `detect_document_format()`, to the target format."""
    tree = load_from_document_bytes(data, filename=filename)
    return convert_document_tree_to_bytes(tree, target_format=target_format)
