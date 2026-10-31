# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import abc
import logging


import schema
from schema import SchemaError, Schema
from wacryptolib.exceptions import SchemaValidationError


def summarize_validation_error_lines(lines, max_lines=10, max_line_length=120) -> str:
    """Build a bounded error message from validator lines, which may embed huge reprs of the validated data
    (payloads, ciphertexts...). Each line keeps its head (usually a field name) and its tail (usually the reason).

    Same for the lines list: python-schema puts the outer context first and the innermost cause LAST."""
    half = max_line_length // 2
    lines = [(line if len(line) <= max_line_length else line[:half] + " [...] " + line[-half:]) for line in lines]
    if len(lines) > max_lines:
        head_count = max_lines // 3
        tail_count = max_lines - head_count - 1  # One line is taken by the skip marker
        skipped_count = len(lines) - head_count - tail_count
        lines = lines[:head_count] + ["[... %d lines skipped]" % skipped_count] + lines[-tail_count:]
    return "\n".join(lines)


def summarize_python_schema_error(exc: SchemaError, max_lines=10) -> str:
    lines = exc.code.splitlines()
    if len(lines) > max_lines:
        # "Or(<schema>) did not validate <data>" lines only introduce the per-alternative causes that follow them,
        # and would push these causes (e.g. a "Wrong key" of a non-last alternative) out of the summary
        lines = [line for line in lines if not (line.startswith("Or(") and " did not validate " in line)] or lines
    return summarize_validation_error_lines(lines, max_lines=max_lines)


def validate_data_against_schema(data_tree, schema: Schema):
    """
    Validate data against provided PYTHON-schema, and raise SchemaValidationError if problems occur.
    """
    try:
        schema.validate(data_tree)
    except SchemaError as exc:
        # Not chained, else tracebacks would still dump the whole data tree
        raise SchemaValidationError(
            "Error validating data tree with python-schema: {}".format(summarize_python_schema_error(exc))
        ) from None


def get_validation_micro_schemas(extended_json_format=False):
    """
    Get python-schema compatible microschemas for basic types,
    for their python or extended-json representations.

    :param extended_json_format: If True, schemas validate extended JSON format (RELAXED mode).
                                  Both canonical ($binary) and relaxed ($uuid) formats are accepted
                                  for compatibility, but RELAXED is the default and expected format.
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

        # RELAXED mode (default) uses $uuid format with hex string (32 chars without dashes)
        _micro_schema_uuid_hex = schema.And(str, schema.Regex(r"^[0-9a-fA-F]{32}$"))

        # Support both RELAXED ($uuid) and CANONICAL ($binary) formats for UUIDs
        # RELAXED is the default and expected format
        micro_schema_uid = schema.Or(
            {"$uuid": _micro_schema_uuid_hex},  # RELAXED format (default)
            {"$binary": {"base64": _micro_schema_base64, "subType": schema.Or("03", "04")}},  # CANONICAL format
        )

        micro_schema_binary = {"$binary": {"base64": _micro_schema_base64, "subType": "00"}}

        # Support both RELAXED (plain int) and CANONICAL (wrapped) formats for integers
        # RELAXED is the default and expected format
        micro_schema_int = schema.Or(
            int,  # RELAXED format (default) - plain integers
            {"$numberInt": _micro_schema_integer},  # CANONICAL format
            {"$numberLong": _micro_schema_integer},  # CANONICAL format
        )

    class MicroSchemas:
        schema_uid = micro_schema_uid
        schema_binary = micro_schema_binary
        schema_int = micro_schema_int

    return MicroSchemas