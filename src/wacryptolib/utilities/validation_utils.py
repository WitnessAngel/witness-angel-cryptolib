# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import abc
import logging


import schema
from schema import SchemaError, Schema
from wacryptolib.exceptions import SchemaValidationError


def validate_data_against_schema(data_tree, schema: Schema):
    """
    Validate data against provided PYTHON-schema, and raise SchemaValidationError if problems occur.
    """
    try:
        schema.validate(data_tree)
    except SchemaError as exc:
        raise SchemaValidationError("Error validating data tree with python-schema: {}".format(exc)) from exc


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