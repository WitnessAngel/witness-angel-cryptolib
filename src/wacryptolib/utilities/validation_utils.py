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


def get_validation_micro_schemas(extended_json_format=False):  # FIXME push to docs?
    """
    Get python-schema compatible microschemas for basic types,
    for their python or extended-json representations.
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

        micro_schema_uid = {
            "$binary": {"base64": _micro_schema_base64, "subType": schema.Or("03", "04")}
        }  # Type 04 is the future!

        micro_schema_binary = {"$binary": {"base64": _micro_schema_base64, "subType": "00"}}

        micro_schema_int = schema.Or({"$numberInt": _micro_schema_integer}, {"$numberLong": _micro_schema_integer})

    class MicroSchemas:
        schema_uid = micro_schema_uid
        schema_binary = micro_schema_binary
        schema_int = micro_schema_int

    return MicroSchemas