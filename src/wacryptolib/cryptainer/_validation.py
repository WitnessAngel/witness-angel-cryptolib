# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Union

import jsonschema
import schema as pythonschema
from bson import json_util
from jsonschema import validate as jsonschema_validate
from schema import Or, Optional as OptionalKey, And, Schema, Use

from wacryptolib.cipher import SUPPORTED_CIPHER_ALGOS
from wacryptolib.cryptainer import logger, LOCAL_KEYFACTORY_TRUSTEE_MARKER, CRYPTAINER_TRUSTEE_TYPES, CRYPTAINER_STATES, \
    CRYPTAINER_FORMAT, PAYLOAD_CIPHERTEXT_LOCATIONS, OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER, SHARED_SECRET_ALGO_MARKER
from wacryptolib.exceptions import SchemaValidationError
from wacryptolib.keygen import SUPPORTED_ASYMMETRIC_KEY_ALGOS, SUPPORTED_SYMMETRIC_KEY_ALGOS
from wacryptolib.signature import SUPPORTED_SIGNATURE_ALGOS
from wacryptolib.utilities import get_validation_micro_schemas, SUPPORTED_HASH_ALGOS


def _create_cryptostructure_schema(for_cryptainer: bool, for_cryptosig: bool, extended_json_format: bool):
    """Create validation schema for confs and cryptainers, as well as cryptosig conf/data.

    :param for_cryptainer: true to add "after processing" fields of cryptainer/cryptosig
    :param for_cryptosig: true to limit fields to those of media signatures (no ciphers are configured)
    :param extended_json_format: true if the schema is formatted as extended-json format (with $binary etc.)

    :return: a schema.
    """

    micro_schemas = get_validation_micro_schemas(extended_json_format=extended_json_format)

    extra_cryptainer = {}
    extra_payload_cipher_layer = {}
    extra_asymmetric_cipher_algo_block = {}

    trustee_schemas = Or(
        LOCAL_KEYFACTORY_TRUSTEE_MARKER,
        {
            "trustee_type": CRYPTAINER_TRUSTEE_TYPES.AUTHENTICATOR_TRUSTEE,
            "keystore_uid": micro_schemas.schema_uid,
            OptionalKey("keystore_owner"): str,
            # Optional for retrocompatibility only, may be left empty even if present!
        },
        {"trustee_type": CRYPTAINER_TRUSTEE_TYPES.JSONRPC_API_TRUSTEE, "jsonrpc_url": str},
    )

    payload_signature = {
        "payload_digest_algo": Or(*SUPPORTED_HASH_ALGOS),
        "payload_signature_algo": Or(*SUPPORTED_SIGNATURE_ALGOS),
        "payload_signature_trustee": trustee_schemas,
        OptionalKey("keychain_uid"): micro_schemas.schema_uid,
    }

    if for_cryptainer:
        extra_payload_signature = {
            OptionalKey("payload_digest_value"): micro_schemas.schema_binary,
            OptionalKey("payload_signature_struct"): {
                "signature_value": micro_schemas.schema_binary,
                "signature_timestamp_utc": micro_schemas.schema_int,
            },
        }
        payload_signature.update(extra_payload_signature)

        extra_cryptainer = {
            "cryptainer_state": Or(CRYPTAINER_STATES.STARTED, CRYPTAINER_STATES.FINISHED),
            "cryptainer_format": CRYPTAINER_FORMAT,
            "cryptainer_uid": micro_schemas.schema_uid,
            "cryptainer_metadata": Or(dict, None),
            "payload_ciphertext_struct": Or(
                {
                    "ciphertext_location": PAYLOAD_CIPHERTEXT_LOCATIONS.INLINE,
                    "ciphertext_value": micro_schemas.schema_binary,
                },
                OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER,
            ),
        }

        extra_payload_cipher_layer = {
            "payload_macs": {OptionalKey("tag"): micro_schemas.schema_binary},  # For now only "tag" is used
            "key_ciphertext": micro_schemas.schema_binary,
        }

        extra_asymmetric_cipher_algo_block = {"key_ciphertext": micro_schemas.schema_binary}

    ASYMMETRIC_CIPHER_ALGO_BLOCK = {
        "key_cipher_algo": Or(*SUPPORTED_ASYMMETRIC_KEY_ALGOS),
        "key_cipher_trustee": trustee_schemas,
        OptionalKey("keychain_uid"): micro_schemas.schema_uid,
    }

    _ALL_POSSIBLE_CIPHER_LAYERS_LIST = [ASYMMETRIC_CIPHER_ALGO_BLOCK]  # Built for recursive schema!
    ALL_POSSIBLE_CIPHER_LAYERS_LIST_NON_EMPTY = And(_ALL_POSSIBLE_CIPHER_LAYERS_LIST, len)

    SYMMETRIC_CIPHER_ALGO_BLOCK = Schema(
        {
            "key_cipher_algo": Or(*SUPPORTED_SYMMETRIC_KEY_ALGOS),
            "key_cipher_layers": ALL_POSSIBLE_CIPHER_LAYERS_LIST_NON_EMPTY,  # Must be non-empty!
            **extra_asymmetric_cipher_algo_block,
        },
        name="recursive_symmetric_cipher",
        as_reference=True,
    )
    _ALL_POSSIBLE_CIPHER_LAYERS_LIST.append(SYMMETRIC_CIPHER_ALGO_BLOCK)

    def validate_shared_secret_threshold(shared_secret_struct):
        threshold = shared_secret_struct["key_shared_secret_threshold"]
        if not isinstance(threshold, int):  # It's an extended-json payload
            threshold = json_util.object_hook()
        if threshold < 1:
            raise ValueError("Shared secret threshold must be strictly positive")
        if threshold > len(shared_secret_struct["key_shared_secret_shards"]):
            raise ValueError("Shared secret threshold can't be greater than number of shards")
        return True

    SHARED_SECRET_CRYPTAINER_BLOCK = Schema(
        And(
            {
                "key_cipher_algo": SHARED_SECRET_ALGO_MARKER,
                "key_shared_secret_shards": [{"key_cipher_layers": ALL_POSSIBLE_CIPHER_LAYERS_LIST_NON_EMPTY}],
                "key_shared_secret_threshold": micro_schemas.schema_int,
            },
            validate_shared_secret_threshold,
        ),
        name="recursive_shared_secret",
        as_reference=True,
    )
    _ALL_POSSIBLE_CIPHER_LAYERS_LIST.append(SHARED_SECRET_CRYPTAINER_BLOCK)

    def _handle_payload_signatures_retrocompatibility(layer_dict):
        if "payload_signatures" in layer_dict and "payload_ciphertext_signatures" not in layer_dict:
            layer_dict["payload_ciphertext_signatures"] = layer_dict.pop("payload_signatures")  # Old naming
            ## print(">>>>>>>> WE convert legacy name 'payload_signatures' ->", layer_dict)
        return layer_dict

    full_schema_dict = {
        **extra_cryptainer,
        OptionalKey("payload_plaintext_signatures"): [payload_signature],  # PLAIN data signatures
        "payload_cipher_layers": And(
            [
                And(
                    Use(_handle_payload_signatures_retrocompatibility),
                    {
                        "payload_cipher_algo": Or(*SUPPORTED_CIPHER_ALGOS),
                        "payload_ciphertext_signatures": [payload_signature],  # Signatures AFTER encryption
                        **extra_payload_cipher_layer,
                        "key_cipher_layers": ALL_POSSIBLE_CIPHER_LAYERS_LIST_NON_EMPTY,
                    },
                )
            ],
            len,
        ),  # Must be non-empty!
        OptionalKey("keychain_uid"): micro_schemas.schema_uid,
    }

    if for_cryptosig:
        # Subset of cryptainer just for plaintext signatures (as config or as finished signature) !
        full_schema_dict = {"payload_plaintext_signatures": And([payload_signature], len)}  # MANDATORY HERE
        if for_cryptainer:
            _relevant_sig_fields = ["cryptainer_state", "cryptainer_format", "cryptainer_uid", "cryptainer_metadata"]
            full_schema_dict.update({k: v for (k, v) in full_schema_dict.items() if k in _relevant_sig_fields})

    return Schema(full_schema_dict)


# CONFIGURATION IN ORDER TO ENCRYPT DATA
CRYPTOCONF_SCHEMA_PYTHON = _create_cryptostructure_schema(
    for_cryptainer=False, for_cryptosig=False, extended_json_format=False
)
CRYPTOCONF_SCHEMA_JSON = _create_cryptostructure_schema(
    for_cryptainer=False, for_cryptosig=False, extended_json_format=True
).json_schema("cryptoconf_schema.json")

# CONTAINER OF ENCRYPTED DATA
CRYPTAINER_SCHEMA_PYTHON = _create_cryptostructure_schema(
    for_cryptainer=True, for_cryptosig=False, extended_json_format=False
)
CRYPTAINER_SCHEMA_JSON = _create_cryptostructure_schema(
    for_cryptainer=True, for_cryptosig=False, extended_json_format=True
).json_schema("cryptainer_schema.json")

# CONFIGURATION IN ORDER TO ONLY SIGN DATA
SIGCONF_SCHEMA_PYTHON = _create_cryptostructure_schema(
    for_cryptainer=False, for_cryptosig=True, extended_json_format=False
)
SIGCONF_SCHEMA_JSON = _create_cryptostructure_schema(
    for_cryptainer=False, for_cryptosig=True, extended_json_format=True
).json_schema("sig_schema.json")

# CONTAINER OF SIGNATURES FOR DATA
SIGAINER_SCHEMA_PYTHON = _create_cryptostructure_schema(
    for_cryptainer=True, for_cryptosig=True, extended_json_format=False
)
SIGAINER_SCHEMA_JSON = _create_cryptostructure_schema(
    for_cryptainer=True, for_cryptosig=True, extended_json_format=True
).json_schema("sig_schema.json")


def _validate_data_tree(data_tree: dict, validation_schema: Union[dict, Schema]):  # Fixme why call it "valid_schema"?
    """Allows the validation of a data_tree with a pythonschema or jsonschema

    :param data_tree: cryptainer or cryptoconf to validate
    :param valid_schema: validation scheme
    """
    if isinstance(validation_schema, Schema):
        # we use the python schema module
        try:
            validation_schema.validate(data_tree)
        except pythonschema.SchemaError as exc:
            raise SchemaValidationError("Error validating data tree with python-schema: {}".format(exc)) from exc

    else:
        # we use the json schema module
        assert isinstance(validation_schema, dict)
        try:
            jsonschema_validate(instance=data_tree, schema=validation_schema)
        except jsonschema.exceptions.ValidationError as exc:
            raise SchemaValidationError("Error validating data tree with json-schema: {}".format(exc)) from exc


def check_cryptoconf_sanity(cryptoconf: dict, jsonschema_mode=False):
    """Validate the format of an encryption config.

    :param jsonschema_mode: If True, the cryptoconf must have been loaded as raw json
           (with $binary, $numberInt and such) and will be checked using a jsonschema validator.
    """

    schema = CRYPTOCONF_SCHEMA_JSON if jsonschema_mode else CRYPTOCONF_SCHEMA_PYTHON
    _validate_data_tree(data_tree=cryptoconf, validation_schema=schema)


def check_cryptainer_sanity(cryptainer: dict, jsonschema_mode=False):
    """Validate the format of a cryptainer.

    :param jsonschema_mode: If True, the cryptainer must have been loaded as raw json
           (with $binary, $numberInt and such) and will be checked using a jsonschema validator.
    """

    schema = CRYPTAINER_SCHEMA_JSON if jsonschema_mode else CRYPTAINER_SCHEMA_PYTHON
    _validate_data_tree(data_tree=cryptainer, validation_schema=schema)


def check_sigconf_sanity(cryptoconf: dict, jsonschema_mode=False):
    """Validate the format of a plaintext signature config.

    :param jsonschema_mode: If True, the sigconf must have been loaded as raw json
           (with $binary, $numberInt and such) and will be checked using a jsonschema validator.
    """

    schema = SIGCONF_SCHEMA_JSON if jsonschema_mode else SIGCONF_SCHEMA_PYTHON
    _validate_data_tree(data_tree=cryptoconf, validation_schema=schema)


def check_sigainer_sanity(cryptoconf: dict, jsonschema_mode=False):
    """Validate the format of a plaintext signature file.

    :param jsonschema_mode: If True, the sigainer must have been loaded as raw json
           (with $binary, $numberInt and such) and will be checked using a jsonschema validator.
    """

    schema = SIGAINER_SCHEMA_JSON if jsonschema_mode else SIGAINER_SCHEMA_PYTHON
    _validate_data_tree(data_tree=cryptoconf, validation_schema=schema)
