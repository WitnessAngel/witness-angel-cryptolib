# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Upfront validation of the inputs of the flightbox core, kept compact for microcontrollers: wacryptolib relies on
the "schema" package for this, which is too heavy here.

Everything is checked before the first random draw: the cryptoconf against the grammar of the encryptor
specification, the subset implemented by this port, the nesting depths, the cryptainer metadata, and the
availability and sanity of every public key.
"""

from uuid import UUID

from ._flightbox import SHARED_SECRET_ALGO_MARKER, KEY_CIPHERTEXT_FORMAT_JSON, KEY_CIPHERTEXT_FORMATS


# Maximum key cipher nesting level (the "key_cipher_layers" of a payload cipher layer being at level 1), which
# bounds the recursion of the flightbox core; the encryptor specification requires at least 8
MAX_KEY_CIPHER_NESTING = 8

# Nesting levels of the cryptainer metadata, itself at level 1 (so that it also fits in WA-CBOR documents)
MAX_METADATA_NESTING = 63

_SYMMETRIC_CIPHER_ALGOS = ("AES_CBC", "AES_EAX", "CHACHA20_POLY1305")
_ASYMMETRIC_CIPHER_ALGOS = ("RSA_OAEP", "ECIES_X25519", "ML_KEM_768")

# Required and optional fields of each trustee type, besides "trustee_type"
_TRUSTEE_FIELDS = {
    "local_keyfactory": ((), ()),
    "authenticator": (("keystore_uid",), ("keystore_owner",)),
    "jsonrpc_api": (("jsonrpc_url",), ()),
}

_EXTENDED_JSON_KEYWORDS = (
    "$binary", "$uuid", "$date", "$numberInt", "$numberLong", "$numberDouble", "$numberDecimal", "$undefined"
)


class FlightboxError(RuntimeError):
    """Base of the errors of this port (a RuntimeError for compatibility with its previous versions)."""


class InvalidInputError(FlightboxError):
    """The cryptoconf or the cryptainer metadata violates the encryptor specification."""


class UnsupportedFeatureError(FlightboxError):
    """Valid input, but outside the subset implemented by this port."""


class NestingTooDeepError(FlightboxError):
    """Key cipher layers or cryptainer metadata are nested beyond the limits of this port."""


class MissingPublicKeyError(FlightboxError):
    """An asymmetric key cipher layer resolves to no public key."""


class KeyConstraintError(FlightboxError):
    """A public key violates the constraints of its algorithm."""


def _check_dict(value, required, optional, label):
    if not isinstance(value, dict):
        raise InvalidInputError("%s must be a dict" % label)
    for key in value:
        if key not in required and key not in optional:
            raise InvalidInputError("Unknown key %r in %s" % (key, label))
    for key in required:
        if key not in value:
            raise InvalidInputError("Missing key %r in %s" % (key, label))


def _check_non_empty_list(value, label):
    if type(value) is not list or not value:  # Tuples are rejected, like in wacryptolib
        raise InvalidInputError("%s must be a non-empty list" % label)


def _check_uuid(value, label):
    if not isinstance(value, UUID):  # Especially not its string representation
        raise InvalidInputError("%s must be a UUID" % label)


def _check_signature_confs(value, label):
    if type(value) is not list:
        raise InvalidInputError("%s must be a list" % label)
    if value:  # Nothing here can compute payload digests, nor request signatures (steps 2 and 3)
        raise UnsupportedFeatureError("Signatures are not supported, %s must be empty" % label)


def _check_algo(algo, known_algos, supported_algos, label):
    if algo not in known_algos:
        raise InvalidInputError("Unknown %s %r" % (label, algo))
    if algo not in supported_algos:
        raise UnsupportedFeatureError("Unsupported %s %r" % (label, algo))


def _check_trustee(trustee):
    trustee_type = trustee.get("trustee_type") if isinstance(trustee, dict) else None
    if not isinstance(trustee_type, str) or trustee_type not in _TRUSTEE_FIELDS:
        raise InvalidInputError("Trustee must be a dict with a known trustee_type")
    required, optional = _TRUSTEE_FIELDS[trustee_type]
    _check_dict(trustee, ("trustee_type",) + required, optional, "trustee")
    for key, value in trustee.items():
        if key == "keystore_uid":
            _check_uuid(value, key)
        elif not isinstance(value, str):
            raise InvalidInputError("Trustee field %s must be a string" % key)


def _check_key_cipher_layers(flightbox_utilities, key_cipher_layers, default_keychain_uid, level):
    if level > MAX_KEY_CIPHER_NESTING:
        raise NestingTooDeepError("Key cipher layers are nested beyond %d levels" % MAX_KEY_CIPHER_NESTING)
    _check_non_empty_list(key_cipher_layers, "key_cipher_layers")

    for key_cipher_layer in key_cipher_layers:
        if not isinstance(key_cipher_layer, dict):
            raise InvalidInputError("Key cipher layer must be a dict")
        key_cipher_algo = key_cipher_layer.get("key_cipher_algo")

        if key_cipher_algo == SHARED_SECRET_ALGO_MARKER:
            _check_dict(
                key_cipher_layer,
                ("key_cipher_algo", "key_shared_secret_threshold", "key_shared_secret_shards"),
                (),
                "shared secret layer",
            )
            shards = key_cipher_layer["key_shared_secret_shards"]
            _check_non_empty_list(shards, "key_shared_secret_shards")
            threshold = key_cipher_layer["key_shared_secret_threshold"]
            if type(threshold) is not int or not 1 <= threshold <= len(shards):  # A boolean is no integer here
                raise InvalidInputError("Shared secret threshold must be an integer between 1 and the shard count")
            for shard in shards:
                _check_dict(shard, ("key_cipher_layers",), (), "shared secret shard")
                _check_key_cipher_layers(
                    flightbox_utilities, shard["key_cipher_layers"], default_keychain_uid, level + 1
                )

        elif key_cipher_algo in _SYMMETRIC_CIPHER_ALGOS:
            _check_dict(key_cipher_layer, ("key_cipher_algo", "key_cipher_layers"), (), "symmetric key cipher layer")
            _check_algo(
                key_cipher_algo,
                _SYMMETRIC_CIPHER_ALGOS,
                flightbox_utilities.SUPPORTED_SYMMETRIC_CIPHER_ALGOS,
                "key_cipher_algo",
            )
            _check_key_cipher_layers(
                flightbox_utilities, key_cipher_layer["key_cipher_layers"], default_keychain_uid, level + 1
            )

        else:
            _check_algo(
                key_cipher_algo,
                _ASYMMETRIC_CIPHER_ALGOS,
                flightbox_utilities.SUPPORTED_ASYMMETRIC_CIPHER_ALGOS,
                "key_cipher_algo",
            )
            _check_dict(
                key_cipher_layer,
                ("key_cipher_algo", "key_cipher_trustee"),
                ("keychain_uid",),
                "asymmetric key cipher layer",
            )
            _check_trustee(key_cipher_layer["key_cipher_trustee"])
            if "keychain_uid" in key_cipher_layer:
                keychain_uid = key_cipher_layer["keychain_uid"]
                _check_uuid(keychain_uid, "keychain_uid")
            else:
                keychain_uid = default_keychain_uid
                if keychain_uid is None:
                    # The core would generate a random default keychain uid, which can't match any provisioned key
                    raise MissingPublicKeyError(
                        "No keychain_uid in asymmetric key cipher layer nor at cryptoconf root"
                    )
            # Raises if the trustee type is unsupported, or if the public key is missing or invalid
            flightbox_utilities.get_public_key(
                trustee=key_cipher_layer["key_cipher_trustee"], key_algo=key_cipher_algo, keychain_uid=keychain_uid
            )


def validate_cryptoconf(flightbox_utilities, cryptoconf):
    """Check the whole cryptoconf, and resolve the public key of each of its asymmetric key cipher layers."""
    _check_dict(cryptoconf, ("payload_cipher_layers",), ("payload_plaintext_signatures", "keychain_uid"), "cryptoconf")
    default_keychain_uid = cryptoconf.get("keychain_uid")
    if "keychain_uid" in cryptoconf:
        _check_uuid(default_keychain_uid, "keychain_uid")
    if "payload_plaintext_signatures" in cryptoconf:
        _check_signature_confs(cryptoconf["payload_plaintext_signatures"], "payload_plaintext_signatures")

    _check_non_empty_list(cryptoconf["payload_cipher_layers"], "payload_cipher_layers")
    for payload_cipher_layer in cryptoconf["payload_cipher_layers"]:
        _check_dict(
            payload_cipher_layer,
            ("payload_cipher_algo", "key_cipher_layers"),
            ("payload_ciphertext_signatures", "payload_signatures"),
            "payload cipher layer",
        )
        if ("payload_ciphertext_signatures" in payload_cipher_layer) == ("payload_signatures" in payload_cipher_layer):
            raise InvalidInputError(
                "Payload cipher layer must have exactly one of payload_ciphertext_signatures and payload_signatures"
            )
        for key in ("payload_ciphertext_signatures", "payload_signatures"):
            if key in payload_cipher_layer:
                _check_signature_confs(payload_cipher_layer[key], key)
        _check_algo(
            payload_cipher_layer["payload_cipher_algo"],
            _SYMMETRIC_CIPHER_ALGOS,
            flightbox_utilities.SUPPORTED_SYMMETRIC_CIPHER_ALGOS,
            "payload_cipher_algo",
        )
        _check_key_cipher_layers(
            flightbox_utilities, payload_cipher_layer["key_cipher_layers"], default_keychain_uid, 1
        )


def _check_metadata_tree(value, level):
    if isinstance(value, dict) or type(value) is list:
        if level > MAX_METADATA_NESTING:
            raise NestingTooDeepError("Cryptainer metadata is nested beyond %d levels" % MAX_METADATA_NESTING)
        if type(value) is list:
            for item in value:
                _check_metadata_tree(item, level + 1)
            return
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidInputError("Keys of cryptainer metadata must be strings, not %s" % type(key).__name__)
            _check_metadata_tree(item, level + 1)
        if len(value) == 1 and key in _EXTENDED_JSON_KEYWORDS:  # Would be read back as a typed value
            raise InvalidInputError("Extended JSON keyword %r is forbidden as single key of a metadata dict" % key)
    elif value is None or isinstance(value, (str, bytes, bool, UUID)):
        pass
    elif isinstance(value, int):
        if not -(1 << 63) <= value < (1 << 63):
            raise UnsupportedFeatureError("Integers of cryptainer metadata must fit in 64 signed bits")
    else:  # Floats, tuples, bytearrays, sets... which the JSON encoder of MicroPython might output as invalid JSON
        raise UnsupportedFeatureError("Unsupported type %s in cryptainer metadata" % type(value).__name__)


def validate_cryptainer_metadata(cryptainer_metadata):
    """Check that the metadata is None or a dict tree of portable types, see the encryptor specification."""
    if cryptainer_metadata is None:
        return
    if not isinstance(cryptainer_metadata, dict):
        raise InvalidInputError("Cryptainer metadata must be a dict or None")
    _check_metadata_tree(cryptainer_metadata, 1)


def validate_flightbox_inputs(flightbox_utilities, cryptoconf, cryptainer_metadata, key_ciphertext_format):
    """Check all the inputs of FlightBox.generate_cryptainer_base_and_secrets(), without any random draw."""
    if key_ciphertext_format != KEY_CIPHERTEXT_FORMAT_JSON:
        if key_ciphertext_format in KEY_CIPHERTEXT_FORMATS:
            raise UnsupportedFeatureError("Unsupported key ciphertext format %r" % (key_ciphertext_format,))
        raise InvalidInputError("Unknown key ciphertext format %r" % (key_ciphertext_format,))
    validate_cryptainer_metadata(cryptainer_metadata)
    validate_cryptoconf(flightbox_utilities, cryptoconf)
