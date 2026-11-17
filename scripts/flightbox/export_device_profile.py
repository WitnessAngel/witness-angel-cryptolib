#!/usr/bin/env python
# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Export a flightbox DEVICE PROFILE: a WA-CBOR document holding a cryptoconf and the raw public keys of its trustees,
which provisions an embedded encryptor (see docs/flightbox_specifications/flightbox_device_profile_specification.md).

    PYTHONPATH=src python scripts/flightbox/export_device_profile.py CRYPTOCONF_FILE KEYSTORE_POOL_DIR -o NAME.cbor

The cryptoconf file may be in Extended JSON or WA-CBOR (recognized like wacryptolib's document loader does). Public
keys are taken from the local keyfactory and the imported authenticator keystores of the filesystem keystore pool;
jsonrpc_api trustees are not supported. On any error, the script exits with a non-zero status and writes nothing.
"""

import argparse
import base64
import os
import sys
import tempfile
from pathlib import Path

DEVICE_PROFILE_FORMAT = "flightbox_device_profile_1.0"
DEVICE_PROFILE_EXTENSION = ".cbor"

LOCAL_KEYFACTORY_TRUSTEE_TYPE = "local_keyfactory"
AUTHENTICATOR_TRUSTEE_TYPE = "authenticator"
JSONRPC_API_TRUSTEE_TYPE = "jsonrpc_api"

SHARED_SECRET_ALGO_MARKER = "[SHARED_SECRET]"
ASYMMETRIC_KEY_ALGOS = ("RSA_OAEP", "ECIES_X25519", "ML_KEM_768")

# Algorithm OIDs of SubjectPublicKeyInfo structures, and expected raw key sizes
_RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"
_X25519_OID = "1.3.101.110"
_ML_KEM_768_OID = "2.16.840.1.101.3.4.4.2"
_EXPECTED_SPKI_ALGORITHM_OIDS = {
    "RSA_OAEP": _RSA_ENCRYPTION_OID,
    "ECIES_X25519": _X25519_OID,
    "ML_KEM_768": _ML_KEM_768_OID,
}
X25519_PUBLIC_KEY_SIZE = 32
ML_KEM_768_PUBLIC_KEY_SIZE = 1184


class DeviceProfileExportError(Exception):
    """The device profile can't be exported (invalid input, missing key, existing output...)."""


# DER PARSING OF PUBLIC KEYS #


def _read_der_tlv(data: bytes, position: int = 0):
    """Return (tag, value, next_position) of the DER item at `position`."""
    if position + 2 > len(data):
        raise DeviceProfileExportError("Truncated DER data")
    tag = data[position]
    length = data[position + 1]
    position += 2
    if length & 0x80:
        length_size = length & 0x7F
        if not 1 <= length_size <= 4 or position + length_size > len(data):
            raise DeviceProfileExportError("Invalid DER length")
        length = int.from_bytes(data[position : position + length_size], "big")
        position += length_size
    if position + length > len(data):
        raise DeviceProfileExportError("Truncated DER data")
    return tag, data[position : position + length], position + length


def _read_der_sequence_items(data: bytes) -> list:
    items = []
    position = 0
    while position < len(data):
        tag, value, position = _read_der_tlv(data, position)
        items.append((tag, value))
    return items


def _decode_der_oid(data: bytes) -> str:
    first, rest = data[0], data[1:]
    components = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    value = 0
    for byte in rest:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            components.append(value)
            value = 0
    return ".".join(str(component) for component in components)


def _decode_pem_public_key(public_key_pem: bytes) -> bytes:
    lines = public_key_pem.decode("ascii").strip().splitlines()
    if not lines or lines[0] != "-----BEGIN PUBLIC KEY-----" or lines[-1] != "-----END PUBLIC KEY-----":
        raise DeviceProfileExportError("Public key is not a PEM SubjectPublicKeyInfo")
    return base64.b64decode("".join(lines[1:-1]), validate=True)


def _strip_leading_zero_bytes(value: bytes) -> bytes:
    stripped = value.lstrip(b"\x00")
    if not stripped:
        raise DeviceProfileExportError("Null RSA integer")
    return stripped


def convert_public_key_pem_to_raw(public_key_pem: bytes, key_algo: str):
    """Return the raw form of a PEM SubjectPublicKeyInfo public key, as stored in device profiles: a dict of
    unsigned big-endian "modulus" and "public_exponent" bytes for RSA_OAEP, else the raw key bytes.

    The key is first loaded by wacryptolib, which checks that it is a valid key of that algorithm."""
    from wacryptolib.keygen import load_asymmetric_key_from_pem_bytestring

    load_asymmetric_key_from_pem_bytestring(public_key_pem, key_algo=key_algo)  # Validation only

    spki_tag, spki, _ = _read_der_tlv(_decode_pem_public_key(public_key_pem))
    spki_items = _read_der_sequence_items(spki) if spki_tag == 0x30 else []
    if len(spki_items) != 2 or spki_items[0][0] != 0x30 or spki_items[1][0] != 0x03:
        raise DeviceProfileExportError("Malformed SubjectPublicKeyInfo of %s key" % key_algo)
    algorithm_items = _read_der_sequence_items(spki_items[0][1])
    if not algorithm_items or algorithm_items[0][0] != 0x06:
        raise DeviceProfileExportError("Malformed algorithm identifier of %s key" % key_algo)
    algorithm_oid = _decode_der_oid(algorithm_items[0][1])
    if algorithm_oid != _EXPECTED_SPKI_ALGORITHM_OIDS[key_algo]:
        raise DeviceProfileExportError("Unexpected algorithm OID %s for a %s key" % (algorithm_oid, key_algo))
    bit_string = spki_items[1][1]
    if not bit_string or bit_string[0] != 0:
        raise DeviceProfileExportError("Malformed public key bit string of %s key" % key_algo)
    key_bytes = bit_string[1:]

    if key_algo == "RSA_OAEP":
        rsa_tag, rsa_public_key, _ = _read_der_tlv(key_bytes)
        rsa_items = _read_der_sequence_items(rsa_public_key) if rsa_tag == 0x30 else []
        if len(rsa_items) != 2 or rsa_items[0][0] != 0x02 or rsa_items[1][0] != 0x02:
            raise DeviceProfileExportError("Malformed RSA public key")
        return dict(
            modulus=_strip_leading_zero_bytes(rsa_items[0][1]),
            public_exponent=_strip_leading_zero_bytes(rsa_items[1][1]),
        )

    expected_size = X25519_PUBLIC_KEY_SIZE if key_algo == "ECIES_X25519" else ML_KEM_768_PUBLIC_KEY_SIZE
    if len(key_bytes) != expected_size:
        raise DeviceProfileExportError("%s public key has %d bytes instead of %d" % (key_algo, len(key_bytes), expected_size))
    return key_bytes


# PROFILE BUILDING #


def get_trustee_identity(trustee: dict) -> tuple:
    """Identity of a trustee for key lookups, which ignores the informative "keystore_owner"."""
    trustee_type = trustee["trustee_type"]
    if trustee_type == AUTHENTICATOR_TRUSTEE_TYPE:
        return (trustee_type, trustee["keystore_uid"])
    if trustee_type == JSONRPC_API_TRUSTEE_TYPE:
        return (trustee_type, trustee["jsonrpc_url"])
    return (trustee_type,)


def iter_asymmetric_key_cipher_layers(cryptoconf: dict):
    """Yield the asymmetric key cipher layers of a cryptoconf, depth first, in cryptoconf order."""

    def _walk_key_cipher_layers(key_cipher_layers):
        for key_cipher_layer in key_cipher_layers:
            key_cipher_algo = key_cipher_layer["key_cipher_algo"]
            if key_cipher_algo == SHARED_SECRET_ALGO_MARKER:
                for shard_conf in key_cipher_layer["key_shared_secret_shards"]:
                    yield from _walk_key_cipher_layers(shard_conf["key_cipher_layers"])
            elif key_cipher_algo in ASYMMETRIC_KEY_ALGOS:
                yield key_cipher_layer
            else:  # Symmetric key cipher layer, whose sub-key is protected by its own key cipher layers
                yield from _walk_key_cipher_layers(key_cipher_layer["key_cipher_layers"])

    for payload_cipher_layer in cryptoconf["payload_cipher_layers"]:
        yield from _walk_key_cipher_layers(payload_cipher_layer["key_cipher_layers"])


def _get_trustee_keystore(keystore_pool_dir: Path, trustee: dict):
    from wacryptolib.keystore import FilesystemKeystorePool, ReadonlyFilesystemKeystore

    trustee_type = trustee["trustee_type"]
    if trustee_type == LOCAL_KEYFACTORY_TRUSTEE_TYPE:
        keystore_dir = keystore_pool_dir / FilesystemKeystorePool.LOCAL_KEYFACTORY_DIRNAME
        keystore_label = "local keyfactory"
    elif trustee_type == AUTHENTICATOR_TRUSTEE_TYPE:
        keystore_dir = (
            keystore_pool_dir
            / FilesystemKeystorePool.FOREIGN_KEYSTORES_DIRNAME
            / (FilesystemKeystorePool.FOREIGN_KEYSTORE_PREFIX + str(trustee["keystore_uid"]))
        )
        keystore_label = "authenticator keystore %s" % trustee["keystore_uid"]
    else:
        raise DeviceProfileExportError(
            "Trustees of type %r are not supported by device profile export" % trustee_type
        )
    if not keystore_dir.is_dir():
        raise DeviceProfileExportError("Missing %s in keystore pool %s" % (keystore_label, keystore_pool_dir))
    return ReadonlyFilesystemKeystore(keystore_dir), keystore_label


def build_device_profile(cryptoconf: dict, keystore_pool_dir) -> dict:
    """Return the device profile tree of a cryptoconf, with one public key entry per distinct (trustee identity,
    keychain uid, key algo) that its asymmetric key cipher layers use."""
    from wacryptolib.cryptainer import check_cryptoconf_sanity
    from wacryptolib.exceptions import KeyDoesNotExist

    keystore_pool_dir = Path(keystore_pool_dir)
    if not keystore_pool_dir.is_dir():
        raise DeviceProfileExportError("Keystore pool directory %s does not exist" % keystore_pool_dir)

    try:
        check_cryptoconf_sanity(cryptoconf)
    except Exception as exc:
        raise DeviceProfileExportError("Invalid cryptoconf: %s" % exc) from exc

    root_keychain_uid = cryptoconf.get("keychain_uid")
    if not root_keychain_uid:
        raise DeviceProfileExportError(
            "Device profiles require a cryptoconf with a root keychain_uid, so that every key can be provisioned"
        )

    trustee_public_keys = []
    seen_key_identifiers = set()
    for key_cipher_layer in iter_asymmetric_key_cipher_layers(cryptoconf):
        trustee = key_cipher_layer["key_cipher_trustee"]
        key_algo = key_cipher_layer["key_cipher_algo"]
        keychain_uid = key_cipher_layer.get("keychain_uid") or root_keychain_uid
        key_identifier = (get_trustee_identity(trustee), keychain_uid, key_algo)
        if key_identifier in seen_key_identifiers:
            continue
        seen_key_identifiers.add(key_identifier)

        keystore, keystore_label = _get_trustee_keystore(keystore_pool_dir, trustee)
        try:
            public_key_pem = keystore.get_public_key(keychain_uid=keychain_uid, key_algo=key_algo)
        except KeyDoesNotExist as exc:
            raise DeviceProfileExportError(
                "Missing %s public key of keychain %s in %s" % (key_algo, keychain_uid, keystore_label)
            ) from exc
        trustee_public_keys.append(
            dict(
                trustee=dict(trustee),
                keychain_uid=keychain_uid,
                key_algo=key_algo,
                public_key=convert_public_key_pem_to_raw(public_key_pem, key_algo=key_algo),
            )
        )

    return dict(
        device_profile_format=DEVICE_PROFILE_FORMAT,
        cryptoconf=cryptoconf,
        trustee_public_keys=trustee_public_keys,
    )


def get_device_profile_output_path(output_path) -> Path:
    """Check that an output path ends with ".cbor" in any letter case, and return it with that extension
    lowercased, the rest of the name being kept as typed."""
    output_path = Path(output_path)
    name = output_path.name
    extension = name[-len(DEVICE_PROFILE_EXTENSION) :]
    if len(name) <= len(DEVICE_PROFILE_EXTENSION) or not extension.isascii() or extension.lower() != DEVICE_PROFILE_EXTENSION:
        raise DeviceProfileExportError("Device profile file name must end with %r: %s" % (DEVICE_PROFILE_EXTENSION, name))
    return output_path.with_name(name[: -len(DEVICE_PROFILE_EXTENSION)] + DEVICE_PROFILE_EXTENSION)


def _write_file(output_path: Path, data: bytes, force: bool):
    if not force:
        with open(output_path, "xb") as output_file:  # Exclusive creation
            try:
                output_file.write(data)
            except BaseException:
                output_file.close()
                os.remove(output_path)
                raise
        return
    file_descriptor, temporary_path = tempfile.mkstemp(
        dir=os.path.dirname(os.path.abspath(output_path)), prefix=".device-profile-", suffix=".tmp"
    )
    try:
        with os.fdopen(file_descriptor, "wb") as output_file:
            output_file.write(data)
        os.replace(temporary_path, output_path)
    except BaseException:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)
        raise


def export_device_profile(cryptoconf_path, keystore_pool_dir, output_path, force=False) -> Path:
    """Export the device profile of a cryptoconf file (Extended JSON or WA-CBOR), and return the path written."""
    from wacryptolib.utilities import dump_to_cbor_bytes, load_from_document_file

    output_path = get_device_profile_output_path(output_path)
    if not force and os.path.lexists(output_path):
        raise DeviceProfileExportError("Output file %s already exists, use --force to overwrite it" % output_path)
    try:
        cryptoconf = load_from_document_file(cryptoconf_path)
    except Exception as exc:
        raise DeviceProfileExportError("Can't load cryptoconf %s: %s" % (cryptoconf_path, exc)) from exc
    if not isinstance(cryptoconf, dict):
        raise DeviceProfileExportError("Cryptoconf %s is not a map" % cryptoconf_path)
    device_profile = build_device_profile(cryptoconf, keystore_pool_dir=keystore_pool_dir)
    device_profile_bytes = dump_to_cbor_bytes(device_profile)
    try:
        _write_file(output_path, device_profile_bytes, force=force)
    except FileExistsError as exc:
        raise DeviceProfileExportError("Output file %s already exists, use --force to overwrite it" % output_path) from exc
    return output_path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Export a flightbox device profile (WA-CBOR) from a cryptoconf.")
    parser.add_argument("cryptoconf", help="cryptoconf file, in Extended JSON or WA-CBOR")
    parser.add_argument("keystore_pool", help="directory of a filesystem keystore pool holding the trustees' keys")
    parser.add_argument("-o", "--output", required=True, help="output device profile file, ending with .cbor")
    parser.add_argument("--force", action="store_true", help="overwrite the output file if it exists")
    args = parser.parse_args(argv)
    try:
        output_path = export_device_profile(args.cryptoconf, args.keystore_pool, args.output, force=args.force)
    except (DeviceProfileExportError, OSError) as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    print("Device profile written to %s" % output_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
