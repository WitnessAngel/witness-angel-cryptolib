#!/usr/bin/env python
# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Produce RAW compatibility fixtures with an OLD wacryptolib, installed in the current (throwaway) environment.

    python -I generate_legacy_release.py --output-dir <new dir> --plaintexts-dir <corpus>/plaintexts

This script is run by build_legacy_generations.py, inside venvs of old releases (Python 3.9+): it must stay
compatible with all of them, only use their APIs (feature-detected), and never import anything from this repository.
It writes a keystore pool, cryptoconfs, cryptainers, signatures and cipherdicts with the release's own serializers,
plus a "report.json" describing them; corpus sidecars are added afterwards by the modern driver.
"""

import argparse
import inspect
import json
import platform
import tempfile
from pathlib import Path
from unittest import mock
from uuid import UUID

try:
    from importlib.metadata import version as get_distribution_version
except ImportError:  # pragma: no cover
    get_distribution_version = None

from wacryptolib import cryptainer as cryptainer_module
from wacryptolib.authenticator import initialize_authenticator
from wacryptolib.cipher import encrypt_bytestring
from wacryptolib.keygen import generate_symkey, load_asymmetric_key_from_pem_bytestring
from wacryptolib.keystore import (
    FilesystemKeystore,
    FilesystemKeystorePool,
    ReadonlyFilesystemKeystore,
    generate_keypair_for_storage,
)
from wacryptolib.signature import sign_message
from wacryptolib.utilities import dump_to_json_file

LOCAL_KEYCHAIN_UIDS = [UUID("0c0c0c0c-0000-4000-8000-00000000000%d" % idx) for idx in (1, 2, 3)]
LOCAL_KEY_ALGOS = ("RSA_OAEP", "RSA_PSS", "DSA_DSS", "ECC_DSS")
AUTHENTICATOR_KEY_ALGO = "RSA_OAEP"  # The only one that authenticators of these releases created
AUTHENTICATORS = [  # Same naming conventions as generate_current.py
    ("alice", "a11ce000-0000-4000-8000-000000000001"),
    ("bob", "b0b00000-0000-4000-8000-000000000002"),
    ("carol", "ca201000-0000-4000-8000-000000000003"),
]
KEYSTORE_PASSPHRASE_HINT = "Dummy compatibility passphrase, see the pool sidecar"
LOCAL = cryptainer_module.LOCAL_KEYFACTORY_TRUSTEE_MARKER
SHARED_SECRET = cryptainer_module.SHARED_SECRET_ALGO_MARKER


def get_library_version():
    if get_distribution_version:
        try:
            return get_distribution_version("wacryptolib")
        except Exception:  # pragma: no cover
            pass
    import wacryptolib

    return getattr(wacryptolib, "__version__", "unknown")


def get_dependency_versions():
    versions = {}
    for name in ("pycryptodome", "pymongo", "extjson", "schema"):
        try:
            versions[name] = get_distribution_version(name)
        except Exception:
            pass
    return versions


def get_crypto_backend_name():
    try:
        from wacryptolib._crypto_backend import BACKEND_NAME

        return BACKEND_NAME
    except ImportError:
        return "pycryptodome"  # The only backend of these releases


def authenticator_info(name, keystore_uid):
    return dict(
        name=name,
        keystore_uid=UUID(keystore_uid),
        keystore_owner="compat-%s" % name,
        passphrase="compat-%s-passphrase" % name,
        keychain_uid=UUID(keystore_uid[:-4] + "00c1"),
    )


def authenticator_layer(info):
    trustee = dict(trustee_type="authenticator", keystore_uid=info["keystore_uid"], keystore_owner=info["keystore_owner"])
    return dict(key_cipher_algo=AUTHENTICATOR_KEY_ALGO, key_cipher_trustee=trustee, keychain_uid=info["keychain_uid"])


def local_layer(key_cipher_algo="RSA_OAEP", keychain_uid=None):
    layer = dict(key_cipher_algo=key_cipher_algo, key_cipher_trustee=LOCAL)
    if keychain_uid:
        layer["keychain_uid"] = keychain_uid
    return layer


def signature(signature_algo, digest_algo, keychain_uid=None):
    conf = dict(payload_digest_algo=digest_algo, payload_signature_algo=signature_algo, payload_signature_trustee=LOCAL)
    if keychain_uid:
        conf["keychain_uid"] = keychain_uid
    return conf


def get_ciphertext_signatures_field():
    """Before 2024-08, the ciphertext signatures field was named "payload_signatures"."""
    for field in ("payload_ciphertext_signatures", "payload_signatures"):
        layer = dict(payload_cipher_algo="AES_CBC", key_cipher_layers=[local_layer()])
        layer[field] = []
        if is_cryptoconf_supported(dict(payload_cipher_layers=[layer])):
            return field
    raise RuntimeError("No known field name for ciphertext signatures")


def payload_layer(payload_cipher_algo, key_cipher_layers, signatures=()):
    layer = dict(payload_cipher_algo=payload_cipher_algo, key_cipher_layers=key_cipher_layers)
    layer[get_ciphertext_signatures_field()] = list(signatures)
    return layer


def is_cryptoconf_supported(cryptoconf):
    try:
        cryptainer_module.check_cryptoconf_sanity(cryptoconf)
        return True
    except Exception:
        return False


def build_cryptoconfs(authenticators):
    alice, bob, carol = authenticators
    candidates = [
        ("01_single_layer", 1, False, "Single AES_EAX payload layer, its key wrapped with a local RSA_OAEP key",
         dict(payload_cipher_layers=[payload_layer("AES_EAX", [local_layer()])])),
        ("02_ciphertext_signature", 2, False,
         "AES_CBC payload layer with a local RSA_OAEP key layer and a DSA_DSS signature",
         dict(payload_cipher_layers=[payload_layer("AES_CBC", [local_layer()], [signature("DSA_DSS", "SHA256")])])),
        ("03_multiple_payload_layers", 3, False,
         "Three payload layers (AES_EAX, AES_CBC, CHACHA20_POLY1305) with RSA_OAEP key layers of two keychains, and "
         "RSA_PSS and ECC_DSS signatures",
         dict(payload_cipher_layers=[
             payload_layer("AES_EAX", [local_layer()]),
             payload_layer("AES_CBC", [local_layer(keychain_uid=LOCAL_KEYCHAIN_UIDS[1])]),
             payload_layer("CHACHA20_POLY1305", [local_layer()], [
                 signature("RSA_PSS", "SHA512"), signature("ECC_DSS", "SHA3_256", LOCAL_KEYCHAIN_UIDS[1])]),
         ])),
        ("04_recursive_key_layers", 4, False,
         "AES_CBC payload layer whose key is wrapped by a local RSA_OAEP key, then by an AES_EAX key itself "
         "wrapped by another local RSA_OAEP key",
         dict(payload_cipher_layers=[payload_layer("AES_CBC", [
             local_layer(),
             dict(key_cipher_algo="AES_EAX", key_cipher_layers=[local_layer(keychain_uid=LOCAL_KEYCHAIN_UIDS[2])]),
         ], [signature("ECC_DSS", "SHA512")])])),
        ("05_shamir_authenticators", 5, True,
         "CHACHA20_POLY1305 payload layer whose key is wrapped by a local RSA_OAEP key, then split into a 2-of-3 "
         "Shamir shared secret over passphrase-protected authenticators, with an RSA_PSS signature",
         dict(payload_cipher_layers=[payload_layer("CHACHA20_POLY1305", [
             local_layer(),
             dict(key_cipher_algo=SHARED_SECRET, key_shared_secret_threshold=2, key_shared_secret_shards=[
                 dict(key_cipher_layers=[authenticator_layer(alice)]),
                 dict(key_cipher_layers=[authenticator_layer(bob)]),
                 dict(key_cipher_layers=[authenticator_layer(carol)]),
             ]),
         ], [signature("RSA_PSS", "SHA256")])])),
        ("06_plaintext_signature", 6, False,
         "Plaintext ECC_DSS signature, and AES_EAX payload layer with a local RSA_OAEP key layer and a DSA_DSS "
         "ciphertext signature",
         dict(payload_plaintext_signatures=[signature("ECC_DSS", "SHA256", LOCAL_KEYCHAIN_UIDS[2])],
              payload_cipher_layers=[payload_layer("AES_EAX", [local_layer()], [signature("DSA_DSS", "SHA512")])])),
    ]
    cryptoconfs = []
    for name, level, uses_authenticators, description, cryptoconf in candidates:
        if is_cryptoconf_supported(cryptoconf):  # E.g. no symmetric key layers before v0.11
            cryptoconfs.append(dict(name=name, level=level, uses_authenticators=uses_authenticators,
                                    description=description, cryptoconf=cryptoconf))
    return cryptoconfs


CRYPTAINER_SPECS = [  # (name, cryptoconf name, plaintext size, mode, cryptainer metadata, description)
    ("01_single_layer_empty_payload", "01_single_layer", 0, "inline", None, "Empty payload, inline"),
    ("02_signed_inline", "02_ciphertext_signature", 33, "inline", None, "Small signed payload, inline"),
    ("03_multiple_layers_offloaded_with_metadata", "03_multiple_payload_layers", 65539, "offloaded",
     {"compat_device": "compat-camera-1", "compat_index": 3}, "64 KiB payload, offloaded, with cryptainer metadata"),
    ("03_multiple_layers_streamed", "03_multiple_payload_layers", 4099, "streamed", None,
     "Payload encrypted by the streaming pipeline (offloaded)"),
    ("04_recursive_key_layers", "04_recursive_key_layers", 257, "inline", None,
     "Payload whose key goes through a symmetric key layer, inline"),
    ("05_shamir_authenticators", "05_shamir_authenticators", 4099, "inline", {"compat_device": "compat-recorder-2"},
     "Payload protected by a 2-of-3 Shamir shared secret over authenticators, inline, with cryptainer metadata"),
    ("06_plaintext_signature_offloaded", "06_plaintext_signature", 257, "offloaded", None,
     "Payload with plaintext and ciphertext signatures, offloaded"),
]


def call_with_keychain_uid(function, cryptoconf, keychain_uid, **kwargs):
    """Before v0.11, the default keychain UID was an argument instead of a cryptoconf field."""
    if "keychain_uid" in inspect.signature(function).parameters:
        return function(cryptoconf=cryptoconf, keychain_uid=keychain_uid, **kwargs)
    return function(cryptoconf=dict(cryptoconf, keychain_uid=keychain_uid), **kwargs)


def build_keystore_pool(pool_dir, authenticators, work_dir):
    pool_dir.mkdir()
    keystore_pool = FilesystemKeystorePool(pool_dir)
    local_keystore = keystore_pool.get_local_keyfactory()
    for keychain_uid in LOCAL_KEYCHAIN_UIDS:
        for key_algo in LOCAL_KEY_ALGOS:
            generate_keypair_for_storage(key_algo, keystore=local_keystore, keychain_uid=keychain_uid)

    for info in authenticators:
        authenticator_dir = work_dir / info["keystore_owner"]
        with mock.patch("wacryptolib.authenticator.generate_uuid0", return_value=info["keystore_uid"]):
            initialize_authenticator(authenticator_dir, keystore_owner=info["keystore_owner"],
                                     keystore_passphrase_hint=KEYSTORE_PASSPHRASE_HINT)
        generate_keypair_for_storage(AUTHENTICATOR_KEY_ALGO, keystore=FilesystemKeystore(authenticator_dir),
                                     keychain_uid=info["keychain_uid"], passphrase=info["passphrase"])
        # Import like the apps of the time did (later releases strip some sensitive metadata fields here)
        try:
            from wacryptolib.operations import import_keystore_from_path
        except ImportError:
            keystore_class = ReadonlyFilesystemKeystore
            if not hasattr(keystore_class, "export_to_keystore_tree"):  # Only on writable keystores in v0.9
                keystore_class = FilesystemKeystore
            keystore_tree = keystore_class(authenticator_dir).export_to_keystore_tree(include_private_keys=True)
            keystore_pool.import_foreign_keystore_from_keystore_tree(keystore_tree)
        else:
            import_keystore_from_path(keystore_pool, authenticator_dir, include_private_keys=True)
    return keystore_pool


def load_local_key(pool_dir, key_algo, private):
    keystore = ReadonlyFilesystemKeystore(pool_dir / "local_keyfactory")
    getter = keystore.get_private_key if private else keystore.get_public_key
    return load_asymmetric_key_from_pem_bytestring(getter(keychain_uid=LOCAL_KEYCHAIN_UIDS[0], key_algo=key_algo),
                                                   key_algo=key_algo)


def sign(message, signature_algo, private_key):
    parameters = inspect.signature(sign_message).parameters
    key_argument = "private_key" if "private_key" in parameters else "key"  # Renamed after v0.9
    return sign_message(message, signature_algo=signature_algo, **{key_argument: private_key})


def plaintext_name(size):
    return "p%08d.bin" % size


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--plaintexts-dir", required=True, type=Path)
    args = parser.parse_args(argv)

    output_dir = args.output_dir
    output_dir.mkdir()  # Must not exist yet
    for subdir in ("cryptoconfs", "cryptainers", "signatures", "cipherdicts"):
        (output_dir / subdir).mkdir()

    def read_plaintext(size):
        return (args.plaintexts_dir / plaintext_name(size)).read_bytes()

    authenticators = [authenticator_info(name, keystore_uid) for name, keystore_uid in AUTHENTICATORS]
    with tempfile.TemporaryDirectory() as work_dir:
        build_keystore_pool(output_dir / "pool", authenticators, Path(work_dir))
    pool_dir = output_dir / "pool"

    report = dict(
        library_version=get_library_version(),
        python_version=platform.python_version(),
        crypto_backend=get_crypto_backend_name(),
        dependency_versions=get_dependency_versions(),
        pool="pool",
        authenticators=[dict(name=info["name"], keystore_uid=str(info["keystore_uid"]),
                             keystore_owner=info["keystore_owner"], passphrase=info["passphrase"],
                             keychain_uid=str(info["keychain_uid"])) for info in authenticators],
        cryptoconfs=[], cryptainers=[], signatures=[], cipherdicts=[],
    )

    cryptoconfs = {}
    for spec in build_cryptoconfs(authenticators):
        cryptoconf = spec.pop("cryptoconf")
        if "keychain_uid" not in inspect.signature(cryptainer_module.encrypt_payload_into_cryptainer).parameters:
            cryptoconf = dict(cryptoconf, keychain_uid=LOCAL_KEYCHAIN_UIDS[0])
        cryptoconfs[spec["name"]] = cryptoconf
        dump_to_json_file(output_dir / "cryptoconfs" / (spec["name"] + ".cryptoconf"), cryptoconf)
        report["cryptoconfs"].append(dict(spec, file="cryptoconfs/%s.cryptoconf" % spec["name"]))

    keystore_pool = FilesystemKeystorePool(pool_dir)
    for name, cryptoconf_name, size, mode, cryptainer_metadata, description in CRYPTAINER_SPECS:
        if cryptoconf_name not in cryptoconfs:
            continue
        cryptoconf = {k: v for k, v in cryptoconfs[cryptoconf_name].items() if k != "keychain_uid"}
        cryptainer_path = output_dir / "cryptainers" / (name + cryptainer_module.CRYPTAINER_SUFFIX)
        if mode == "streamed":
            call_with_keychain_uid(
                cryptainer_module.encrypt_payload_and_stream_cryptainer_to_filesystem, cryptoconf,
                LOCAL_KEYCHAIN_UIDS[0], payload=read_plaintext(size), cryptainer_filepath=cryptainer_path,
                cryptainer_metadata=cryptainer_metadata, keystore_pool=keystore_pool)
        else:
            cryptainer = call_with_keychain_uid(
                cryptainer_module.encrypt_payload_into_cryptainer, cryptoconf, LOCAL_KEYCHAIN_UIDS[0],
                payload=read_plaintext(size), cryptainer_metadata=cryptainer_metadata, keystore_pool=keystore_pool)
            cryptainer_module.dump_cryptainer_to_filesystem(cryptainer_path, cryptainer,
                                                            offload_payload_ciphertext=(mode == "offloaded"))
        report["cryptainers"].append(dict(
            name=name, file="cryptainers/" + cryptainer_path.name, cryptoconf=cryptoconf_name,
            plaintext=plaintext_name(size), mode=mode, cryptainer_metadata=cryptainer_metadata,
            description=description))

    for signature_algo in ("RSA_PSS", "DSA_DSS", "ECC_DSS"):
        size = 257
        signature_path = output_dir / "signatures" / ("%s_%s.signature" % (signature_algo, plaintext_name(size)[:-4]))
        signature_dict = sign(read_plaintext(size), signature_algo, load_local_key(pool_dir, signature_algo, True))
        dump_to_json_file(signature_path, signature_dict)
        report["signatures"].append(dict(file="signatures/" + signature_path.name, signature_algo=signature_algo,
                                         plaintext=plaintext_name(size)))

    for cipher_algo, sizes in (("AES_CBC", (33, 4099)), ("AES_EAX", (33, 4099)), ("CHACHA20_POLY1305", (33, 4099)),
                               ("RSA_OAEP", (257,))):
        for size in sizes:
            if cipher_algo == "RSA_OAEP":
                symkey = None
                key_dict = dict(key=load_local_key(pool_dir, cipher_algo, False))
            else:
                symkey = key_dict = generate_symkey(cipher_algo)
            cipherdict = encrypt_bytestring(read_plaintext(size), cipher_algo=cipher_algo, key_dict=key_dict)
            cipherdict_path = output_dir / "cipherdicts" / ("%s_%s.cipherdict" % (cipher_algo, plaintext_name(size)[:-4]))
            dump_to_json_file(cipherdict_path, cipherdict)
            report["cipherdicts"].append(dict(
                file="cipherdicts/" + cipherdict_path.name, cipher_algo=cipher_algo, plaintext=plaintext_name(size),
                symkey={k: v.hex() for k, v in symkey.items()} if symkey else None,
                local_keychain_uid=str(LOCAL_KEYCHAIN_UIDS[0])))

    (output_dir / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf8")
    print("Legacy fixtures of wacryptolib %s written to %s" % (report["library_version"], output_dir))


if __name__ == "__main__":
    main()
