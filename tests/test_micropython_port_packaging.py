# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests of the packaging of the MicroPython flightbox port (reimplementations/micropython/): its vendored copies and
patches, its platform utilities, and a smoke run of the port whose cryptainers wacryptolib decrypts. The smoke run uses
CPython, plus the MicroPython interpreter of the WA_MICROPYTHON environment variable (or "micropython" in PATH), if
any: e.g. WA_MICROPYTHON=/path/to/micropython (a command line, split on whitespace)."""

import importlib
import importlib.util
import json
import logging
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

REPOSITORY_DIR = Path(__file__).resolve().parents[1]
MICROPYTHON_DIR = REPOSITORY_DIR / "reimplementations" / "micropython"


def _load_module_from_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def port_utilities():
    """The port's platform utilities module, imported like its main.py does on CPython, lib/ after the stdlib."""
    added_paths = [str(MICROPYTHON_DIR / "src"), str(MICROPYTHON_DIR / "lib")]
    sys.path.extend(added_paths)
    try:
        yield importlib.import_module("cryptainer.flightbox_utilities_implementation")
    finally:
        for added_path in added_paths:
            sys.path.remove(added_path)


# UUID0


class _FakeTimeModule:
    def __init__(self, unix_time_ns, epoch_year=1970, has_time_ns=True, integer_time=False, clock_error=None):
        self._time_ns = unix_time_ns - (946684800 * 10**9 if epoch_year == 2000 else 0)  # Counted from the port's epoch
        self._epoch_year = epoch_year
        self._integer_time = integer_time
        self._clock_error = clock_error
        if has_time_ns:
            self.time_ns = self._get_time_ns

    def _get_time_ns(self):
        if self._clock_error:
            raise self._clock_error
        return self._time_ns

    def time(self):
        if self._clock_error:
            raise self._clock_error
        return self._time_ns // 10**9 if self._integer_time else self._time_ns / 10**9

    def gmtime(self, secs):
        assert secs == 0
        return (self._epoch_year, 1, 1, 0, 0, 0, 3, 1)


UNIX_TIME_NS = 1763600000123456789  # 2025-11-20, with sub-second digits


@pytest.mark.parametrize(
    "fake_time_kwargs, expected_tsi",
    [
        (dict(), UNIX_TIME_NS // 100000),  # Unix port, like CPython
        (dict(epoch_year=2000), UNIX_TIME_NS // 100000),  # Bare-metal port counting from 2000-01-01
        (dict(epoch_year=2000, has_time_ns=False, integer_time=True), UNIX_TIME_NS // 10**9 * 10000),
        (dict(has_time_ns=False), UNIX_TIME_NS // 100000),
        (dict(clock_error=OSError(19, "ENODEV")), 0),  # A zero time prefix without a usable clock
    ],
)
def test_micropython_uuid0_time_prefix_is_unix_time_on_every_port(port_utilities, monkeypatch, fake_time_kwargs,
                                                                   expected_tsi):
    monkeypatch.setattr(port_utilities, "time", _FakeTimeModule(UNIX_TIME_NS, **fake_time_kwargs))
    uid_bytes = port_utilities._generate_uuid0().bytes
    tsi = int.from_bytes(uid_bytes[:6], "big")
    assert abs(tsi - expected_tsi) <= 1  # Float rounding of time.time()
    assert uid_bytes[6:] != port_utilities._generate_uuid0().bytes[6:]  # 80 random bits


# VENDORED COPIES


@pytest.fixture(scope="module")
def vendoring_script():
    return _load_module_from_path("micropython_vendor_dependencies", MICROPYTHON_DIR / "vendor_dependencies.py")


def test_micropython_vendored_copies_are_verbatim(vendoring_script):
    copies = dict(vendoring_script.SHARED_SOURCES)
    for module_path in [*sorted((MICROPYTHON_DIR / "stubs").glob("*.py")), *vendoring_script.SHARED_MODULES]:
        copies[module_path] = MICROPYTHON_DIR / "lib" / module_path.name
    assert REPOSITORY_DIR / "src/wacryptolib/_crypto_backend/pycryptodome_secret_sharing.py" in copies
    stale_copies = [copy_path.relative_to(REPOSITORY_DIR).as_posix() for original_path, copy_path in copies.items()
                    if copy_path.read_bytes() != original_path.read_bytes()]
    assert not stale_copies, "Rerun vendor_dependencies.py to refresh %s" % stale_copies


def test_micropython_vendoring_patches_are_applied():
    git = shutil.which("git")
    if not git or not (REPOSITORY_DIR / ".git").exists():
        pytest.skip("Needs git and a repository checkout")
    patch_paths = sorted((MICROPYTHON_DIR / "patches").glob("*.patch"))
    assert patch_paths
    for patch_path in patch_paths:
        # Applying a patch in reverse only succeeds if lib/ contains its changes
        subprocess.run([git, "apply", "--reverse", "--check", "--directory",
                        (MICROPYTHON_DIR / "lib").relative_to(REPOSITORY_DIR).as_posix(), str(patch_path)],
                       cwd=REPOSITORY_DIR, check=True)


# SMOKE RUN OF THE PORT


# Run by CPython or MicroPython, so without f-strings nor star-unpacking; arguments: port dir, keys file, output file
PORT_DRIVER_SOURCE = r'''
import sys

port_dir, keys_path, output_path = sys.argv[1:4]
sys.path.insert(0, port_dir + "/src")
if sys.implementation.name == "micropython":
    sys.path.insert(1, port_dir + "/lib")
else:  # Like main.py: lib/ after the stdlib but ahead of site-packages
    import os, site
    site_dirs = [os.path.normcase(os.path.abspath(p)) for p in site.getsitepackages() + [site.getusersitepackages()]]
    lib_index = next((i for i, p in enumerate(sys.path) if os.path.normcase(os.path.abspath(p)) in site_dirs),
                     len(sys.path))
    sys.path.insert(lib_index, port_dir + "/lib")

import binascii
import json
import logging
from uuid import UUID

from extjson import dump_to_json_bytes
from cryptainer._flightbox import FlightBox
from cryptainer.flightbox_utilities_implementation import FlightboxUtilitiesImpl

with open(keys_path) as keys_file:
    keys = json.load(keys_file)
keystore_uid = UUID(bytes=binascii.unhexlify(keys["keystore_uid"]))
keychain_uid = UUID(bytes=binascii.unhexlify(keys["keychain_uid"]))
keystore_data = {keystore_uid: {keychain_uid: dict(n=int(keys["n"]), e=keys["e"],
                                                   x25519=binascii.unhexlify(keys["x25519"]))}}
flightbox = FlightBox(FlightboxUtilitiesImpl(logger=logging.getLogger("port"), keystore_data=keystore_data))


def asymmetric(key_cipher_algo):
    return dict(key_cipher_algo=key_cipher_algo,
                key_cipher_trustee=dict(trustee_type="authenticator", keystore_uid=keystore_uid))


def payload_layer(key_cipher_layers):
    return dict(payload_cipher_algo="AES_CBC", key_cipher_layers=key_cipher_layers, payload_ciphertext_signatures=[])


cryptoconfs = dict(
    rsa=[payload_layer([asymmetric("RSA_OAEP")])],
    nested=[
        payload_layer([asymmetric("ECIES_X25519"),
                       dict(key_cipher_algo="AES_CBC", key_cipher_layers=[asymmetric("RSA_OAEP")])]),
        payload_layer([asymmetric("ECIES_X25519")]),
    ],
    shamir=[payload_layer([dict(key_cipher_algo="[SHARED_SECRET]", key_shared_secret_threshold=2,
                                key_shared_secret_shards=[
                                    dict(key_cipher_layers=[asymmetric("RSA_OAEP")]),
                                    dict(key_cipher_layers=[asymmetric("ECIES_X25519")]),
                                    dict(key_cipher_layers=[asymmetric("ECIES_X25519"), asymmetric("RSA_OAEP")]),
                                ])])],
)
results = []
for name in sorted(cryptoconfs):
    cryptoconf = dict(keychain_uid=keychain_uid, payload_cipher_layers=cryptoconfs[name])
    cryptainer, secrets = flightbox.generate_cryptainer_base_and_secrets(
        cryptoconf, cryptainer_metadata=None if name == "rsa" else dict(name=name))
    results.append(dict(name=name, cryptainer=cryptainer, secrets=secrets))
with open(output_path, "wb") as output_file:
    output_file.write(dump_to_json_bytes(results))
'''


def _get_micropython_command():
    command = os.environ.get("WA_MICROPYTHON")  # E.g. the path of a unix port binary
    if command:
        return command.split()
    binary = shutil.which("micropython")
    return [binary] if binary else None


@pytest.fixture(scope="module")
def port_keystore_pool_and_keys():
    from wacryptolib.keystore import InMemoryKeystorePool, generate_keypair_for_storage

    convert_public_key_pem_to_raw = _load_module_from_path(
        "export_device_profile", REPOSITORY_DIR / "scripts" / "flightbox" / "export_device_profile.py"
    ).convert_public_key_pem_to_raw

    keystore_uid, keychain_uid = uuid.uuid4(), uuid.uuid4()
    keystore_pool = InMemoryKeystorePool()
    keystore_pool._register_fake_imported_storage_uids([keystore_uid])
    keystore = keystore_pool.get_foreign_keystore(keystore_uid)
    raw_keys = {}
    for key_algo in ("RSA_OAEP", "ECIES_X25519"):
        keypair = generate_keypair_for_storage(key_algo, keystore=keystore, keychain_uid=keychain_uid)
        raw_keys[key_algo] = convert_public_key_pem_to_raw(keypair["public_key"], key_algo=key_algo)
    keys = dict(
        keystore_uid=keystore_uid.hex,
        keychain_uid=keychain_uid.hex,
        n=str(int.from_bytes(raw_keys["RSA_OAEP"]["modulus"], "big")),
        e=int.from_bytes(raw_keys["RSA_OAEP"]["public_exponent"], "big"),
        x25519=raw_keys["ECIES_X25519"].hex(),
    )
    return keystore_pool, keys


@pytest.mark.parametrize("interpreter", ["cpython", "micropython"])
def test_micropython_port_cryptainers_are_decrypted_by_wacryptolib(interpreter, port_keystore_pool_and_keys, tmp_path):
    from wacryptolib.cipher import encrypt_bytestring
    from wacryptolib.cryptainer import CRYPTAINER_STATES, check_cryptainer_sanity, decrypt_payload_from_cryptainer
    from wacryptolib.utilities import load_from_json_bytes

    command = [sys.executable, "-I"] if interpreter == "cpython" else _get_micropython_command()
    if not command:
        pytest.skip("No MicroPython interpreter (set WA_MICROPYTHON, or put micropython in PATH)")
    keystore_pool, keys = port_keystore_pool_and_keys
    driver_path, keys_path, output_path = tmp_path / "driver.py", tmp_path / "keys.json", tmp_path / "output.json"
    driver_path.write_text(PORT_DRIVER_SOURCE, encoding="utf8")
    keys_path.write_text(json.dumps(keys), encoding="utf8")

    subprocess.run([*command, str(driver_path), str(MICROPYTHON_DIR), str(keys_path), str(output_path)],
                   check=True, timeout=600)

    results = load_from_json_bytes(output_path.read_bytes())
    assert [result["name"] for result in results] == ["nested", "rsa", "shamir"]
    payload = b"Some payload of the MicroPython port"
    for result in results:
        cryptainer, secrets = result["cryptainer"], result["secrets"]
        assert cryptainer["cryptainer_metadata"] == (None if result["name"] == "rsa" else dict(name=result["name"]))
        # Steps 2 and 3, which the port does not implement yet
        extracts = secrets["payload_cipher_layer_extracts"]
        assert len(extracts) == len(cryptainer["payload_cipher_layers"])
        ciphertext = payload
        for payload_cipher_layer, extract in zip(cryptainer["payload_cipher_layers"], extracts):
            cipherdict = encrypt_bytestring(ciphertext, cipher_algo=extract["cipher_algo"], key_dict=extract["symkey"])
            ciphertext = cipherdict.pop("ciphertext")
            payload_cipher_layer["payload_macs"] = cipherdict
        cryptainer["payload_ciphertext_struct"] = dict(ciphertext_location="inline", ciphertext_value=ciphertext)
        cryptainer["cryptainer_state"] = CRYPTAINER_STATES.FINISHED
        check_cryptainer_sanity(cryptainer)

        decrypted, error_report = decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)
        assert decrypted == payload, (result["name"], error_report)
