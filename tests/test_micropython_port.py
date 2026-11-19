# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests of the MicroPython flightbox port (reimplementations/micropython/), run with CPython: they cover the logic
of its own modules, not what differs on a MicroPython interpreter (builtins, stdlib stubs of lib/, memory limits)."""

import ast
import importlib
import importlib.util
import logging
import sys
import uuid
from pathlib import Path

import pytest

from wacryptolib.shared_secret import recombine_secret_from_shards

REPOSITORY_DIR = Path(__file__).resolve().parents[1]
MICROPYTHON_DIR = REPOSITORY_DIR / "reimplementations" / "micropython"


def _load_module_from_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# UUID STUB


@pytest.fixture(scope="module")
def uuid_stub():
    return _load_module_from_path("micropython_uuid_stub", MICROPYTHON_DIR / "stubs" / "uuid.py")


def test_micropython_uuid_stub_is_vendored_verbatim():
    assert (MICROPYTHON_DIR / "lib" / "uuid.py").read_bytes() == (MICROPYTHON_DIR / "stubs" / "uuid.py").read_bytes()


def test_micropython_uuid_stub_has_value_semantics(uuid_stub):
    reference = uuid.UUID("5e840838-7532-4b32-ba72-ccd17f7c923a")

    uid = uuid_stub.UUID(str(reference))
    assert (uid.bytes, uid.int, uid.hex, str(uid)) == (reference.bytes, reference.int, reference.hex, str(reference))

    for other in (
        uuid_stub.UUID(bytes=reference.bytes),
        uuid_stub.UUID(bytes=bytearray(reference.bytes)),
        uuid_stub.UUID(int=reference.int),
        uuid_stub.UUID(hex=reference.hex),
        uuid_stub.UUID("urn:uuid:{%s}" % reference),
    ):
        assert other is not uid
        assert other == uid and not (other != uid)
        assert hash(other) == hash(uid)
        assert isinstance(other.bytes, bytes)
        assert {uid: "value"}[other] == "value"  # A keystore dict is keyed by value, not by object identity

    different = uuid_stub.UUID(int=reference.int + 1)
    assert different != uid and different not in {uid: "value"}
    assert uid != str(reference) and uid != reference.bytes
    assert uuid_stub.UUID(int=0).bytes == bytes(16)  # The nil UUID is a valid value
    assert uuid_stub.uuid4() != uuid_stub.uuid4()

    for invalid_arguments in (dict(hex="1234"), dict(bytes=b"123"), dict(int=1 << 128), dict(int=-1)):
        with pytest.raises(ValueError):
            uuid_stub.UUID(**invalid_arguments)
    for invalid_arguments in (dict(), dict(hex=reference.hex, int=reference.int)):
        with pytest.raises(TypeError):
            uuid_stub.UUID(**invalid_arguments)


# PORT MODULES


@pytest.fixture(scope="module")
def port():
    """The port's "cryptainer" package, imported like its main.py does on CPython: stdlib modules and installed
    packages take precedence over the stubs and vendored copies of lib/."""
    added_paths = [str(MICROPYTHON_DIR / "src"), str(MICROPYTHON_DIR / "lib")]
    sys.path.extend(added_paths)
    try:
        yield importlib.import_module("cryptainer.flightbox_utilities_implementation")
    finally:
        for added_path in added_paths:
            sys.path.remove(added_path)


# SHAMIR SHARED SECRETS


SHAMIR_SOURCE_PATH = REPOSITORY_DIR / "src" / "wacryptolib" / "_crypto_backend" / "pycryptodome_secret_sharing.py"
SHAMIR_COPY_PATH = MICROPYTHON_DIR / "src" / "cryptainer" / "pycryptodome_secret_sharing.py"


def test_micropython_shamir_module_is_a_verbatim_copy():
    assert SHAMIR_COPY_PATH.read_bytes() == SHAMIR_SOURCE_PATH.read_bytes(), "Both Shamir modules must be kept equal"


def test_shamir_module_calls_builtin_constructors_without_keywords():
    # MicroPython's int(), bytes()... take no keyword arguments ("function doesn't take keyword arguments")
    tree = ast.parse(SHAMIR_SOURCE_PATH.read_text(encoding="utf8"))
    keyword_calls = [
        "%s() at line %d" % (node.func.id, node.lineno)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("int", "bytes", "bytearray", "str", "bin", "range")
        and node.keywords
    ]
    assert not keyword_calls, keyword_calls


@pytest.mark.parametrize("shard_count, threshold_count", [(1, 1), (2, 1), (2, 2), (5, 3)])
def test_micropython_shamir_shards_are_recombined_by_wacryptolib(port, shard_count, threshold_count):
    utilities = port.FlightboxUtilitiesImpl(logger=logging.getLogger("micropython_port"), keystore_data={})
    secret = b"A secret longer than a single chunk of 16 bytes"
    shards = utilities.split_secret_into_shards(secret, shard_count=shard_count, threshold_count=threshold_count)
    assert [shard[0] for shard in shards] == list(range(1, shard_count + 1))
    assert recombine_secret_from_shards(shards[-threshold_count:]) == secret
