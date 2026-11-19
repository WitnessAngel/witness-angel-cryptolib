# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Support of the interoperability tests of the flightbox encryptors against wacryptolib (design D13): builds,
corpus helpers.

They drive the test driver (wa_flightbox_test_driver) and the CLI (wa_flightbox_encrypt_file_cli) of the builds
listed in WA_FLIGHTBOX_C_BUILD_DIR, separated by os.pathsep (":" on POSIX): directories holding these two tools,
that is CMake build directories of the C library configured with -DWA_BUILD_TOOLS=ON, and cargo target directories
of the Rust tools (such as reimplementations/rust/target/debug). Each build reports its implementation ("c" when it
does not say), its crypto backend and its document formats ("build-info" driver subcommand). Every test is skipped
when no build is given.

Run from the repository root, e.g.:
    WA_FLIGHTBOX_C_BUILD_DIR=build_mbedtls:build_wolfcrypt pytest reimplementations/c-language/tests/interop
"""

import json
import os
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path


INTEROP_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = INTEROP_DIR.parents[3]
COMPATIBILITY_ROOT = REPOSITORY_ROOT / "compatibility"
C_UNIT_TESTS_DIR = INTEROP_DIR.parent / "unit"

# Corpus helpers of wacryptolib's own compatibility tests, and the device profile helpers next to this file
for _path in (REPOSITORY_ROOT / "tests", INTEROP_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import _compatibility_corpus as corpus  # noqa: E402
import device_profile_test_helpers as profile_helpers  # noqa: E402

check_key_ciphertext_formats = corpus.check_key_ciphertext_formats

BUILD_DIR_ENVIRONMENT_VARIABLE = "WA_FLIGHTBOX_C_BUILD_DIR"
DRIVER_NAME = "wa_flightbox_test_driver"
CLI_NAME = "wa_flightbox_encrypt_file_cli"
DOCUMENT_FORMATS = ("json", "cbor")

# Bytes arguments of the driver are given in hex up to this length, else through a file (a single command line
# argument is limited to 128 KiB on Linux)
MAXIMUM_INLINE_BYTES_ARGUMENT_LENGTH = 16 * 1024


class CBuild:
    """A build directory of the C library or of the Rust tools, with its tools, implementation ("c" or "rust"),
    crypto backend and enabled document formats."""

    def __init__(self, build_dir: Path):
        self.build_dir = build_dir
        self.driver_path = self._find_executable(DRIVER_NAME)
        self.cli_path = self._find_executable(CLI_NAME)
        build_info = self.run_driver("build-info")
        # The C driver does not report its implementation
        self.implementation = build_info.get("implementation", "c")
        self.backend = build_info["backend"]
        self.document_formats = tuple(build_info["document_formats"])

    def _find_executable(self, name):
        for candidate in (self.build_dir / name, self.build_dir / (name + ".exe")):
            if candidate.is_file():
                return candidate
        raise RuntimeError(
            "%s not found in %s (C: configure with -DWA_BUILD_TOOLS=ON; Rust: build wa_flightbox_host_tools)"
            % (name, self.build_dir)
        )

    @property
    def identity(self):
        """What two builds must differ by to be worth comparing: (implementation, backend)."""
        return (self.implementation, self.backend)

    @property
    def is_c_implementation(self):
        return self.implementation == "c"

    @property
    def name(self):
        prefix = "" if self.is_c_implementation else self.implementation + "-"
        return "%s%s-%s" % (prefix, self.backend.lower(), "+".join(self.document_formats))

    def run_driver(self, *arguments) -> dict:
        """Run a driver subcommand, and return its JSON output (the subcommand ran, whatever its status).

        Arguments are strings (hex ones included) or paths; bytes are passed in hex, or through a temporary file
        ("@FILE") beyond the command line limits."""
        with tempfile.TemporaryDirectory() as temporary_dir:
            command = [str(self.driver_path)]
            for index, argument in enumerate(arguments):
                if isinstance(argument, bytes):
                    if len(argument) <= MAXIMUM_INLINE_BYTES_ARGUMENT_LENGTH:
                        argument = argument.hex()
                    else:
                        argument_path = Path(temporary_dir) / ("argument_%d.bin" % index)
                        argument_path.write_bytes(argument)
                        argument = "@" + str(argument_path)
                command.append(str(argument))
            process = subprocess.run(command, capture_output=True, timeout=600)
        assert process.returncode == 0, (command[1:4], process.returncode, process.stderr.decode(errors="replace"))
        return json.loads(process.stdout)

    def run_cli(self, *arguments, cwd=None, input_bytes=None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.cli_path), *map(str, arguments)], capture_output=True, cwd=cwd, input=input_bytes, timeout=600
        )

    def __repr__(self):
        return "<CBuild %s at %s>" % (self.name, self.build_dir)


@lru_cache(maxsize=None)
def get_c_builds() -> tuple:
    """The builds listed in WA_FLIGHTBOX_C_BUILD_DIR, in the given order (an error for a listed but unusable one)."""
    value = os.environ.get(BUILD_DIR_ENVIRONMENT_VARIABLE, "").strip()
    if not value:
        return ()
    return tuple(CBuild(Path(build_dir).resolve()) for build_dir in value.split(os.pathsep) if build_dir.strip())


def get_c_builds_by_identity() -> dict:
    """The first build of each (implementation, backend) having both document formats."""
    builds = {}
    for c_build in get_c_builds():
        if set(c_build.document_formats) == set(DOCUMENT_FORMATS):
            builds.setdefault(c_build.identity, c_build)
    return builds


# CORPUS HELPERS #


def load_corpus_cryptoconf(relative_path: str):
    """(cryptoconf, sidecar, keystore pool dir) of a corpus cryptoconf, e.g. "2026_current/05_shamir_authenticators.
    cryptoconf" (relative to compatibility/cryptoconfs)."""
    asset_path = COMPATIBILITY_ROOT / "cryptoconfs" / relative_path
    sidecar_path = corpus.get_sidecar_path(asset_path)
    sidecar = corpus.load_sidecar(sidecar_path)
    cryptoconf = corpus.load_document_asset(sidecar_path)
    pool_dir = corpus.resolve_relpath(sidecar_path, sidecar["keystore_pool"])
    return cryptoconf, sidecar, pool_dir


def has_signatures(cryptoconf: dict) -> bool:
    """Whether a cryptoconf has a payload plaintext signature or a payload ciphertext signature (legacy key name
    included), which the C encryptor rejects."""
    if cryptoconf.get("payload_plaintext_signatures"):
        return True
    return any(
        layer.get("payload_ciphertext_signatures") or layer.get("payload_signatures")
        for layer in cryptoconf["payload_cipher_layers"]
    )


@lru_cache(maxsize=None)
def get_valid_corpus_cryptoconfs() -> tuple:
    """Every valid cryptoconf of the corpus, all generations and both serializations of the WA-CBOR pairs, as sorted
    (profile name, path relative to compatibility/cryptoconfs) pairs. Names are "<generation without its year>_<asset
    stem>", plus "_cbor" or "_json" for an asset whose other serialization is also in the corpus."""
    cryptoconfs_dir = COMPATIBILITY_ROOT / "cryptoconfs"
    asset_paths = []
    for sidecar_path in corpus.iter_sidecar_paths(cryptoconfs_dir):
        if corpus.load_sidecar(sidecar_path)["expected_valid"]:
            asset_paths.append(corpus.get_asset_path(sidecar_path))
    stems = [(path.parent.name, path.name.split(".")[0]) for path in asset_paths]
    result = []
    for path, stem in zip(asset_paths, stems):
        generation, asset_stem = stem
        name = "%s_%s" % (generation.split("_", 1)[1], asset_stem)
        if stems.count(stem) > 1:
            name += "_" + ("cbor" if path.name.endswith(".cbor") else "json")
        result.append((name, path.relative_to(cryptoconfs_dir).as_posix()))
    names = [name for name, _relative_path in result]
    assert len(set(names)) == len(names), names
    return tuple(sorted(result))


def export_device_profile_bytes(cryptoconf: dict, keystore_pool_dir: Path) -> bytes:
    """A device profile made by the export script (which validates the cryptoconf and keys)."""
    from wacryptolib.utilities import dump_to_cbor_bytes

    export_script = profile_helpers.import_export_script()
    return dump_to_cbor_bytes(export_script.build_device_profile(cryptoconf, keystore_pool_dir))


def copy_keystore_pool_dir(pool_dir: Path, work_dir: Path) -> Path:
    """A fresh copy of a corpus pool directory, in work_dir."""
    import shutil

    target_dir = Path(work_dir) / ("pool-%d" % len(list(Path(work_dir).glob("pool-*"))))
    shutil.copytree(pool_dir, target_dir)
    return target_dir


def copy_keystore_pool(pool_dir: Path, work_dir: Path):
    """A FilesystemKeystorePool over a fresh copy of a corpus pool."""
    from wacryptolib.keystore import FilesystemKeystorePool

    return FilesystemKeystorePool(copy_keystore_pool_dir(pool_dir, work_dir))


def get_tree_shape(tree):
    """The shape of a document tree: maps and lists kept, scalars replaced by their type name (byte strings, UUIDs,
    datetimes and integers compared by type only)."""
    if isinstance(tree, dict):
        return {key: get_tree_shape(value) for key, value in tree.items()}
    if isinstance(tree, list):
        return [get_tree_shape(item) for item in tree]
    if isinstance(tree, str):
        return tree
    return type(tree).__name__
