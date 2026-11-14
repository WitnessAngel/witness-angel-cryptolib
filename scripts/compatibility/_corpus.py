# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Write-side utilities of the compatibility/ corpus, shared by the generation scripts of this folder.

A generation is written into a hidden staging directory of the corpus, and only renamed into place once complete.
Existing generation directories are never touched: the corpus is frozen and append-only (see compatibility/README.md).
"""

import datetime
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT_DIR / "src"), str(ROOT_DIR / "tests")]  # Use the wacryptolib under test, not an installed one

import _compatibility_corpus as corpus  # noqa: E402
from _compatibility_corpus import CORPUS_DIR, SCHEMA_SUFFIX, SCHEMAS_DIR, SIDECAR_SUFFIX  # noqa: E402
from jsonschema import Draft202012Validator  # noqa: E402

# Directories of the corpus which are split into generations (plaintexts are shared by all generations)
GENERATION_KIND_DIRNAMES = ("keystores", "cipherdicts", "signatures", "cryptoconfs", "cryptainers")
PLAINTEXTS_DIRNAME = "plaintexts"
GENERATION_NAME_REGEX = r"^[0-9]{4}_[a-z0-9][a-z0-9._-]*$"
STAGING_DIR_PREFIX = ".staging-"


class GenerationAlreadyExists(Exception):
    """Raised when asked to write a generation of which a directory already exists in the corpus."""


def to_relpath(target_path: Path, sidecar_path: Path) -> str:
    """Return the POSIX path of `target_path` relative to the directory of `sidecar_path`."""
    return Path(os.path.relpath(target_path, sidecar_path.parent)).as_posix()


def get_library_commit():
    """Return the current git commit of the repository, or None if unavailable."""
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT_DIR, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def build_provenance(method: str, *, legacy_forms=None, notes=None, **overrides) -> dict:
    """Return a provenance block for fixtures produced right now, by default with the in-tree library."""
    from wacryptolib._crypto_backend import BACKEND_NAME

    provenance = dict(
        method=method,
        library_version=get_in_tree_library_version(),
        library_commit=get_library_commit(),
        python_version=platform.python_version(),
        crypto_backend=BACKEND_NAME,
        produced_on=datetime.date.today().isoformat(),
    )
    provenance.update(overrides)
    if legacy_forms:
        provenance["legacy_forms"] = sorted(legacy_forms)
    if notes:
        provenance["notes"] = notes
    return {key: value for key, value in provenance.items() if value is not None}


def get_in_tree_library_version() -> str:
    """The in-tree library is the development version of the next release declared in pyproject.toml."""
    pyproject = (ROOT_DIR / "pyproject.toml").read_text(encoding="utf8")
    return re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE).group(1) + "+dev"


def build_requirements(algorithms=(), pem_protections=()) -> dict:
    """Return a requirements block; "none" PEM protections are not requirements."""
    return dict(
        algorithms=sorted({algo.upper() for algo in algorithms}),
        pem_protections=sorted(set(pem_protections) - {"none"}),
    )


def dump_json_sidecar_bytes(sidecar: dict) -> bytes:
    """Sidecars are plain JSON, indented, with LF line endings, and keys in a stable order."""
    return (json.dumps(sidecar, indent=2, ensure_ascii=False) + "\n").encode("utf8")


def dump_extjson_asset_bytes(data, canonical=False) -> bytes:
    """Assets are serialized exactly like the library does (extended JSON, sorted keys)."""
    from wacryptolib.utilities import dump_to_json_bytes

    return dump_to_json_bytes(data, canonical=canonical) if canonical else dump_to_json_bytes(data)


def _write_file_atomically(path: Path, data: bytes):
    """Write a file through a temporary sibling, refusing to overwrite an existing file."""
    if path.exists():
        raise FileExistsError("Refusing to overwrite corpus file %s" % path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(".%s.tmp-%s" % (path.name, uuid.uuid4().hex[:8]))
    temp_path.write_bytes(data)
    os.rename(temp_path, path)  # Fails on Windows if the target appeared meanwhile, unlike os.replace()


class SidecarWriterMixin:
    """Build, validate and serialize sidecars; paths given to these methods are FINAL corpus paths."""

    corpus_dir: Path
    _registry = None

    def _get_registry(self):
        if self._registry is None:
            self._registry = corpus.load_schema_registry(self.corpus_dir / SCHEMAS_DIR.name)
        return self._registry

    def build_sidecar(
        self,
        *,
        asset_path: Path,
        fixture_kind: str,
        generation: str,
        description: str,
        provenance: dict,
        requirements: dict,
        asset_files_dir: Path = None,
        **fields
    ) -> dict:
        """Return a validated sidecar for the (final) `asset_path`, whose files are currently in `asset_files_dir`."""
        sidecar_path = corpus.get_sidecar_path(asset_path)
        schema_path = self.corpus_dir / SCHEMAS_DIR.name / (fixture_kind + SCHEMA_SUFFIX)
        current_asset_path = (asset_files_dir or asset_path.parent) / asset_path.name
        asset_sha256 = corpus.compute_asset_sha256(corpus.get_sidecar_path(current_asset_path))
        sidecar = {
            "$schema": to_relpath(schema_path, sidecar_path),
            "fixture_kind": fixture_kind,
            "generation": generation,
            "description": description,
            "provenance": provenance,
            "requirements": requirements,
            **fields,
            "asset_sha256": asset_sha256,
        }
        registry = self._get_registry()
        Draft202012Validator(registry.contents(fixture_kind + SCHEMA_SUFFIX), registry=registry).validate(sidecar)
        return sidecar


class PlaintextWriter(SidecarWriterMixin):
    """Add missing plaintexts to the shared plaintexts/ directory (existing ones are left untouched)."""

    def __init__(self, generation: str, corpus_dir: Path = CORPUS_DIR):
        self.generation = generation
        self.corpus_dir = Path(corpus_dir)
        self.plaintexts_dir = self.corpus_dir / PLAINTEXTS_DIRNAME

    @staticmethod
    def get_plaintext_name(size: int) -> str:
        return "p%08d.bin" % size

    def get_plaintext_path(self, size: int) -> Path:
        return self.plaintexts_dir / self.get_plaintext_name(size)

    def ensure_plaintext(self, size: int) -> Path:
        """Return the path of the plaintext of this size, generating it (and its sidecar) if missing."""
        plaintext_path = self.get_plaintext_path(size)
        sidecar_path = corpus.get_sidecar_path(plaintext_path)
        if plaintext_path.exists():
            assert sidecar_path.exists(), sidecar_path
            return plaintext_path

        seed = ("wacryptolib-compatibility-plaintext-%d" % size).encode("ascii")
        plaintext = corpus.generate_sha256_counter_bytes(seed, size)
        staging_dir = self.plaintexts_dir / (STAGING_DIR_PREFIX + uuid.uuid4().hex[:8])
        staging_dir.mkdir(parents=True)
        try:
            (staging_dir / plaintext_path.name).write_bytes(plaintext)
            sidecar = self.build_sidecar(
                asset_path=plaintext_path,
                asset_files_dir=staging_dir,
                fixture_kind="plaintext",
                generation=self.generation,
                description="Deterministic pseudo-random plaintext of %d bytes" % size,
                provenance=build_provenance("genuine"),
                requirements=build_requirements(),
                size=size,
                generator=dict(algo="sha256_counter", seed=seed.hex()),
            )
            _write_file_atomically(plaintext_path, plaintext)
            _write_file_atomically(sidecar_path, dump_json_sidecar_bytes(sidecar))
        finally:
            shutil.rmtree(staging_dir)
        return plaintext_path


class GenerationWriter(SidecarWriterMixin):
    """Write a new generation of fixtures, spread over the kind directories of the corpus.

    Everything is written into a hidden staging directory, then each kind directory of the generation is renamed into
    place by commit(). Construction fails (GenerationAlreadyExists) without touching anything if any directory of
    this generation already exists. Usable as a context manager, which discards the staging directory on error.
    """

    def __init__(self, generation: str, corpus_dir: Path = CORPUS_DIR):
        if not re.match(GENERATION_NAME_REGEX, generation):
            raise ValueError("Invalid generation name %r" % generation)
        self.generation = generation
        self.corpus_dir = Path(corpus_dir)
        self.final_dirs = {
            kind_dirname: self.corpus_dir / kind_dirname / generation for kind_dirname in GENERATION_KIND_DIRNAMES
        }
        existing_dirs = [path for path in self.final_dirs.values() if path.exists()]
        if existing_dirs:
            raise GenerationAlreadyExists(
                "Generation %r already exists in the corpus, at %s" % (generation, ", ".join(map(str, existing_dirs)))
            )
        self.staging_root = self.corpus_dir / ("%s%s-%s" % (STAGING_DIR_PREFIX, generation, uuid.uuid4().hex[:8]))
        self.staging_root.mkdir()
        self.committed_dirs = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            self.discard()

    def get_final_path(self, kind_dirname: str, *parts: str) -> Path:
        """Return the path that a file of this generation will have in the corpus, once committed."""
        return self.final_dirs[kind_dirname].joinpath(*parts)

    def get_staging_path(self, final_path: Path) -> Path:
        relative_path = final_path.relative_to(self.corpus_dir)
        assert relative_path.parts[0] in GENERATION_KIND_DIRNAMES and relative_path.parts[1] == self.generation, (
            final_path
        )
        return self.staging_root / relative_path

    def write_bytes(self, final_path: Path, data: bytes) -> Path:
        staging_path = self.get_staging_path(final_path)
        if staging_path.exists():
            raise FileExistsError("Fixture %s was already written in this generation" % final_path)
        staging_path.parent.mkdir(parents=True, exist_ok=True)
        staging_path.write_bytes(data)
        return final_path

    def write_extjson_asset(self, final_path: Path, data, canonical=False) -> Path:
        return self.write_bytes(final_path, dump_extjson_asset_bytes(data, canonical=canonical))

    def get_staging_dir(self, final_path: Path) -> Path:
        """Return a (created) staging directory where to build a directory asset, e.g. a keystore pool."""
        staging_path = self.get_staging_path(final_path)
        staging_path.mkdir(parents=True, exist_ok=False)
        return staging_path

    def write_sidecar(self, asset_path: Path, *, fixture_kind: str, description: str, provenance: dict,
                      requirements: dict, **fields) -> Path:
        """Write the sidecar of an already-staged asset (whose final path is `asset_path`)."""
        sidecar = self.build_sidecar(
            asset_path=asset_path,
            asset_files_dir=self.get_staging_path(asset_path).parent,
            fixture_kind=fixture_kind,
            generation=self.generation,
            description=description,
            provenance=provenance,
            requirements=requirements,
            **fields
        )
        return self.write_bytes(corpus.get_sidecar_path(asset_path), dump_json_sidecar_bytes(sidecar))

    def commit(self) -> list:
        """Rename the staged kind directories into place, and return the list of created generation directories."""
        assert self.committed_dirs is None, "Generation already committed"
        committed_dirs = []
        for kind_dirname, final_dir in self.final_dirs.items():
            staging_dir = self.staging_root / kind_dirname / self.generation
            if not staging_dir.exists():
                continue
            final_dir.parent.mkdir(exist_ok=True)
            os.rename(staging_dir, final_dir)  # Fails if the target appeared meanwhile, contrary to os.replace()
            committed_dirs.append(final_dir)
        shutil.rmtree(self.staging_root)
        self.committed_dirs = committed_dirs
        return committed_dirs

    def iter_committed_sidecar_paths(self):
        for committed_dir in self.committed_dirs:
            for sidecar_path in sorted(committed_dir.rglob("*" + SIDECAR_SUFFIX)):
                if not corpus._is_hidden_or_schema(sidecar_path, self.corpus_dir):
                    yield sidecar_path

    def discard(self):
        """Delete the staging directory, and the generation directories if already committed by this writer."""
        shutil.rmtree(self.staging_root, ignore_errors=True)
        for committed_dir in self.committed_dirs or ():
            shutil.rmtree(committed_dir)
        self.committed_dirs = None


def check_generation_fixtures(sidecar_paths, work_dir: Path) -> dict:
    """Run the full fixture checks of the test suite on freshly generated sidecars.

    Return a {sidecar_path: skip reason} dict for fixtures the active backend cannot check, and raise on any failure.
    """
    skipped = {}
    for sidecar_path in sidecar_paths:
        try:
            corpus.check_fixture(sidecar_path, work_dir=work_dir)
        except corpus.FixtureSkipped as exc:
            skipped[sidecar_path] = str(exc)
        except Exception as exc:
            raise AssertionError("Freshly generated fixture %s fails its checks: %r" % (sidecar_path, exc)) from exc
    return skipped



def write_sidecar_for_existing_asset(asset_path: Path, *, fixture_kind: str, generation: str, description: str,
                                     provenance: dict, requirements: dict, corpus_dir: Path = CORPUS_DIR,
                                     **fields) -> Path:
    """Add the missing sidecar of an asset already in the corpus (e.g. a migrated fixture); never overwrites."""
    writer = SidecarWriterMixin()
    writer.corpus_dir = Path(corpus_dir)
    sidecar = writer.build_sidecar(
        asset_path=asset_path,
        fixture_kind=fixture_kind,
        generation=generation,
        description=description,
        provenance=provenance,
        requirements=requirements,
        **fields
    )
    sidecar_path = corpus.get_sidecar_path(asset_path)
    _write_file_atomically(sidecar_path, dump_json_sidecar_bytes(sidecar))
    return sidecar_path
