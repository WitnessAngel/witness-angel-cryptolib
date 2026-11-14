#!/usr/bin/env python
# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Add the legacy generations of the compatibility corpus, produced by OLD wacryptolib versions.

    python scripts/compatibility/build_legacy_generations.py [--only 0.9 --only 2328abe ...] [--synthesize 0.10]

For each legacy source (PyPI releases, or a git commit through a temporary worktree), a throwaway venv is created
with an old Python, generate_legacy_release.py runs inside it, and its raw outputs are wrapped into a new corpus
generation with sidecars ("genuine" provenance). If a source cannot be installed or run (or if --synthesize is
given), equivalent fixtures are SYNTHESIZED instead: produced by the in-tree library, then down-converted to the
legacy forms ("payload_signatures" field, CANONICAL extended JSON), with a "synthesized" provenance.

Every generation is checked with the in-tree library right after being written, and removed if any check fails.
"""

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import _corpus
from _corpus import corpus
from generate_current import NO_PASSPHRASE_SCENARIOS, AuthenticatorSpec, _shamir_scenarios

LEGACY_SCRIPT_PATH = Path(__file__).resolve().parent / "generate_legacy_release.py"

LEGACY_SOURCES = [
    dict(label="0.9", generation="2022_v0.9_genuine", pip_spec="wacryptolib==0.9", python="3.9"),
    dict(label="0.10", generation="2022_v0.10_genuine", pip_spec="wacryptolib==0.10", python="3.9"),
    dict(label="0.11", generation="2023_v0.11_genuine", pip_spec="wacryptolib==0.11", python="3.9"),
    dict(
        label="2328abe",
        generation="2024_pre_signature_rename",
        git_commit="2328abe9e3abf2ecc85df53f88c1d56727ee5b72",  # Last commit before the "payload_signatures" rename
        python="3.11",
    ),
]

SYNTHESIZED_GENERATION_SUFFIX = "_synthesized"


class LegacySourceUnavailable(Exception):
    """Raised when a legacy wacryptolib cannot be installed or run."""


def _run(command, **kwargs):
    print("$", " ".join(str(part) for part in command))
    result = subprocess.run([str(part) for part in command], capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise LegacySourceUnavailable(
            "Command %s failed:\n%s\n%s" % (command, result.stdout[-3000:], result.stderr[-3000:])
        )
    return result.stdout


def _get_python_launcher(python_version: str) -> list:
    if sys.platform == "win32":
        return ["py", "-%s" % python_version]
    return ["python%s" % python_version]


def _get_venv_python(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def ensure_legacy_venv(source: dict, venvs_dir: Path, work_dir: Path) -> Path:
    """Return the python executable of a venv where the legacy wacryptolib is installed (created if missing)."""
    venv_dir = venvs_dir / ("v" + source["label"])
    venv_python = _get_venv_python(venv_dir)
    if venv_python.exists():
        return venv_python
    try:
        _run(_get_python_launcher(source["python"]) + ["-m", "venv", venv_dir])
        _run([venv_python, "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
        if "pip_spec" in source:
            _run([venv_python, "-m", "pip", "install", "--quiet", source["pip_spec"]])
        else:
            worktree_dir = work_dir / ("worktree-" + source["label"])
            _run(["git", "worktree", "add", "--detach", worktree_dir, source["git_commit"]], cwd=_corpus.ROOT_DIR)
            try:
                _run([venv_python, "-m", "pip", "install", "--quiet", worktree_dir])
            finally:
                _run(["git", "worktree", "remove", "--force", worktree_dir], cwd=_corpus.ROOT_DIR)
    except LegacySourceUnavailable:
        shutil.rmtree(venv_dir, ignore_errors=True)  # Do not leave a half-built venv behind
        raise
    return venv_python


def run_legacy_script(python_executable: list, output_dir: Path, env=None) -> dict:
    _run(
        python_executable
        + [LEGACY_SCRIPT_PATH, "--output-dir", output_dir, "--plaintexts-dir", _corpus.CORPUS_DIR / "plaintexts"],
        env=env,
        cwd=output_dir.parent,  # Never the repository, whose packages must not shadow the legacy ones
    )
    return json.loads((output_dir / "report.json").read_text(encoding="utf8"))


# SYNTHESIZED FALLBACK #

LEGACY_FIELD_RENAMINGS = {"payload_ciphertext_signatures": "payload_signatures"}


def _rename_legacy_fields(tree):
    if isinstance(tree, dict):
        return {LEGACY_FIELD_RENAMINGS.get(key, key): _rename_legacy_fields(value) for key, value in tree.items()}
    if isinstance(tree, list):
        return [_rename_legacy_fields(item) for item in tree]
    return tree


def down_convert_outputs(output_dir: Path):
    """Turn outputs of the in-tree library into the legacy wire forms (field names, CANONICAL extended JSON)."""
    from wacryptolib.utilities import dump_to_json_bytes, load_from_json_file

    for subdir in ("cryptoconfs", "cryptainers", "signatures", "cipherdicts"):
        for path in sorted((output_dir / subdir).iterdir()):
            if path.name.endswith(".payload"):
                continue
            data = _rename_legacy_fields(load_from_json_file(path))
            path.write_bytes(dump_to_json_bytes(data, canonical=True))


def synthesize_legacy_outputs(output_dir: Path) -> dict:
    """Run the legacy script with the IN-TREE library, then down-convert its outputs."""
    env = dict(os.environ, PYTHONPATH=str(_corpus.ROOT_DIR / "src"))
    report = run_legacy_script([sys.executable], output_dir, env=env)
    down_convert_outputs(output_dir)
    return report


# WRAPPING OF RAW OUTPUTS INTO A GENERATION #


def detect_legacy_forms(path: Path) -> list:
    if path.is_dir():
        return sorted({form for file in path.rglob("*.json") for form in detect_legacy_forms(file)})
    content = path.read_bytes()
    forms = []
    if b'"subType": "04"' in content or b'"$numberInt"' in content or b'"$numberLong"' in content:
        forms.append("canonical_extjson")
    if b'"payload_signatures"' in content:
        forms.append("payload_signatures_field")
    if b'"digest_list"' in content:
        forms.append("rsa_oaep_digest_list_field")
    if path.name == ".keystore.json":
        forms.append("legacy_keystore_metadata_filename")
    return forms


class LegacyGenerationBuilder:
    def __init__(self, writer: _corpus.GenerationWriter, source: dict, report: dict, output_dir: Path,
                 synthesized: bool):
        self.writer = writer
        self.source = source
        self.report = report
        self.output_dir = output_dir
        self.synthesized = synthesized
        self.authenticators = []
        for entry in report["authenticators"]:
            spec = AuthenticatorSpec(entry["name"], entry["keystore_uid"], ("RSA_OAEP",))
            assert (spec.keystore_owner, spec.passphrase, str(spec.keychain_uid)) == (
                entry["keystore_owner"],
                entry["passphrase"],
                entry["keychain_uid"],
            ), entry
            self.authenticators.append(spec)
        self.pool_path = writer.get_final_path("keystores", "legacy_pool")
        self.plaintexts_dir = writer.corpus_dir / "plaintexts"

    def get_provenance(self, asset_source_path: Path) -> dict:
        legacy_forms = detect_legacy_forms(asset_source_path)
        dependencies = ", ".join("%s %s" % item for item in sorted(self.report["dependency_versions"].items()))
        if self.synthesized:
            return _corpus.build_provenance(
                "synthesized",
                legacy_forms=legacy_forms or ["canonical_extjson"],
                notes="Stands for the outputs of %s, which could not be run: produced by the in-tree library, then "
                "down-converted to legacy forms" % self.describe_source(),
            )
        provenance = dict(
            method="genuine",
            library_version=self.report["library_version"],
            python_version=self.report["python_version"],
            crypto_backend=self.report["crypto_backend"],
            produced_on=datetime.date.today().isoformat(),
            notes="Produced by %s, on CPython %s with %s (the latest dependencies installable then, not those of "
            "the release date)" % (self.describe_source(), self.report["python_version"], dependencies),
        )
        if "git_commit" in self.source:
            provenance.update(library_version=self.get_library_version(), library_commit=self.source["git_commit"])
        if legacy_forms:
            provenance["legacy_forms"] = legacy_forms
        return provenance

    def describe_source(self) -> str:
        if "pip_spec" in self.source:
            return "%s from PyPI" % self.source["pip_spec"]
        return "wacryptolib at git commit %s" % self.source["git_commit"][:10]

    def get_library_version(self) -> str:
        if "git_commit" in self.source and not self.synthesized:
            return self.report["library_version"] + "+dev"  # Unreleased development state
        return self.source["label"] if "pip_spec" in self.source else self.report["library_version"]

    def copy_asset(self, relative_source: str, final_path: Path):
        source_path = self.output_dir / relative_source
        self.writer.write_bytes(final_path, source_path.read_bytes())
        offloaded_path = source_path.with_name(source_path.name + ".payload")
        if offloaded_path.exists():
            self.writer.write_bytes(final_path.with_name(final_path.name + ".payload"), offloaded_path.read_bytes())
        return source_path

    def _pool_ref(self, asset_path: Path) -> str:
        return _corpus.to_relpath(self.pool_path, asset_path)

    def _plaintext_relpath(self, plaintext_name: str, asset_path: Path) -> str:
        return _corpus.to_relpath(self.plaintexts_dir / plaintext_name, asset_path)

    def build(self):
        self.build_pool()
        self.build_cipherdicts()
        self.build_signatures()
        cryptoconf_specs = self.build_cryptoconfs()
        self.build_cryptainers(cryptoconf_specs)

    def build_pool(self):
        source_pool_dir = self.output_dir / self.report["pool"]
        staging_dir = self.writer.get_staging_dir(self.pool_path)
        shutil.copytree(source_pool_dir, staging_dir, dirs_exist_ok=True)
        local_keypairs = corpus.list_keystore_keypairs(staging_dir / "local_keyfactory")
        entries = []
        for authenticator in self.authenticators:
            keystore_dir = corpus.get_pool_keystore_dir(staging_dir, str(authenticator.keystore_uid))
            entries.append(
                dict(
                    keystore_uid=str(authenticator.keystore_uid),
                    keystore_owner=authenticator.keystore_owner,
                    passphrase=authenticator.passphrase,
                    keypairs=corpus.list_keystore_keypairs(keystore_dir),
                )
            )
        all_keypairs = local_keypairs + [keypair for entry in entries for keypair in entry["keypairs"]]
        self.pool_requirements = _corpus.build_requirements(
            [keypair["key_algo"] for keypair in all_keypairs], [keypair["pem_protection"] for keypair in all_keypairs]
        )
        self.writer.write_sidecar(
            self.pool_path,
            fixture_kind="keystore_pool",
            description="Keystore pool of %s: local keyfactory (RSA_OAEP, RSA_PSS, DSA_DSS, ECC_DSS keys of three "
            "keychains, unprotected) and three imported authenticators with a passphrase-protected RSA_OAEP key"
            % self.describe_source(),
            provenance=self.get_provenance(source_pool_dir),
            requirements=self.pool_requirements,
            local_keyfactory=dict(keypairs=local_keypairs),
            authenticators=entries,
        )

    def _local_key_ref(self, asset_path: Path, key_algo: str, private: bool) -> dict:
        key_ref = dict(
            keystore_pool=self._pool_ref(asset_path),
            keystore="local_keyfactory",
            keychain_uid="0c0c0c0c-0000-4000-8000-000000000001",
            key_algo=key_algo,
        )
        if private:
            key_ref["passphrase"] = None
        return key_ref

    def build_cipherdicts(self):
        for entry in self.report["cipherdicts"]:
            cipher_algo = entry["cipher_algo"]
            asset_path = self.writer.get_final_path(
                "cipherdicts", cipher_algo, entry["plaintext"].replace(".bin", ".cipherdict")
            )
            source_path = self.copy_asset(entry["file"], asset_path)
            size = int(entry["plaintext"][1:9])
            fields = dict(cipher_algo=cipher_algo, plaintext=self._plaintext_relpath(entry["plaintext"], asset_path))
            if entry["symkey"]:
                fields.update(direction="bidirectional", symkey=entry["symkey"])
                description = "%s encryption of a %d-byte plaintext by %s, with its symmetric key"
            else:
                fields.update(direction="decrypt_only", private_key=self._local_key_ref(asset_path, cipher_algo, True))
                description = "%s encryption of a %d-byte plaintext by %s, decryptable with a pool key"
            self.writer.write_sidecar(
                asset_path,
                fixture_kind="cipherdict",
                description=description % (cipher_algo, size, self.describe_source()),
                provenance=self.get_provenance(source_path),
                requirements=_corpus.build_requirements([cipher_algo]),
                **fields
            )

    def build_signatures(self):
        for entry in self.report["signatures"]:
            signature_algo = entry["signature_algo"]
            asset_path = self.writer.get_final_path(
                "signatures", signature_algo, entry["plaintext"].replace(".bin", ".signature")
            )
            source_path = self.copy_asset(entry["file"], asset_path)
            self.writer.write_sidecar(
                asset_path,
                fixture_kind="signature",
                description="%s signature of a plaintext by %s" % (signature_algo, self.describe_source()),
                provenance=self.get_provenance(source_path),
                requirements=_corpus.build_requirements([signature_algo]),
                signature_algo=signature_algo,
                message=self._plaintext_relpath(entry["plaintext"], asset_path),
                public_key=self._local_key_ref(asset_path, signature_algo, False),
                expected_valid=True,
            )

    def _structure_requirements(self, structure_path: Path, uses_authenticators: bool) -> dict:
        from wacryptolib.utilities import load_from_json_file

        structure = load_from_json_file(structure_path)
        pem_protections = self.pool_requirements["pem_protections"] if uses_authenticators else ()
        return _corpus.build_requirements(corpus.collect_structure_algorithms(structure), pem_protections)

    def _full_passphrase_mapper(self) -> dict:
        return {authenticator.trustee_id: [authenticator.passphrase] for authenticator in self.authenticators}

    def build_cryptoconfs(self) -> dict:
        cryptoconf_specs = {}
        for entry in self.report["cryptoconfs"]:
            asset_path = self.writer.get_final_path("cryptoconfs", entry["name"] + ".cryptoconf")
            source_path = self.copy_asset(entry["file"], asset_path)
            self.writer.write_sidecar(
                asset_path,
                fixture_kind="cryptoconf",
                description=entry["description"] + " (as written by %s)" % self.describe_source(),
                provenance=self.get_provenance(source_path),
                requirements=self._structure_requirements(source_path, entry["uses_authenticators"]),
                expected_valid=True,
                sophistication_level=entry["level"],
                keystore_pool=self._pool_ref(asset_path),
                passphrase_mapper=self._full_passphrase_mapper() if entry["uses_authenticators"] else {},
                min_library_version=self.get_library_version(),
            )
            cryptoconf_specs[entry["name"]] = dict(entry, path=asset_path)
        return cryptoconf_specs

    def build_cryptainers(self, cryptoconf_specs: dict):
        for entry in self.report["cryptainers"]:
            cryptoconf_spec = cryptoconf_specs[entry["cryptoconf"]]
            asset_path = self.writer.get_final_path("cryptainers", entry["name"] + ".crypt")
            source_path = self.copy_asset(entry["file"], asset_path)
            if cryptoconf_spec["uses_authenticators"]:
                scenarios = _shamir_scenarios(self.authenticators, threshold=2)
            else:
                scenarios = NO_PASSPHRASE_SCENARIOS
            self.writer.write_sidecar(
                asset_path,
                fixture_kind="cryptainer",
                description=entry["description"] + " (by %s)" % self.describe_source(),
                provenance=self.get_provenance(source_path),
                requirements=self._structure_requirements(source_path, cryptoconf_spec["uses_authenticators"]),
                plaintext=self._plaintext_relpath(entry["plaintext"], asset_path),
                keystore_pool=self._pool_ref(asset_path),
                cryptoconf=_corpus.to_relpath(cryptoconf_spec["path"], asset_path),
                cryptainer_metadata=entry["cryptainer_metadata"],
                extjson_flavor="canonical",
                payload_offloaded=entry["mode"] in ("offloaded", "streamed"),
                decryption_scenarios=scenarios,
            )


def build_legacy_generation(source: dict, venvs_dir: Path, force_synthesized=False,
                            corpus_dir: Path = _corpus.CORPUS_DIR) -> list:
    with tempfile.TemporaryDirectory(prefix="wacryptolib-legacy-") as work_dir:
        work_dir = Path(work_dir)
        output_dir = work_dir / "outputs"
        synthesized = force_synthesized
        report = None
        if not synthesized:
            try:
                venv_python = ensure_legacy_venv(source, venvs_dir, work_dir)
                report = run_legacy_script([venv_python, "-I"], output_dir)
            except LegacySourceUnavailable as exc:
                print("WARNING: %s is unavailable, synthesizing its fixtures instead (%s)" % (source["label"], exc))
                shutil.rmtree(output_dir, ignore_errors=True)
                synthesized = True
        if synthesized:
            report = synthesize_legacy_outputs(output_dir)

        generation = source["generation"]
        if synthesized:
            generation = generation.replace("_genuine", "") + SYNTHESIZED_GENERATION_SUFFIX
        with _corpus.GenerationWriter(generation, corpus_dir=corpus_dir) as writer:
            LegacyGenerationBuilder(writer, source, report, output_dir, synthesized=synthesized).build()
            committed_dirs = writer.commit()
            try:
                skipped = _corpus.check_generation_fixtures(list(writer.iter_committed_sidecar_paths()), work_dir)
            except BaseException:
                writer.discard()
                raise
    assert not skipped, skipped  # Legacy fixtures only use algorithms of all backends
    print("Generation %s written and checked, in:" % generation)
    for committed_dir in committed_dirs:
        print("   ", committed_dir)
    return committed_dirs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    labels = [source["label"] for source in LEGACY_SOURCES]
    parser.add_argument("--only", action="append", choices=labels, help="Legacy source(s) to build (default: all)")
    parser.add_argument("--synthesize", action="append", choices=labels, default=[],
                        help="Legacy source(s) to synthesize instead of running them")
    parser.add_argument("--venvs-dir", type=Path, default=Path(tempfile.gettempdir()) / "wacryptolib_compat_venvs",
                        help="Where throwaway venvs of legacy versions are created (and reused)")
    args = parser.parse_args(argv)
    args.venvs_dir.mkdir(parents=True, exist_ok=True)

    for source in LEGACY_SOURCES:
        if args.only and source["label"] not in args.only:
            continue
        try:
            build_legacy_generation(source, args.venvs_dir, force_synthesized=source["label"] in args.synthesize)
        except _corpus.GenerationAlreadyExists as exc:
            print("SKIPPED: %s" % exc)


if __name__ == "__main__":
    main()
