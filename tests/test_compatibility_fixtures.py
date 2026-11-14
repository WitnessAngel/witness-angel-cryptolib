# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Checks that the current library still reads, validates, verifies and decrypts all fixtures of the frozen compatibility/
corpus (see compatibility/README.md), on the ACTIVE crypto backend.

Fixtures declaring requirements that this backend lacks (e.g. ML_KEM_768 on the pure-python fallback) are skipped, so
this module must NOT be marked "requires_pycryptodome".
"""

import json
import shutil

import jsonschema
import pytest

import _compatibility_corpus as corpus

SIDECAR_PATHS = list(corpus.iter_sidecar_paths())


def _get_fixture_id(sidecar_path):
    """Return "kind/generation/name" (or "plaintexts/name"), i.e. the asset path relative to the corpus."""
    return corpus.get_asset_path(sidecar_path).relative_to(corpus.CORPUS_DIR).as_posix()


@pytest.fixture(scope="module")
def schema_registry():
    return corpus.load_schema_registry()


def _check_fixture_or_skip(sidecar_path, work_dir, registry=None):
    try:
        return corpus.check_fixture(sidecar_path, work_dir=work_dir, registry=registry)
    except corpus.FixtureSkipped as exc:
        pytest.skip(str(exc))


def test_corpus_is_populated():
    kinds = {json.loads(path.read_text(encoding="utf8"))["fixture_kind"] for path in SIDECAR_PATHS}
    assert kinds == set(corpus.FIXTURE_KINDS)


@pytest.mark.parametrize("sidecar_path", SIDECAR_PATHS, ids=[_get_fixture_id(path) for path in SIDECAR_PATHS])
def test_compatibility_fixture(sidecar_path, schema_registry, tmp_path):
    # Sidecar schema and asset digests are checked before any requirement-based skipping
    _check_fixture_or_skip(sidecar_path, work_dir=tmp_path, registry=schema_registry)


def test_corpus_has_no_orphan():
    assert corpus.find_orphan_paths() == []


def test_corpus_only_uses_local_and_authenticator_trustees():
    assert corpus.find_forbidden_trustees() == []


def test_corpus_covers_all_supported_algorithms():
    assert corpus.find_uncovered_algorithms() == {}


# SELF-TESTS OF THE CORPUS CHECKS, ON BROKEN COPIES OF A PART OF THE CORPUS #

_COPIED_GENERATION = "2022_v0.9_genuine"


@pytest.fixture
def corpus_copy_dir(tmp_path):
    """A partial copy of the corpus (schemas, plaintexts, and one legacy generation), which is sound on its own."""
    corpus_copy_dir = tmp_path / "compatibility"
    shutil.copytree(corpus.SCHEMAS_DIR, corpus_copy_dir / corpus.SCHEMAS_DIR.name)
    shutil.copytree(corpus.CORPUS_DIR / "plaintexts", corpus_copy_dir / "plaintexts")
    for kind_dirname in ("keystores", "cryptoconfs", "cryptainers"):
        shutil.copytree(
            corpus.CORPUS_DIR / kind_dirname / _COPIED_GENERATION, corpus_copy_dir / kind_dirname / _COPIED_GENERATION
        )
    assert corpus.find_orphan_paths(corpus_copy_dir) == []
    assert corpus.find_forbidden_trustees(corpus_copy_dir) == []
    return corpus_copy_dir


def _get_copied_cryptainer_paths(corpus_copy_dir):
    cryptainer_path = corpus_copy_dir / "cryptainers" / _COPIED_GENERATION / "02_signed_inline.crypt"
    return cryptainer_path, corpus.get_sidecar_path(cryptainer_path)


def test_corpus_checks_detect_sidecar_typo(corpus_copy_dir, tmp_path):
    _cryptainer_path, sidecar_path = _get_copied_cryptainer_paths(corpus_copy_dir)
    corpus.check_fixture(sidecar_path, work_dir=tmp_path)

    sidecar_path.write_text(sidecar_path.read_text(encoding="utf8").replace('"description"', '"descripton"'))
    with pytest.raises(jsonschema.ValidationError, match="descripton"):
        corpus.check_fixture(sidecar_path, work_dir=tmp_path)


def test_corpus_checks_detect_unknown_fixture_kind(corpus_copy_dir, tmp_path):
    _cryptainer_path, sidecar_path = _get_copied_cryptainer_paths(corpus_copy_dir)
    sidecar = json.loads(sidecar_path.read_text(encoding="utf8"))
    sidecar["fixture_kind"] = "cryptoblob"
    sidecar_path.write_text(json.dumps(sidecar))
    with pytest.raises(ValueError, match="unknown fixture kind"):
        corpus.check_fixture(sidecar_path, work_dir=tmp_path)


def test_corpus_checks_detect_modified_asset_byte(corpus_copy_dir, tmp_path):
    cryptainer_path, sidecar_path = _get_copied_cryptainer_paths(corpus_copy_dir)
    cryptainer_bytes = bytearray(cryptainer_path.read_bytes())
    cryptainer_bytes[-1:] = b"\n" if cryptainer_bytes[-1:] != b"\n" else b" "
    cryptainer_path.write_bytes(bytes(cryptainer_bytes))
    with pytest.raises(AssertionError, match="differ from their recorded SHA-256 digests"):
        corpus.check_fixture(sidecar_path, work_dir=tmp_path)


def test_corpus_checks_detect_orphans(corpus_copy_dir):
    cryptainer_path, sidecar_path = _get_copied_cryptainer_paths(corpus_copy_dir)
    sidecar_path.unlink()
    assert corpus.find_orphan_paths(corpus_copy_dir) == ["Asset without its sidecar: %s" % cryptainer_path]

    cryptainer_path.rename(cryptainer_path.with_name("stray.crypt.payload"))
    (corpus_copy_dir / "plaintexts" / "p00000001.bin").unlink()
    assert corpus.find_orphan_paths(corpus_copy_dir) == [
        "Sidecar without its asset: %s" % (corpus_copy_dir / "plaintexts" / "p00000001.bin.json"),
        "File belonging to no fixture: %s" % cryptainer_path.with_name("stray.crypt.payload"),
    ]


def test_corpus_checks_detect_remote_trustee(corpus_copy_dir):
    cryptoconf_path = next((corpus_copy_dir / "cryptoconfs" / _COPIED_GENERATION).glob("*.cryptoconf"))
    cryptoconf_text = cryptoconf_path.read_text(encoding="utf8")
    assert '"trustee_type": "local_keyfactory"' in cryptoconf_text
    cryptoconf_path.write_text(
        cryptoconf_text.replace(
            '"trustee_type": "local_keyfactory"', '"trustee_type": "jsonrpc_api", "jsonrpc_url": "http://example.com"', 1
        )
    )
    assert corpus.find_forbidden_trustees(corpus_copy_dir) == [
        "Forbidden trustee types ['jsonrpc_api'] in %s" % cryptoconf_path
    ]


def test_corpus_checks_detect_uncovered_algorithm(monkeypatch):
    from wacryptolib.cipher import CIPHER_ALGOS_REGISTRY
    from wacryptolib.keygen import ASYMMETRIC_KEY_ALGOS_REGISTRY
    from wacryptolib.signature import SIGNATURE_ALGOS_REGISTRY

    monkeypatch.setitem(CIPHER_ALGOS_REGISTRY, "NEW_CIPHER", {})
    monkeypatch.setitem(SIGNATURE_ALGOS_REGISTRY, "NEW_SIGNATURE", {})
    monkeypatch.setitem(ASYMMETRIC_KEY_ALGOS_REGISTRY, "NEW_KEY", {})
    assert corpus.find_uncovered_algorithms() == {
        "cipher_algos": ["NEW_CIPHER"],
        "signature_algos": ["NEW_SIGNATURE"],
        "asymmetric_key_algos": ["NEW_KEY"],
    }


def test_corpus_checks_skip_fixtures_by_backend_requirements(tmp_path):
    pq_sidecar_path = corpus.CORPUS_DIR / "cryptainers" / "2026_post_quantum" / "pq_hybrid_cryptainer.crypt.json"
    with pytest.raises(corpus.FixtureSkipped, match="fallback crypto backend lacks ML_DSA_65, ML_KEM_768"):
        corpus.check_fixture(pq_sidecar_path, work_dir=tmp_path, backend_name="fallback")

    classic_sidecar_path = corpus.CORPUS_DIR / "cryptainers" / _COPIED_GENERATION / "02_signed_inline.crypt.json"
    assert corpus.get_missing_requirements(corpus.load_sidecar(classic_sidecar_path), "fallback") == []


def test_corpus_checks_detect_obsolete_backend_limitation(tmp_path, monkeypatch):
    from wacryptolib._crypto_backend import BACKEND_NAME

    classic_sidecar_path = corpus.CORPUS_DIR / "cryptainers" / _COPIED_GENERATION / "02_signed_inline.crypt.json"
    classic_algorithms = set(corpus.load_sidecar(classic_sidecar_path)["requirements"]["algorithms"])
    assert classic_algorithms
    monkeypatch.setitem(
        corpus.BACKEND_LIMITATIONS, BACKEND_NAME, {"algorithms": classic_algorithms, "pem_protections": set()}
    )
    with pytest.raises(AssertionError, match="BACKEND_LIMITATIONS must be updated"):
        corpus.check_fixture(classic_sidecar_path, work_dir=tmp_path)
