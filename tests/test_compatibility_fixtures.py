# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Checks that the current library still reads, validates, verifies and decrypts all fixtures of the frozen compatibility/
corpus (see compatibility/README.md), on the ACTIVE crypto backend.

Fixtures declaring requirements that this backend lacks (e.g. ML_KEM_768 on the pure-python fallback) are skipped, so
this module must NOT be marked "requires_pycryptodome".
"""

import importlib.util
import json
import shutil
import sys

import jsonschema
import pytest

import _compatibility_corpus as corpus

SIDECAR_PATHS = list(corpus.iter_sidecar_paths())

_CBOR_PAIRS_GENERATION = "2026_cbor_pairs"


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


def test_corpus_new_generations_use_lowercase_names():
    assert corpus.find_non_lowercase_names() == []

    # Frozen generations keep their uppercase names, which are accepted
    assert (corpus.CORPUS_DIR / "cipherdicts" / "2026_current" / "AES_CBC").is_dir()
    assert "2026_current" in corpus.MIXED_CASE_GENERATIONS
    assert _CBOR_PAIRS_GENERATION not in corpus.MIXED_CASE_GENERATIONS


def test_corpus_holds_document_format_pairs_and_invalid_cbor_documents():
    sidecars = {
        path: json.loads(path.read_text(encoding="utf8"))
        for path in SIDECAR_PATHS
        if _CBOR_PAIRS_GENERATION in path.parts
    }
    paired_kinds = {sidecar["fixture_kind"] for sidecar in sidecars.values() if "equivalent_asset" in sidecar}
    assert paired_kinds == {"cipherdict", "signature", "cryptoconf", "cryptainer"}
    paired_cryptainer_names = sorted(
        corpus.get_asset_path(path).name
        for path, sidecar in sidecars.items()
        if sidecar["fixture_kind"] == "cryptainer" and "equivalent_asset" in sidecar
    )
    assert any(name.endswith(".crypt.json") for name in paired_cryptainer_names)
    assert any(name.endswith(".crypt.cbor") for name in paired_cryptainer_names)
    assert {sidecar["payload_offloaded"] for sidecar in sidecars.values() if sidecar["fixture_kind"] == "cryptainer"} == {
        True,
        False,
    }
    expected_decoding_errors = {
        sidecar["expected_decoding_error"] for sidecar in sidecars.values() if "expected_decoding_error" in sidecar
    }
    assert expected_decoding_errors == {
        "unsupported_tag",
        "non_text_key",
        "duplicate_key",
        "extjson_keyword_map",
        "malformed_datetime",
    }


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


def test_corpus_sidecar_disambiguation(tmp_path):
    # One generation holds a legacy cryptainer and its sidecar, another one a JSON cryptainer and its sidecar
    legacy_dir = tmp_path / "cryptainers" / "2022_legacy"
    current_dir = tmp_path / "cryptainers" / "2030_current"
    for path in [
        legacy_dir / "a.crypt",
        legacy_dir / "a.crypt.json",
        current_dir / "b.crypt.json",
        current_dir / "b.crypt.json.json",
        current_dir / "c.crypt.cbor",
        current_dir / "c.crypt.cbor.json",
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{}")

    assert list(corpus.iter_sidecar_paths(tmp_path)) == [
        legacy_dir / "a.crypt.json",
        current_dir / "b.crypt.json.json",
        current_dir / "c.crypt.cbor.json",
    ]
    assert list(corpus.iter_asset_paths(tmp_path)) == [
        legacy_dir / "a.crypt",
        current_dir / "b.crypt.json",
        current_dir / "c.crypt.cbor",
    ]
    assert corpus.get_asset_path(legacy_dir / "a.crypt.json") == legacy_dir / "a.crypt"
    assert corpus.get_asset_path(current_dir / "b.crypt.json.json") == current_dir / "b.crypt.json"
    for asset_path in corpus.iter_asset_paths(tmp_path):
        assert corpus.get_expected_fixture_kind(asset_path) == "cryptainer"
    assert corpus.find_orphan_paths(tmp_path) == []

    # Without its asset, a legacy sidecar becomes a JSON cryptainer asset, which lacks its own sidecar
    (legacy_dir / "a.crypt").unlink()
    assert corpus.find_orphan_paths(tmp_path) == ["Asset without its sidecar: %s" % (legacy_dir / "a.crypt.json")]


def test_corpus_fixture_kinds_from_asset_names():
    for asset_name, fixture_kind in [
        ("p00000001.bin", "plaintext"),
        ("x.cipherdict", "cipherdict"),
        ("x.cipherdict.json", "cipherdict"),
        ("x.cipherdict.cbor", "cipherdict"),
        ("x.signature.cbor", "signature"),
        ("x.cryptoconf.json", "cryptoconf"),
        ("x.crypt", "cryptainer"),
        ("x.crypt.json", "cryptainer"),
        ("x.crypt.cbor", "cryptainer"),
        ("p00000001.bin.json", None),  # Only a sidecar
        ("x.crypt.payload", None),
        ("x.json", None),
        ("x.cbor", None),
    ]:
        assert corpus.get_fixture_kind_from_asset_name(asset_name) == fixture_kind, asset_name


def test_corpus_checks_detect_non_lowercase_name_in_new_generation(tmp_path):
    for relative_path in [
        "cipherdicts/2022_v0.9_genuine/AES_CBC/p00000001.cipherdict",  # Frozen generation
        "cipherdicts/2030_new/AES_CBC/p00000001.cipherdict.json",
        "cipherdicts/2030_new/aes_cbc/p00000002.cipherdict.json",
        "cryptainers/2030_new/Clip.crypt.json",
        "keystores/2030_new/pool/local_keyfactory/0c0c0c0c-0000-4000-8000-000000000001_RSA_OAEP_public_key.pem",
    ]:
        path = tmp_path.joinpath(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{}")
    assert corpus.find_non_lowercase_names(tmp_path) == [
        "Non-lowercase name in generation 2030_new: %s" % tmp_path.joinpath("keystores/2030_new/pool/local_keyfactory/"
        "0c0c0c0c-0000-4000-8000-000000000001_RSA_OAEP_public_key.pem"),
        "Non-lowercase name in generation 2030_new: %s" % tmp_path.joinpath("cipherdicts/2030_new/AES_CBC"),
        "Non-lowercase name in generation 2030_new: %s" % tmp_path.joinpath("cryptainers/2030_new/Clip.crypt.json"),
    ]


@pytest.fixture
def cbor_pairs_corpus_copy_dir(tmp_path):
    """A partial copy of the corpus (schemas, plaintexts, and the generation of Extended JSON / WA-CBOR pairs)."""
    corpus_copy_dir = tmp_path / "compatibility"
    shutil.copytree(corpus.SCHEMAS_DIR, corpus_copy_dir / corpus.SCHEMAS_DIR.name)
    shutil.copytree(corpus.CORPUS_DIR / "plaintexts", corpus_copy_dir / "plaintexts")
    for kind_dirname in corpus.GENERATION_KIND_DIRNAMES:
        shutil.copytree(
            corpus.CORPUS_DIR / kind_dirname / _CBOR_PAIRS_GENERATION,
            corpus_copy_dir / kind_dirname / _CBOR_PAIRS_GENERATION,
        )
    assert corpus.find_orphan_paths(corpus_copy_dir) == []
    return corpus_copy_dir


def test_corpus_checks_detect_non_equivalent_pair(cbor_pairs_corpus_copy_dir, tmp_path):
    from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes

    cryptoconfs_dir = cbor_pairs_corpus_copy_dir / "cryptoconfs" / _CBOR_PAIRS_GENERATION
    json_asset_path = cryptoconfs_dir / "01_single_layer.cryptoconf.json"
    json_sidecar_path = corpus.get_sidecar_path(json_asset_path)
    cbor_sidecar_path = corpus.get_sidecar_path(cryptoconfs_dir / "01_single_layer.cryptoconf.cbor")
    json_sidecar = corpus.load_sidecar(json_sidecar_path)
    corpus.check_equivalent_asset(json_sidecar_path, json_sidecar)
    corpus.check_equivalent_asset(cbor_sidecar_path, corpus.load_sidecar(cbor_sidecar_path))

    # Same tree, but not the bytes that the library writes
    cryptoconf = load_from_json_bytes(json_asset_path.read_bytes())
    json_asset_path.write_bytes(json.dumps(json.loads(json_asset_path.read_bytes()), indent=4).encode("utf8"))
    assert load_from_json_bytes(json_asset_path.read_bytes()) == cryptoconf
    with pytest.raises(AssertionError, match="byte for byte"):
        corpus.check_equivalent_asset(cbor_sidecar_path, corpus.load_sidecar(cbor_sidecar_path))

    # Different trees
    cryptoconf["payload_cipher_layers"][0]["payload_cipher_algo"] = "AES_CBC"
    json_asset_path.write_bytes(dump_to_json_bytes(cryptoconf))
    with pytest.raises(AssertionError, match="different trees"):
        corpus.check_equivalent_asset(json_sidecar_path, json_sidecar)


def test_corpus_checks_detect_accepted_invalid_cbor_document(cbor_pairs_corpus_copy_dir, tmp_path):
    from wacryptolib.utilities import dump_to_cbor_bytes

    invalid_dir = cbor_pairs_corpus_copy_dir / "cryptoconfs" / _CBOR_PAIRS_GENERATION / "invalid"
    asset_path = invalid_dir / "duplicate_key.cryptoconf.cbor"
    sidecar_path = corpus.get_sidecar_path(asset_path)
    sidecar = corpus.load_sidecar(sidecar_path)
    assert sidecar["expected_decoding_error"] == "duplicate_key"
    corpus.check_cryptoconf_fixture(sidecar_path, sidecar, tmp_path)

    asset_path.write_bytes(dump_to_cbor_bytes({"payload_cipher_layers": []}))
    with pytest.raises(AssertionError, match="was decoded"):
        corpus.check_cryptoconf_fixture(sidecar_path, sidecar, tmp_path)


def test_corpus_checks_detect_wrong_document_format(cbor_pairs_corpus_copy_dir):
    cryptoconfs_dir = cbor_pairs_corpus_copy_dir / "cryptoconfs" / _CBOR_PAIRS_GENERATION
    sidecar_path = corpus.get_sidecar_path(cryptoconfs_dir / "01_single_layer.cryptoconf.cbor")
    sidecar = corpus.load_sidecar(sidecar_path)
    corpus.check_document_format(sidecar_path, sidecar)
    with pytest.raises(AssertionError, match="unlike what its sidecar declares"):
        corpus.check_document_format(sidecar_path, dict(sidecar, document_format="json"))


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


# SELF-TESTS OF THE GENERATION TOOLING OF scripts/compatibility/, ON TEMPORARY CORPORA #


@pytest.fixture(scope="module")
def corpus_tooling():
    """The write-side module of the generation tooling (imported without leaving its sys.path changes behind)."""
    tooling_path = corpus.CORPUS_DIR.parent / "scripts" / "compatibility" / "_corpus.py"
    saved_sys_path = list(sys.path)
    try:
        spec = importlib.util.spec_from_file_location("_compatibility_corpus_tooling", tooling_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_sys_path
    return module


def _list_tree(directory):
    return sorted(path.relative_to(directory).as_posix() for path in directory.rglob("*"))


def test_generation_tooling_refuses_existing_generation(corpus_tooling, tmp_path):
    existing_dir = tmp_path / "cryptoconfs" / "2030_new"
    existing_dir.mkdir(parents=True)
    tree_before = _list_tree(tmp_path)
    with pytest.raises(corpus_tooling.GenerationAlreadyExists, match="2030_new"):
        corpus_tooling.GenerationWriter("2030_new", corpus_dir=tmp_path)
    assert _list_tree(tmp_path) == tree_before


def test_generation_tooling_refuses_uppercase_names(corpus_tooling, tmp_path):
    tree_before = _list_tree(tmp_path)

    with pytest.raises(corpus_tooling.NonLowercaseName, match="AES_CBC"):
        with corpus_tooling.GenerationWriter("2030_new", corpus_dir=tmp_path) as writer:
            writer.write_bytes(writer.get_final_path("cipherdicts", "AES_CBC", "p00000061.cipherdict.json"), b"{}")
    assert _list_tree(tmp_path) == tree_before

    # Names created by library code inside staging directories (e.g. keystore pools) are checked at commit time
    with pytest.raises(corpus_tooling.NonLowercaseName, match="Key_File.pem"):
        with corpus_tooling.GenerationWriter("2030_new", corpus_dir=tmp_path) as writer:
            writer.write_bytes(writer.get_final_path("cipherdicts", "aes_cbc", "p00000061.cipherdict.json"), b"{}")
            pool_staging_dir = writer.get_staging_dir(writer.get_final_path("keystores", "pool"))
            (pool_staging_dir / "Key_File.pem").write_bytes(b"")
            writer.commit()
    assert _list_tree(tmp_path) == tree_before

    with corpus_tooling.GenerationWriter("2030_new", corpus_dir=tmp_path) as writer:
        writer.write_bytes(writer.get_final_path("cipherdicts", "aes_cbc", "p00000061.cipherdict.json"), b"{}")
        assert writer.commit() == [tmp_path / "cipherdicts" / "2030_new"]
    assert _list_tree(tmp_path) == [
        "cipherdicts",
        "cipherdicts/2030_new",
        "cipherdicts/2030_new/aes_cbc",
        "cipherdicts/2030_new/aes_cbc/p00000061.cipherdict.json",
    ]
