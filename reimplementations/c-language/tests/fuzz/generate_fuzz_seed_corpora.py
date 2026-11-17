# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate the seed corpora of the libFuzzer targets (task 3.8 of the OpenSpec change add-c-flightbox-encryptor):
- wacbor_subprofile_decoder/: the test vectors of section 10 of the WA-CBOR specification, the device profile samples
  of the C unit tests, and the WA-CBOR documents of the compatibility corpus (up to 64 KiB);
- device_profile_loader/: the device profile samples of the C unit tests (profiles exported from the corpus
  cryptoconfs, and their mutations).

Run from the repository root, in the wacryptolib environment:
    python reimplementations/c-language/tests/fuzz/generate_fuzz_seed_corpora.py OUTPUT_DIR
"""

import importlib.util
import json
import re
import sys
from pathlib import Path

FUZZ_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = FUZZ_DIR.parents[3]
UNIT_TESTS_DIR = FUZZ_DIR.parent / "unit"
SPECIFICATION_PATH = REPOSITORY_ROOT / "docs" / "specifications" / "wa_cbor_document_format.md"
MAXIMUM_CORPUS_DOCUMENT_SIZE = 64 * 1024


def _load_device_profile_samples():
    spec = importlib.util.spec_from_file_location(
        "generate_device_profile_samples", UNIT_TESTS_DIR / "generate_device_profile_samples.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.collect_device_profile_samples()


def _load_specification_vectors():
    specification_text = SPECIFICATION_PATH.read_text(encoding="utf-8")
    match = re.search(r"^```json wa-cbor-test-vectors\n(.*?)^```", specification_text, re.MULTILINE | re.DOTALL)
    assert match, "No test vector block found in the WA-CBOR specification"
    vectors = json.loads(match.group(1))
    return vectors["valid"] + vectors["invalid"]


def _write_seeds(target_dir: Path, seeds: dict):
    target_dir.mkdir(parents=True, exist_ok=True)
    for name, data in seeds.items():
        (target_dir / (re.sub(r"[^A-Za-z0-9_.-]", "_", name) + ".cbor")).write_bytes(data)
    print("%d seeds written to %s" % (len(seeds), target_dir))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__)
        return 2
    output_dir = Path(argv[0])

    profile_seeds = {"profile_" + sample["name"]: sample["data"] for sample in _load_device_profile_samples()}

    decoder_seeds = {"vector_" + vector["name"]: bytes.fromhex(vector["cbor_hex"]) for vector in _load_specification_vectors()}
    decoder_seeds.update(profile_seeds)
    compatibility_root = REPOSITORY_ROOT / "compatibility"
    for document_path in sorted(compatibility_root.rglob("*.cbor")):
        if document_path.stat().st_size <= MAXIMUM_CORPUS_DOCUMENT_SIZE:
            relative_name = document_path.relative_to(compatibility_root).as_posix()
            decoder_seeds["corpus_" + relative_name] = document_path.read_bytes()

    _write_seeds(output_dir / "wacbor_subprofile_decoder", decoder_seeds)
    _write_seeds(output_dir / "device_profile_loader", profile_seeds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
