# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""The committed test vector files of the Rust flightbox encryptor are those its generator produces."""

import importlib.util
from pathlib import Path

import pytest

GENERATOR_PATH = (
    Path(__file__).resolve().parents[1] / "reimplementations" / "rust" / "test_vectors" / "generate_rust_test_vectors.py"
)


@pytest.mark.requires_pycryptodome
def test_rust_flightbox_test_vectors_are_up_to_date():
    spec = importlib.util.spec_from_file_location("generate_rust_test_vectors", GENERATOR_PATH)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)

    rendered_files = generator.render_vector_files()
    assert rendered_files
    for file_name, expected_content in rendered_files.items():
        committed_path = generator.OUTPUT_DIR / file_name
        assert committed_path.is_file(), "Missing %s: run %s" % (committed_path, GENERATOR_PATH.name)
        committed_content = committed_path.read_bytes().decode("ascii")
        assert committed_content == expected_content, "%s is outdated or altered: run %s" % (
            file_name,
            GENERATOR_PATH.name,
        )
