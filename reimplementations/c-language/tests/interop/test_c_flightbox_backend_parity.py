# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Parity of the builds (task 9.7): with the same deterministic random source and clock, the builds given, which
differ by their implementation (C or Rust) or by their crypto backend (Mbed TLS, wolfCrypt, RustCrypto), give
byte-identical cryptainers and payload files, in each format; and chunking does not change the output, one-shot and
chunked encryptions giving the same payload ciphertext.
"""

import pytest

from c_flightbox_interop_support import get_c_builds_by_identity
from test_c_flightbox_cryptainer_interop import _generate_payload, check_c_cryptainer, encrypt_with_c_driver

DOCUMENT_FORMATS = ("json", "cbor")

# Every payload and key cipher algorithm, shared secrets and nested symmetric layers
PARITY_PROFILE_NAMES = (
    "synthetic_all_payload_algos",
    "synthetic_nested_symmetric_layers",
    "synthetic_nested_shared_secrets",
    "current_05_shamir_authenticators",
    "post_quantum_07_pq_hybrid_unsigned",
)


def _get_builds_to_compare():
    """One build per (implementation, backend), in the order given: each one is compared with the first."""
    builds = get_c_builds_by_identity()
    if len(builds) < 2:
        pytest.skip(
            "Parity needs builds of two implementations or backends, with both formats (got %s)" % sorted(builds)
        )
    return list(builds.values())


def _read_outputs(cryptainer_path):
    payload_path = cryptainer_path.with_name(cryptainer_path.name + ".payload")
    return cryptainer_path.read_bytes(), payload_path.read_bytes() if payload_path.exists() else None


@pytest.mark.parametrize("is_offloaded", [False, True], ids=["inline", "offloaded"])
@pytest.mark.parametrize("document_format", DOCUMENT_FORMATS)
@pytest.mark.parametrize("profile_name", PARITY_PROFILE_NAMES)
def test_identical_output_from_all_builds(profile_name, document_format, is_offloaded, tmp_path):
    payload = _generate_payload(65539)
    builds = _get_builds_to_compare()
    outputs = []
    for c_build in builds:
        case_dir = tmp_path / ("%s_%s" % c_build.identity)
        cryptainer_path = encrypt_with_c_driver(
            c_build, profile_name, document_format, payload, "non_ascii", is_offloaded, 4093, case_dir
        )
        outputs.append(_read_outputs(cryptainer_path))
    for c_build, output in zip(builds[1:], outputs[1:]):
        assert output == outputs[0], (builds[0].identity, c_build.identity)
    # And the shared output is a valid cryptainer
    check_c_cryptainer(cryptainer_path, profile_name, document_format, payload, "non_ascii", is_offloaded, tmp_path)


CHUNK_SIZES = (0, 1, 15, 16, 17, 4093, 65536)


def test_chunking_does_not_change_the_output(c_build, document_format, tmp_path):
    """One-shot (chunk size 0) and chunked encryptions, with the same seed, give the same payload ciphertext and
    the same cryptainer (in each build, and each of its formats)."""
    payload = _generate_payload(65539)
    outputs = {}
    for chunk_size in CHUNK_SIZES:
        cryptainer_path = encrypt_with_c_driver(
            c_build, "synthetic_all_payload_algos", document_format, payload, "ascii", True, chunk_size,
            tmp_path / ("chunk_size_%d" % chunk_size),
        )  # fmt: skip
        outputs[chunk_size] = _read_outputs(cryptainer_path)
    for chunk_size in CHUNK_SIZES[1:]:
        assert outputs[chunk_size][1] == outputs[0][1], chunk_size  # Payload ciphertext
        assert outputs[chunk_size][0] == outputs[0][0], chunk_size  # Cryptainer
