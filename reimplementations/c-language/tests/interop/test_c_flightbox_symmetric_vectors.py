# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Symmetric encryption of the C library against the corpus (task 9.3): every valid symmetric cipherdict fixture of
compatibility/cipherdicts/, all generations, is re-encrypted by the C driver from its own symkey and plaintext, and
must give the same cipherdict, byte for byte (through each C writer). Tampered fixtures, which are decryption tests,
are left aside.
"""

import pytest

from c_flightbox_interop_support import COMPATIBILITY_ROOT, corpus

SYMMETRIC_CIPHER_ALGOS = ("AES_CBC", "AES_EAX", "CHACHA20_POLY1305")


def _iter_symmetric_fixture_sidecars():
    for sidecar_path in corpus.iter_sidecar_paths(COMPATIBILITY_ROOT / "cipherdicts"):
        sidecar = corpus.load_sidecar(sidecar_path)
        if sidecar["cipher_algo"] in SYMMETRIC_CIPHER_ALGOS and sidecar.get("expected_valid", True):
            yield sidecar_path


SYMMETRIC_FIXTURE_SIDECARS = sorted(_iter_symmetric_fixture_sidecars())


def test_symmetric_fixtures_are_found():
    assert len(SYMMETRIC_FIXTURE_SIDECARS) >= 80
    algos = {corpus.load_sidecar(sidecar_path)["cipher_algo"] for sidecar_path in SYMMETRIC_FIXTURE_SIDECARS}
    assert algos == set(SYMMETRIC_CIPHER_ALGOS)


@pytest.mark.parametrize(
    "sidecar_path",
    SYMMETRIC_FIXTURE_SIDECARS,
    ids=lambda path: str(path.relative_to(COMPATIBILITY_ROOT / "cipherdicts")).replace("\\", "/"),
)
def test_symmetric_cipherdict_fixture(c_build, sidecar_path):
    from wacryptolib.utilities import dump_to_cbor_bytes, dump_to_json_bytes, load_from_cbor_bytes, load_from_json_bytes

    sidecar = corpus.load_sidecar(sidecar_path)
    expected_cipherdict = corpus.load_document_asset(sidecar_path)
    plaintext = corpus.resolve_relpath(sidecar_path, sidecar["plaintext"]).read_bytes()
    symkey = sidecar["symkey"]
    iv_or_nonce = symkey["iv"] if sidecar["cipher_algo"] == "AES_CBC" else symkey["nonce"]

    output = c_build.run_driver("symmetric-encrypt", sidecar["cipher_algo"], symkey["key"], iv_or_nonce, plaintext)
    assert output["status"] == "WA_STATUS_OK", output
    if "cbor" in c_build.document_formats:
        assert load_from_cbor_bytes(bytes.fromhex(output["cbor"])) == expected_cipherdict
        assert bytes.fromhex(output["cbor"]) == dump_to_cbor_bytes(expected_cipherdict)
    if "json" in c_build.document_formats:
        assert load_from_json_bytes(bytes.fromhex(output["json"])) == expected_cipherdict
        assert bytes.fromhex(output["json"]) == dump_to_json_bytes(expected_cipherdict)
