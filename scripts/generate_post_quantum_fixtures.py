#!/usr/bin/env python
# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later
"""Regenerate tests/fixtures/post_quantum/ (hybrid ML-KEM-768 + RSA-OAEP cryptainer signed with ML-DSA-65)."""

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from test_wacryptolib_cryptainer import PQ_FIXTURES_DIR, _build_pq_hybrid_cryptainer  # noqa: E402
from wacryptolib.cryptainer import dump_cryptainer_to_filesystem  # noqa: E402
from wacryptolib.keystore import FilesystemKeystorePool  # noqa: E402


def main():
    shutil.rmtree(PQ_FIXTURES_DIR, ignore_errors=True)
    keystore_pool_dir = PQ_FIXTURES_DIR / "keystore_pool"
    keystore_pool_dir.mkdir(parents=True)
    cryptainer = _build_pq_hybrid_cryptainer(FilesystemKeystorePool(keystore_pool_dir))
    dump_cryptainer_to_filesystem(
        PQ_FIXTURES_DIR / "pq_hybrid_cryptainer.crypt", cryptainer=cryptainer, offload_payload_ciphertext=False
    )
    print("Fixtures regenerated in", PQ_FIXTURES_DIR)


if __name__ == "__main__":
    main()
