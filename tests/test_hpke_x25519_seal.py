# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import subprocess
import sys

import pytest

from wacryptolib import _crypto_backend
from wacryptolib._crypto_backend import hpke_x25519_seal
from wacryptolib.cipher import ECIES_X25519_HPKE_AEAD_ID, decrypt_bytestring
from wacryptolib.keygen import generate_keypair, load_asymmetric_key_from_pem_bytestring

from _test_mockups import skip_if_fallback_backend

h = bytes.fromhex


def test_x25519_rfc7748_vectors():
    # RFC 7748 section 5.2
    assert hpke_x25519_seal.x25519(
        h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ) == h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    assert hpke_x25519_seal.x25519(
        h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
        h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
    ) == h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")

    # RFC 7748 section 6.1
    alice_private_key = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob_public_key = h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    assert hpke_x25519_seal.x25519(alice_private_key, hpke_x25519_seal._X25519_BASE_POINT) == h(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )
    assert hpke_x25519_seal.x25519(alice_private_key, bob_public_key) == h(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    )


def test_hpke_key_schedule_rfc9180_vector():
    # RFC 9180 appendix A.2.1, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, base mode
    enc, key, base_nonce = hpke_x25519_seal._derive_key_schedule(
        receiver_public_key=h("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"),
        ephemeral_private_key=h("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"),
        info=h("4f6465206f6e2061204772656369616e2055726e"),
    )
    assert enc == h("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
    assert key == h("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91")
    assert base_nonce == h("5c4d98150661b848853b547f")


@pytest.mark.parametrize("plaintext", [b"", b"abc", b"x" * 300])
def test_pure_seal_is_decryptable_by_pycryptodome(plaintext):
    skip_if_fallback_backend("ECC")
    keypair = generate_keypair(key_algo="ECIES_X25519", serialize=False)
    raw_public_key = keypair["public_key"].export_key(format="raw")

    enc, ciphertext = hpke_x25519_seal.seal(raw_public_key, plaintext)
    assert len(enc) == 32 and len(ciphertext) == len(plaintext) + 16

    assert _crypto_backend.decrypt_via_hpke(enc, ciphertext, keypair["private_key"], ECIES_X25519_HPKE_AEAD_ID) == plaintext
    cipherdict = dict(kem_ciphertext=enc, ciphertext=ciphertext)
    assert decrypt_bytestring(cipherdict, cipher_algo="ECIES_X25519", key_dict=dict(key=keypair["private_key"])) == plaintext

    assert hpke_x25519_seal.seal(raw_public_key, plaintext) != (enc, ciphertext)  # Randomized


def test_pure_seal_rejects_invalid_public_keys():
    skip_if_fallback_backend("ECC")
    with pytest.raises(ValueError, match="low order"):
        hpke_x25519_seal.seal(bytes(32), b"abc")  # All-zero point yields an all-zero shared secret
    with pytest.raises(ValueError, match="32 bytes"):
        hpke_x25519_seal.seal(b"abc", b"abc")

    raw_public_key = generate_keypair(key_algo="ECIES_X25519", serialize=False)["public_key"].export_key(format="raw")
    high_bit_public_key = raw_public_key[:31] + bytes([raw_public_key[31] | 0x80])
    p_plus_one_public_key = (2**255 - 19 + 1).to_bytes(32, "little")  # Same point as u=1
    for non_canonical_public_key in (high_bit_public_key, p_plus_one_public_key):
        with pytest.raises(ValueError, match="Non-canonical"):
            hpke_x25519_seal.seal(non_canonical_public_key, b"abc")


def test_fallback_backend_seals_with_pure_python(tmp_path):
    skip_if_fallback_backend("ECC")  # The keypair is generated and used natively, around the fallback subprocess
    # Fallback mode is decided at import time, so it needs a fresh interpreter
    keypair = generate_keypair(key_algo="ECIES_X25519", serialize=True)
    (tmp_path / "public_key.pem").write_bytes(keypair["public_key"])
    script = """if True:
        import sys
        from pathlib import Path
        from wacryptolib import _crypto_backend
        from wacryptolib.cipher import encrypt_bytestring
        from wacryptolib.keygen import load_asymmetric_key_from_pem_bytestring
        assert _crypto_backend.pycryptodome._patch_pycryptodome_internals
        tmp_path = Path(sys.argv[1])
        public_key = load_asymmetric_key_from_pem_bytestring((tmp_path / "public_key.pem").read_bytes(), key_algo="ECIES_X25519")
        assert isinstance(public_key, bytes) and len(public_key) == 32
        cipherdict = encrypt_bytestring(b"hello", cipher_algo="ECIES_X25519", key_dict=dict(key=public_key))
        (tmp_path / "kem_ciphertext").write_bytes(cipherdict["kem_ciphertext"])
        (tmp_path / "ciphertext").write_bytes(cipherdict["ciphertext"])
    """
    env = dict(os.environ, FORCE_WACRYPTOLIB_FALLBACK_BACKEND="1", PYTHONPATH=os.pathsep.join(sys.path))
    subprocess.run([sys.executable, "-c", script, str(tmp_path)], env=env, check=True)

    cipherdict = dict(
        kem_ciphertext=(tmp_path / "kem_ciphertext").read_bytes(), ciphertext=(tmp_path / "ciphertext").read_bytes()
    )
    private_key = load_asymmetric_key_from_pem_bytestring(keypair["private_key"], key_algo="ECIES_X25519")
    assert decrypt_bytestring(cipherdict, cipher_algo="ECIES_X25519", key_dict=dict(key=private_key)) == b"hello"
