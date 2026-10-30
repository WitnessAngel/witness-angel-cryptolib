# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
The crypto backend is selected once, at import time, so each case runs in a fresh interpreter.
"""

import os
import subprocess
import sys
import textwrap

import pytest

BLOCK_PYCRYPTODOME = 'sys.modules["Crypto"] = None\n'
BLOCK_FALLBACK_PACKAGES = 'sys.modules["pyaes"] = sys.modules["pkcs1"] = None\n'


def _run(*script_parts, force_fallback=False):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    env.pop("FORCE_WACRYPTOLIB_FALLBACK_BACKEND", None)
    if force_fallback:
        env["FORCE_WACRYPTOLIB_FALLBACK_BACKEND"] = "1"
    return subprocess.run(
        [sys.executable, "-c", "import sys\n" + "".join(textwrap.dedent(part) for part in script_parts)], env=env, capture_output=True, text=True
    )


def _assert_backend(script_prefix, expected_backend_name, force_fallback=False):
    result = _run(
        script_prefix,
        "from wacryptolib import _crypto_backend, cipher, keygen, signature\n",
        "print(_crypto_backend.BACKEND_NAME)\n",
        force_fallback=force_fallback,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected_backend_name


def test_native_backend_is_selected_by_default():
    pytest.importorskip("Crypto.Cipher.AES")
    _assert_backend("", "pycryptodome")


def test_native_backend_leaves_pycryptodome_untouched():
    pytest.importorskip("Crypto.Cipher.AES")
    script = """
        import importlib
        names = ["Crypto.Util._raw_api", "Crypto.Util.strxor", "Crypto.Cipher.AES", "Crypto.Cipher.PKCS1_OAEP",
                 "Crypto.Cipher.ChaCha20_Poly1305", "Crypto.Hash.SHA512", "Crypto.Hash.BLAKE2s"]
        def snapshot():
            return {(name, attr): value for name in names
                    for attr, value in vars(importlib.import_module(name)).items()}
        before = snapshot()
        from wacryptolib import _crypto_backend, cipher, keygen, signature
        assert _crypto_backend.BACKEND_NAME == "pycryptodome"
        keygen.generate_keypair(key_algo="ECIES_X25519")
        after = snapshot()
        changed = [key for key in before if after[key] is not before[key]]
        assert not changed, changed
    """
    result = _run(script)
    assert result.returncode == 0, result.stderr


def test_fallback_backend_is_selected_when_forced():
    _assert_backend("", "fallback", force_fallback=True)


def test_fallback_backend_is_selected_without_pycryptodome():
    _assert_backend(BLOCK_PYCRYPTODOME, "fallback")


def test_fallback_backend_is_selected_when_pycryptodome_native_code_cannot_load():
    pytest.importorskip("Crypto.Cipher.AES")
    script = """
        import Crypto.Util._raw_api
        def forbidden_dlopen(name, cdecl):
            raise OSError("Cannot load native module %s (like on iOS)" % name)
        Crypto.Util._raw_api.load_pycryptodome_raw_lib = forbidden_dlopen
    """
    _assert_backend(script, "fallback")


def test_import_fails_explicitly_without_any_backend():
    result = _run(BLOCK_PYCRYPTODOME, BLOCK_FALLBACK_PACKAGES, "import wacryptolib.cipher\n")
    assert result.returncode != 0
    assert "No usable crypto backend" in result.stderr
    assert "pycryptodome" in result.stderr and "'fallbacks' extra" in result.stderr


def test_fallback_backend_works_through_the_high_level_api():
    script = """
        from wacryptolib import _crypto_backend
        from wacryptolib.cipher import encrypt_bytestring, decrypt_bytestring
        from wacryptolib.keygen import generate_keypair, load_asymmetric_key_from_pem_bytestring
        from wacryptolib.signature import sign_message, verify_message_signature
        assert _crypto_backend.BACKEND_NAME == "fallback"
        for key_algo in ("ECIES_X25519", "RSA_OAEP"):
            keypair = generate_keypair(key_algo=key_algo, passphrase=b"pass")
            public_key = load_asymmetric_key_from_pem_bytestring(keypair["public_key"], key_algo=key_algo)
            private_key = load_asymmetric_key_from_pem_bytestring(
                keypair["private_key"], key_algo=key_algo, passphrase=b"pass")
            cipherdict = encrypt_bytestring(b"hello", cipher_algo=key_algo, key_dict=dict(key=public_key))
            assert decrypt_bytestring(cipherdict, cipher_algo=key_algo, key_dict=dict(key=private_key)) == b"hello"
        for signature_algo in ("RSA_PSS", "DSA_DSS"):
            keypair = generate_keypair(key_algo=signature_algo, serialize=False)
            signature = sign_message(b"hello", signature_algo=signature_algo, private_key=keypair["private_key"])
            verify_message_signature(message=b"hello", signature_algo=signature_algo, signature=signature,
                                     public_key=keypair["public_key"])
    """
    result = _run(BLOCK_PYCRYPTODOME, script)
    assert result.returncode == 0, result.stderr


def test_backend_name_matches_environment():
    from wacryptolib import _crypto_backend

    try:
        from Crypto.Cipher import AES  # noqa: F401
    except (ImportError, OSError):
        native_backend_usable = False
    else:
        native_backend_usable = not os.getenv("FORCE_WACRYPTOLIB_FALLBACK_BACKEND")
    assert _crypto_backend.BACKEND_NAME == ("pycryptodome" if native_backend_usable else "fallback")
