# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from datetime import datetime
from unittest import mock

import pytest

import wacryptolib
from wacryptolib.exceptions import SignatureVerificationError, SignatureCreationError

from _test_mockups import skip_if_fallback_backend


def _common_signature_checks(keypair, message, signature, signature_algo):
    assert isinstance(signature["signature_value"], bytes)
    assert isinstance(signature["signature_timestamp_utc"], int)
    utcnow = datetime.utcnow().timestamp()
    assert utcnow - 10 <= signature["signature_timestamp_utc"] <= utcnow

    wacryptolib.signature.verify_message_signature(
        public_key=keypair["public_key"], message=message, signature=signature, signature_algo=signature_algo
    )

    with pytest.raises(SignatureVerificationError, match="signature"):
        wacryptolib.signature.verify_message_signature(
            public_key=keypair["public_key"], message=message + b"X", signature=signature, signature_algo=signature_algo
        )

    signature_corrupted = signature.copy()
    signature_corrupted["signature_value"] += b"x"
    with pytest.raises(SignatureVerificationError, match="signature"):
        wacryptolib.signature.verify_message_signature(
            public_key=keypair["public_key"],
            message=message,
            signature=signature_corrupted,
            signature_algo=signature_algo,
        )

    signature_corrupted = signature.copy()
    signature_corrupted["signature_timestamp_utc"] += 1
    with pytest.raises(SignatureVerificationError, match="signature"):
        wacryptolib.signature.verify_message_signature(
            public_key=keypair["public_key"],
            message=message,
            signature=signature_corrupted,
            signature_algo=signature_algo,
        )


def test_sign_and_verify_with_rsa_key():
    message = b"Hello"

    keypair = wacryptolib.keygen.generate_keypair(key_algo="RSA_PSS", serialize=False, key_length_bits=2048)
    signature = wacryptolib.signature.sign_message(
        private_key=keypair["private_key"], message=message, signature_algo="RSA_PSS"
    )
    _common_signature_checks(keypair=keypair, message=message, signature=signature, signature_algo="RSA_PSS")


def test_sign_and_verify_with_dsa_key():
    message = "Mon hât èst joli".encode("utf-8")

    keypair = wacryptolib.keygen.generate_keypair(key_algo="DSA_DSS", serialize=False, key_length_bits=2048)
    signature = wacryptolib.signature.sign_message(
        private_key=keypair["private_key"], message=message, signature_algo="DSA_DSS"
    )
    _common_signature_checks(keypair=keypair, message=message, signature=signature, signature_algo="DSA_DSS")


def test_sign_and_verify_with_ecc_key():
    skip_if_fallback_backend("ECC")
    message = "Msd sd 867_ss".encode("utf-8")

    keypair = wacryptolib.keygen.generate_keypair(key_algo="ECC_DSS", serialize=False, curve="p256")
    signature = wacryptolib.signature.sign_message(
        private_key=keypair["private_key"], message=message, signature_algo="ECC_DSS"
    )
    _common_signature_checks(keypair=keypair, message=message, signature=signature, signature_algo="ECC_DSS")


def test_generic_signature_errors():
    message = b"Hello"

    keypair = wacryptolib.keygen.generate_keypair(key_algo="RSA_OAEP", serialize=False, key_length_bits=2048)
    signature = wacryptolib.signature.sign_message(
        private_key=keypair["private_key"], message=message, signature_algo="RSA_PSS"
    )

    with pytest.raises(ValueError, match="Unknown signature algorithm"):
        wacryptolib.signature.sign_message(private_key=keypair["private_key"], message=message, signature_algo="EIXH")

    with pytest.raises(ValueError, match="Incompatible key type"):
        wacryptolib.signature.sign_message(
            private_key=keypair["private_key"], message=message, signature_algo="DSA_DSS"  # RSA key not accepted here
        )

    with pytest.raises(SignatureCreationError):
        with mock.patch(
            "wacryptolib.signature._compute_timestamped_hash", side_effect=ValueError
        ):  # Test rare cas where signing would be broken
            wacryptolib.signature.sign_message(
                private_key=keypair["private_key"], message=message, signature_algo="RSA_PSS"
            )

    with pytest.raises(ValueError, match="Unknown signature algorithm"):
        wacryptolib.signature.verify_message_signature(
            public_key=keypair["public_key"], message=message, signature=signature, signature_algo="XPZH"
        )


def test_sign_and_verify_with_ml_dsa_key():
    skip_if_fallback_backend("ML-KEM/ML-DSA")
    message = b"Post-quantum hello"

    keypair = wacryptolib.keygen.generate_keypair(key_algo="ML_DSA_65", serialize=False)
    signature = wacryptolib.signature.sign_message(
        private_key=keypair["private_key"], message=message, signature_algo="ML_DSA_65"
    )
    _common_signature_checks(keypair=keypair, message=message, signature=signature, signature_algo="ML_DSA_65")

    assert len(signature["signature_value"]) == 3309  # ML-DSA-65 signature size

    # Hedged (randomized) signing: same message and timestamp give different signatures
    with mock.patch("wacryptolib.signature._get_utc_timestamp", return_value=signature["signature_timestamp_utc"]):
        signature2 = wacryptolib.signature.sign_message(
            private_key=keypair["private_key"], message=message, signature_algo="ML_DSA_65"
        )
    assert signature2["signature_timestamp_utc"] == signature["signature_timestamp_utc"]
    assert signature2["signature_value"] != signature["signature_value"]
    wacryptolib.signature.verify_message_signature(
        public_key=keypair["public_key"], message=message, signature=signature2, signature_algo="ML_DSA_65"
    )

    # Incompatible key families are rejected
    for other_key_algo in ("RSA_PSS", "ML_KEM_768"):
        other_keypair = wacryptolib.keygen.generate_keypair(key_algo=other_key_algo, serialize=False)
        with pytest.raises(ValueError, match="Incompatible key type"):
            wacryptolib.signature.sign_message(
                private_key=other_keypair["private_key"], message=message, signature_algo="ML_DSA_65"
            )
        with pytest.raises(ValueError, match="Incompatible key type"):
            wacryptolib.signature.verify_message_signature(
                public_key=other_keypair["public_key"], message=message, signature=signature, signature_algo="ML_DSA_65"
            )


@pytest.mark.parametrize("param_set_name", ["ML_DSA_44", "ML_DSA_87"])
def test_ml_dsa_65_rejects_other_ml_dsa_parameter_sets(param_set_name):
    skip_if_fallback_backend("ML-KEM/ML-DSA")
    from Crypto.PublicKey import MLDSA
    from wacryptolib.exceptions import KeyLoadingError
    from wacryptolib.keygen import load_asymmetric_key_from_pem_bytestring

    message = b"Hello"
    private_key = MLDSA.generate(param_set=getattr(MLDSA.ParamSet, param_set_name))
    public_key = private_key.public_key()

    with pytest.raises(ValueError, match="Incompatible key type"):
        wacryptolib.signature.sign_message(private_key=private_key, message=message, signature_algo="ML_DSA_65")

    keypair = wacryptolib.keygen.generate_keypair(key_algo="ML_DSA_65", serialize=False)
    signature = wacryptolib.signature.sign_message(
        private_key=keypair["private_key"], message=message, signature_algo="ML_DSA_65"
    )
    with pytest.raises(ValueError, match="Incompatible key type"):
        wacryptolib.signature.verify_message_signature(
            message=message, signature_algo="ML_DSA_65", signature=signature, public_key=public_key
        )

    for key in (public_key, private_key):
        with pytest.raises(KeyLoadingError, match="Incompatible key type"):
            load_asymmetric_key_from_pem_bytestring(key_pem=key.export_key(format="PEM"), key_algo="ML_DSA_65")


@pytest.mark.parametrize("key_algo", ["RSA_PSS", "ECC_DSS", "DSA_DSS", "ML_DSA_65"])
def test_sign_message_with_public_key_raises_signature_creation_error(key_algo):
    if key_algo in ("ECC_DSS", "ML_DSA_65"):
        skip_if_fallback_backend(key_algo)
    keypair = wacryptolib.keygen.generate_keypair(key_algo=key_algo, serialize=False)
    with pytest.raises(SignatureCreationError):
        wacryptolib.signature.sign_message(private_key=keypair["public_key"], message=b"Hello", signature_algo=key_algo)
