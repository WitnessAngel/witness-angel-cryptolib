from datetime import datetime
from unittest import mock

import pytest

import wacryptolib
from wacryptolib.exceptions import SignatureVerificationError, SignatureCreationError


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
