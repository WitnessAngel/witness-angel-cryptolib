import uuid
from datetime import datetime

import pytest

import wacryptolib


def _common_signature_checks(keypair, plaintext, signature):

    assert isinstance(signature["digest"], bytes)
    assert isinstance(signature["type"], str)
    assert isinstance(signature["timestamp_utc"], int)
    utcnow = datetime.utcnow().timestamp()
    assert utcnow - 10 <= signature["timestamp_utc"] <= utcnow

    wacryptolib.signature.verify_signature(
        key=keypair["public_key"], plaintext=plaintext, signature=signature
    )

    with pytest.raises(ValueError, match="signature"):
        wacryptolib.signature.verify_signature(
            key=keypair["public_key"], plaintext=plaintext + b"X", signature=signature
        )

    signature_corrupted = signature.copy()
    signature_corrupted["digest"] += b"x"
    with pytest.raises(ValueError, match="signature"):
        wacryptolib.signature.verify_signature(
            key=keypair["public_key"],
            plaintext=plaintext,
            signature=signature_corrupted,
        )

    signature_corrupted = signature.copy()
    signature_corrupted["timestamp_utc"] += 1
    with pytest.raises(ValueError, match="signature"):
        wacryptolib.signature.verify_signature(
            key=keypair["public_key"],
            plaintext=plaintext,
            signature=signature_corrupted,
        )


def test_sign_and_verify_with_rsa_key():
    uid = uuid.uuid4()
    plaintext = b"Hello"

    keypair = wacryptolib.key_generation._generate_rsa_keypair_as_objects(
        uid, key_length=2048
    )
    signature = wacryptolib.signature.sign_message(
        key=keypair["private_key"], plaintext=plaintext, signature_type="PSS"
    )
    _common_signature_checks(keypair=keypair, plaintext=plaintext, signature=signature)


def test_sign_and_verify_with_dsa_key():
    uid = uuid.uuid4()
    plaintext = "Mon hât èst joli".encode("utf-8")

    keypair = wacryptolib.key_generation._generate_dsa_keypair_as_objects(
        uid, key_length=2048
    )
    signature = wacryptolib.signature.sign_message(
        key=keypair["private_key"], plaintext=plaintext, signature_type="DSS"
    )
    _common_signature_checks(keypair=keypair, plaintext=plaintext, signature=signature)


def test_sign_and_verify_with_ecc_key():
    uid = uuid.uuid4()
    plaintext = "Msd sd 867_ss".encode("utf-8")

    keypair = wacryptolib.key_generation._generate_ecc_keypair_as_objects(
        uid, curve="p256"
    )
    signature = wacryptolib.signature.sign_message(
        key=keypair["private_key"], plaintext=plaintext, signature_type="DSS"
    )
    _common_signature_checks(keypair=keypair, plaintext=plaintext, signature=signature)


def test_generic_signature_errors():
    uid = uuid.uuid4()
    plaintext = b"Hello"

    keypair = wacryptolib.key_generation._generate_rsa_keypair_as_objects(
        uid, key_length=2048
    )

    with pytest.raises(ValueError, match="Unknown signature type"):
        wacryptolib.signature.sign_message(
            key=keypair["private_key"], plaintext=plaintext, signature_type="EIXH"
        )

    with pytest.raises(ValueError, match="Incompatible key type"):
        wacryptolib.signature.sign_message(
            key=keypair["private_key"],
            plaintext=plaintext,
            signature_type="DSS",  # RSA key not accepted here
        )

    with pytest.raises(ValueError, match="Unknown signature type"):
        wacryptolib.signature.verify_signature(
            key=keypair["public_key"], plaintext=plaintext, signature=dict(type="XPZH")
        )
