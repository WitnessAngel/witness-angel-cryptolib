from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import wacryptolib


def test_generate_shared_secret():
    keypair = wacryptolib.key_generation.generate_rsa_keypair(None)
    public_key, private_key = wacryptolib.key_generation.rsakey_to_bytes(keypair)

    keys_info = wacryptolib.sharedsecret.generate_shared_secret_key(
        public_key=public_key,
        private_key=private_key,
        shares_count=3,
        threshold_count=2,
    )

    private_key_reconstructed = wacryptolib.sharedsecret.reconstruct_shared_secret_key(
        keys_info["shares"], shares_count=3
    )

    assert private_key_reconstructed == private_key


def test_sign_and_verify_rsa():
    keypair = wacryptolib.key_generation.generate_rsa_keypair(None)
    data_hash, signature = wacryptolib.signature.sign_rsa(
        private_key=RSA.RsaKey.export_key(keypair["private_key"]), plaintext=b"Hello"
    )

    wacryptolib.signature.verify_rsa_signature(
        public_key=RSA.RsaKey.export_key(keypair["public_key"]),
        data_hash=data_hash,
        signature=signature,
    )


def test_aes_cbc():
    key = get_random_bytes(16)

    binary_content = "Mon hât èst joli".encode("utf-8")

    cipher_text = wacryptolib.cipher.encrypt_via_aes_cbc(
        key=key, plaintext=binary_content
    )

    decipher_text = wacryptolib.cipher.decrypt_via_aes_cbc(
        key=key, ciphertext=cipher_text
    )

    assert decipher_text == binary_content


def test_aes_eax():
    key = get_random_bytes(16)

    binary_content = "Mon hât èst joli".encode("utf-8")

    ciphertext, tag, nonce = wacryptolib.cipher.encrypt_via_aes_eax(
        key=key, plaintext=binary_content
    )

    wacryptolib.cipher.decrypt_via_aes_eax(
        key=key, ciphertext=ciphertext, tag=tag, nonce=nonce
    )


def test_sign_dsa():
    keypair = wacryptolib.key_generation.generate_dsa_keypair(None)
    public_key = keypair["public_key"]
    private_key = keypair["private_key"]
    binary_content = "Mon hât èst joli".encode("utf-8")
    timestamp_verifier = datetime.timestamp(datetime.now())

    signature, timestamp = wacryptolib.signature.sign_dsa(
        private_key=private_key, plaintext=binary_content
    )
    wacryptolib.signature.verify_dsa_signature(
        public_key=public_key,
        plaintext=binary_content,
        signature=signature,
        timestamp=timestamp,
    )

    assert timestamp == timestamp_verifier, "timestamps don't correspond"
