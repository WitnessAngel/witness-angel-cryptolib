from datetime import datetime

from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes

import wacryptolib


def test_split_bytestring_as_shamir_shares():
    keypair = wacryptolib.key_generation.generate_rsa_keypair(None)
    private_key = RSA.RsaKey.export_key(keypair["private_key"])

    shares = wacryptolib.shared_secret.split_bytestring_as_shamir_shares(
        bytestring=private_key,
        shares_count=3,
        threshold_count=2,
    )

    private_key_reconstructed = wacryptolib.shared_secret.reconstruct_bytestring(
        shares, shares_count=3, length=len(private_key)
    )

    assert private_key_reconstructed == private_key


def test_remove_share():
    key = b'\xe7i`.2{k\xf2\xe92\x04c;U[\x96'
    shares = [(1, b'u\x87\xff"\xc3\xeb\x8a\xd5y\xa4\x99\x83\xa9y\x01\xd3'),
              (2, b'\xc2\xb4^7\xd1Z\xa9\xbd\xc8\x1f?\xa2\x1f\r\xef\x9b'),
              (3, b'PZ\xc1; \xcaH\x9aX\x89\xa2B\x8d!\xb5\xde'),
              (4, b'\xac\xd3\x1c\x1d\xf48\xefl\xabhs\xe1s\xe43\x8c')]

    key_reconstructed = wacryptolib.shared_secret.reconstruct_bytestring(
        shares, shares_count=4, length=len(key)
    )

    assert key_reconstructed == key


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


def test_sign_ecdsa():
    # keypair = wacryptolib.key_generation.generate_dsa_keypair(None)
    keypair = wacryptolib.key_generation.generate_ecc_keypair(None, curve="p256")
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


def test_generate_ecc_keypair():
    keypair = wacryptolib.key_generation.generate_ecc_keypair(None, "p256")
    assert isinstance(keypair["public_key"], ECC.EccKey), isinstance(keypair["private_key"], ECC.EccKey)


def test_chacha20():
    key = get_random_bytes(32)
    binary_content = "Mon hât èst joli".encode("utf-8")

    ciphertext, tag, nonce, header = wacryptolib.cipher.encrypt_via_chacha20_poly1305(key, binary_content)

    deciphertext = wacryptolib.cipher.decrypt_via_chacha20_poly1305(key=key, ciphertext=ciphertext, nonce=nonce,
                                                                    tag=tag, header=header)

    assert deciphertext == binary_content


def test_oaep():
    keypair = wacryptolib.key_generation.generate_rsa_keypair(None)
    binary_content = "Mon hât èst joli".encode("utf-8")

    ciphertext = wacryptolib.cipher.encrypt_via_oaep(key=keypair["public_key"], plaintext=binary_content)

    deciphertext = wacryptolib.cipher.decrypt_via_oaep(key=keypair["private_key"], ciphertext=ciphertext)

    assert deciphertext == binary_content
