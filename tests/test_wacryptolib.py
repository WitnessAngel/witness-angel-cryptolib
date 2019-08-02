from Crypto.PublicKey import RSA, ECC, DSA
from Crypto.Random import get_random_bytes

import uuid

from src import wacryptolib


def test_generate_keypair_uid():
    # uid1 = uuid.UUID('12345678-1234-5678-1234-567812345678')
    uid1 = uuid.uuid4()
    uid2 = uuid.uuid4()
    uid3 = uuid.uuid4()
    key_type = "ECC"
    keypair1 = wacryptolib.key_generation.generate_assymetric_keypair(uid=uid1, key_type=key_type)
    keypair2 = wacryptolib.key_generation.generate_assymetric_keypair(uid=uid1, key_type=key_type)
    keypair3 = wacryptolib.key_generation.generate_assymetric_keypair(uid=uid3, key_type=key_type)

    cond1 = keypair1 == keypair2
    cond2 = keypair3 != keypair1
    assert cond1 and cond2


def test_split_bytestring_as_shamir_shares():
    keypair = wacryptolib.key_generation.generate_rsa_keypair(None)
    private_key = RSA.RsaKey.export_key(keypair["private_key"])

    shares = wacryptolib.shared_secret.split_bytestring_as_shamir_shares(
        bytestring=private_key, shares_count=3, threshold_count=2
    )

    private_key_reconstructed = wacryptolib.shared_secret.reconstruct_bytestring(
        shares, shares_count=3, bytestring_length=len(private_key)
    )

    assert private_key_reconstructed == private_key


def test_sign_and_verify_rsa():
    keypair = wacryptolib.key_generation.generate_rsa_keypair(None)
    signature = wacryptolib.signature.sign_rsa(
        private_key=keypair["private_key"], plaintext=b"Hello"
    )

    wacryptolib.signature.verify_signature(
        public_key=keypair["public_key"], plaintext=b"Hello", signature=signature
    )


def test_sign_and_verify_ecdsa():
    keypair = wacryptolib.key_generation.generate_ecc_keypair(None, curve="p256")
    signature = wacryptolib.signature.sign_dsa(
        private_key=keypair["private_key"], plaintext="Mon hât èst joli".encode("utf-8")
    )

    wacryptolib.signature.verify_signature(
        public_key=keypair["public_key"],
        plaintext="Mon hât èst joli".encode("utf-8"),
        signature=signature,
    )


def test_sign_and_verify_dsa():
    keypair = wacryptolib.key_generation.generate_dsa_keypair(None)
    signature = wacryptolib.signature.sign_dsa(
        private_key=keypair["private_key"], plaintext="Mon hât èst joli".encode("utf-8")
    )

    wacryptolib.signature.verify_signature(
        public_key=keypair["public_key"],
        plaintext="Mon hât èst joli".encode("utf-8"),
        signature=signature,
    )


def test_aes_cbc_encryption_and_decryption():
    key = get_random_bytes(16)

    binary_content = "Mon hât èst joli".encode("utf-8")

    iv_and_ciphertext = wacryptolib.cipher.encrypt_via_aes_cbc(
        key=key, plaintext=binary_content
    )

    decipher_text = wacryptolib.cipher.decrypt_via_aes_cbc(
        key=key, iv_and_ciphertext=iv_and_ciphertext
    )

    assert decipher_text == binary_content


def test_aes_eax_encryption_and_decryption():
    key = get_random_bytes(16)

    binary_content = "Mon hât èst joli".encode("utf-8")

    encryption = wacryptolib.cipher.encrypt_via_aes_eax(
        key=key, plaintext=binary_content
    )

    wacryptolib.cipher.decrypt_via_aes_eax(key=key, encryption=encryption)


def test_generate_ecc_keypair():
    keypair = wacryptolib.key_generation.generate_ecc_keypair(None, "p256")
    assert isinstance(keypair["public_key"], ECC.EccKey), isinstance(
        keypair["private_key"], ECC.EccKey
    )


def test_chacha20_symetric_encryption_and_decryption():
    key = get_random_bytes(32)
    binary_content = "Mon hât èst joli".encode("utf-8")

    encryption = wacryptolib.cipher.encrypt_via_chacha20_poly1305(
        key, binary_content, header=b"header"
    )

    deciphertext = wacryptolib.cipher.decrypt_via_chacha20_poly1305(
        key=key, encryption=encryption
    )

    assert deciphertext == binary_content


def test_rsa_oaep_encryption_and_decryption():
    keypair = wacryptolib.key_generation.generate_rsa_keypair(None)
    binary_content = "Mon hât èst joli".encode("utf-8")

    ciphertext = wacryptolib.cipher.encrypt_via_rsa_oaep(
        key=keypair["public_key"], plaintext=binary_content
    )

    deciphertext = wacryptolib.cipher.decrypt_via_rsa_oaep(
        key=keypair["private_key"], encryption=ciphertext
    )

    assert deciphertext == binary_content


def test_publickey_generation_with_optional_parameters():
    keypair_rsa = wacryptolib.key_generation.generate_assymetric_keypair(None, "RSA", 1024)
    assert isinstance(keypair_rsa["public_key"], RSA.RsaKey)
    keypair_dsa = wacryptolib.key_generation.generate_assymetric_keypair(None, "DSA", 1024)
    assert isinstance(keypair_dsa["public_key"], DSA.DsaKey)
    keypair_ecc = wacryptolib.key_generation.generate_assymetric_keypair(None, "ECC", "p384")
    assert isinstance(keypair_ecc["public_key"], ECC.EccKey)


def test_publickey_generation_without_optional_parameters():
    keypair_rsa = wacryptolib.key_generation.generate_assymetric_keypair(None, "RSA")
    assert isinstance(keypair_rsa["public_key"], RSA.RsaKey)
    keypair_dsa = wacryptolib.key_generation.generate_assymetric_keypair(None, "DSA")
    assert isinstance(keypair_dsa["public_key"], DSA.DsaKey)
    keypair_ecc = wacryptolib.key_generation.generate_assymetric_keypair(None, "ECC")
    assert isinstance(keypair_ecc["public_key"], ECC.EccKey)
