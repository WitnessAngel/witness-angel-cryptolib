import hashlib

import pytest

pkcs1 = pytest.importorskip("pkcs1")  # Vendored in src/vendors/, for the pure-python fallback backend
pytest.importorskip("cryptography")

import pkcs1.keys
import pkcs1.rsaes_oaep
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


@pytest.mark.parametrize(
    "hash_class, cryptography_hash",
    [(hashlib.sha1, hashes.SHA1), (hashlib.sha512, hashes.SHA512)],  # SHA512 is what fallback_adapter uses
)
def test_pkcs1_oaep_interoperability_with_cryptography(hash_class, cryptography_hash):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.private_numbers()
    pkcs1_public_key = pkcs1.keys.RsaPublicKey(numbers.public_numbers.n, numbers.public_numbers.e)
    pkcs1_private_key = pkcs1.keys.RsaPrivateKey(numbers.public_numbers.n, numbers.d)

    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=cryptography_hash()), algorithm=cryptography_hash(), label=None
    )
    message = b"interoperable secret"

    ciphertext = pkcs1.rsaes_oaep.encrypt(pkcs1_public_key, message=message, label=b"", hash_class=hash_class)
    assert private_key.decrypt(ciphertext, oaep_padding) == message

    ciphertext = private_key.public_key().encrypt(message, oaep_padding)
    assert pkcs1.rsaes_oaep.decrypt(pkcs1_private_key, message=ciphertext, label=b"", hash_class=hash_class) == message
