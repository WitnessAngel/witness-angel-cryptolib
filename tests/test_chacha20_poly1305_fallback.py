import random

import pytest

from wacryptolib._crypto_backend.chacha20_poly1305 import ChaCha20Poly1305Cipher


def test_chacha20_rfc8439_encryption_test_vector():
    # RFC 8439 section 2.4.2 (encryption starts with block counter 1, like in the AEAD construction);
    # the Poly1305 part is checked against pycryptodome below
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
        b"sunscreen would be it."
    )
    ciphertext = ChaCha20Poly1305Cipher(key, nonce).encrypt(plaintext)
    # RFC 8439 2.4.2 uses counter=1 for encryption, like the AEAD construction
    assert ciphertext.hex().startswith("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b")


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 63, 64, 65, 1000])
def test_chacha20_poly1305_fallback_matches_pycryptodome(size):
    from Crypto.Cipher import ChaCha20_Poly1305

    if not ChaCha20_Poly1305.new.__module__.startswith("Crypto."):
        pytest.skip("pycryptodome's native ChaCha20_Poly1305 is not available (fallback mode)")

    key, nonce = random.randbytes(32), random.randbytes(12)
    plaintext = random.randbytes(size)
    expected = ChaCha20_Poly1305.new(key=key, nonce=nonce).encrypt_and_digest(plaintext)

    assert ChaCha20Poly1305Cipher(key, nonce).encrypt_and_digest(plaintext) == expected

    cipher = ChaCha20Poly1305Cipher(key, nonce)  # Streaming, with irregular chunks
    cut1, cut2 = sorted(random.randint(0, size) for _ in range(2))
    ciphertext = cipher.encrypt(plaintext[:cut1]) + cipher.encrypt(memoryview(plaintext[cut1:cut2]))
    ciphertext += cipher.encrypt(plaintext[cut2:])
    assert (ciphertext, cipher.digest()) == expected

    ciphertext, tag = expected
    assert ChaCha20Poly1305Cipher(key, nonce).decrypt_and_verify(ciphertext, tag) == plaintext
    with pytest.raises(ValueError, match="MAC check failed"):
        ChaCha20Poly1305Cipher(key, nonce).decrypt_and_verify(ciphertext, bytes([tag[0] ^ 1]) + tag[1:])
