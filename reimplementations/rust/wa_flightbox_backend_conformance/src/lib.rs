// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Conformance tests of the crypto backends of the Witness Angel flightbox encryptor: the acceptance test of a
//! [`CryptoBackend`] implementation, be it one of this workspace or an integrator's (for a hardware accelerator).
//!
//! Each `check_*` function exercises one primitive against published vectors (SP 800-38A, RFC 8439, FIPS 180-4,
//! RFC 4231, RFC 7748) and known answers computed with pycryptodome, including the corners of the contract:
//! streaming over several calls, the counter wrap-around, the empty ChaCha20-Poly1305 stream, and a raw RSA input
//! not below the modulus. They panic on the first difference, like assertions. In a test of the backend crate:
//!
//! ```ignore
//! #[test]
//! fn conformance() {
//!     wa_flightbox_backend_conformance::check_all::<MyBackend>();
//! }
//! ```
//!
//! The [`portable_primitive_checks`] module checks the portable primitives of the core crate over a backend, and
//! the [`test_support`] module holds what the tests of this workspace share.

#![forbid(unsafe_code)]

pub mod portable_primitive_checks;
pub mod test_support;

use wa_flightbox::ErrorKind;
use wa_flightbox::crypto_backend::{
    AES_BLOCK_SIZE, Aes256Encryptor, ChaCha20Poly1305Encryptor, CryptoBackend, ML_KEM_768_CIPHERTEXT_SIZE,
    ML_KEM_768_SHARED_SECRET_SIZE,
};

use crate::test_support::{encode_hex, hex_array_field, hex_field, items, vectors};

/// Hex in messages: differences are readable, and long values do not flood the output with byte lists.
fn assert_bytes_eq(actual: &[u8], expected: &[u8], what: &str) {
    assert!(
        actual == expected,
        "{what}:\n  actual   {}\n  expected {}",
        encode_hex(actual),
        encode_hex(expected)
    );
}

/// Run every check.
pub fn check_all<B: CryptoBackend>() {
    check_aes_256_cbc::<B>();
    check_aes_256_ctr::<B>();
    check_chacha20_poly1305::<B>();
    check_sha256_and_sha512::<B>();
    check_hmac_sha256::<B>();
    check_x25519::<B>();
    check_rsa_public_operation::<B>();
    check_ml_kem_768_encapsulation::<B>();
}

/// AES-256-CBC: SP 800-38A F.2.5 in one call, block by block and in uneven calls, the chaining value being carried
/// from call to call; lengths that are not multiples of the block size are refused.
pub fn check_aes_256_cbc<B: CryptoBackend>() {
    let vector = &vectors::backend_conformance()["sp800_38a"];
    let key = hex_array_field(vector, "key");
    let plaintext = hex_field(vector, "plaintext");
    let iv: [u8; AES_BLOCK_SIZE] = hex_array_field(vector, "cbc_iv");
    let expected_ciphertext = hex_field(vector, "cbc_ciphertext");
    assert_eq!(plaintext.len(), 4 * AES_BLOCK_SIZE);

    for call_lengths in [&[64usize][..], &[16, 16, 16, 16], &[16, 48], &[0, 32, 0, 32]] {
        let mut aes = B::Aes256::new(&key).expect("AES-256 key setup");
        let mut chaining_value = iv;
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut offset = 0;
        for &call_length in call_lengths {
            aes.encrypt_cbc_blocks(
                &mut chaining_value,
                &plaintext[offset..offset + call_length],
                &mut ciphertext[offset..offset + call_length],
            )
            .expect("AES-256-CBC encryption");
            offset += call_length;
            if offset > 0 {
                assert_bytes_eq(
                    &chaining_value,
                    &expected_ciphertext[offset - AES_BLOCK_SIZE..offset],
                    "AES-256-CBC chaining value after a call (the last ciphertext block)",
                );
            }
        }
        assert_bytes_eq(
            &ciphertext,
            &expected_ciphertext,
            "AES-256-CBC ciphertext (SP 800-38A F.2.5)",
        );
    }

    let mut aes = B::Aes256::new(&key).expect("AES-256 key setup");
    let mut chaining_value = iv;
    let mut output = [0u8; 17];
    let error = aes
        .encrypt_cbc_blocks(&mut chaining_value, &plaintext[..17], &mut output)
        .expect_err("AES-256-CBC of 17 bytes must be refused");
    assert_eq!(
        error.kind(),
        ErrorKind::InvalidArgument,
        "AES-256-CBC of a length that is not a multiple of 16"
    );
    let error = aes
        .encrypt_cbc_blocks(&mut chaining_value, &plaintext[..32], &mut output[..16])
        .expect_err("AES-256-CBC into an output of another length must be refused");
    assert_eq!(
        error.kind(),
        ErrorKind::InvalidArgument,
        "AES-256-CBC with different input and output lengths"
    );
}

/// AES-256-CTR with a 128-bit big-endian counter: SP 800-38A F.5.5 in one call and in several, the counter block
/// being carried from call to call, and a counter wrapping around 2^128.
pub fn check_aes_256_ctr<B: CryptoBackend>() {
    let all_vectors = vectors::backend_conformance();
    let vector = &all_vectors["sp800_38a"];
    let key = hex_array_field(vector, "key");
    let plaintext = hex_field(vector, "plaintext");
    let initial_counter: [u8; AES_BLOCK_SIZE] = hex_array_field(vector, "ctr_counter");
    let expected_ciphertext = hex_field(vector, "ctr_ciphertext");

    for call_lengths in [&[64usize][..], &[16, 16, 16, 16], &[48, 16], &[0, 16, 0, 48]] {
        let mut aes = B::Aes256::new(&key).expect("AES-256 key setup");
        let mut counter_block = initial_counter;
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut offset = 0;
        for &call_length in call_lengths {
            aes.encrypt_ctr_blocks(
                &mut counter_block,
                &plaintext[offset..offset + call_length],
                &mut ciphertext[offset..offset + call_length],
            )
            .expect("AES-256-CTR encryption");
            offset += call_length;
            let expected_counter = u128::from_be_bytes(initial_counter) + (offset / AES_BLOCK_SIZE) as u128;
            assert_bytes_eq(
                &counter_block,
                &expected_counter.to_be_bytes(),
                "AES-256-CTR counter block after a call (advanced by one per block)",
            );
        }
        assert_bytes_eq(
            &ciphertext,
            &expected_ciphertext,
            "AES-256-CTR ciphertext (SP 800-38A F.5.5)",
        );
    }

    let vector = &all_vectors["ctr_wraparound"];
    let mut aes = B::Aes256::new(&hex_array_field(vector, "key")).expect("AES-256 key setup");
    let mut counter_block: [u8; AES_BLOCK_SIZE] = hex_array_field(vector, "counter");
    let plaintext = hex_field(vector, "plaintext");
    let mut ciphertext = vec![0u8; plaintext.len()];
    aes.encrypt_ctr_blocks(&mut counter_block, &plaintext, &mut ciphertext)
        .expect("AES-256-CTR encryption");
    assert_bytes_eq(
        &ciphertext,
        &hex_field(vector, "ciphertext"),
        "AES-256-CTR ciphertext across the counter wrap",
    );
    assert_bytes_eq(
        &counter_block,
        &hex_field(vector, "next_counter"),
        "AES-256-CTR counter block after the wrap",
    );

    let mut output = [0u8; 15];
    let error = aes
        .encrypt_ctr_blocks(&mut counter_block, &plaintext[..15], &mut output)
        .expect_err("AES-256-CTR of 15 bytes must be refused");
    assert_eq!(
        error.kind(),
        ErrorKind::InvalidArgument,
        "AES-256-CTR of a length that is not a multiple of 16"
    );
}

/// ChaCha20-Poly1305: RFC 8439 2.8.2 in one call and in calls of any lengths, and the stream without any data.
pub fn check_chacha20_poly1305<B: CryptoBackend>() {
    let vector = &vectors::backend_conformance()["rfc8439"];
    let key = hex_array_field(vector, "key");
    let nonce = hex_array_field(vector, "nonce");
    let associated_data = hex_field(vector, "aad");
    let plaintext = hex_field(vector, "plaintext");
    let expected_ciphertext = hex_field(vector, "ciphertext");
    let expected_tag = hex_field(vector, "tag");

    for call_lengths in [
        &[usize::MAX][..],
        &[1, 15, 17, 0, 31, usize::MAX],
        &[16, 16, 64, usize::MAX],
        &[7; 17],
    ] {
        let mut aead = B::ChaCha20Poly1305::new(&key, &nonce, &associated_data).expect("ChaCha20-Poly1305 key setup");
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut offset = 0;
        for &call_length in call_lengths {
            let call_length = call_length.min(plaintext.len() - offset);
            aead.encrypt(
                &plaintext[offset..offset + call_length],
                &mut ciphertext[offset..offset + call_length],
            )
            .expect("ChaCha20-Poly1305 encryption");
            offset += call_length;
        }
        assert_eq!(offset, plaintext.len());
        let tag = aead.finish().expect("ChaCha20-Poly1305 tag");
        assert_bytes_eq(
            &ciphertext,
            &expected_ciphertext,
            "ChaCha20-Poly1305 ciphertext (RFC 8439 2.8.2)",
        );
        assert_bytes_eq(&tag, &expected_tag, "ChaCha20-Poly1305 tag (RFC 8439 2.8.2)");
    }

    // No associated data and no data: with and without an empty call
    for has_empty_call in [false, true] {
        let mut aead = B::ChaCha20Poly1305::new(&key, &nonce, &[]).expect("ChaCha20-Poly1305 key setup");
        if has_empty_call {
            aead.encrypt(&[], &mut [])
                .expect("ChaCha20-Poly1305 encryption of nothing");
        }
        let tag = aead.finish().expect("ChaCha20-Poly1305 tag");
        assert_bytes_eq(
            &tag,
            &hex_field(vector, "empty_message_tag"),
            "ChaCha20-Poly1305 tag of an empty stream",
        );
    }

    let mut aead = B::ChaCha20Poly1305::new(&key, &nonce, &[]).expect("ChaCha20-Poly1305 key setup");
    let mut output = [0u8; 3];
    let error = aead
        .encrypt(&plaintext[..4], &mut output)
        .expect_err("ChaCha20-Poly1305 into an output of another length must be refused");
    assert_eq!(
        error.kind(),
        ErrorKind::InvalidArgument,
        "ChaCha20-Poly1305 with different input and output lengths"
    );
}

/// SHA-256 and SHA-512: FIPS 180-4 examples, the message being given whole, in parts and with empty parts.
pub fn check_sha256_and_sha512<B: CryptoBackend>() {
    for vector in items(&vectors::backend_conformance()["sha"]) {
        let message = hex_field(vector, "message");
        let middle = message.len() / 2;
        let partitions: [&[&[u8]]; 4] = [
            &[&message],
            &[&message[..middle], &message[middle..]],
            &[&[], &message, &[]],
            &[],
        ];
        // The last partition, of no part at all, is the empty message
        for parts in &partitions[..if message.is_empty() { 4 } else { 3 }] {
            let digest = B::compute_sha256(parts).expect("SHA-256");
            assert_bytes_eq(&digest, &hex_field(vector, "sha256"), "SHA-256 digest (FIPS 180-4)");
            let digest = B::compute_sha512(parts).expect("SHA-512");
            assert_bytes_eq(&digest, &hex_field(vector, "sha512"), "SHA-512 digest (FIPS 180-4)");
        }
    }
}

/// HMAC-SHA256: RFC 4231 test cases 1, 2 and 6 (a key longer than a block), the data being given whole and in
/// parts.
pub fn check_hmac_sha256<B: CryptoBackend>() {
    for vector in items(&vectors::backend_conformance()["hmac_sha256"]) {
        let key = hex_field(vector, "key");
        let data = hex_field(vector, "data");
        let middle = data.len() / 2;
        let partitions: [&[&[u8]]; 3] = [
            &[&data],
            &[&data[..middle], &data[middle..]],
            &[&[], &data[..1], &data[1..]],
        ];
        for parts in partitions {
            let mac = B::compute_hmac_sha256(&key, parts).expect("HMAC-SHA256");
            assert_bytes_eq(&mac, &hex_field(vector, "mac"), "HMAC-SHA256 (RFC 4231)");
        }
    }
}

/// X25519: RFC 7748 5.2 (a peer key whose top bit is set and masked) and 6.1; a low-order peer key gives zeros
/// and no error, the encryptor checking the shared secret itself.
pub fn check_x25519<B: CryptoBackend>() {
    let vector = &vectors::backend_conformance()["rfc7748"];
    let shared_secret =
        B::x25519_compute_shared_secret(&hex_array_field(vector, "scalar"), &hex_array_field(vector, "u"))
            .expect("X25519");
    assert_bytes_eq(
        &shared_secret,
        &hex_field(vector, "output"),
        "X25519 function (RFC 7748 5.2)",
    );

    let alice_private = hex_array_field(vector, "alice_private");
    let public_key = B::x25519_compute_public_key(&alice_private).expect("X25519 public key");
    assert_bytes_eq(
        &public_key,
        &hex_field(vector, "alice_public"),
        "X25519 public key (RFC 7748 6.1)",
    );
    let shared_secret = B::x25519_compute_shared_secret(&alice_private, &hex_array_field(vector, "bob_public"))
        .expect("X25519 shared secret");
    assert_bytes_eq(
        &shared_secret,
        &hex_field(vector, "shared"),
        "X25519 shared secret (RFC 7748 6.1)",
    );

    // The contract allows zeros or a failure, nothing else
    if let Ok(shared_secret) = B::x25519_compute_shared_secret(&alice_private, &[0; 32]) {
        assert_bytes_eq(
            &shared_secret,
            &[0; 32],
            "X25519 shared secret with the point of order 1",
        );
    }
}

/// The raw RSA public operation: known answers with 4096-bit (e = 65537) and 2048-bit (e = 3) keys, the inputs 0
/// and 1, and the refusal of an input not below the modulus and of wrong lengths.
pub fn check_rsa_public_operation<B: CryptoBackend>() {
    for vector in items(&vectors::backend_conformance()["raw_rsa"]) {
        let modulus = hex_field(vector, "modulus");
        let public_exponent = hex_field(vector, "public_exponent");
        let input = hex_field(vector, "input");
        let mut output = vec![0xa5u8; modulus.len()];
        B::rsa_compute_public_operation(&modulus, &public_exponent, &input, &mut output).expect("RSA public operation");
        assert_bytes_eq(
            &output,
            &hex_field(vector, "output"),
            "RSA public operation (input^e mod n)",
        );

        for small_input in [0u8, 1] {
            let mut input = vec![0u8; modulus.len()];
            *input.last_mut().expect("a modulus of some bytes") = small_input;
            let mut output = vec![0xa5u8; modulus.len()];
            B::rsa_compute_public_operation(&modulus, &public_exponent, &input, &mut output)
                .expect("RSA public operation on 0 or 1");
            assert_bytes_eq(
                &output,
                &input,
                "RSA public operation on 0 or 1 (itself, with leading zeros)",
            );
        }

        for (what, bad_input) in [("the modulus", &modulus), ("all ones", &vec![0xff; modulus.len()])] {
            let error = B::rsa_compute_public_operation(&modulus, &public_exponent, bad_input, &mut output)
                .expect_err("an RSA input not below the modulus must be refused");
            assert_eq!(
                error.kind(),
                ErrorKind::InvalidArgument,
                "RSA public operation on {what}"
            );
        }
        let error = B::rsa_compute_public_operation(&modulus, &public_exponent, &input[1..], &mut output)
            .expect_err("an RSA input shorter than the modulus must be refused");
        assert_eq!(
            error.kind(),
            ErrorKind::InvalidArgument,
            "RSA public operation on a short input"
        );
        let short_length = output.len() - 1;
        let error = B::rsa_compute_public_operation(&modulus, &public_exponent, &input, &mut output[..short_length])
            .expect_err("an RSA output shorter than the modulus must be refused");
        assert_eq!(
            error.kind(),
            ErrorKind::InvalidArgument,
            "RSA public operation into a short output"
        );
    }
}

/// ML-KEM-768 encapsulation from given randomness: a known answer of pycryptodome (FIPS 203). The modulus check of
/// encapsulation keys belongs to the portable profile loader, so it is not tested here.
pub fn check_ml_kem_768_encapsulation<B: CryptoBackend>() {
    let vector = &vectors::backend_conformance()["ml_kem_768"];
    let public_key = hex_array_field(vector, "public_key");
    let coins = hex_array_field(vector, "coins");
    let mut ciphertext = [0u8; ML_KEM_768_CIPHERTEXT_SIZE];
    let mut shared_secret = [0u8; ML_KEM_768_SHARED_SECRET_SIZE];
    B::ml_kem_768_encapsulate_derandomized(&public_key, &coins, &mut ciphertext, &mut shared_secret)
        .expect("ML-KEM-768 encapsulation");
    assert_bytes_eq(&ciphertext, &hex_field(vector, "ciphertext"), "ML-KEM-768 ciphertext");
    assert_bytes_eq(
        &shared_secret,
        &hex_field(vector, "shared_secret"),
        "ML-KEM-768 shared secret",
    );
}
