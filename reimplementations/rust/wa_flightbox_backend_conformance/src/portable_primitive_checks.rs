// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Checks of the portable primitives of the core crate (CMAC, EAX, the symmetric streams, HKDF, HPKE, RSA-OAEP,
//! key wrapping) over a given backend: they are written once in the core crate, and must give the same results
//! whatever the backend under them. Vectors are published ones (SP 800-38B, RFC 5869, RFC 9180) or come from
//! wacryptolib and pycryptodome with injected randomness. Like the conformance checks, these panic on the first
//! difference.

use wa_flightbox::crypto_backend::CryptoBackend;
use wa_flightbox::{DocumentFormat, ErrorKind, Value, internals};

use crate::test_support::{
    DeterministicHooks, ReplayedRandomHooks, encode_hex, hex_array_field, hex_field, integer_field, items, text_field,
    vectors,
};

fn assert_bytes_eq(actual: &[u8], expected: &[u8], what: &str) {
    assert!(
        actual == expected,
        "{what}:\n  actual   {}\n  expected {}",
        encode_hex(actual),
        encode_hex(expected)
    );
}

fn bytes_of<'a>(cipherdict: &'a Value, key: &str) -> &'a [u8] {
    cipherdict
        .get(key)
        .and_then(Value::as_bytes)
        .unwrap_or_else(|| panic!("no byte string {key} in the cipherdict"))
}

fn keys_of(map: &Value) -> Vec<&str> {
    map.as_map().expect("a map").iter().map(|(key, _)| key).collect()
}

/// Run every check.
pub fn check_all<B: CryptoBackend>() {
    check_aes_cmac::<B>();
    check_aes_eax::<B>();
    check_symmetric_cipherdicts_and_streams::<B>();
    check_hkdf_sha256::<B>();
    check_hpke_base_mode_seal::<B>();
    check_rsa_oaep::<B>();
    check_key_struct_wrapping::<B>();
}

/// AES-256 CMAC: the examples of SP 800-38B D.3, the message being fed whole and in pieces of 1, 15, 16 and 17
/// bytes.
pub fn check_aes_cmac<B: CryptoBackend>() {
    let vector = &vectors::primitives()["cmac"];
    let key = hex_array_field(vector, "key");
    let full_message = hex_field(vector, "full_message");
    let cases = items(&vector["cases"]);
    assert_eq!(cases.len(), 4);
    for case in cases {
        let message = &full_message[..integer_field(case, "message_length")];
        let expected_mac = hex_field(case, "mac");
        let mac = internals::compute_aes_cmac::<B>(&key, &[message]).expect("CMAC");
        assert_bytes_eq(&mac, &expected_mac, "AES-256 CMAC (SP 800-38B D.3)");
        for piece_length in [1, 15, 16, 17] {
            let pieces: Vec<&[u8]> = message.chunks(piece_length).collect();
            let mac = internals::compute_aes_cmac::<B>(&key, &pieces).expect("CMAC");
            assert_bytes_eq(&mac, &expected_mac, "AES-256 CMAC of a message fed in pieces");
        }
        let mac = internals::compute_aes_cmac::<B>(&key, &[&[], message, &[]]).expect("CMAC");
        assert_bytes_eq(&mac, &expected_mac, "AES-256 CMAC of a message fed with empty pieces");
    }
}

/// AES-256 EAX without header: pycryptodome's outputs over the messages and nonces of the EAX paper.
pub fn check_aes_eax<B: CryptoBackend>() {
    let all_vectors = vectors::primitives();
    let eax_vectors = items(&all_vectors["eax"]);
    assert!(eax_vectors.len() >= 10);
    for vector in eax_vectors {
        let (key, nonce, message) = (
            hex_field(vector, "key"),
            hex_field(vector, "nonce"),
            hex_field(vector, "message"),
        );
        let cipherdict =
            internals::symmetric_encrypt_to_cipherdict::<B>("AES_EAX", &key, &nonce, &message).expect("EAX");
        assert_bytes_eq(
            bytes_of(&cipherdict, "ciphertext"),
            &hex_field(vector, "ciphertext"),
            "AES-256 EAX ciphertext",
        );
        assert_bytes_eq(
            bytes_of(&cipherdict, "tag"),
            &hex_field(vector, "tag"),
            "AES-256 EAX tag",
        );
    }
}

/// The three payload ciphers: wacryptolib's cipherdicts for plaintexts of 0, 15, 16, 17 and 100 bytes, their
/// shapes and tag sizes, and the streamed encryption in pieces of 1, 15, 16 and 17 bytes against the one-shot one.
pub fn check_symmetric_cipherdicts_and_streams<B: CryptoBackend>() {
    let all_vectors = vectors::primitives();
    let symmetric_vectors = items(&all_vectors["symmetric_cipherdicts"]);
    assert_eq!(symmetric_vectors.len(), 15);
    for vector in symmetric_vectors {
        let cipher_algo = text_field(vector, "cipher_algo");
        let key = hex_field(vector, "key");
        let iv_or_nonce = hex_field(vector, "iv_or_nonce");
        let plaintext = hex_field(vector, "plaintext");
        let expected_ciphertext = hex_field(vector, "ciphertext");
        let expected_tag = hex_field(vector, "tag");
        assert_eq!(
            internals::symmetric_iv_or_nonce_length(cipher_algo),
            Some(iv_or_nonce.len())
        );

        let cipherdict = internals::symmetric_encrypt_to_cipherdict::<B>(cipher_algo, &key, &iv_or_nonce, &plaintext)
            .expect("symmetric encryption");
        assert_bytes_eq(
            bytes_of(&cipherdict, "ciphertext"),
            &expected_ciphertext,
            "one-shot ciphertext",
        );
        if cipher_algo == "AES_CBC" {
            assert_eq!(keys_of(&cipherdict), ["ciphertext"], "keys of an AES_CBC cipherdict");
            assert_eq!(
                expected_ciphertext.len(),
                plaintext.len() / 16 * 16 + 16,
                "PKCS#7 padded length"
            );
        } else {
            assert_eq!(
                keys_of(&cipherdict),
                ["ciphertext", "tag"],
                "keys of an AEAD cipherdict"
            );
            assert_eq!(expected_tag.len(), 16);
            assert_bytes_eq(bytes_of(&cipherdict, "tag"), &expected_tag, "one-shot tag");
        }

        for piece_length in [1, 15, 16, 17, 4096] {
            let (ciphertext, tag) =
                internals::symmetric_encrypt_in_pieces::<B>(cipher_algo, &key, &iv_or_nonce, &plaintext, piece_length)
                    .expect("streamed symmetric encryption");
            assert_bytes_eq(&ciphertext, &expected_ciphertext, "ciphertext streamed in pieces");
            assert_bytes_eq(
                tag.as_ref().map_or(&[][..], |tag| &tag[..]),
                &expected_tag,
                "tag of a streamed encryption",
            );
        }
    }

    // Wrong key or nonce sizes and unknown algorithms are refused
    for (cipher_algo, key_length, iv_or_nonce_length) in [
        ("AES_CBC", 31, 16),
        ("AES_CBC", 32, 12),
        ("CHACHA20_POLY1305", 32, 16),
        ("AES_GCM", 32, 16),
        ("aes_cbc", 32, 16),
    ] {
        let error = internals::symmetric_encrypt_to_cipherdict::<B>(
            cipher_algo,
            &vec![0; key_length],
            &vec![0; iv_or_nonce_length],
            b"",
        )
        .expect_err("an invalid symkey must be refused");
        assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    }
    assert_eq!(internals::symmetric_iv_or_nonce_length("RSA_OAEP"), None);
}

/// HKDF-SHA256: RFC 5869 A.1 to A.3, and the bounds of the output length.
pub fn check_hkdf_sha256<B: CryptoBackend>() {
    let all_vectors = vectors::primitives();
    let hkdf_vectors = items(&all_vectors["hkdf_sha256"]);
    assert_eq!(hkdf_vectors.len(), 3);
    for vector in hkdf_vectors {
        let prk = internals::hkdf_sha256_extract::<B>(&hex_field(vector, "salt"), &hex_field(vector, "ikm"))
            .expect("HKDF-Extract");
        assert_bytes_eq(&prk, &hex_field(vector, "prk"), "HKDF-SHA256 PRK (RFC 5869)");
        let okm = internals::hkdf_sha256_expand::<B>(&prk, &hex_field(vector, "info"), integer_field(vector, "length"))
            .expect("HKDF-Expand");
        assert_bytes_eq(&okm, &hex_field(vector, "okm"), "HKDF-SHA256 OKM (RFC 5869)");
    }
    let prk = [7u8; 32];
    assert_eq!(
        internals::hkdf_sha256_expand::<B>(&prk, b"", 255 * 32)
            .expect("the longest output")
            .len(),
        8160
    );
    for refused_length in [0, 255 * 32 + 1] {
        let error = internals::hkdf_sha256_expand::<B>(&prk, b"", refused_length).expect_err("an invalid HKDF length");
        assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    }
}

/// HPKE base mode seal: the RFC 9180 A.2.1 vector (DHKEM X25519, HKDF-SHA256, ChaCha20-Poly1305), a seal with
/// empty info and AAD as in cryptainers, and the ML-KEM-768 KEM (0x0041) with given coins, both opened by
/// pycryptodome when the vectors were generated. The KEM draws exactly its randomness, in one call.
pub fn check_hpke_base_mode_seal<B: CryptoBackend>() {
    let all_vectors = vectors::primitives();

    let vector = &all_vectors["rfc9180"];
    let mut hooks = ReplayedRandomHooks::new(&hex_field(vector, "skem"));
    let (enc, sealed) = internals::hpke_base_mode_seal::<B>(
        &mut hooks,
        "x25519",
        &hex_field(vector, "pkrm"),
        &hex_field(vector, "info"),
        &hex_field(vector, "aad"),
        &hex_field(vector, "plaintext"),
    )
    .expect("HPKE seal");
    assert_bytes_eq(&enc, &hex_field(vector, "enc"), "HPKE enc (RFC 9180 A.2.1)");
    assert_bytes_eq(
        &sealed,
        &hex_field(vector, "ciphertext"),
        "HPKE ciphertext of sequence number 0 (RFC 9180 A.2.1)",
    );
    assert!(
        hooks.is_exhausted() && hooks.call_count == 1,
        "DHKEM X25519 draws its 32-byte scalar in one call"
    );

    for (kem_name, vector_name, randomness_name, public_key_length, enc_length) in [
        ("x25519", "hpke_x25519", "ephemeral_scalar", 32, 32),
        ("ml-kem-768", "hpke_ml_kem_768", "coins", 1184, 1088),
    ] {
        let vector = &all_vectors[vector_name];
        let public_key = hex_field(vector, "public_key");
        let plaintext = hex_field(vector, "plaintext");
        assert_eq!(internals::hpke_kem_public_key_length(kem_name), Some(public_key_length));
        let mut hooks = ReplayedRandomHooks::new(&hex_field(vector, randomness_name));
        let (enc, sealed) =
            internals::hpke_base_mode_seal::<B>(&mut hooks, kem_name, &public_key, &[], &[], &plaintext)
                .expect("HPKE seal");
        assert_eq!(enc.len(), enc_length);
        assert_eq!(sealed.len(), plaintext.len() + 16);
        assert_bytes_eq(&enc, &hex_field(vector, "enc"), "HPKE enc");
        assert_bytes_eq(&sealed, &hex_field(vector, "sealed"), "HPKE sealed bytes");
        assert!(
            hooks.is_exhausted() && hooks.call_count == 1,
            "the KEM draws 32 bytes in one call"
        );

        // A public key of another length is refused before any draw
        let mut hooks = ReplayedRandomHooks::new(&[0; 32]);
        let error = internals::hpke_base_mode_seal::<B>(&mut hooks, kem_name, &public_key[1..], &[], &[], &plaintext)
            .expect_err("a short public key must be refused");
        assert_eq!(error.kind(), ErrorKind::InvalidArgument);
        assert_eq!(hooks.call_count, 0);
        // A failing random hook is reported as such
        let mut hooks = ReplayedRandomHooks::new(&[0; 31]);
        let error = internals::hpke_base_mode_seal::<B>(&mut hooks, kem_name, &public_key, &[], &[], &plaintext)
            .expect_err("a failing random hook");
        assert_eq!(error.kind(), ErrorKind::RandomnessFailure);
    }
    assert_eq!(internals::hpke_kem_public_key_length("p256"), None);

    // The all-zero shared secret of a low-order X25519 key is refused, whatever the backend does of it
    let mut hooks = DeterministicHooks::new(1);
    let error = internals::hpke_base_mode_seal::<B>(&mut hooks, "x25519", &[0; 32], &[], &[], b"key")
        .expect_err("a low-order X25519 key must be refused");
    assert!(
        matches!(
            error.kind(),
            ErrorKind::KeyConstraintViolation | ErrorKind::CryptoBackendFailure
        ),
        "low-order X25519 key: {error}"
    );
}

/// RSA-OAEP with SHA-512, MGF1-SHA-512 and an empty label: pycryptodome's encoding and ciphertext for a fixed
/// seed, and the 60-byte chunking (no chunk for an empty plaintext), one 64-byte seed being drawn per chunk.
pub fn check_rsa_oaep<B: CryptoBackend>() {
    let vector = &vectors::primitives()["rsa_oaep"];
    let modulus = hex_field(vector, "modulus");
    let public_exponent = hex_field(vector, "public_exponent");
    let message = hex_field(vector, "message");
    let seed = hex_field(vector, "seed");
    assert_eq!((modulus.len(), message.len(), seed.len()), (256, 60, 64));

    let encoded_message =
        internals::rsa_oaep_sha512_encode_padding::<B>(&message, &hex_array_field(vector, "seed"), modulus.len())
            .expect("OAEP encoding");
    assert_bytes_eq(
        &encoded_message,
        &hex_field(vector, "encoded_message"),
        "OAEP encoded message",
    );
    // The longest message of a 2048-bit key is 256 - 130 bytes long
    assert!(internals::rsa_oaep_sha512_encode_padding::<B>(&[1; 126], &[2; 64], 256).is_ok());
    let error = internals::rsa_oaep_sha512_encode_padding::<B>(&[1; 127], &[2; 64], 256).expect_err("a long message");
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);

    let mut hooks = ReplayedRandomHooks::new(&seed);
    let cipherdict = internals::rsa_oaep_encrypt_into_chunks::<B>(&mut hooks, &modulus, &public_exponent, &message)
        .expect("RSA-OAEP encryption");
    assert_eq!(keys_of(&cipherdict), ["ciphertext_chunks"]);
    let chunks = cipherdict
        .get("ciphertext_chunks")
        .and_then(Value::as_array)
        .expect("an array of chunks");
    assert_eq!(chunks.len(), 1);
    assert_bytes_eq(
        chunks[0].as_bytes().expect("a chunk"),
        &hex_field(vector, "ciphertext"),
        "RSA-OAEP ciphertext",
    );
    assert!(hooks.is_exhausted() && hooks.call_count == 1);

    for (plaintext_length, expected_chunk_count) in [(0usize, 0usize), (1, 1), (60, 1), (61, 2), (120, 2), (121, 3)] {
        let mut hooks = DeterministicHooks::new(7);
        let cipherdict = internals::rsa_oaep_encrypt_into_chunks::<B>(
            &mut hooks,
            &modulus,
            &public_exponent,
            &vec![0x5a; plaintext_length],
        )
        .expect("RSA-OAEP encryption");
        let chunks = cipherdict
            .get("ciphertext_chunks")
            .and_then(Value::as_array)
            .expect("an array of chunks");
        assert_eq!(
            chunks.len(),
            expected_chunk_count,
            "chunks of a {plaintext_length}-byte plaintext"
        );
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.as_bytes().is_some_and(|bytes| bytes.len() == modulus.len()))
        );
        assert_eq!(
            hooks.random_call_count, expected_chunk_count as u64,
            "one seed per chunk"
        );
    }

    let mut hooks = DeterministicHooks::new(7);
    hooks.failing_random_call_index = Some(1);
    let error = internals::rsa_oaep_encrypt_into_chunks::<B>(&mut hooks, &modulus, &public_exponent, &[0; 61])
        .expect_err("a failing random hook");
    assert_eq!(error.kind(), ErrorKind::RandomnessFailure);
}

/// Key struct wrapping with each asymmetric algorithm, in each enabled format: the shape and sizes of the
/// cipherdicts (encryptor specification, section 3.5). The key struct of an `AES_CBC` symkey without metadata takes
/// 2 RSA-OAEP chunks in WA-CBOR, against 6 in Extended JSON.
pub fn check_key_struct_wrapping<B: CryptoBackend>() {
    let all_vectors = vectors::primitives();
    let rsa_modulus = hex_field(&all_vectors["rsa_oaep"], "modulus");
    let rsa_public_exponent = hex_field(&all_vectors["rsa_oaep"], "public_exponent");
    let x25519_public_key = hex_field(&all_vectors["hpke_x25519"], "public_key");
    let ml_kem_public_key = hex_field(&all_vectors["hpke_ml_kem_768"], "public_key");
    let limits = wa_flightbox::EncryptorLimits::default();

    for (format, expected_rsa_chunk_count) in [(DocumentFormat::Cbor, 2), (DocumentFormat::ExtendedJson, 6)] {
        if !format.is_enabled() {
            let error = internals::serialize_key_struct(format, &[0; 32], None).expect_err("a disabled format");
            assert_eq!(error.kind(), ErrorKind::UnsupportedFeature);
            continue;
        }
        let symkey = internals::serialize_symkey(format, "AES_CBC", &[0x11; 32], &[0x22; 16]).expect("a symkey");
        let key_struct = internals::serialize_key_struct(format, &symkey, None).expect("a key struct");

        internals::check_public_key("RSA_OAEP", &rsa_modulus, &rsa_public_exponent, &limits).expect("a valid RSA key");
        let mut hooks = DeterministicHooks::new(3);
        let cipherdict = internals::asymmetric_wrap_key_struct::<B>(
            &mut hooks,
            format,
            "RSA_OAEP",
            &rsa_modulus,
            &rsa_public_exponent,
            &symkey,
            None,
        )
        .expect("RSA-OAEP wrapping");
        assert_eq!(keys_of(&cipherdict), ["ciphertext_chunks"]);
        let chunks = cipherdict
            .get("ciphertext_chunks")
            .and_then(Value::as_array)
            .expect("an array of chunks");
        assert_eq!(chunks.len(), key_struct.len().div_ceil(60));
        assert_eq!(
            chunks.len(),
            expected_rsa_chunk_count,
            "RSA-OAEP chunks of an AES_CBC key struct in {format:?}"
        );

        for (cipher_algo, public_key, kem_ciphertext_length) in [
            ("ECIES_X25519", &x25519_public_key, 32),
            ("ML_KEM_768", &ml_kem_public_key, 1088),
        ] {
            internals::check_public_key(cipher_algo, public_key, &[], &limits).expect("a valid public key");
            let mut hooks = DeterministicHooks::new(3);
            let cipherdict = internals::asymmetric_wrap_key_struct::<B>(
                &mut hooks,
                format,
                cipher_algo,
                public_key,
                &[],
                &symkey,
                None,
            )
            .expect("HPKE wrapping");
            assert_eq!(keys_of(&cipherdict), ["ciphertext", "kem_ciphertext"]);
            assert_eq!(bytes_of(&cipherdict, "kem_ciphertext").len(), kem_ciphertext_length);
            assert_eq!(bytes_of(&cipherdict, "ciphertext").len(), key_struct.len() + 16);
            assert_eq!(hooks.random_call_count, 1);
        }
    }
    assert!(internals::is_asymmetric_cipher_algo("RSA_OAEP") && !internals::is_asymmetric_cipher_algo("AES_CBC"));
}
