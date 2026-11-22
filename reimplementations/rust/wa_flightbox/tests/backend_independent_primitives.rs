// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! The portable primitives needing no crypto backend: UUID0 and symkey generation, Shamir secret sharing, the
//! constraints on trustee public keys, and the serialization of symkeys, shards and key structs.

use wa_flightbox::{DocumentFormat, EncryptorLimits, ErrorKind, Map, PlatformHooks, RandomFailure, Value, internals};
use wa_flightbox_backend_conformance::test_support::{
    DeterministicHooks, ReplayedRandomHooks, encode_hex, hex_field, integer_field, items, vectors,
};

/// Hooks recording the size of each random draw, with or without a clock.
struct RecordingHooks {
    draw_lengths: Vec<usize>,
    unix_time: Option<u64>,
    clock_call_count: usize,
}

impl RecordingHooks {
    fn new(unix_time: Option<u64>) -> Self {
        Self {
            draw_lengths: Vec::new(),
            unix_time,
            clock_call_count: 0,
        }
    }
}

impl PlatformHooks for RecordingHooks {
    fn fill_random(&mut self, buffer: &mut [u8]) -> Result<(), RandomFailure> {
        self.draw_lengths.push(buffer.len());
        buffer.fill(0xa5);
        Ok(())
    }

    fn unix_time_in_ten_thousandths_of_second(&mut self) -> Option<u64> {
        self.clock_call_count += 1;
        self.unix_time
    }
}

#[test]
fn uuid0_has_a_48_bit_time_prefix_and_80_random_bits() {
    let mut hooks = RecordingHooks::new(Some(0x0000_0102_0304_0506));
    let uuid = internals::generate_uuid0(&mut hooks).unwrap();
    assert_eq!(uuid[..6], [1, 2, 3, 4, 5, 6]);
    assert_eq!(uuid[6..], [0xa5; 10]);
    assert_eq!((hooks.draw_lengths.as_slice(), hooks.clock_call_count), (&[10][..], 1));

    // The two most significant bytes of the time are dropped
    let mut hooks = RecordingHooks::new(Some(0xffee_0102_0304_0506));
    assert_eq!(internals::generate_uuid0(&mut hooks).unwrap()[..6], [1, 2, 3, 4, 5, 6]);

    // The default time of the test drivers: 2026-01-01T00:00:00Z
    let mut hooks = DeterministicHooks::new(1);
    let uuid = internals::generate_uuid0(&mut hooks).unwrap();
    assert_eq!(uuid[..6], DeterministicHooks::DEFAULT_TIME.to_be_bytes()[2..]);
    assert_eq!(encode_hex(&uuid[..6]), "1012a48a9000");
    // The clock of the test drivers advances by one unit per call
    assert_eq!(
        encode_hex(&internals::generate_uuid0(&mut hooks).unwrap()[..6]),
        "1012a48a9001"
    );
}

#[test]
fn uuid0_without_clock_has_a_zero_time_prefix() {
    let mut hooks = RecordingHooks::new(None);
    let uuid = internals::generate_uuid0(&mut hooks).unwrap();
    assert_eq!(uuid[..6], [0; 6]);
    assert_eq!(uuid[6..], [0xa5; 10]);
    assert_eq!(hooks.draw_lengths, [10]);

    let mut hooks = ReplayedRandomHooks::new(&[0; 9]);
    assert_eq!(
        internals::generate_uuid0(&mut hooks).unwrap_err().kind(),
        ErrorKind::RandomnessFailure
    );
}

#[test]
fn symkeys_draw_their_key_then_their_iv_or_nonce() {
    for (cipher_algo, iv_or_nonce_length) in [("AES_CBC", 16), ("AES_EAX", 16), ("CHACHA20_POLY1305", 12)] {
        let mut hooks = RecordingHooks::new(None);
        let (key, iv_or_nonce) = internals::generate_symkey(&mut hooks, cipher_algo).unwrap();
        assert_eq!((key.len(), iv_or_nonce.len()), (32, iv_or_nonce_length));
        assert_eq!(hooks.draw_lengths, [32, iv_or_nonce_length]);
        assert_eq!(hooks.clock_call_count, 0);

        // The bytes are those of the generator, in order
        let mut hooks = DeterministicHooks::new(5);
        let (key, iv_or_nonce) = internals::generate_symkey(&mut hooks, cipher_algo).unwrap();
        let mut reference_hooks = DeterministicHooks::new(5);
        let mut expected_key = [0u8; 32];
        let mut expected_iv_or_nonce = vec![0u8; iv_or_nonce_length];
        reference_hooks.fill_random(&mut expected_key).unwrap();
        reference_hooks.fill_random(&mut expected_iv_or_nonce).unwrap();
        assert_eq!((key.as_slice(), iv_or_nonce), (&expected_key[..], expected_iv_or_nonce));

        for failing_call_index in 0..2 {
            let mut hooks = DeterministicHooks::new(5);
            hooks.failing_random_call_index = Some(failing_call_index);
            let error = internals::generate_symkey(&mut hooks, cipher_algo).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::RandomnessFailure);
        }
    }
    let mut hooks = RecordingHooks::new(None);
    assert_eq!(
        internals::generate_symkey(&mut hooks, "AES_GCM").unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    assert!(hooks.draw_lengths.is_empty());
}

// GF(2^128) helpers of the test-only recombination

type Element = [u8; 16];

fn element(value: u128) -> Element {
    value.to_be_bytes()
}

fn add(a: &Element, b: &Element) -> Element {
    element(u128::from_be_bytes(*a) ^ u128::from_be_bytes(*b))
}

fn invert(a: &Element) -> Element {
    // a^(2^128 - 2), by square and multiply
    let mut result = element(1);
    let mut power = *a;
    for bit_index in 0..128 {
        if bit_index >= 1 {
            result = internals::gf128_multiply(&result, &power);
        }
        power = internals::gf128_multiply(&power, &power);
    }
    result
}

/// Lagrange interpolation at 0 of the given `(index, shard)` pairs, then PKCS#7 unpadding.
fn recombine(shards: &[(usize, &[u8])]) -> Vec<u8> {
    let shard_length = shards[0].1.len();
    assert!(shard_length.is_multiple_of(16) && shards.iter().all(|(_, shard)| shard.len() == shard_length));
    let mut padded_secret = Vec::new();
    for chunk_offset in (0..shard_length).step_by(16) {
        let mut chunk = element(0);
        for (index, shard) in shards {
            let x = element(*index as u128);
            let y: Element = shard[chunk_offset..chunk_offset + 16].try_into().unwrap();
            let (mut numerator, mut denominator) = (element(1), element(1));
            for (other_index, _) in shards.iter().filter(|(other_index, _)| other_index != index) {
                let other_x = element(*other_index as u128);
                numerator = internals::gf128_multiply(&numerator, &other_x);
                denominator = internals::gf128_multiply(&denominator, &add(&x, &other_x));
            }
            let weight = internals::gf128_multiply(&numerator, &invert(&denominator));
            chunk = add(&chunk, &internals::gf128_multiply(&y, &weight));
        }
        padded_secret.extend_from_slice(&chunk);
    }
    let padding_length = usize::from(*padded_secret.last().unwrap());
    assert!(
        (1..=16).contains(&padding_length),
        "invalid PKCS#7 padding after recombination"
    );
    assert!(
        padded_secret[padded_secret.len() - padding_length..]
            .iter()
            .all(|byte| usize::from(*byte) == padding_length)
    );
    padded_secret.truncate(padded_secret.len() - padding_length);
    padded_secret
}

#[test]
fn gf128_multiplication_follows_the_field_of_pycryptodome() {
    let (one, x) = (element(1), element(2));
    let value = element(0x0123_4567_89ab_cdef_0f1e_2d3c_4b5a_6978);
    assert_eq!(internals::gf128_multiply(&value, &one), value);
    assert_eq!(internals::gf128_multiply(&one, &value), value);
    assert_eq!(internals::gf128_multiply(&value, &element(0)), element(0));
    // x^127 * x = x^128 = x^7 + x^2 + x + 1
    assert_eq!(internals::gf128_multiply(&element(1 << 127), &x), element(0x87));
    let other = element(0xfedc_ba98_7654_3210_8877_6655_4433_2211);
    assert_eq!(
        internals::gf128_multiply(&value, &other),
        internals::gf128_multiply(&other, &value)
    );
    assert_eq!(internals::gf128_multiply(&value, &invert(&value)), one);
}

#[test]
fn shamir_shards_equal_those_of_pycryptodome_with_injected_coefficients() {
    let vector = &vectors::primitives()["shamir"];
    let secret = hex_field(vector, "secret");
    let (shard_count, threshold_count) = (
        integer_field(vector, "shard_count"),
        integer_field(vector, "threshold_count"),
    );
    let mut hooks = ReplayedRandomHooks::new(&hex_field(vector, "coefficients"));
    let shards = internals::shamir_split_secret_into_shards(&mut hooks, &secret, shard_count, threshold_count).unwrap();
    let expected_shards: Vec<Vec<u8>> = items(&vector["shards"])
        .iter()
        .map(|shard| wa_flightbox_backend_conformance::test_support::decode_hex(shard.as_str().unwrap()))
        .collect();
    assert_eq!(shards, expected_shards);
    // threshold - 1 coefficients of 16 bytes per 16-byte chunk of the padded secret, each in its own draw
    assert!(hooks.is_exhausted());
    assert_eq!(hooks.call_count, 4);
}

#[test]
fn shamir_shards_recombine_from_any_threshold_of_them() {
    // Secrets shorter than a block, of whole blocks (a full padding block is added), and of several blocks
    for secret_length in [0usize, 1, 15, 16, 17, 32, 43, 60] {
        let secret: Vec<u8> = (0..secret_length).map(|index| (index * 7 + 3) as u8).collect();
        let padded_length = secret_length / 16 * 16 + 16;
        for (shard_count, threshold_count) in [(1usize, 1usize), (3, 1), (3, 3), (5, 3), (5, 2), (30, 4)] {
            let mut hooks = DeterministicHooks::new(11);
            let shards =
                internals::shamir_split_secret_into_shards(&mut hooks, &secret, shard_count, threshold_count).unwrap();
            assert_eq!(shards.len(), shard_count);
            assert!(shards.iter().all(|shard| shard.len() == padded_length));
            assert_eq!(
                hooks.random_call_count as usize,
                (threshold_count - 1) * padded_length / 16
            );

            let indexed: Vec<(usize, &[u8])> = shards
                .iter()
                .enumerate()
                .map(|(index, shard)| (index + 1, shard.as_slice()))
                .collect();
            // The first ones, the last ones, and spread ones
            assert_eq!(recombine(&indexed[..threshold_count]), secret);
            assert_eq!(recombine(&indexed[shard_count - threshold_count..]), secret);
            let step = (shard_count / threshold_count).max(1);
            let spread: Vec<_> = indexed.iter().copied().step_by(step).take(threshold_count).collect();
            assert_eq!(recombine(&spread), secret);
            if threshold_count == 1 {
                // Every shard is the padded secret itself
                assert!(shards.iter().all(|shard| shard[..secret_length] == secret[..]));
            } else if secret_length > 0 {
                // One shard less gives something else
                let too_few = &indexed[..threshold_count - 1];
                let chunk: Vec<u8> = too_few[0].1[..16].to_vec();
                assert!(threshold_count == 2 || chunk != secret[..secret_length.min(16)]);
            }
        }
    }
}

#[test]
fn shamir_refuses_invalid_counts_and_reports_random_failures() {
    // At most 30 shards (section 3.7)
    for (shard_count, threshold_count) in [(0usize, 0usize), (3, 0), (3, 4), (0, 1), (31, 2), (31, 31), (300, 2)] {
        let mut hooks = DeterministicHooks::new(1);
        let error = internals::shamir_split_secret_into_shards(&mut hooks, b"secret", shard_count, threshold_count)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidArgument);
        assert_eq!(hooks.random_call_count, 0);
    }
    assert_eq!(wa_flightbox::MAX_SHARED_SECRET_SHARD_COUNT, 30);
    let mut hooks = DeterministicHooks::new(1);
    let shards = internals::shamir_split_secret_into_shards(&mut hooks, b"secret", 30, 30).unwrap();
    assert_eq!(shards.len(), 30);
    let mut hooks = DeterministicHooks::new(1);
    hooks.failing_random_call_index = Some(1);
    let error = internals::shamir_split_secret_into_shards(&mut hooks, b"secret", 3, 3).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RandomnessFailure);
}

fn rsa_key() -> (Vec<u8>, Vec<u8>) {
    let all_vectors = vectors::primitives();
    (
        hex_field(&all_vectors["rsa_oaep"], "modulus"),
        hex_field(&all_vectors["rsa_oaep"], "public_exponent"),
    )
}

fn check_rsa(modulus: &[u8], public_exponent: &[u8], limits: &EncryptorLimits) -> Result<(), ErrorKind> {
    internals::check_public_key("RSA_OAEP", modulus, public_exponent, limits).map_err(|error| error.kind())
}

#[test]
fn rsa_public_key_constraints() {
    let limits = EncryptorLimits::default();
    let violation = Err(ErrorKind::KeyConstraintViolation);
    let (modulus, public_exponent) = rsa_key();
    assert_eq!(modulus.len(), 256);
    assert_eq!(check_rsa(&modulus, &public_exponent, &limits), Ok(()));
    assert_eq!(check_rsa(&modulus, &[3], &limits), Ok(()));
    assert_eq!(check_rsa(&modulus, &[1, 0, 1], &limits), Ok(()));

    // Exponents: empty, below 3, even, with a leading zero, not below the modulus
    assert_eq!(check_rsa(&modulus, &[], &limits), violation);
    assert_eq!(check_rsa(&modulus, &[1], &limits), violation);
    assert_eq!(check_rsa(&modulus, &[2], &limits), violation);
    assert_eq!(check_rsa(&modulus, &[1, 0, 0], &limits), violation);
    assert_eq!(check_rsa(&modulus, &[0, 1, 0, 1], &limits), violation);
    assert_eq!(check_rsa(&modulus, &modulus, &limits), violation);
    let mut above_modulus = modulus.clone();
    above_modulus[0] = 0xff;
    above_modulus[1] = 0xff;
    assert_eq!(check_rsa(&modulus, &above_modulus, &limits), violation);
    let mut longer_exponent = vec![1u8];
    longer_exponent.extend_from_slice(&modulus);
    assert_eq!(check_rsa(&modulus, &longer_exponent, &limits), violation);
    // The largest odd exponent below the modulus, coprime with it (n - 2: gcd(n, n - 2) = gcd(n, 2) = 1)
    let mut modulus_minus_two = modulus.clone();
    let last = modulus_minus_two.len() - 1;
    assert!(modulus_minus_two[last] >= 2);
    modulus_minus_two[last] -= 2;
    assert_eq!(check_rsa(&modulus, &modulus_minus_two, &limits), Ok(()));

    // Moduli: empty, even, with a leading zero, too short, too long
    assert_eq!(check_rsa(&[], &public_exponent, &limits), violation);
    let mut even_modulus = modulus.clone();
    even_modulus[last] &= 0xfe;
    assert_eq!(check_rsa(&even_modulus, &public_exponent, &limits), violation);
    let mut padded_modulus = vec![0u8];
    padded_modulus.extend_from_slice(&modulus);
    assert_eq!(check_rsa(&padded_modulus, &public_exponent, &limits), violation);
    assert_eq!(
        check_rsa(&modulus[1..], &public_exponent, &limits),
        violation,
        "a 2040-bit modulus"
    );
    let mut modulus_of_2047_bits = modulus.clone();
    modulus_of_2047_bits[0] = 0x7f;
    assert_eq!(check_rsa(&modulus_of_2047_bits, &public_exponent, &limits), violation);

    // Sizes against the configured maximum (odd values with a top bit set, exponent 3 coprime unless 3 divides)
    let odd_modulus = |byte_length: usize| {
        let mut bytes = vec![0xffu8; byte_length];
        bytes[byte_length - 1] = 0xfd; // 2^(8k) - 3: odd; divisible by 3 only if 2^(8k) = 0 mod 3, never
        bytes
    };
    assert_eq!(check_rsa(&odd_modulus(512), &[3], &limits), Ok(()));
    assert_eq!(check_rsa(&odd_modulus(513), &[3], &limits), violation);
    let small_limits = EncryptorLimits::new(8, 64, 2048).unwrap();
    assert_eq!(check_rsa(&odd_modulus(256), &[3], &small_limits), Ok(()));
    assert_eq!(check_rsa(&odd_modulus(257), &[3], &small_limits), violation);
    let large_limits = EncryptorLimits::new(8, 64, 8192).unwrap();
    assert_eq!(check_rsa(&odd_modulus(1024), &[3], &large_limits), Ok(()));
    assert_eq!(check_rsa(&odd_modulus(1025), &[3], &large_limits), violation);

    // An exponent sharing a factor with the modulus: 2^2048 - 1 is divisible by 3, 5, 17 and 257
    let all_ones = vec![0xffu8; 256];
    for shared_factor in [&[3u8][..], &[5], &[15], &[1, 1], &[0x0f, 0x0f]] {
        assert_eq!(
            check_rsa(&all_ones, shared_factor, &limits),
            violation,
            "exponent {shared_factor:?}"
        );
    }
    assert_eq!(
        check_rsa(&all_ones, &[7], &limits),
        Ok(()),
        "7 does not divide 2^2048 - 1"
    );
    assert_eq!(
        check_rsa(&all_ones, &[0x0b], &limits),
        Ok(()),
        "11 does not divide 2^2048 - 1"
    );
}

#[test]
fn x25519_public_key_constraints() {
    let limits = EncryptorLimits::default();
    let check =
        |key: &[u8]| internals::check_public_key("ECIES_X25519", key, &[], &limits).map_err(|error| error.kind());
    let violation = Err(ErrorKind::KeyConstraintViolation);
    let valid_key = hex_field(&vectors::primitives()["hpke_x25519"], "public_key");
    assert_eq!(check(&valid_key), Ok(()));
    assert_eq!(check(&valid_key[..31]), violation);
    assert_eq!(check(&[valid_key.as_slice(), &[0]].concat()), violation);
    assert_eq!(check(&[]), violation);

    // Low-order points: 0, 1, the two points of order 8, p - 1
    let mut key = [0u8; 32];
    assert_eq!(check(&key), violation);
    key[0] = 1;
    assert_eq!(check(&key), violation);
    key[0] = 2;
    assert_eq!(check(&key), Ok(()));
    for low_order_point in [
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        let key = wa_flightbox_backend_conformance::test_support::decode_hex(low_order_point);
        assert_eq!(check(&key), violation, "{low_order_point}");
    }
    // Non-canonical encodings: p to 2^255 - 1, and anything with the top bit set
    let mut p = [0xffu8; 32];
    p[31] = 0x7f;
    for low_byte in [0xed, 0xee, 0xff] {
        p[0] = low_byte;
        assert_eq!(check(&p), violation, "low byte {low_byte:#x}");
    }
    p[0] = 0xeb; // p - 2
    assert_eq!(check(&p), Ok(()));
    let mut top_bit_set = valid_key.clone();
    top_bit_set[31] |= 0x80;
    assert_eq!(check(&top_bit_set), violation);
}

#[test]
fn ml_kem_768_public_key_constraints() {
    let limits = EncryptorLimits::default();
    let check = |key: &[u8]| internals::check_public_key("ML_KEM_768", key, &[], &limits).map_err(|error| error.kind());
    let violation = Err(ErrorKind::KeyConstraintViolation);
    let valid_key = hex_field(&vectors::primitives()["hpke_ml_kem_768"], "public_key");
    assert_eq!(valid_key.len(), 1184);
    assert_eq!(check(&valid_key), Ok(()));
    assert_eq!(check(&valid_key[..1183]), violation);
    assert_eq!(check(&[valid_key.as_slice(), &[0]].concat()), violation);

    // A coefficient of 3329 (0xd01), as first then as second of a pair, at both ends of the polynomials
    for triple_offset in [0usize, 1149] {
        let mut key = valid_key.clone();
        key[triple_offset] = 0x01;
        key[triple_offset + 1] = (key[triple_offset + 1] & 0xf0) | 0x0d;
        assert_eq!(check(&key), violation);
        let mut key = valid_key.clone();
        key[triple_offset + 1] = (key[triple_offset + 1] & 0x0f) | 0x10;
        key[triple_offset + 2] = 0xd0;
        assert_eq!(check(&key), violation);
        // 3328 is the largest reduced coefficient
        let mut key = valid_key.clone();
        key[triple_offset] = 0x00;
        key[triple_offset + 1] = (key[triple_offset + 1] & 0xf0) | 0x0d;
        assert_eq!(check(&key), Ok(()));
    }
    // The 32 bytes of rho are free
    let mut key = valid_key.clone();
    key[1152..].fill(0xff);
    assert_eq!(check(&key), Ok(()));
}

#[test]
fn unknown_asymmetric_algorithms_are_refused() {
    let limits = EncryptorLimits::default();
    for cipher_algo in ["RSA", "rsa_oaep", "AES_CBC", ""] {
        assert!(!internals::is_asymmetric_cipher_algo(cipher_algo));
        let error = internals::check_public_key(cipher_algo, &[1; 32], &[], &limits).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    }
    for cipher_algo in ["RSA_OAEP", "ECIES_X25519", "ML_KEM_768"] {
        assert!(internals::is_asymmetric_cipher_algo(cipher_algo));
    }
}

fn enabled_formats() -> Vec<DocumentFormat> {
    [DocumentFormat::ExtendedJson, DocumentFormat::Cbor]
        .into_iter()
        .filter(|format| format.is_enabled())
        .collect()
}

/// Read a serialized structure back: both formats are decoded to a tree (the JSON one through `serde_json`).
fn read_back(format: DocumentFormat, serialized: &[u8]) -> serde_json::Value {
    fn from_tree(tree: &Value) -> serde_json::Value {
        if let Some(map) = tree.as_map() {
            serde_json::Value::Object(
                map.iter()
                    .map(|(key, value)| (key.to_owned(), from_tree(value)))
                    .collect(),
            )
        } else if let Some(array) = tree.as_array() {
            serde_json::Value::Array(array.iter().map(from_tree).collect())
        } else if let Some(bytes) = tree.as_bytes() {
            serde_json::json!({ "bytes": encode_hex(bytes) })
        } else if let Some(integer) = tree.as_integer() {
            serde_json::json!(integer)
        } else if let Some(text) = tree.as_text() {
            serde_json::json!(text)
        } else if tree.is_null() {
            serde_json::Value::Null
        } else {
            panic!("unexpected value {tree:?}")
        }
    }
    fn from_extended_json(json: &serde_json::Value) -> serde_json::Value {
        match json {
            serde_json::Value::Object(object) if object.contains_key("$binary") => {
                assert_eq!(object["$binary"]["subType"], "00");
                let bytes = decode_base64(object["$binary"]["base64"].as_str().unwrap());
                serde_json::json!({ "bytes": encode_hex(&bytes) })
            }
            serde_json::Value::Object(object) => serde_json::Value::Object(
                object
                    .iter()
                    .map(|(key, value)| (key.clone(), from_extended_json(value)))
                    .collect(),
            ),
            serde_json::Value::Array(array) => serde_json::Value::Array(array.iter().map(from_extended_json).collect()),
            other => other.clone(),
        }
    }
    match format {
        DocumentFormat::Cbor => {
            from_tree(&wa_flightbox::decode_document_from_cbor(serialized, &EncryptorLimits::default()).unwrap())
        }
        _ => from_extended_json(&serde_json::from_slice(serialized).unwrap()),
    }
}

fn decode_base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes = Vec::new();
    let (mut accumulator, mut bit_count) = (0u32, 0);
    for character in text.bytes().filter(|character| *character != b'=') {
        let digit = ALPHABET
            .iter()
            .position(|candidate| *candidate == character)
            .expect("a base64 digit");
        accumulator = (accumulator << 6) | digit as u32;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            bytes.push((accumulator >> bit_count) as u8);
        }
    }
    bytes
}

fn bytes_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({ "bytes": encode_hex(bytes) })
}

#[test]
fn symkeys_shards_and_key_structs_have_their_specified_layouts() {
    assert!(!enabled_formats().is_empty());
    for format in enabled_formats() {
        for (cipher_algo, iv_or_nonce_name, iv_or_nonce_length) in [
            ("AES_CBC", "iv", 16),
            ("AES_EAX", "nonce", 16),
            ("CHACHA20_POLY1305", "nonce", 12),
        ] {
            let (key, iv_or_nonce) = ([0x11u8; 32], vec![0x22u8; iv_or_nonce_length]);
            let serialized = internals::serialize_symkey(format, cipher_algo, &key, &iv_or_nonce).unwrap();
            let expected = serde_json::json!({ "key": bytes_json(&key), iv_or_nonce_name: bytes_json(&iv_or_nonce) });
            assert_eq!(read_back(format, &serialized), expected);
        }
        assert_eq!(
            internals::serialize_symkey(format, "AES_CBC", &[0; 32], &[0; 12])
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidArgument
        );

        // Shards are [index, bytes] pairs, the index being written from 1
        let shard = [0x33u8; 48];
        for shard_index in [0usize, 1, 254] {
            let serialized = internals::serialize_shard(format, shard_index, &shard).unwrap();
            assert_eq!(
                read_back(format, &serialized),
                serde_json::json!([shard_index + 1, bytes_json(&shard)])
            );
        }

        // Key structs: the key bytes and the metadata, null when there are none
        let key_bytes = [0x44u8; 70];
        let serialized = internals::serialize_key_struct(format, &key_bytes, None).unwrap();
        assert_eq!(
            read_back(format, &serialized),
            serde_json::json!({ "key_bytes": bytes_json(&key_bytes), "cryptainer_metadata": null })
        );
        let metadata =
            Value::from(Map::from_entries([("camera", Value::from("front")), ("index", Value::from(3i64))]).unwrap());
        let serialized = internals::serialize_key_struct(format, &key_bytes, Some(&metadata)).unwrap();
        assert_eq!(
            read_back(format, &serialized),
            serde_json::json!({ "key_bytes": bytes_json(&key_bytes), "cryptainer_metadata": { "camera": "front", "index": 3 } })
        );
    }
    // The exact bytes of each format, for an AES_CBC symkey
    if DocumentFormat::ExtendedJson.is_enabled() {
        let serialized =
            internals::serialize_symkey(DocumentFormat::ExtendedJson, "AES_CBC", &[0; 32], &[0xff; 16]).unwrap();
        assert_eq!(
            core::str::from_utf8(&serialized).unwrap(),
            "{\"iv\": {\"$binary\": {\"base64\": \"/////////////////////w==\", \"subType\": \"00\"}}, \"key\": \
             {\"$binary\": {\"base64\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\", \"subType\": \"00\"}}}"
        );
    }
    if DocumentFormat::Cbor.is_enabled() {
        let serialized = internals::serialize_symkey(DocumentFormat::Cbor, "AES_CBC", &[0; 32], &[0xff; 16]).unwrap();
        let mut expected = vec![0xa2, 0x62, b'i', b'v', 0x50];
        expected.extend_from_slice(&[0xff; 16]);
        expected.extend_from_slice(&[0x63, b'k', b'e', b'y', 0x58, 0x20]);
        expected.extend_from_slice(&[0; 32]);
        assert_eq!(serialized, expected);
        assert_eq!(serialized.len(), 59);
    }
    for format in [DocumentFormat::ExtendedJson, DocumentFormat::Cbor] {
        if !format.is_enabled() {
            let error = internals::serialize_symkey(format, "AES_CBC", &[0; 32], &[0; 16]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::UnsupportedFeature);
        }
    }
}
