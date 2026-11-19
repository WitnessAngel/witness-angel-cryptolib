// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! The document codecs against wacryptolib's outputs and against the test vectors of section 10 of the WA-CBOR
//! specification.

use wa_flightbox::{DocumentFormat, EncryptorLimits, ErrorKind, Value, decode_document_from_cbor, write_document};
#[cfg(feature = "wa-cbor")]
use wa_flightbox_backend_conformance::test_support::encode_hex;
use wa_flightbox_backend_conformance::test_support::{hex_field, items, text_field, vectors};

fn serialize(tree: &Value, format: DocumentFormat) -> Vec<u8> {
    let mut output = Vec::new();
    write_document(tree, format, &mut output).unwrap();
    output
}

/// Symkeys, key structs, nested cipherdicts, shard tuples, text escapes (`"Café ☕"`, a non-BMP character,
/// controls) and key orders: decoded from CBOR with unsorted keys, each tree is written like wacryptolib does.
#[test]
fn writers_give_the_bytes_of_wacryptolib() {
    let limits = EncryptorLimits::default();
    let samples = vectors::writer_expected_outputs();
    let names: Vec<&str> = items(&samples)
        .iter()
        .map(|sample| text_field(sample, "name"))
        .collect();
    for expected_name in [
        "symkey_aes_cbc",
        "key_struct_with_metadata",
        "nested_cipherdict",
        "shard_tuple",
        "text_escapes_and_key_orders",
    ] {
        assert!(names.contains(&expected_name), "missing writer sample {expected_name}");
    }
    for sample in items(&samples) {
        let name = text_field(sample, "name");
        let tree = decode_document_from_cbor(&hex_field(sample, "unsorted_input_cbor"), &limits)
            .unwrap_or_else(|error| panic!("writer sample {name} is not decoded: {error}"));
        #[cfg(feature = "extended-json")]
        assert_eq!(
            String::from_utf8(serialize(&tree, DocumentFormat::ExtendedJson)).unwrap(),
            text_field(sample, "expected_extended_json"),
            "Extended JSON of writer sample {name}"
        );
        #[cfg(feature = "wa-cbor")]
        assert_eq!(
            encode_hex(&serialize(&tree, DocumentFormat::Cbor)),
            text_field(sample, "expected_wacbor"),
            "WA-CBOR of writer sample {name}"
        );
        #[cfg(not(feature = "extended-json"))]
        assert_eq!(
            write_document(&tree, DocumentFormat::ExtendedJson, &mut Vec::new())
                .unwrap_err()
                .kind(),
            ErrorKind::UnsupportedFeature
        );
        #[cfg(not(feature = "wa-cbor"))]
        assert_eq!(
            write_document(&tree, DocumentFormat::Cbor, &mut Vec::new())
                .unwrap_err()
                .kind(),
            ErrorKind::UnsupportedFeature
        );
    }
}

/// Every vector of the specification: accepted ones decode (and are written back to the same bytes when they are
/// deterministic, and to the specification's Extended JSON), valid ones outside the sub-profile are unsupported,
/// invalid ones are decoding errors.
#[test]
fn wacbor_specification_vectors() {
    let limits = EncryptorLimits::default();
    let all_vectors = vectors::wacbor_specification();
    let mut counts = std::collections::HashMap::new();
    for vector in items(&all_vectors) {
        let name = text_field(vector, "name");
        let expectation = text_field(vector, "expectation");
        *counts.entry(expectation).or_insert(0) += 1;
        let cbor = hex_field(vector, "cbor");
        let result = decode_document_from_cbor(&cbor, &limits);
        let kind = result.as_ref().err().map(|error| error.kind());
        match expectation {
            "accepted" => {
                let tree = result.unwrap_or_else(|error| panic!("vector {name} is not decoded: {error}"));
                #[cfg(feature = "wa-cbor")]
                if vector["is_deterministic"].as_bool().unwrap() {
                    assert_eq!(
                        encode_hex(&serialize(&tree, DocumentFormat::Cbor)),
                        encode_hex(&cbor),
                        "vector {name} written back"
                    );
                }
                #[cfg(feature = "extended-json")]
                assert_eq!(
                    String::from_utf8(serialize(&tree, DocumentFormat::ExtendedJson)).unwrap(),
                    text_field(vector, "extjson"),
                    "Extended JSON of vector {name}"
                );
                let _ = tree;
            }
            "unsupported" => assert_eq!(kind, Some(ErrorKind::UnsupportedType), "vector {name}"),
            "decoding_error" => assert_eq!(kind, Some(ErrorKind::DecodingError), "vector {name}"),
            "unsupported_or_decoding_error" => assert!(
                matches!(kind, Some(ErrorKind::UnsupportedType | ErrorKind::DecodingError)),
                "vector {name}: {kind:?}"
            ),
            "nesting_too_deep" => assert_eq!(kind, Some(ErrorKind::NestingTooDeep), "vector {name}"),
            other => panic!("unknown expectation {other} of vector {name}"),
        }
    }
    for expectation in ["accepted", "unsupported", "decoding_error", "nesting_too_deep"] {
        assert!(
            counts.get(expectation).copied().unwrap_or(0) > 0,
            "no vector with expectation {expectation}"
        );
    }
}

/// A map of `entry_count` entries whose keys come in descending order.
fn map_with_descending_keys(entry_count: u32) -> Vec<u8> {
    let mut cbor = vec![0xBA];
    cbor.extend_from_slice(&entry_count.to_be_bytes());
    for index in (0..entry_count).rev() {
        cbor.push(0x66);
        cbor.extend_from_slice(format!("{index:06x}").as_bytes());
        cbor.push(0x00);
    }
    cbor
}

/// Decoding time does not depend on the order of map keys: 200,000 keys in descending order took minutes when
/// each entry was inserted at its sorted position, every insertion moving all the entries before it.
#[test]
fn a_large_map_with_descending_keys_is_decoded_quickly() {
    let entry_count = 200_000;
    let cbor = map_with_descending_keys(entry_count);
    let start = std::time::Instant::now();
    let document = decode_document_from_cbor(&cbor, &EncryptorLimits::default()).unwrap();
    let elapsed = start.elapsed();
    let map = document.as_map().unwrap();
    assert_eq!(map.len(), entry_count as usize);
    assert_eq!(map.entry_at(0).map(|(key, _)| key), Some("000000"));
    assert_eq!(map.entry_at(199_999).map(|(key, _)| key), Some("030d3f"));
    assert!(map.iter().zip(map.iter().skip(1)).all(|(left, right)| left.0 < right.0));
    // A fraction of a second, even unoptimized: the bound only tells linearithmic time from quadratic time
    assert!(elapsed.as_secs() < 5, "decoded in {elapsed:?}");

    // With a duplicate of the first key at the end: refused as fast
    let mut cbor = map_with_descending_keys(entry_count + 1);
    let duplicate_position = cbor.len() - 8;
    cbor.copy_within(5..13, duplicate_position);
    let start = std::time::Instant::now();
    assert_eq!(
        decode_document_from_cbor(&cbor, &EncryptorLimits::default())
            .unwrap_err()
            .kind(),
        ErrorKind::DecodingError
    );
    assert!(start.elapsed().as_secs() < 5, "refused in {:?}", start.elapsed());
}

/// The metadata decoding entry applies the configured depth limit.
#[test]
fn decoding_applies_the_depth_limit() {
    // [[[[[[[[[0]]]]]]]]]: 9 arrays
    let mut cbor = vec![0x81; 9];
    cbor.push(0x00);
    assert!(decode_document_from_cbor(&cbor, &EncryptorLimits::default()).is_ok());
    let limits = EncryptorLimits::new(8, 8, 4096).unwrap();
    assert_eq!(
        decode_document_from_cbor(&cbor, &limits).unwrap_err().kind(),
        ErrorKind::NestingTooDeep
    );
    assert!(decode_document_from_cbor(&cbor[1..], &limits).is_ok());
}
