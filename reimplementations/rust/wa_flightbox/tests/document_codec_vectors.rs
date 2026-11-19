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
