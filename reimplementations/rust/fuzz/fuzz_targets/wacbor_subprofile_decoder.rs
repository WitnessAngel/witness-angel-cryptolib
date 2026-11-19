// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Fuzz target of the WA-CBOR sub-profile decoder: any input gives a tree or one of the decoder's error kinds,
//! without panic; an accepted tree is written in both formats, its WA-CBOR writing being a fixed point of
//! decoding and writing, and its Extended JSON writing being ASCII. Same checks as the C target.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wa_flightbox::{DocumentFormat, EncryptorLimits, ErrorKind, decode_document_from_cbor, write_document};

fuzz_target!(|data: &[u8]| {
    let limits = EncryptorLimits::default();
    let tree = match decode_document_from_cbor(data, &limits) {
        Ok(tree) => tree,
        Err(error) => {
            assert!(
                matches!(
                    error.kind(),
                    ErrorKind::UnsupportedType
                        | ErrorKind::DecodingError
                        | ErrorKind::NestingTooDeep
                        | ErrorKind::OutOfMemory
                ),
                "unexpected decoding error: {error:?}"
            );
            return;
        }
    };

    let mut first_writing = Vec::new();
    write_document(&tree, DocumentFormat::Cbor, &mut first_writing).expect("an accepted tree is written as WA-CBOR");
    let decoded_again =
        decode_document_from_cbor(&first_writing, &limits).expect("the WA-CBOR writing of an accepted tree is decoded");
    let mut second_writing = Vec::new();
    write_document(&decoded_again, DocumentFormat::Cbor, &mut second_writing)
        .expect("a tree decoded twice is written as WA-CBOR");
    assert_eq!(
        first_writing, second_writing,
        "the WA-CBOR writing is not a fixed point"
    );

    let mut json_writing = Vec::new();
    write_document(&tree, DocumentFormat::ExtendedJson, &mut json_writing)
        .expect("an accepted tree is written as Extended JSON");
    assert!(json_writing.is_ascii(), "the Extended JSON writing is not ASCII");
});
