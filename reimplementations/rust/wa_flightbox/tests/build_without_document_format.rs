// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! The library built without any document format (`cargo test -p wa_flightbox --no-default-features --test
//! build_without_document_format`): it builds, since a crypto backend crate built alone enables no format, loads
//! device profiles, and refuses every cryptainer creation before drawing anything.
//!
//! The other test files need at least one format; this one is empty when a format is enabled.

#![cfg(not(any(feature = "extended-json", feature = "wa-cbor")))]

use wa_flightbox::{
    CryptainerEncryptor, DeviceProfile, DocumentFormat, EncryptorLimits, EncryptorOptions, ErrorKind, NoPayloadSink,
    encrypt_payload_in_one_call,
};
use wa_flightbox_backend_conformance::test_support::{DeterministicHooks, device_profile_sample};
use wa_flightbox_backend_rustcrypto::RustCryptoBackend;

#[test]
fn every_creation_is_refused_as_an_unsupported_feature() {
    let device_profile = DeviceProfile::load_from_cbor(
        &device_profile_sample("minimal_rsa_authenticator"),
        &EncryptorLimits::default(),
    )
    .expect("device profiles are readable in every build");
    let requested_formats = [
        EncryptorOptions::default().document_format,
        DocumentFormat::ExtendedJson,
        DocumentFormat::Cbor,
    ];
    for document_format in requested_formats {
        assert!(!document_format.is_enabled());
        assert_eq!(document_format.cryptainer_suffix(), None);
        let options = EncryptorOptions {
            document_format,
            ..EncryptorOptions::default()
        };

        let mut hooks = DeterministicHooks::new(1);
        let error = CryptainerEncryptor::<RustCryptoBackend, NoPayloadSink>::create(
            &device_profile,
            None,
            &options,
            &mut hooks,
        )
        .err()
        .expect("a refused creation");
        assert_eq!(error.kind(), ErrorKind::UnsupportedFeature);

        let mut payload_sink = Vec::new();
        let error = CryptainerEncryptor::<RustCryptoBackend, _>::create_offloaded(
            &device_profile,
            None,
            &options,
            &mut hooks,
            &mut payload_sink,
        )
        .err()
        .expect("a refused creation");
        assert_eq!(error.kind(), ErrorKind::UnsupportedFeature);
        assert!(payload_sink.is_empty());

        let mut cryptainer_sink = Vec::new();
        let error = encrypt_payload_in_one_call::<RustCryptoBackend, _>(
            &device_profile,
            None,
            &options,
            &mut hooks,
            b"payload",
            &mut cryptainer_sink,
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnsupportedFeature);
        assert!(cryptainer_sink.is_empty());
    }
}
