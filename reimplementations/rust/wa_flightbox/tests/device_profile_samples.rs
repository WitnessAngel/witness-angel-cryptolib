// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Device profile loading over the samples of the C library's unit tests: valid profiles (exported from the
//! compatibility corpus or built by hand) and one invalid profile per rule of the `flightbox-device-profile`
//! specification, each with its expected error kind and location.

use wa_flightbox::{DEVICE_PROFILE_FORMAT, DeviceProfile, EncryptorLimits, ErrorKind};
use wa_flightbox_backend_conformance::test_support::{hex_field, integer_field, items, text_field, vectors};

fn find_sample_cbor(name: &str) -> Vec<u8> {
    let samples = vectors::device_profile_samples();
    let sample = items(&samples)
        .iter()
        .find(|sample| text_field(sample, "name") == name)
        .unwrap_or_else(|| panic!("no device profile sample named {name}"));
    hex_field(sample, "cbor")
}

#[test]
fn every_sample_has_its_expected_outcome() {
    let limits = EncryptorLimits::default();
    let samples = vectors::device_profile_samples();
    let mut valid_count = 0;
    let mut seen_kinds = std::collections::HashSet::new();
    for sample in items(&samples) {
        let name = text_field(sample, "name");
        let expected_status = text_field(sample, "expected_status");
        let result = DeviceProfile::load_from_cbor(&hex_field(sample, "cbor"), &limits);
        match result {
            Ok(device_profile) => {
                assert_eq!(expected_status, "WA_STATUS_OK", "sample {name} was accepted");
                assert_eq!(
                    device_profile.trustee_public_key_count(),
                    integer_field(sample, "expected_key_entry_count"),
                    "key entries of sample {name}"
                );
                assert!(
                    device_profile.cryptoconf().as_map().is_some(),
                    "cryptoconf of sample {name}"
                );
                assert_eq!(
                    device_profile
                        .cryptoconf()
                        .get("keychain_uid")
                        .and_then(|uid| uid.as_uuid()),
                    Some(device_profile.root_keychain_uid()),
                    "root keychain uid of sample {name}"
                );
                valid_count += 1;
            }
            Err(error) => {
                let status_name = error.kind().status_name();
                let alternative_status = sample["alternative_status"].as_str();
                assert!(
                    status_name == expected_status || Some(status_name) == alternative_status,
                    "sample {name}: {status_name} at {:?}, expected {expected_status} (or {alternative_status:?})",
                    error.location()
                );
                // A null location is not checked (several are acceptable)
                if let Some(expected_location) = sample["expected_location"].as_str() {
                    assert_eq!(error.location(), expected_location, "error location of sample {name}");
                }
                seen_kinds.insert(error.kind());
            }
        }
    }
    assert!(valid_count >= 15, "only {valid_count} valid samples");
    for kind in [
        ErrorKind::UnsupportedFormat,
        ErrorKind::DecodingError,
        ErrorKind::InvalidProfile,
        ErrorKind::UnsupportedType,
        ErrorKind::UnsupportedSignature,
        ErrorKind::MissingPublicKey,
        ErrorKind::KeyConstraintViolation,
        ErrorKind::NestingTooDeep,
    ] {
        assert!(seen_kinds.contains(&kind), "no sample is rejected with {kind:?}");
    }
}

#[test]
fn limits_are_those_given_at_loading() {
    let cbor = find_sample_cbor("rsa_4096_bits");
    assert!(DeviceProfile::load_from_cbor(&cbor, &EncryptorLimits::default()).is_ok());
    // A lower RSA bound refuses the 4096-bit key
    let limits = EncryptorLimits::new(8, 64, 3072).unwrap();
    let error = DeviceProfile::load_from_cbor(&cbor, &limits).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::KeyConstraintViolation);
    assert_eq!(error.location(), "trustee_public_keys[0]");

    // Nine nested key cipher layers pass with a limit of 9 (and then fail on something else or load)
    let cbor = find_sample_cbor("key_cipher_nesting_9_levels");
    let error = DeviceProfile::load_from_cbor(&cbor, &EncryptorLimits::default()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NestingTooDeep);
    let limits = EncryptorLimits::new(9, 64, 4096).unwrap();
    match DeviceProfile::load_from_cbor(&cbor, &limits) {
        Ok(device_profile) => assert_eq!(device_profile.limits(), &limits),
        Err(error) => assert_ne!(error.kind(), ErrorKind::NestingTooDeep, "at {}", error.location()),
    }

    // A lower CBOR depth refuses a profile that the default one accepts
    let cbor = find_sample_cbor("nested_all_layer_kinds");
    assert!(DeviceProfile::load_from_cbor(&cbor, &EncryptorLimits::default()).is_ok());
    let limits = EncryptorLimits::new(8, 8, 4096).unwrap();
    assert_eq!(
        DeviceProfile::load_from_cbor(&cbor, &limits).unwrap_err().kind(),
        ErrorKind::NestingTooDeep
    );
}

#[test]
fn a_profile_is_reusable_and_keeps_its_document() {
    let cbor = find_sample_cbor("nested_all_layer_kinds");
    let device_profile = DeviceProfile::load_from_cbor(&cbor, &EncryptorLimits::default()).unwrap();
    assert_eq!(DEVICE_PROFILE_FORMAT, "flightbox_device_profile_1.0");
    let payload_cipher_layers = device_profile
        .cryptoconf()
        .get("payload_cipher_layers")
        .and_then(|layers| layers.as_array())
        .unwrap();
    assert!(!payload_cipher_layers.is_empty());
    assert_eq!(device_profile.trustee_public_key_count(), 5);
    // Debug output does not dump key material
    assert!(format!("{device_profile:?}").len() < 400);
}
