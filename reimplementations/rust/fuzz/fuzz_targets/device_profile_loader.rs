// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Fuzz target of the device profile loader: any input is accepted or rejected without panic, and an accepted
//! profile creates a cryptainer in each format, with an inline then an offloaded payload ciphertext. Same checks
//! as the C target.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wa_flightbox::{
    CryptainerEncryptor, DeviceProfile, DocumentFormat, EncryptorLimits, EncryptorOptions, PlatformHooks,
    RandomFailure, encrypt_payload_in_one_call,
};
use wa_flightbox_backend_rustcrypto::RustCryptoBackend;

const PAYLOAD: &[u8] = b"fuzzed device profile payload";

/// Not random: runs must be reproducible from their input.
struct CounterHooks {
    counter: u8,
}

impl PlatformHooks for CounterHooks {
    fn fill_random(&mut self, buffer: &mut [u8]) -> Result<(), RandomFailure> {
        for byte in buffer {
            self.counter = self.counter.wrapping_mul(5).wrapping_add(1);
            *byte = self.counter;
        }
        Ok(())
    }

    fn unix_time_in_ten_thousandths_of_second(&mut self) -> Option<u64> {
        Some(17_000_000_000_000)
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(device_profile) = DeviceProfile::load_from_cbor(data, &EncryptorLimits::default()) else {
        return;
    };
    for document_format in [DocumentFormat::ExtendedJson, DocumentFormat::Cbor] {
        let options = EncryptorOptions {
            document_format,
            ..EncryptorOptions::default()
        };
        let mut hooks = CounterHooks { counter: 0 };

        let mut cryptainer = Vec::new();
        encrypt_payload_in_one_call::<RustCryptoBackend, _>(
            &device_profile,
            None,
            &options,
            &mut hooks,
            PAYLOAD,
            &mut cryptainer,
        )
        .expect("an accepted profile creates a cryptainer with an inline payload ciphertext");
        assert!(!cryptainer.is_empty());

        let mut payload_ciphertext = Vec::new();
        let mut cryptainer = Vec::new();
        let mut encryptor = CryptainerEncryptor::<RustCryptoBackend, _>::create_offloaded(
            &device_profile,
            None,
            &options,
            &mut hooks,
            &mut payload_ciphertext,
        )
        .expect("an accepted profile creates an encryptor with an offloaded payload ciphertext");
        encryptor
            .encrypt_payload_chunk(PAYLOAD)
            .expect("a payload chunk is encrypted");
        encryptor
            .finalize()
            .expect("the cryptainer is finalized")
            .write_cryptainer(&mut cryptainer)
            .expect("the cryptainer is written");
        assert!(!cryptainer.is_empty() && !payload_ciphertext.is_empty());
    }
});
