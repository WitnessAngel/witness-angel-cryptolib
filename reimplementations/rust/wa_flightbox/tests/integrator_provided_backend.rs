// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! A crypto backend provided by an integrator, as one would route AES to a hardware peripheral: defined here
//! with the public trait only, it delegates to the RustCrypto backend and counts its bulk AES calls. The payload
//! reaches it in whole processing slices, not block by block.

use std::sync::atomic::{AtomicUsize, Ordering};

use wa_flightbox::crypto_backend::*;
use wa_flightbox::{CryptainerEncryptor, DeviceProfile, EncryptorLimits, EncryptorOptions, Result};
use wa_flightbox_backend_conformance::test_support::{DeterministicHooks, device_profile_sample};
use wa_flightbox_backend_rustcrypto::{RustCryptoAes256, RustCryptoBackend};

static CBC_CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
static CBC_BLOCK_COUNT: AtomicUsize = AtomicUsize::new(0);
static CTR_CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
static CTR_BLOCK_COUNT: AtomicUsize = AtomicUsize::new(0);
static LARGEST_CBC_CALL: AtomicUsize = AtomicUsize::new(0);

/// As a driver of an AES peripheral would be: one call per buffer.
struct PeripheralAes(RustCryptoAes256);

impl Aes256Encryptor for PeripheralAes {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Result<Self> {
        Ok(Self(RustCryptoAes256::new(key)?))
    }

    fn encrypt_cbc_blocks(
        &mut self,
        chaining_value: &mut [u8; AES_BLOCK_SIZE],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        CBC_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
        CBC_BLOCK_COUNT.fetch_add(input.len() / AES_BLOCK_SIZE, Ordering::Relaxed);
        LARGEST_CBC_CALL.fetch_max(input.len(), Ordering::Relaxed);
        self.0.encrypt_cbc_blocks(chaining_value, input, output)
    }

    fn encrypt_ctr_blocks(
        &mut self,
        counter_block: &mut [u8; AES_BLOCK_SIZE],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        CTR_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
        CTR_BLOCK_COUNT.fetch_add(input.len() / AES_BLOCK_SIZE, Ordering::Relaxed);
        self.0.encrypt_ctr_blocks(counter_block, input, output)
    }
}

/// Hardware AES, everything else from the software backend.
struct IntegratorBackend;

impl CryptoBackend for IntegratorBackend {
    type Aes256 = PeripheralAes;
    type ChaCha20Poly1305 = <RustCryptoBackend as CryptoBackend>::ChaCha20Poly1305;

    fn compute_sha256(parts: &[&[u8]]) -> Result<[u8; SHA256_DIGEST_SIZE]> {
        RustCryptoBackend::compute_sha256(parts)
    }

    fn compute_sha512(parts: &[&[u8]]) -> Result<[u8; SHA512_DIGEST_SIZE]> {
        RustCryptoBackend::compute_sha512(parts)
    }

    fn compute_hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Result<[u8; SHA256_DIGEST_SIZE]> {
        RustCryptoBackend::compute_hmac_sha256(key, parts)
    }

    fn x25519_compute_public_key(private_scalar: &[u8; X25519_KEY_SIZE]) -> Result<[u8; X25519_KEY_SIZE]> {
        RustCryptoBackend::x25519_compute_public_key(private_scalar)
    }

    fn x25519_compute_shared_secret(
        private_scalar: &[u8; X25519_KEY_SIZE],
        peer_public_key: &[u8; X25519_KEY_SIZE],
    ) -> Result<[u8; X25519_KEY_SIZE]> {
        RustCryptoBackend::x25519_compute_shared_secret(private_scalar, peer_public_key)
    }

    fn rsa_compute_public_operation(
        modulus: &[u8],
        public_exponent: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        RustCryptoBackend::rsa_compute_public_operation(modulus, public_exponent, input, output)
    }

    fn ml_kem_768_encapsulate_derandomized(
        public_key: &[u8; ML_KEM_768_PUBLIC_KEY_SIZE],
        coins: &[u8; ML_KEM_768_COINS_SIZE],
        ciphertext: &mut [u8; ML_KEM_768_CIPHERTEXT_SIZE],
        shared_secret: &mut [u8; ML_KEM_768_SHARED_SECRET_SIZE],
    ) -> Result<()> {
        RustCryptoBackend::ml_kem_768_encapsulate_derandomized(public_key, coins, ciphertext, shared_secret)
    }
}

fn reset_counters() {
    for counter in [
        &CBC_CALL_COUNT,
        &CBC_BLOCK_COUNT,
        &CTR_CALL_COUNT,
        &CTR_BLOCK_COUNT,
        &LARGEST_CBC_CALL,
    ] {
        counter.store(0, Ordering::Relaxed);
    }
}

fn load_sample(name: &str) -> DeviceProfile {
    DeviceProfile::load_from_cbor(&device_profile_sample(name), &EncryptorLimits::default()).unwrap()
}

/// Encrypt with the integrator backend, and check the cryptainer against the one of the RustCrypto backend.
fn encrypt_with_both_backends(sample_name: &str, options: &EncryptorOptions, payload: &[u8], chunk_length: usize) {
    let device_profile = load_sample(sample_name);
    let mut hooks = DeterministicHooks::new(95);
    let mut encryptor =
        CryptainerEncryptor::<IntegratorBackend>::create(&device_profile, None, options, &mut hooks).unwrap();
    for chunk in payload.chunks(chunk_length) {
        encryptor.encrypt_payload_chunk(chunk).unwrap();
    }
    let finished = encryptor.finalize().unwrap();

    let mut hooks = DeterministicHooks::new(95);
    let mut reference_encryptor =
        CryptainerEncryptor::<RustCryptoBackend>::create(&device_profile, None, options, &mut hooks).unwrap();
    reference_encryptor.encrypt_payload_chunk(payload).unwrap();
    assert_eq!(
        finished.cryptainer(),
        reference_encryptor.finalize().unwrap().cryptainer()
    );
}

/// One test function: the counters are shared by the whole binary.
#[test]
fn bulk_aes_calls_follow_processing_slices_not_blocks() {
    const PAYLOAD_LENGTH: usize = 64 * 1024;
    let payload = vec![0x3cu8; PAYLOAD_LENGTH];

    // The integrator backend passes the conformance suite, as any backend must
    wa_flightbox_backend_conformance::check_all::<IntegratorBackend>();
    wa_flightbox_backend_conformance::portable_primitive_checks::check_all::<IntegratorBackend>();

    // AES_CBC payload layer, its key wrapped with RSA-OAEP: every AES call comes from the payload
    for (slice_size, chunk_length) in [
        (4096usize, PAYLOAD_LENGTH),
        (4096, 4096),
        (1024, PAYLOAD_LENGTH),
        (16384, 50_000),
        (4096, 1000),
    ] {
        reset_counters();
        let options = EncryptorOptions {
            payload_processing_slice_size: slice_size,
            ..EncryptorOptions::default()
        };
        encrypt_with_both_backends("minimal_rsa_authenticator", &options, &payload, chunk_length);
        // The chunks are cut in slices: each one is a call, plus the padding block at finalization
        let slice_count: usize = payload
            .chunks(chunk_length)
            .map(|chunk| chunk.len().div_ceil(slice_size))
            .sum();
        let context = format!("slices of {slice_size}, chunks of {chunk_length}");
        let cbc_call_count = CBC_CALL_COUNT.load(Ordering::Relaxed);
        if chunk_length % 16 == 0 {
            assert_eq!(cbc_call_count, slice_count + 1, "{context}");
        } else {
            // A slice that does not end on a block boundary leaves a remainder, completed in a call of one block
            assert!(
                (slice_count + 1..=2 * slice_count + 1).contains(&cbc_call_count),
                "{context}: {cbc_call_count}"
            );
        }
        assert_eq!(
            CBC_BLOCK_COUNT.load(Ordering::Relaxed),
            PAYLOAD_LENGTH / 16 + 1,
            "{context}"
        );
        assert!(
            cbc_call_count < PAYLOAD_LENGTH / 16 / 8,
            "{context}: far fewer calls than blocks"
        );
        let largest_call = LARGEST_CBC_CALL.load(Ordering::Relaxed);
        assert!(
            largest_call + 16 > slice_size.min(chunk_length),
            "{context}: whole slices in a call ({largest_call})"
        );
        assert_eq!(CTR_CALL_COUNT.load(Ordering::Relaxed), 0);
    }

    // AES_EAX first payload layer (then CHACHA20_POLY1305): one CTR call per slice for the payload; the OMAC of
    // the ciphertext is computed in bulk calls too, of 16 blocks
    reset_counters();
    encrypt_with_both_backends(
        "nested_all_layer_kinds",
        &EncryptorOptions::default(),
        &payload,
        PAYLOAD_LENGTH,
    );
    assert_eq!(CTR_CALL_COUNT.load(Ordering::Relaxed), PAYLOAD_LENGTH / 4096);
    assert_eq!(CTR_BLOCK_COUNT.load(Ordering::Relaxed), PAYLOAD_LENGTH / 16);
    let cbc_call_count = CBC_CALL_COUNT.load(Ordering::Relaxed);
    assert!(
        cbc_call_count < PAYLOAD_LENGTH / 16 / 8,
        "{cbc_call_count} CBC-MAC calls"
    );
    assert!(CBC_BLOCK_COUNT.load(Ordering::Relaxed) >= PAYLOAD_LENGTH / 16);
}
