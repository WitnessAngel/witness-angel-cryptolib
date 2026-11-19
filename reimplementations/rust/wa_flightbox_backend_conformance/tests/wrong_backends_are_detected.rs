// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! The conformance suite detects wrong backends: one whose outputs have a flipped bit fails every check, and
//! backends with subtler faults (state not carried across calls, contract checks missing) fail the check of the
//! primitive concerned.

use wa_flightbox::Result;
use wa_flightbox::crypto_backend::*;
use wa_flightbox_backend_conformance as conformance;
use wa_flightbox_backend_rustcrypto::{RustCryptoAes256, RustCryptoBackend, RustCryptoChaCha20Poly1305};

/// What a faulty backend does wrong.
trait Fault {
    /// Flip a bit of every output
    const CORRUPTS_OUTPUTS: bool = false;
    /// Do not write the chaining value and the counter block back
    const FORGETS_BLOCK_MODE_STATE: bool = false;
    /// Accept an RSA input not below the modulus (computing with the input reduced)
    const ACCEPTS_LARGE_RSA_INPUT: bool = false;
}

struct FaultyBackend<F: Fault>(core::marker::PhantomData<F>);
struct FaultyAes<F: Fault>(RustCryptoAes256, core::marker::PhantomData<F>);
struct FaultyChaCha<F: Fault>(RustCryptoChaCha20Poly1305, core::marker::PhantomData<F>);

fn corrupt<F: Fault>(output: &mut [u8]) {
    if F::CORRUPTS_OUTPUTS {
        if let Some(last_byte) = output.last_mut() {
            *last_byte ^= 0x01;
        }
    }
}

impl<F: Fault> Aes256Encryptor for FaultyAes<F> {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Result<Self> {
        Ok(Self(RustCryptoAes256::new(key)?, core::marker::PhantomData))
    }

    fn encrypt_cbc_blocks(
        &mut self,
        chaining_value: &mut [u8; AES_BLOCK_SIZE],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        let mut new_chaining_value = *chaining_value;
        self.0.encrypt_cbc_blocks(&mut new_chaining_value, input, output)?;
        if !F::FORGETS_BLOCK_MODE_STATE {
            *chaining_value = new_chaining_value;
        }
        corrupt::<F>(output);
        Ok(())
    }

    fn encrypt_ctr_blocks(
        &mut self,
        counter_block: &mut [u8; AES_BLOCK_SIZE],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        let mut new_counter_block = *counter_block;
        self.0.encrypt_ctr_blocks(&mut new_counter_block, input, output)?;
        if !F::FORGETS_BLOCK_MODE_STATE {
            *counter_block = new_counter_block;
        }
        corrupt::<F>(output);
        Ok(())
    }
}

impl<F: Fault> ChaCha20Poly1305Encryptor for FaultyChaCha<F> {
    fn new(
        key: &[u8; CHACHA20_POLY1305_KEY_SIZE],
        nonce: &[u8; CHACHA20_POLY1305_NONCE_SIZE],
        associated_data: &[u8],
    ) -> Result<Self> {
        Ok(Self(
            RustCryptoChaCha20Poly1305::new(key, nonce, associated_data)?,
            core::marker::PhantomData,
        ))
    }

    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        self.0.encrypt(input, output)
    }

    fn finish(self) -> Result<[u8; AEAD_TAG_SIZE]> {
        let mut tag = self.0.finish()?;
        corrupt::<F>(&mut tag);
        Ok(tag)
    }
}

impl<F: Fault> CryptoBackend for FaultyBackend<F> {
    type Aes256 = FaultyAes<F>;
    type ChaCha20Poly1305 = FaultyChaCha<F>;

    fn compute_sha256(parts: &[&[u8]]) -> Result<[u8; SHA256_DIGEST_SIZE]> {
        let mut digest = RustCryptoBackend::compute_sha256(parts)?;
        corrupt::<F>(&mut digest);
        Ok(digest)
    }

    fn compute_sha512(parts: &[&[u8]]) -> Result<[u8; SHA512_DIGEST_SIZE]> {
        let mut digest = RustCryptoBackend::compute_sha512(parts)?;
        corrupt::<F>(&mut digest);
        Ok(digest)
    }

    fn compute_hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Result<[u8; SHA256_DIGEST_SIZE]> {
        let mut mac = RustCryptoBackend::compute_hmac_sha256(key, parts)?;
        corrupt::<F>(&mut mac);
        Ok(mac)
    }

    fn x25519_compute_public_key(private_scalar: &[u8; X25519_KEY_SIZE]) -> Result<[u8; X25519_KEY_SIZE]> {
        let mut public_key = RustCryptoBackend::x25519_compute_public_key(private_scalar)?;
        corrupt::<F>(&mut public_key);
        Ok(public_key)
    }

    fn x25519_compute_shared_secret(
        private_scalar: &[u8; X25519_KEY_SIZE],
        peer_public_key: &[u8; X25519_KEY_SIZE],
    ) -> Result<[u8; X25519_KEY_SIZE]> {
        let mut shared_secret = RustCryptoBackend::x25519_compute_shared_secret(private_scalar, peer_public_key)?;
        corrupt::<F>(&mut shared_secret);
        Ok(shared_secret)
    }

    fn rsa_compute_public_operation(
        modulus: &[u8],
        public_exponent: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        if F::ACCEPTS_LARGE_RSA_INPUT && input.len() == modulus.len() && input >= modulus {
            // As a library reducing its input would: here, simply computed from another value
            let mut reduced_input = vec![0u8; modulus.len()];
            reduced_input[modulus.len() - 1] = 2;
            return RustCryptoBackend::rsa_compute_public_operation(modulus, public_exponent, &reduced_input, output);
        }
        RustCryptoBackend::rsa_compute_public_operation(modulus, public_exponent, input, output)?;
        corrupt::<F>(output);
        Ok(())
    }

    fn ml_kem_768_encapsulate_derandomized(
        public_key: &[u8; ML_KEM_768_PUBLIC_KEY_SIZE],
        coins: &[u8; ML_KEM_768_COINS_SIZE],
        ciphertext: &mut [u8; ML_KEM_768_CIPHERTEXT_SIZE],
        shared_secret: &mut [u8; ML_KEM_768_SHARED_SECRET_SIZE],
    ) -> Result<()> {
        RustCryptoBackend::ml_kem_768_encapsulate_derandomized(public_key, coins, ciphertext, shared_secret)?;
        corrupt::<F>(shared_secret);
        Ok(())
    }
}

struct NoFault;
impl Fault for NoFault {}

struct CorruptedOutputs;
impl Fault for CorruptedOutputs {
    const CORRUPTS_OUTPUTS: bool = true;
}

struct ForgottenBlockModeState;
impl Fault for ForgottenBlockModeState {
    const FORGETS_BLOCK_MODE_STATE: bool = true;
}

struct LargeRsaInputAccepted;
impl Fault for LargeRsaInputAccepted {
    const ACCEPTS_LARGE_RSA_INPUT: bool = true;
}

type Corrupted = FaultyBackend<CorruptedOutputs>;

/// The wrapper itself is transparent: the failures below come from the faults.
#[test]
fn the_wrapper_without_fault_passes() {
    conformance::check_all::<FaultyBackend<NoFault>>();
}

#[test]
#[should_panic(expected = "AES-256-CBC")]
fn corrupted_aes_256_cbc() {
    conformance::check_aes_256_cbc::<Corrupted>();
}

#[test]
#[should_panic(expected = "AES-256-CTR")]
fn corrupted_aes_256_ctr() {
    conformance::check_aes_256_ctr::<Corrupted>();
}

#[test]
#[should_panic(expected = "ChaCha20-Poly1305 tag")]
fn corrupted_chacha20_poly1305() {
    conformance::check_chacha20_poly1305::<Corrupted>();
}

#[test]
#[should_panic(expected = "SHA-256 digest")]
fn corrupted_sha() {
    conformance::check_sha256_and_sha512::<Corrupted>();
}

#[test]
#[should_panic(expected = "HMAC-SHA256")]
fn corrupted_hmac_sha256() {
    conformance::check_hmac_sha256::<Corrupted>();
}

#[test]
#[should_panic(expected = "X25519")]
fn corrupted_x25519() {
    conformance::check_x25519::<Corrupted>();
}

#[test]
#[should_panic(expected = "RSA public operation")]
fn corrupted_rsa_public_operation() {
    conformance::check_rsa_public_operation::<Corrupted>();
}

#[test]
#[should_panic(expected = "ML-KEM-768 shared secret")]
fn corrupted_ml_kem_768_encapsulation() {
    conformance::check_ml_kem_768_encapsulation::<Corrupted>();
}

#[test]
#[should_panic]
fn corrupted_whole_suite() {
    conformance::check_all::<Corrupted>();
}

#[test]
#[should_panic(expected = "AES-256-CBC chaining value")]
fn forgotten_cbc_chaining_value() {
    conformance::check_aes_256_cbc::<FaultyBackend<ForgottenBlockModeState>>();
}

#[test]
#[should_panic(expected = "AES-256-CTR counter block")]
fn forgotten_ctr_counter_block() {
    conformance::check_aes_256_ctr::<FaultyBackend<ForgottenBlockModeState>>();
}

#[test]
#[should_panic(expected = "an RSA input not below the modulus must be refused")]
fn large_rsa_input_accepted() {
    conformance::check_rsa_public_operation::<FaultyBackend<LargeRsaInputAccepted>>();
}
