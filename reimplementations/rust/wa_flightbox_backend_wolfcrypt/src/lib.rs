// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! wolfCrypt crypto backend of the Witness Angel flightbox encryptor: the same wolfCrypt 5.8 functions as the C
//! library's adapter, called through bindings that `bindgen` generates at build time from the headers of the
//! wolfSSL tree being compiled (see `build.rs` for `WA_WOLFSSL_SOURCE_DIR` and `WA_WOLFSSL_USER_SETTINGS_DIR`).
//!
//! For products that need wolfCrypt's certifications or its hardware ports. The default backend is
//! `wa_flightbox_backend_rustcrypto`, which has no C code.
//!
//! `unsafe` code is confined to the `wolfcrypt_ffi` module, whose functions are safe to call with any argument;
//! it is denied everywhere else. Two wolfCrypt behaviours are evened out, as in the C adapter:
//! - ChaCha20-Poly1305 is composed from the ChaCha20 and Poly1305 functions as RFC 8439 section 2.8, since
//!   wolfCrypt's streaming AEAD stops at 4 GiB and refuses an empty message without associated data;
//! - the raw RSA operation refuses an input not below the modulus, which `wc_RsaDirect()` does not check.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

mod wolfcrypt_ffi;

use wa_flightbox::crypto_backend::{
    AEAD_TAG_SIZE, AES_256_KEY_SIZE, AES_BLOCK_SIZE, Aes256Encryptor, CHACHA20_POLY1305_KEY_SIZE,
    CHACHA20_POLY1305_MAXIMUM_DATA_LENGTH, CHACHA20_POLY1305_NONCE_SIZE, ChaCha20Poly1305Encryptor, CryptoBackend,
    ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_COINS_SIZE, ML_KEM_768_PUBLIC_KEY_SIZE, ML_KEM_768_SHARED_SECRET_SIZE,
    SHA256_DIGEST_SIZE, SHA512_DIGEST_SIZE, X25519_KEY_SIZE,
};
use wa_flightbox::{Error, ErrorKind, Result};
use zeroize::Zeroize;

use crate::wolfcrypt_ffi::WolfCryptFailure;

fn backend_failure(_failure: WolfCryptFailure) -> Error {
    Error::new(ErrorKind::CryptoBackendFailure)
}

fn invalid_argument() -> Error {
    Error::new(ErrorKind::InvalidArgument)
}

/// The wolfCrypt backend: a type without data, used as the backend parameter of encryptors.
#[derive(Clone, Copy, Debug, Default)]
pub struct WolfCryptBackend;

/// AES-256 encryption by wolfCrypt. The key schedule is freed and wiped when dropped.
pub struct WolfCryptAes256 {
    context: wolfcrypt_ffi::Aes256Context,
}

fn check_block_lengths(input: &[u8], output: &[u8]) -> Result<()> {
    if input.len() != output.len() || !input.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(invalid_argument());
    }
    Ok(())
}

impl Aes256Encryptor for WolfCryptAes256 {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Result<Self> {
        Ok(Self {
            context: wolfcrypt_ffi::Aes256Context::new(key).map_err(backend_failure)?,
        })
    }

    fn encrypt_cbc_blocks(
        &mut self,
        chaining_value: &mut [u8; AES_BLOCK_SIZE],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        check_block_lengths(input, output)?;
        self.context
            .encrypt_cbc_blocks(chaining_value, input, output)
            .map_err(backend_failure)
    }

    fn encrypt_ctr_blocks(
        &mut self,
        counter_block: &mut [u8; AES_BLOCK_SIZE],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        check_block_lengths(input, output)?;
        self.context
            .encrypt_ctr_blocks(counter_block, input, output)
            .map_err(backend_failure)
    }
}

/// A ChaCha20-Poly1305 streaming encryption by wolfCrypt. The states are wiped when dropped.
pub struct WolfCryptChaCha20Poly1305 {
    context: wolfcrypt_ffi::ChaCha20Poly1305Context,
    associated_data_length: u64,
    data_length: u64,
}

impl ChaCha20Poly1305Encryptor for WolfCryptChaCha20Poly1305 {
    fn new(
        key: &[u8; CHACHA20_POLY1305_KEY_SIZE],
        nonce: &[u8; CHACHA20_POLY1305_NONCE_SIZE],
        associated_data: &[u8],
    ) -> Result<Self> {
        let mut context = wolfcrypt_ffi::ChaCha20Poly1305Context::new(key, nonce).map_err(backend_failure)?;
        let associated_data_length = associated_data.len() as u64;
        context.authenticate(associated_data).map_err(backend_failure)?;
        context
            .pad_authenticated_data(associated_data_length)
            .map_err(backend_failure)?;
        Ok(Self {
            context,
            associated_data_length,
            data_length: 0,
        })
    }

    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        if input.len() != output.len() || input.len() as u64 > CHACHA20_POLY1305_MAXIMUM_DATA_LENGTH - self.data_length
        {
            return Err(invalid_argument());
        }
        self.context.encrypt(input, output).map_err(backend_failure)?;
        self.data_length += input.len() as u64;
        Ok(())
    }

    fn finish(mut self) -> Result<[u8; AEAD_TAG_SIZE]> {
        // Padding of the ciphertext, then both lengths as 64-bit little-endian integers
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&self.associated_data_length.to_le_bytes());
        lengths[8..].copy_from_slice(&self.data_length.to_le_bytes());
        self.context
            .pad_authenticated_data(self.data_length)
            .map_err(backend_failure)?;
        self.context.authenticate(&lengths).map_err(backend_failure)?;
        self.context.compute_tag().map_err(backend_failure)
    }
}

/// Whether `left < right`, as big-endian integers of the same length, without a data-dependent branch: the left
/// side is an OAEP-encoded key.
fn is_below(left: &[u8], right: &[u8]) -> bool {
    let mut borrow = 0u16;
    for (left_byte, right_byte) in left.iter().zip(right).rev() {
        borrow = (u16::from(*left_byte)
            .wrapping_sub(u16::from(*right_byte))
            .wrapping_sub(borrow))
            >> 15;
    }
    borrow == 1
}

impl CryptoBackend for WolfCryptBackend {
    type Aes256 = WolfCryptAes256;
    type ChaCha20Poly1305 = WolfCryptChaCha20Poly1305;

    fn compute_sha256(parts: &[&[u8]]) -> Result<[u8; SHA256_DIGEST_SIZE]> {
        wolfcrypt_ffi::compute_sha256(parts).map_err(backend_failure)
    }

    fn compute_sha512(parts: &[&[u8]]) -> Result<[u8; SHA512_DIGEST_SIZE]> {
        wolfcrypt_ffi::compute_sha512(parts).map_err(backend_failure)
    }

    fn compute_hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Result<[u8; SHA256_DIGEST_SIZE]> {
        if u32::try_from(key.len()).is_err() {
            return Err(invalid_argument());
        }
        wolfcrypt_ffi::compute_hmac_sha256(key, parts).map_err(backend_failure)
    }

    fn x25519_compute_public_key(private_scalar: &[u8; X25519_KEY_SIZE]) -> Result<[u8; X25519_KEY_SIZE]> {
        let mut base_point = [0u8; X25519_KEY_SIZE];
        base_point[0] = 9;
        Self::x25519_compute_shared_secret(private_scalar, &base_point)
    }

    fn x25519_compute_shared_secret(
        private_scalar: &[u8; X25519_KEY_SIZE],
        peer_public_key: &[u8; X25519_KEY_SIZE],
    ) -> Result<[u8; X25519_KEY_SIZE]> {
        // wc_curve25519_generic() requires a clamped scalar, and does not mask the top bit of the u-coordinate
        let mut clamped_scalar = *private_scalar;
        clamped_scalar[0] &= 248;
        clamped_scalar[31] = (clamped_scalar[31] & 127) | 64;
        let mut masked_point = *peer_public_key;
        masked_point[31] &= 127;
        let result = wolfcrypt_ffi::x25519_multiply(&clamped_scalar, &masked_point);
        clamped_scalar.zeroize();
        result.map_err(backend_failure)
    }

    fn rsa_compute_public_operation(
        modulus: &[u8],
        public_exponent: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        if modulus.is_empty()
            || modulus[0] == 0
            || modulus.len() > wolfcrypt_ffi::MAXIMUM_RSA_MODULUS_LENGTH
            || public_exponent.is_empty()
            || public_exponent.len() > modulus.len()
            || input.len() != modulus.len()
            || output.len() != modulus.len()
            || !is_below(input, modulus)
        {
            return Err(invalid_argument());
        }
        wolfcrypt_ffi::rsa_compute_public_operation(modulus, public_exponent, input, output).map_err(backend_failure)
    }

    fn ml_kem_768_encapsulate_derandomized(
        public_key: &[u8; ML_KEM_768_PUBLIC_KEY_SIZE],
        coins: &[u8; ML_KEM_768_COINS_SIZE],
        ciphertext: &mut [u8; ML_KEM_768_CIPHERTEXT_SIZE],
        shared_secret: &mut [u8; ML_KEM_768_SHARED_SECRET_SIZE],
    ) -> Result<()> {
        wolfcrypt_ffi::ml_kem_768_encapsulate_derandomized(public_key, coins, ciphertext, shared_secret)
            .map_err(backend_failure)
    }
}
