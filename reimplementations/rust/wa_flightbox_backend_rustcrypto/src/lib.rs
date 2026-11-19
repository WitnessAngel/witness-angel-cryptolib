// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Pure-Rust crypto backend of the Witness Angel flightbox encryptor, over the RustCrypto crates: the default
//! backend, without `unsafe` code of ours nor any C code, for hosts and `no_std` devices alike.
//!
//! | Primitive | Crate |
//! |---|---|
//! | AES-256 (CBC and CTR chaining are written here, over bulk block calls) | `aes` |
//! | ChaCha20-Poly1305 (composed here as RFC 8439, to stream and to enforce its data limit) | `chacha20`, `poly1305` |
//! | SHA-256, SHA-512, HMAC-SHA256 | `sha2`, `hmac` |
//! | X25519 | `x25519-dalek` |
//! | RSA public operation | `crypto-bigint` |
//! | ML-KEM-768 encapsulation | `ml-kem` |
//!
//! The software AES of the `aes` crate is constant-time (fixsliced); on targets with AES instructions it uses
//! them. For a hardware AES peripheral, write a backend whose `Aes256` type drives the peripheral and which
//! delegates everything else to [`RustCryptoBackend`].

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod aes_block_modes;
mod chacha20_poly1305_stream;
mod rsa_public_operation;

use hmac::{Hmac, KeyInit, Mac};
use ml_kem::EncapsulationKey768;
use sha2::{Digest, Sha256, Sha512};
use wa_flightbox::crypto_backend::{
    CryptoBackend, ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_COINS_SIZE, ML_KEM_768_PUBLIC_KEY_SIZE,
    ML_KEM_768_SHARED_SECRET_SIZE, SHA256_DIGEST_SIZE, SHA512_DIGEST_SIZE, X25519_KEY_SIZE,
};
use wa_flightbox::{Error, ErrorKind, Result};
use zeroize::Zeroize;

pub use crate::aes_block_modes::RustCryptoAes256;
pub use crate::chacha20_poly1305_stream::RustCryptoChaCha20Poly1305;

/// The RustCrypto backend: a type without data, used as the backend parameter of encryptors.
#[derive(Clone, Copy, Debug, Default)]
pub struct RustCryptoBackend;

impl CryptoBackend for RustCryptoBackend {
    type Aes256 = RustCryptoAes256;
    type ChaCha20Poly1305 = RustCryptoChaCha20Poly1305;

    fn compute_sha256(parts: &[&[u8]]) -> Result<[u8; SHA256_DIGEST_SIZE]> {
        let mut hasher = Sha256::new();
        for part in parts {
            Digest::update(&mut hasher, part);
        }
        Ok(hasher.finalize().into())
    }

    fn compute_sha512(parts: &[&[u8]]) -> Result<[u8; SHA512_DIGEST_SIZE]> {
        let mut hasher = Sha512::new();
        for part in parts {
            Digest::update(&mut hasher, part);
        }
        Ok(hasher.finalize().into())
    }

    fn compute_hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Result<[u8; SHA256_DIGEST_SIZE]> {
        // HMAC takes keys of any length
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::new(ErrorKind::CryptoBackendFailure))?;
        for part in parts {
            Mac::update(&mut mac, part);
        }
        Ok(mac.finalize().into_bytes().into())
    }

    fn x25519_compute_public_key(private_scalar: &[u8; X25519_KEY_SIZE]) -> Result<[u8; X25519_KEY_SIZE]> {
        Self::x25519_compute_shared_secret(private_scalar, &x25519_dalek::X25519_BASEPOINT_BYTES)
    }

    fn x25519_compute_shared_secret(
        private_scalar: &[u8; X25519_KEY_SIZE],
        peer_public_key: &[u8; X25519_KEY_SIZE],
    ) -> Result<[u8; X25519_KEY_SIZE]> {
        // The same Montgomery ladder as x25519_dalek::x25519(), with the scalar copied into a type wiped when dropped
        // rather than passed by value (x25519-dalek still copies it internally, unwiped). A low-order peer key gives
        // zeros, which the caller checks.
        let secret = x25519_dalek::StaticSecret::from(*private_scalar);
        Ok(secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(*peer_public_key))
            .to_bytes())
    }

    fn rsa_compute_public_operation(
        modulus: &[u8],
        public_exponent: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        rsa_public_operation::rsa_compute_public_operation(modulus, public_exponent, input, output)
    }

    fn ml_kem_768_encapsulate_derandomized(
        public_key: &[u8; ML_KEM_768_PUBLIC_KEY_SIZE],
        coins: &[u8; ML_KEM_768_COINS_SIZE],
        ciphertext: &mut [u8; ML_KEM_768_CIPHERTEXT_SIZE],
        shared_secret: &mut [u8; ML_KEM_768_SHARED_SECRET_SIZE],
    ) -> Result<()> {
        // The key decoding includes the modulus check of FIPS 203
        let encapsulation_key =
            EncapsulationKey768::new(public_key.into()).map_err(|_| Error::new(ErrorKind::KeyConstraintViolation))?;
        // The randomness is borrowed as an array of the crate, not copied
        let (kem_ciphertext, mut kem_shared_secret) = encapsulation_key.encapsulate_deterministic(coins.into());
        ciphertext.copy_from_slice(kem_ciphertext.as_slice());
        shared_secret.copy_from_slice(kem_shared_secret.as_slice());
        kem_shared_secret.zeroize();
        Ok(())
    }
}
