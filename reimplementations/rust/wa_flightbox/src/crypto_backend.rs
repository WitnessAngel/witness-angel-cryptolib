// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! The crypto backend interface (design D3): the bulk or costly primitives that the encryptor takes from a
//! cryptographic library or a hardware accelerator. Everything else (padding, CMAC, EAX, OAEP, HKDF, HPKE, Shamir)
//! is portable code of this crate, written once over this interface.
//!
//! # Contract
//!
//! - **Determinism**: every primitive is fully determined by its inputs. A backend draws no randomness that
//!   affects its outputs: the encryptor draws every random value from the platform hooks and passes it in
//!   (ephemeral scalars, ML-KEM coins).
//! - **Bulk calls**: the CBC and CTR primitives receive whole processing slices (4096 bytes by default), so that a
//!   hardware backend takes its accelerator once per slice, not once per block.
//! - **Errors**: a failure of the underlying library is `ErrorKind::CryptoBackendFailure`; an input outside the
//!   contract below is `ErrorKind::InvalidArgument`. Backends do not panic on any input.
//! - **Secrets**: streaming states hold keys, and are wiped when dropped.
//!
//! The `wa_flightbox_backend_conformance` crate is the acceptance test of an implementation.
//!
//! # Writing a backend
//!
//! A backend is a type without data, implementing [`CryptoBackend`]. A backend for a hardware AES typically
//! provides its own [`Aes256Encryptor`] and delegates the rest to the RustCrypto backend:
//!
//! ```
//! use wa_flightbox::crypto_backend::*;
//! use wa_flightbox::{Error, ErrorKind, Result};
//!
//! struct NullBackend;
//! struct NullAes;
//! struct NullChaCha;
//!
//! fn unavailable<T>() -> Result<T> {
//!     Err(Error::new(ErrorKind::CryptoBackendFailure))
//! }
//!
//! impl Aes256Encryptor for NullAes {
//!     fn new(_key: &[u8; AES_256_KEY_SIZE]) -> Result<Self> {
//!         unavailable()
//!     }
//!     fn encrypt_cbc_blocks(
//!         &mut self,
//!         _chaining_value: &mut [u8; AES_BLOCK_SIZE],
//!         _input: &[u8],
//!         _output: &mut [u8],
//!     ) -> Result<()> {
//!         unavailable()
//!     }
//!     fn encrypt_ctr_blocks(
//!         &mut self,
//!         _counter_block: &mut [u8; AES_BLOCK_SIZE],
//!         _input: &[u8],
//!         _output: &mut [u8],
//!     ) -> Result<()> {
//!         unavailable()
//!     }
//! }
//!
//! impl ChaCha20Poly1305Encryptor for NullChaCha {
//!     fn new(
//!         _key: &[u8; CHACHA20_POLY1305_KEY_SIZE],
//!         _nonce: &[u8; CHACHA20_POLY1305_NONCE_SIZE],
//!         _associated_data: &[u8],
//!     ) -> Result<Self> {
//!         unavailable()
//!     }
//!     fn encrypt(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<()> {
//!         unavailable()
//!     }
//!     fn finish(self) -> Result<[u8; AEAD_TAG_SIZE]> {
//!         unavailable()
//!     }
//! }
//!
//! impl CryptoBackend for NullBackend {
//!     type Aes256 = NullAes;
//!     type ChaCha20Poly1305 = NullChaCha;
//!     fn compute_sha256(_parts: &[&[u8]]) -> Result<[u8; SHA256_DIGEST_SIZE]> {
//!         unavailable()
//!     }
//!     fn compute_sha512(_parts: &[&[u8]]) -> Result<[u8; SHA512_DIGEST_SIZE]> {
//!         unavailable()
//!     }
//!     fn compute_hmac_sha256(_key: &[u8], _parts: &[&[u8]]) -> Result<[u8; SHA256_DIGEST_SIZE]> {
//!         unavailable()
//!     }
//!     fn x25519_compute_public_key(_private_scalar: &[u8; X25519_KEY_SIZE]) -> Result<[u8; X25519_KEY_SIZE]> {
//!         unavailable()
//!     }
//!     fn x25519_compute_shared_secret(
//!         _private_scalar: &[u8; X25519_KEY_SIZE],
//!         _peer_public_key: &[u8; X25519_KEY_SIZE],
//!     ) -> Result<[u8; X25519_KEY_SIZE]> {
//!         unavailable()
//!     }
//!     fn rsa_compute_public_operation(
//!         _modulus: &[u8],
//!         _public_exponent: &[u8],
//!         _input: &[u8],
//!         _output: &mut [u8],
//!     ) -> Result<()> {
//!         unavailable()
//!     }
//!     fn ml_kem_768_encapsulate_derandomized(
//!         _public_key: &[u8; ML_KEM_768_PUBLIC_KEY_SIZE],
//!         _coins: &[u8; ML_KEM_768_COINS_SIZE],
//!         _ciphertext: &mut [u8; ML_KEM_768_CIPHERTEXT_SIZE],
//!         _shared_secret: &mut [u8; ML_KEM_768_SHARED_SECRET_SIZE],
//!     ) -> Result<()> {
//!         unavailable()
//!     }
//! }
//! ```

use crate::error::Result;

/// Size of an AES-256 key.
pub const AES_256_KEY_SIZE: usize = 32;
/// Size of an AES block.
pub const AES_BLOCK_SIZE: usize = 16;
/// Size of a ChaCha20-Poly1305 key.
pub const CHACHA20_POLY1305_KEY_SIZE: usize = 32;
/// Size of a ChaCha20-Poly1305 nonce.
pub const CHACHA20_POLY1305_NONCE_SIZE: usize = 12;
/// RFC 8439: 2^32 - 1 blocks of 64 bytes after the Poly1305 key block (the 32-bit block counter must not wrap).
pub const CHACHA20_POLY1305_MAXIMUM_DATA_LENGTH: u64 = 0xFFFF_FFFF * 64;
/// Size of an AEAD tag (EAX and ChaCha20-Poly1305).
pub const AEAD_TAG_SIZE: usize = 16;
/// Size of a SHA-256 digest.
pub const SHA256_DIGEST_SIZE: usize = 32;
/// Size of a SHA-512 digest.
pub const SHA512_DIGEST_SIZE: usize = 64;
/// Size of X25519 scalars, public keys and shared secrets.
pub const X25519_KEY_SIZE: usize = 32;
/// Size of an ML-KEM-768 encapsulation key.
pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;
/// Size of an ML-KEM-768 ciphertext.
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
/// Size of an ML-KEM-768 shared secret.
pub const ML_KEM_768_SHARED_SECRET_SIZE: usize = 32;
/// Size of the randomness of an ML-KEM-768 encapsulation.
pub const ML_KEM_768_COINS_SIZE: usize = 32;

/// AES-256 with a fixed key, in the encryption direction only. The state is wiped when dropped.
pub trait Aes256Encryptor: Sized {
    /// Expand `key`.
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Result<Self>;

    /// CBC encryption of `input` into `output`, of the same length, a multiple of 16 (0 allowed;
    /// `ErrorKind::InvalidArgument` otherwise). `chaining_value` holds the IV on input, and the last ciphertext
    /// block on output, so that successive calls continue the same CBC stream.
    fn encrypt_cbc_blocks(
        &mut self,
        chaining_value: &mut [u8; AES_BLOCK_SIZE],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()>;

    /// CTR encryption of `input` into `output`, of the same length, a multiple of 16 (0 allowed;
    /// `ErrorKind::InvalidArgument` otherwise). `counter_block` holds the initial counter on input, and the next
    /// one on output, incremented as a 128-bit big-endian integer per block, wrapping around.
    fn encrypt_ctr_blocks(
        &mut self,
        counter_block: &mut [u8; AES_BLOCK_SIZE],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()>;
}

/// A ChaCha20-Poly1305 (RFC 8439) streaming encryption. The state is wiped when dropped.
pub trait ChaCha20Poly1305Encryptor: Sized {
    /// Start an encryption, with its whole associated data (empty in cryptainers).
    fn new(
        key: &[u8; CHACHA20_POLY1305_KEY_SIZE],
        nonce: &[u8; CHACHA20_POLY1305_NONCE_SIZE],
        associated_data: &[u8],
    ) -> Result<Self>;

    /// Encrypt the next bytes of the stream, `input` into `output` of the same length (any length, 0 allowed).
    /// `ErrorKind::InvalidArgument` when the lengths differ, or beyond
    /// [`CHACHA20_POLY1305_MAXIMUM_DATA_LENGTH`] bytes in total, nothing being encrypted by that call.
    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<()>;

    /// End the encryption and return the tag. A stream that encrypted nothing is valid: its tag authenticates the
    /// associated data alone.
    fn finish(self) -> Result<[u8; AEAD_TAG_SIZE]>;
}

/// The primitives of a crypto backend. See the [module documentation](self) for the contract.
pub trait CryptoBackend {
    /// AES-256 block encryption in CBC and CTR modes.
    type Aes256: Aes256Encryptor;
    /// ChaCha20-Poly1305 streaming encryption.
    type ChaCha20Poly1305: ChaCha20Poly1305Encryptor;

    /// SHA-256 of the concatenation of `parts`.
    fn compute_sha256(parts: &[&[u8]]) -> Result<[u8; SHA256_DIGEST_SIZE]>;

    /// SHA-512 of the concatenation of `parts`.
    fn compute_sha512(parts: &[&[u8]]) -> Result<[u8; SHA512_DIGEST_SIZE]>;

    /// HMAC-SHA256 of the concatenation of `parts`, with a key of any length.
    fn compute_hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Result<[u8; SHA256_DIGEST_SIZE]>;

    /// The X25519 public key of a scalar (RFC 7748: little-endian, the scalar being clamped).
    fn x25519_compute_public_key(private_scalar: &[u8; X25519_KEY_SIZE]) -> Result<[u8; X25519_KEY_SIZE]>;

    /// The X25519 shared secret of a scalar and a peer public key (RFC 7748: the scalar is clamped, the top bit of
    /// the u-coordinate masked). A low-order peer key gives an all-zero output or a failure, depending on the
    /// backend: the caller checks for zeros, and such keys are rejected when profiles are loaded.
    fn x25519_compute_shared_secret(
        private_scalar: &[u8; X25519_KEY_SIZE],
        peer_public_key: &[u8; X25519_KEY_SIZE],
    ) -> Result<[u8; X25519_KEY_SIZE]>;

    /// The raw RSA public operation `output = input^e mod n`, on big-endian byte strings: `modulus` without
    /// leading zero byte, `input` and `output` of exactly the length of the modulus. `ErrorKind::InvalidArgument`
    /// when the lengths differ or when `input` is not below the modulus. Only used inside the portable OAEP
    /// encoding, with keys that passed the public key constraints (odd modulus of 2048 bits at least, odd exponent
    /// with 3 <= e < n).
    fn rsa_compute_public_operation(
        modulus: &[u8],
        public_exponent: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()>;

    /// ML-KEM-768 encapsulation with the given randomness (FIPS 203, `ML-KEM.Encaps_internal`). The modulus check
    /// of the encapsulation key is done by the portable profile loader: backends may repeat it or not.
    fn ml_kem_768_encapsulate_derandomized(
        public_key: &[u8; ML_KEM_768_PUBLIC_KEY_SIZE],
        coins: &[u8; ML_KEM_768_COINS_SIZE],
        ciphertext: &mut [u8; ML_KEM_768_CIPHERTEXT_SIZE],
        shared_secret: &mut [u8; ML_KEM_768_SHARED_SECRET_SIZE],
    ) -> Result<()>;
}
