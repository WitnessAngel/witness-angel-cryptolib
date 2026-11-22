// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Witness Angel flightbox encryptor: creation of cryptainers on devices, from a device profile.
//!
//! The crate implements steps 1 to 3 of the flightbox encryptor specification: it loads a device profile (a
//! cryptoconf and the public keys of its trustees), encrypts a payload fed in chunks through the payload cipher
//! layers, and writes a cryptainer in relaxed Extended JSON or in WA-CBOR, which `wacryptolib` decrypts.
//!
//! It is `no_std` (with `alloc`), contains no `unsafe` code, and no cryptographic primitive: those come from a
//! [`crypto_backend::CryptoBackend`], such as the pure-Rust one of the `wa_flightbox_backend_rustcrypto` crate.
//! Randomness and time come from the [`PlatformHooks`] of the integrator.
//!
//! ```ignore
//! let limits = EncryptorLimits::default();
//! let profile = DeviceProfile::load_from_cbor(profile_bytes, &limits)?;        // Immutable, reusable
//! let options = EncryptorOptions::default();
//! let mut encryptor = CryptainerEncryptor::<RustCryptoBackend, _>::create_offloaded(
//!     &profile, None, &options, &mut hooks, &mut payload_file)?;               // Step 1
//! encryptor.encrypt_payload_chunk(chunk)?;                                     // Step 2, any number of times
//! let finished = encryptor.finalize()?;                                        // End of step 2, and step 3
//! finished.write_cryptainer(&mut cryptainer_file)?;
//! ```
//!
//! # Cargo features
//!
//! - `extended-json` (default): cryptainers in relaxed Extended JSON;
//! - `wa-cbor` (default): cryptainers in WA-CBOR, core deterministic encoding.
//!
//! An encryptor needs at least one of them: without any, every document format is refused with
//! `ErrorKind::UnsupportedFeature` (crypto backend crates build the library that way, leaving the choice to the
//! firmware). Device profiles are always WA-CBOR.

#![no_std]
#![forbid(unsafe_code)]
// Faults of inputs are errors, never panics (see the README): in the parsing and algorithm modules, indexing goes
// through `get()` and arithmetic through checked operations. The `primitives` module opts out for its fixed-size
// block arithmetic.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]
// Without a document format, the writers are compiled out and what feeds them is unused
#![cfg_attr(not(any(feature = "extended-json", feature = "wa-cbor")), allow(dead_code))]

extern crate alloc;

mod core;
pub mod crypto_backend;
mod encoding;
mod error;
#[doc(hidden)]
pub mod internals;
mod limits;
mod platform_hooks;
mod primitives;

pub use crate::core::cryptainer_encryptor::{
    CryptainerEncryptor, EncryptorOptions, FinishedCryptainer, encrypt_payload_in_one_call,
};
pub use crate::encoding::device_profile::{DEVICE_PROFILE_FORMAT, DeviceProfile};
pub use crate::encoding::document_serialization::{DocumentFormat, OFFLOADED_PAYLOAD_SUFFIX, write_document};
pub use crate::encoding::value_tree::{Map, UUID_SIZE, Value};
pub use crate::encoding::wacbor_subprofile_decoder::decode_document_from_cbor;
pub use crate::error::{Error, ErrorKind, Result};
pub use crate::limits::{EncryptorLimits, MAX_SHARED_SECRET_SHARD_COUNT, WA_CBOR_MAXIMUM_NESTING_DEPTH};
pub use crate::platform_hooks::{NoPayloadSink, OutputSink, PlatformHooks, RandomFailure, SinkError};
