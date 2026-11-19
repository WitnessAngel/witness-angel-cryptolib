// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Composite constructions of the encryptor specification (section 3), written once over the crypto backend
//! interface so that every backend shares them, and one source of randomness.

// These modules do block arithmetic on buffers whose sizes they establish themselves (fixed-size arrays, scratch
// blocks sized just above): plain indexing and arithmetic are allowed here, unlike in the parsing and core modules
// (design D8).
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use zeroize::Zeroize;

use crate::error::{Error, ErrorKind, Result};
use crate::platform_hooks::PlatformHooks;

pub(crate) mod aes_cbc_pkcs7_padding;
pub(crate) mod aes_cmac_omac1;
pub(crate) mod aes_eax_mode;
pub(crate) mod asymmetric_key_wrapping;
pub(crate) mod hkdf_sha256;
pub(crate) mod hpke_base_mode_seal;
pub(crate) mod hpke_kem_dhkem_x25519;
pub(crate) mod hpke_kem_ml_kem_768;
pub(crate) mod public_key_constraints;
pub(crate) mod rsa_oaep_chunked_encryption;
pub(crate) mod rsa_oaep_sha512_padding;
pub(crate) mod shamir_secret_sharing_gf128;
pub(crate) mod symmetric_cipher_streams;
pub(crate) mod symmetric_key_generation;
pub(crate) mod uuid0_generation;

/// Fill `buffer` from the random hook. On failure, the buffer is wiped (never keep partial output of a failed
/// source) and the error is `ErrorKind::RandomnessFailure`.
pub(crate) fn fill_random_bytes(hooks: &mut dyn PlatformHooks, buffer: &mut [u8]) -> Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }
    if hooks.fill_random(buffer).is_err() {
        buffer.zeroize();
        return Err(Error::new(ErrorKind::RandomnessFailure));
    }
    Ok(())
}

/// A new vector of `length` zero bytes, `ErrorKind::OutOfMemory` when the allocator refuses it.
pub(crate) fn try_zeroed_vec(length: usize) -> Result<alloc::vec::Vec<u8>> {
    let mut bytes = alloc::vec::Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::new(ErrorKind::OutOfMemory))?;
    bytes.resize(length, 0);
    Ok(bytes)
}
