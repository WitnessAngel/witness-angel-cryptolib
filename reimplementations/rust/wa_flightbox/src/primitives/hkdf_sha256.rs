// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! HKDF-SHA256 (RFC 5869) over the HMAC primitive of the backend, with multi-part inputs so that the labeled
//! variants of HPKE need no concatenation buffer.

use zeroize::Zeroize;

use crate::crypto_backend::{CryptoBackend, SHA256_DIGEST_SIZE};
use crate::error::{Error, ErrorKind, Result};

pub(crate) const HKDF_SHA256_PRK_SIZE: usize = SHA256_DIGEST_SIZE;
pub(crate) const HKDF_SHA256_MAXIMUM_OKM_LENGTH: usize = 255 * SHA256_DIGEST_SIZE;
pub(crate) const HKDF_SHA256_MAXIMUM_PART_COUNT: usize = 5;

/// HKDF-Extract: an empty salt stands for 32 zero bytes.
pub(crate) fn hkdf_sha256_extract<B: CryptoBackend>(
    salt: &[u8],
    ikm_parts: &[&[u8]],
) -> Result<[u8; HKDF_SHA256_PRK_SIZE]> {
    const ZERO_SALT: [u8; SHA256_DIGEST_SIZE] = [0; SHA256_DIGEST_SIZE];
    B::compute_hmac_sha256(if salt.is_empty() { &ZERO_SALT } else { salt }, ikm_parts)
}

/// HKDF-Expand into `okm` (1 to 8160 bytes), with an info made of at most 5 parts.
pub(crate) fn hkdf_sha256_expand<B: CryptoBackend>(
    prk: &[u8; HKDF_SHA256_PRK_SIZE],
    info_parts: &[&[u8]],
    okm: &mut [u8],
) -> Result<()> {
    if okm.is_empty() || okm.len() > HKDF_SHA256_MAXIMUM_OKM_LENGTH || info_parts.len() > HKDF_SHA256_MAXIMUM_PART_COUNT
    {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let mut block = [0u8; SHA256_DIGEST_SIZE];
    let mut block_length = 0; // T(0) is empty
    let mut counter = 0u8;
    let mut result = Ok(());
    for okm_piece in okm.chunks_mut(SHA256_DIGEST_SIZE) {
        counter = counter.wrapping_add(1); // At most 255 pieces, by the length check above
        // parts: T(i - 1), the info parts, then the counter byte
        let counter_bytes = [counter];
        let mut parts: [&[u8]; HKDF_SHA256_MAXIMUM_PART_COUNT + 2] = [&[]; HKDF_SHA256_MAXIMUM_PART_COUNT + 2];
        parts[0] = &block[..block_length];
        parts[1..1 + info_parts.len()].copy_from_slice(info_parts);
        parts[1 + info_parts.len()] = &counter_bytes;
        match B::compute_hmac_sha256(prk, &parts[..info_parts.len() + 2]) {
            Ok(next_block) => block = next_block,
            Err(error) => {
                result = Err(error);
                break;
            }
        }
        block_length = SHA256_DIGEST_SIZE;
        okm_piece.copy_from_slice(&block[..okm_piece.len()]);
    }
    block.zeroize();
    if result.is_err() {
        okm.zeroize();
    }
    result
}
