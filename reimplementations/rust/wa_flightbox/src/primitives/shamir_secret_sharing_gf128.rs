// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Shamir secret sharing over GF(2^128) (encryptor specification, section 3.6), as PyCryptodome does it: the
//! field is defined by x^128 + x^7 + x^2 + x + 1, elements are big-endian 16-byte strings, and the secret,
//! PKCS#7-padded, is shared 16 bytes at a time.

use alloc::vec::Vec;

use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, ErrorKind, Result};
use crate::platform_hooks::PlatformHooks;
use crate::primitives::aes_cbc_pkcs7_padding::{PKCS7_BLOCK_SIZE, pkcs7_pad_final_block, pkcs7_padding_length};
use crate::primitives::{fill_random_bytes, try_zeroed_vec};

pub(crate) const GF128_ELEMENT_SIZE: usize = 16;

/// The product of two field elements, in constant time.
pub(crate) fn gf128_multiply(a: &[u8; GF128_ELEMENT_SIZE], b: &[u8; GF128_ELEMENT_SIZE]) -> [u8; GF128_ELEMENT_SIZE] {
    let a = u128::from_be_bytes(*a);
    let b = u128::from_be_bytes(*b);
    let mut result = 0u128;
    // Horner over the bits of b, from x^127 down to x^0: result = result * x + bit * a
    for bit_index in (0..128).rev() {
        let overflow_mask = 0u128.wrapping_sub(result >> 127);
        let bit_mask = 0u128.wrapping_sub((b >> bit_index) & 1);
        result = (result << 1) ^ (0x87 & overflow_mask);
        result ^= a & bit_mask;
    }
    result.to_be_bytes()
}

/// The shards of a secret, all of the same length, wiped when dropped.
pub(crate) struct ShamirShards {
    shards: Zeroizing<Vec<u8>>,
    shard_length: usize,
}

impl ShamirShards {
    /// The shards in index order: the first one has index 1.
    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.shards.chunks_exact(self.shard_length)
    }
}

/// Split `secret` into `shard_count` shards, `threshold_count` of which recover it (1 <= threshold <= count,
/// `ErrorKind::InvalidArgument` otherwise). For each 16-byte chunk of the padded secret, threshold - 1
/// coefficients of 16 bytes are drawn from the random hook, from the highest degree down.
pub(crate) fn shamir_split_secret_into_shards(
    hooks: &mut dyn PlatformHooks,
    secret: &[u8],
    shard_count: usize,
    threshold_count: usize,
) -> Result<ShamirShards> {
    if threshold_count < 1 || threshold_count > shard_count {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let padded_length = secret
        .len()
        .checked_add(pkcs7_padding_length(secret.len()))
        .ok_or(ErrorKind::InvalidArgument)?;
    let total_length = shard_count
        .checked_mul(padded_length)
        .ok_or(ErrorKind::InvalidArgument)?;
    // Shares accumulate in place, by Horner's rule: share_i = share_i * i + coefficient, with share_i = 0 at first
    let mut shards = Zeroizing::new(try_zeroed_vec(total_length)?);
    let mut chunk = Zeroizing::new([0u8; PKCS7_BLOCK_SIZE]);
    let mut coefficient = Zeroizing::new([0u8; GF128_ELEMENT_SIZE]);
    for chunk_offset in (0..padded_length).step_by(GF128_ELEMENT_SIZE) {
        // The chunk, the last one completed by its PKCS#7 padding
        let data = secret.get(chunk_offset..).unwrap_or(&[]);
        let data = &data[..data.len().min(GF128_ELEMENT_SIZE)];
        chunk[..data.len()].copy_from_slice(data);
        if data.len() < GF128_ELEMENT_SIZE {
            pkcs7_pad_final_block(&mut chunk, data.len());
        }
        // Random coefficients from the highest degree down, then the chunk itself as constant term
        for coefficient_index in 0..threshold_count {
            if coefficient_index + 1 < threshold_count {
                fill_random_bytes(hooks, &mut coefficient[..])?;
            } else {
                *coefficient = *chunk;
            }
            for (shard_index, shard) in shards.chunks_exact_mut(padded_length).enumerate() {
                let index_element = ((shard_index as u128) + 1).to_be_bytes();
                let share: &mut [u8; GF128_ELEMENT_SIZE] = (&mut shard
                    [chunk_offset..chunk_offset + GF128_ELEMENT_SIZE])
                    .try_into()
                    .map_err(|_| Error::new(ErrorKind::InternalError))?;
                let mut product = gf128_multiply(share, &index_element);
                for ((share_byte, product_byte), coefficient_byte) in
                    share.iter_mut().zip(product.iter()).zip(coefficient.iter())
                {
                    *share_byte = product_byte ^ coefficient_byte;
                }
                product.zeroize();
            }
        }
    }
    Ok(ShamirShards {
        shards,
        shard_length: padded_length,
    })
}
