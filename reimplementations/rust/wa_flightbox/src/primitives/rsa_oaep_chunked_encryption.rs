// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! The RSA_OAEP key cipher (encryptor specification, section 3.5): the plaintext is cut into chunks of 60 bytes,
//! each one encrypted with RSAES-OAEP (SHA-512, MGF1-SHA-512, empty label) under a 64-byte seed drawn from the
//! random hook, in chunk order. An empty plaintext gives no chunk.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::crypto_backend::CryptoBackend;
use crate::encoding::value_tree::{Map, Value};
use crate::error::{Error, ErrorKind, Result};
use crate::platform_hooks::PlatformHooks;
use crate::primitives::rsa_oaep_sha512_padding::{
    RSA_OAEP_SEED_SIZE, RSA_OAEP_SHA512_OVERHEAD, rsa_oaep_sha512_encode_padding,
};
use crate::primitives::{fill_random_bytes, try_zeroed_vec};

pub(crate) const RSA_OAEP_CHUNK_SIZE: usize = 60;

/// Cipherdict `{"ciphertext_chunks": [bytes(modulus length), ...]}`. `ErrorKind::InvalidArgument` when the
/// modulus has a leading zero byte or is too short for a chunk (190 bytes at least).
pub(crate) fn rsa_oaep_encrypt_into_chunks<B: CryptoBackend>(
    hooks: &mut dyn PlatformHooks,
    modulus: &[u8],
    public_exponent: &[u8],
    plaintext: &[u8],
) -> Result<Value> {
    if modulus.len() < RSA_OAEP_SHA512_OVERHEAD + RSA_OAEP_CHUNK_SIZE || modulus.first() == Some(&0) {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    // Holds each chunk in OAEP-encoded form, so wiped when dropped
    let mut encoded_message = Zeroizing::new(try_zeroed_vec(modulus.len())?);
    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(plaintext.len().div_ceil(RSA_OAEP_CHUNK_SIZE))
        .map_err(|_| ErrorKind::OutOfMemory)?;
    for chunk in plaintext.chunks(RSA_OAEP_CHUNK_SIZE) {
        let mut ciphertext = try_zeroed_vec(modulus.len())?;
        let mut seed = Zeroizing::new([0u8; RSA_OAEP_SEED_SIZE]);
        fill_random_bytes(hooks, &mut seed[..])?;
        rsa_oaep_sha512_encode_padding::<B>(chunk, &seed, &mut encoded_message)?;
        drop(seed);
        B::rsa_compute_public_operation(modulus, public_exponent, &encoded_message, &mut ciphertext)?;
        chunks.push(Value::Bytes(ciphertext));
    }
    let mut cipherdict = Map::new();
    cipherdict.set("ciphertext_chunks", Value::Array(chunks));
    Ok(Value::Map(cipherdict))
}
