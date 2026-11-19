// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! EME-OAEP encoding (RFC 8017, section 7.1.1) with SHA-512, MGF1-SHA-512 and an empty label: the padding of the
//! RSA_OAEP key cipher, over the SHA-512 primitive of the backend.

use zeroize::Zeroize;

use crate::crypto_backend::{CryptoBackend, SHA512_DIGEST_SIZE};
use crate::error::{Error, ErrorKind, Result};

pub(crate) const RSA_OAEP_SEED_SIZE: usize = SHA512_DIGEST_SIZE;
/// 2 * hLen + 2: the encoded message is that much longer than the longest message
pub(crate) const RSA_OAEP_SHA512_OVERHEAD: usize = 2 * SHA512_DIGEST_SIZE + 2;

/// XOR MGF1-SHA-512(mgf_seed) into `target` (RFC 8017, appendix B.2.1).
fn xor_mgf1_sha512_mask<B: CryptoBackend>(mgf_seed: &[u8], target: &mut [u8]) -> Result<()> {
    let mut result = Ok(());
    for (counter, target_piece) in (0u32..).zip(target.chunks_mut(SHA512_DIGEST_SIZE)) {
        match B::compute_sha512(&[mgf_seed, &counter.to_be_bytes()]) {
            Ok(mut digest) => {
                for (target_byte, digest_byte) in target_piece.iter_mut().zip(digest.iter()) {
                    *target_byte ^= digest_byte;
                }
                digest.zeroize();
            }
            Err(error) => {
                result = Err(error);
                break;
            }
        }
    }
    result
}

/// Encode `message` into `encoded_message`, whose length is that of the modulus (k): EM = 0x00 || maskedSeed ||
/// maskedDB, with DB = lHash || PS || 0x01 || M. `ErrorKind::InvalidArgument` unless the message is at most
/// k - 130 bytes long. The encoded message is wiped on failure.
pub(crate) fn rsa_oaep_sha512_encode_padding<B: CryptoBackend>(
    message: &[u8],
    seed: &[u8; RSA_OAEP_SEED_SIZE],
    encoded_message: &mut [u8],
) -> Result<()> {
    let modulus_length = encoded_message.len();
    if modulus_length < RSA_OAEP_SHA512_OVERHEAD || message.len() > modulus_length - RSA_OAEP_SHA512_OVERHEAD {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let result = (|| {
        let (leading_byte, rest) = encoded_message.split_at_mut(1);
        let (masked_seed, masked_db) = rest.split_at_mut(SHA512_DIGEST_SIZE);
        leading_byte[0] = 0x00;
        // lHash: the digest of the empty label
        let label_hash = B::compute_sha512(&[])?;
        let padding_string_length = masked_db.len() - SHA512_DIGEST_SIZE - 1 - message.len();
        masked_db[..SHA512_DIGEST_SIZE].copy_from_slice(&label_hash);
        masked_db[SHA512_DIGEST_SIZE..SHA512_DIGEST_SIZE + padding_string_length].fill(0);
        masked_db[SHA512_DIGEST_SIZE + padding_string_length] = 0x01;
        masked_db[SHA512_DIGEST_SIZE + padding_string_length + 1..].copy_from_slice(message);
        masked_seed.copy_from_slice(seed);
        // maskedDB = DB xor MGF1(seed); maskedSeed = seed xor MGF1(maskedDB)
        xor_mgf1_sha512_mask::<B>(seed, masked_db)?;
        xor_mgf1_sha512_mask::<B>(masked_db, masked_seed)
    })();
    if result.is_err() {
        encoded_message.zeroize();
    }
    result
}
