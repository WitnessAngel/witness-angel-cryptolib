// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! AES-256 in the two bulk modes of the backend interface, over the block cipher of the `aes` crate. The chaining
//! is written here because the interface carries the chaining value and the counter block across calls, which
//! the mode crates keep in their own states.

use aes::Aes256Enc;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use wa_flightbox::crypto_backend::{AES_256_KEY_SIZE, AES_BLOCK_SIZE, Aes256Encryptor};
use wa_flightbox::{Error, ErrorKind, Result};

type AesBlock = aes::Block;

/// AES-256 encryption with a fixed key. The round keys are wiped when dropped (by the `aes` crate).
pub struct RustCryptoAes256 {
    cipher: Aes256Enc,
}

fn check_lengths(input: &[u8], output: &[u8]) -> Result<()> {
    if input.len() != output.len() || !input.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    Ok(())
}

impl Aes256Encryptor for RustCryptoAes256 {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Result<Self> {
        // The key is borrowed as an array of the crate, not copied into an unwiped temporary
        Ok(Self {
            cipher: Aes256Enc::new(key.into()),
        })
    }

    fn encrypt_cbc_blocks(
        &mut self,
        chaining_value: &mut [u8; AES_BLOCK_SIZE],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        check_lengths(input, output)?;
        let (output_blocks, _) = AesBlock::slice_as_chunks_mut(output);
        for (input_block, output_block) in input.chunks_exact(AES_BLOCK_SIZE).zip(output_blocks.iter_mut()) {
            for ((output_byte, input_byte), chaining_byte) in
                output_block.iter_mut().zip(input_block).zip(chaining_value.iter())
            {
                *output_byte = input_byte ^ chaining_byte;
            }
            self.cipher.encrypt_block(output_block);
            chaining_value.copy_from_slice(output_block);
        }
        Ok(())
    }

    fn encrypt_ctr_blocks(
        &mut self,
        counter_block: &mut [u8; AES_BLOCK_SIZE],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        check_lengths(input, output)?;
        // The keystream of the whole call in one bulk encryption, so that parallel AES implementations are used
        let mut counter = u128::from_be_bytes(*counter_block);
        let (output_blocks, _) = AesBlock::slice_as_chunks_mut(output);
        for output_block in output_blocks.iter_mut() {
            output_block.copy_from_slice(&counter.to_be_bytes());
            counter = counter.wrapping_add(1);
        }
        self.cipher.encrypt_blocks(output_blocks);
        for (output_byte, input_byte) in output.iter_mut().zip(input) {
            *output_byte ^= input_byte;
        }
        *counter_block = counter.to_be_bytes();
        Ok(())
    }
}
