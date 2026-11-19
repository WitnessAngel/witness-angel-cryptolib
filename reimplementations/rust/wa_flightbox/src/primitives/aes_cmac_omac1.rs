// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! AES-256 CMAC (NIST SP 800-38B, OMAC1), streaming, over the CBC primitive of the backend: the building block of
//! the EAX mode. The AES context is passed to each call, since the EAX mode shares one between its CMACs and its
//! counter mode.

use zeroize::Zeroize;

use crate::crypto_backend::{AES_BLOCK_SIZE, Aes256Encryptor};
use crate::error::Result;

pub(crate) const AES_CMAC_SIZE: usize = AES_BLOCK_SIZE;

/// Whole blocks are passed to the backend in pieces of this size, the CBC output going to a stack scratch buffer.
const SCRATCH_SIZE: usize = 256;

/// Multiply by x in GF(2^128), big-endian, reduction polynomial x^128 + x^7 + x^2 + x + 1, in constant time.
fn double_subkey(input: &[u8; AES_BLOCK_SIZE]) -> [u8; AES_BLOCK_SIZE] {
    let carry_mask = 0u8.wrapping_sub(input[0] >> 7);
    let mut output = [0u8; AES_BLOCK_SIZE];
    for index in 0..AES_BLOCK_SIZE - 1 {
        output[index] = (input[index] << 1) | (input[index + 1] >> 7);
    }
    output[AES_BLOCK_SIZE - 1] = (input[AES_BLOCK_SIZE - 1] << 1) ^ (0x87 & carry_mask);
    output
}

pub(crate) struct AesCmac {
    chaining_value: [u8; AES_BLOCK_SIZE],
    subkey_1: [u8; AES_BLOCK_SIZE],
    subkey_2: [u8; AES_BLOCK_SIZE],
    /// The last 1 to 16 bytes received, kept back since the final block is processed differently
    pending_block: [u8; AES_BLOCK_SIZE],
    pending_length: usize,
}

impl AesCmac {
    /// CBC-MAC the given whole blocks into the chaining value.
    fn process_blocks<A: Aes256Encryptor>(&mut self, aes: &mut A, mut blocks: &[u8]) -> Result<()> {
        let mut scratch = [0u8; SCRATCH_SIZE];
        let mut result = Ok(());
        while !blocks.is_empty() && result.is_ok() {
            let piece_length = blocks.len().min(SCRATCH_SIZE);
            let (piece, rest) = blocks.split_at(piece_length);
            result = aes.encrypt_cbc_blocks(&mut self.chaining_value, piece, &mut scratch[..piece_length]);
            blocks = rest;
        }
        scratch.zeroize();
        result
    }

    pub(crate) fn start<A: Aes256Encryptor>(aes: &mut A) -> Result<Self> {
        // L = E_K(0^128): the CBC encryption of a zero block with a zero IV
        let mut zero_iv = [0u8; AES_BLOCK_SIZE];
        let mut encrypted_zero_block = [0u8; AES_BLOCK_SIZE];
        aes.encrypt_cbc_blocks(&mut zero_iv, &[0u8; AES_BLOCK_SIZE], &mut encrypted_zero_block)?;
        let subkey_1 = double_subkey(&encrypted_zero_block);
        let subkey_2 = double_subkey(&subkey_1);
        encrypted_zero_block.zeroize();
        zero_iv.zeroize();
        // The MAC itself starts from a zero IV
        Ok(Self {
            chaining_value: [0; AES_BLOCK_SIZE],
            subkey_1,
            subkey_2,
            pending_block: [0; AES_BLOCK_SIZE],
            pending_length: 0,
        })
    }

    /// OMAC^t of EAX: a CMAC whose message starts with a block holding the tweak `t`.
    pub(crate) fn start_omac_with_tweak<A: Aes256Encryptor>(aes: &mut A, tweak: u8) -> Result<Self> {
        let mut cmac = Self::start(aes)?;
        let mut tweak_block = [0u8; AES_BLOCK_SIZE];
        tweak_block[AES_BLOCK_SIZE - 1] = tweak;
        cmac.update(aes, &tweak_block)?;
        Ok(cmac)
    }

    pub(crate) fn update<A: Aes256Encryptor>(&mut self, aes: &mut A, mut data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let fill_length = (AES_BLOCK_SIZE - self.pending_length).min(data.len());
        self.pending_block[self.pending_length..self.pending_length + fill_length]
            .copy_from_slice(&data[..fill_length]);
        self.pending_length += fill_length;
        data = &data[fill_length..];
        if data.is_empty() {
            return Ok(()); // The pending block may be the last one
        }
        // More data follows: the full pending block is not the last one
        let pending_block = self.pending_block;
        self.process_blocks(aes, &pending_block)?;
        // Whole blocks in bulk, keeping back the last 1..16 bytes
        let bulk_length = ((data.len() - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        self.process_blocks(aes, &data[..bulk_length])?;
        let rest = &data[bulk_length..];
        self.pending_length = rest.len();
        self.pending_block[..rest.len()].copy_from_slice(rest);
        Ok(())
    }

    pub(crate) fn finish<A: Aes256Encryptor>(mut self, aes: &mut A) -> Result<[u8; AES_CMAC_SIZE]> {
        let subkey = if self.pending_length == AES_BLOCK_SIZE {
            self.subkey_1 // Complete final block
        } else {
            // Incomplete (or empty) final block: 10* padding
            self.pending_block[self.pending_length] = 0x80;
            self.pending_block[self.pending_length + 1..].fill(0);
            self.subkey_2
        };
        let mut final_block = self.pending_block;
        for (byte, subkey_byte) in final_block.iter_mut().zip(subkey) {
            *byte ^= subkey_byte;
        }
        let result = self.process_blocks(aes, &final_block);
        final_block.zeroize();
        result.map(|()| self.chaining_value)
    }
}

impl Drop for AesCmac {
    fn drop(&mut self) {
        self.chaining_value.zeroize();
        self.subkey_1.zeroize();
        self.subkey_2.zeroize();
        self.pending_block.zeroize();
        self.pending_length = 0;
    }
}
