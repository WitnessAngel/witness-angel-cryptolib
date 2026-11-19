// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! ChaCha20-Poly1305 (RFC 8439, section 2.8) as a streaming encryption, composed from the `chacha20` and
//! `poly1305` crates: the AEAD crate is one-shot, and payloads are streamed.

use chacha20::ChaCha20;
use chacha20::cipher::{Array, KeyIvInit, StreamCipher};
use poly1305::Poly1305;
use poly1305::universal_hash::{KeyInit, UniversalHash};
use wa_flightbox::crypto_backend::{
    AEAD_TAG_SIZE, CHACHA20_POLY1305_KEY_SIZE, CHACHA20_POLY1305_MAXIMUM_DATA_LENGTH, CHACHA20_POLY1305_NONCE_SIZE,
    ChaCha20Poly1305Encryptor,
};
use wa_flightbox::{Error, ErrorKind, Result};
use zeroize::Zeroize;

const POLY1305_BLOCK_SIZE: usize = 16;

/// A ChaCha20-Poly1305 streaming encryption. The cipher and MAC states are wiped when dropped (by their crates).
pub struct RustCryptoChaCha20Poly1305 {
    cipher: ChaCha20,
    mac: Poly1305,
    /// Ciphertext bytes not yet authenticated, short of a Poly1305 block
    pending_block: [u8; POLY1305_BLOCK_SIZE],
    pending_length: usize,
    associated_data_length: u64,
    data_length: u64,
}

impl RustCryptoChaCha20Poly1305 {
    /// Authenticate ciphertext, in whole blocks, the rest being kept for the next call.
    fn authenticate(&mut self, mut ciphertext: &[u8]) {
        if self.pending_length > 0 {
            let fill_length = (POLY1305_BLOCK_SIZE - self.pending_length).min(ciphertext.len());
            self.pending_block[self.pending_length..self.pending_length + fill_length]
                .copy_from_slice(&ciphertext[..fill_length]);
            self.pending_length += fill_length;
            ciphertext = &ciphertext[fill_length..];
            if self.pending_length < POLY1305_BLOCK_SIZE {
                return;
            }
            self.mac.update(&[Array::from(self.pending_block)]);
            self.pending_length = 0;
        }
        let (blocks, rest) = poly1305::Block::slice_as_chunks(ciphertext);
        self.mac.update(blocks);
        self.pending_block[..rest.len()].copy_from_slice(rest);
        self.pending_length = rest.len();
    }
}

impl ChaCha20Poly1305Encryptor for RustCryptoChaCha20Poly1305 {
    fn new(
        key: &[u8; CHACHA20_POLY1305_KEY_SIZE],
        nonce: &[u8; CHACHA20_POLY1305_NONCE_SIZE],
        associated_data: &[u8],
    ) -> Result<Self> {
        let mut cipher = ChaCha20::new(&Array::from(*key), &Array::from(*nonce));
        // The Poly1305 key is the first half of the keystream block of counter 0; data starts at counter 1
        let mut first_block = [0u8; 64];
        cipher.apply_keystream(&mut first_block);
        let mut mac_key = poly1305::Key::default();
        mac_key.copy_from_slice(&first_block[..32]);
        first_block.zeroize();
        let mut mac = Poly1305::new(&mac_key);
        mac_key.zeroize();
        mac.update_padded(associated_data);
        Ok(Self {
            cipher,
            mac,
            pending_block: [0; POLY1305_BLOCK_SIZE],
            pending_length: 0,
            associated_data_length: associated_data.len() as u64,
            data_length: 0,
        })
    }

    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        if input.len() != output.len() || input.len() as u64 > CHACHA20_POLY1305_MAXIMUM_DATA_LENGTH - self.data_length
        {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        self.cipher
            .try_apply_keystream_b2b(input, output)
            .map_err(|_| Error::new(ErrorKind::CryptoBackendFailure))?;
        self.data_length += input.len() as u64;
        self.authenticate(output);
        Ok(())
    }

    fn finish(mut self) -> Result<[u8; AEAD_TAG_SIZE]> {
        if self.pending_length > 0 {
            // Zero padding up to a block
            self.pending_block[self.pending_length..].fill(0);
            self.mac.update(&[Array::from(self.pending_block)]);
        }
        let mut lengths_block = poly1305::Block::default();
        lengths_block[..8].copy_from_slice(&self.associated_data_length.to_le_bytes());
        lengths_block[8..].copy_from_slice(&self.data_length.to_le_bytes());
        self.mac.update(&[lengths_block]);
        Ok(self.mac.finalize().into())
    }
}
