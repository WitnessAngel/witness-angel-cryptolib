// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! AES-256 EAX streaming encryption (Bellare, Rogaway, Wagner), with an empty header and a 16-byte tag, as
//! pycryptodome's `AES.MODE_EAX`: tag = OMAC0(nonce) xor OMAC1(header) xor OMAC2(ciphertext), the ciphertext being
//! the CTR encryption of the plaintext from the counter OMAC0(nonce).

use zeroize::Zeroize;

use crate::crypto_backend::{AEAD_TAG_SIZE, AES_256_KEY_SIZE, AES_BLOCK_SIZE, Aes256Encryptor};
use crate::error::Result;
use crate::primitives::aes_cmac_omac1::{AES_CMAC_SIZE, AesCmac, AesCmacSubkeys};

/// OMAC^t of a whole message.
fn compute_omac<A: Aes256Encryptor>(
    aes: &mut A,
    subkeys: AesCmacSubkeys,
    tweak: u8,
    data: &[u8],
) -> Result<[u8; AES_CMAC_SIZE]> {
    let mut cmac = AesCmac::start_omac_with_tweak(aes, subkeys, tweak)?;
    cmac.update(aes, data)?;
    cmac.finish(aes)
}

pub(crate) struct AesEaxEncryption<A: Aes256Encryptor> {
    aes: A,
    counter_block: [u8; AES_BLOCK_SIZE],
    /// The keystream block in use, of which `keystream_used_length` bytes were consumed
    keystream_block: [u8; AES_BLOCK_SIZE],
    keystream_used_length: usize,
    /// OMAC0(nonce) xor OMAC1(empty header)
    nonce_and_header_omacs: [u8; AES_CMAC_SIZE],
    /// `None` once finished
    ciphertext_omac: Option<AesCmac>,
}

impl<A: Aes256Encryptor> AesEaxEncryption<A> {
    pub(crate) fn start(key: &[u8; AES_256_KEY_SIZE], nonce: &[u8]) -> Result<Self> {
        let mut aes = A::new(key)?;
        // The three OMACs share the subkeys of the key
        let subkeys = AesCmacSubkeys::derive(&mut aes)?;
        // N = OMAC0(nonce), the initial counter
        let counter_block = compute_omac(&mut aes, subkeys.clone(), 0, nonce)?;
        // H = OMAC1(empty header)
        let mut header_omac = compute_omac(&mut aes, subkeys.clone(), 1, &[])?;
        let mut nonce_and_header_omacs = [0u8; AES_CMAC_SIZE];
        for index in 0..AES_CMAC_SIZE {
            nonce_and_header_omacs[index] = counter_block[index] ^ header_omac[index];
        }
        header_omac.zeroize();
        let ciphertext_omac = AesCmac::start_omac_with_tweak(&mut aes, subkeys, 2)?;
        Ok(Self {
            aes,
            counter_block,
            keystream_block: [0; AES_BLOCK_SIZE],
            keystream_used_length: AES_BLOCK_SIZE,
            nonce_and_header_omacs,
            ciphertext_omac: Some(ciphertext_omac),
        })
    }

    /// Encrypt `input` into `output`, of the same length (any length).
    pub(crate) fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        let length = input.len().min(output.len());
        let mut offset = 0;
        // Rest of the previous keystream block
        while offset < length && self.keystream_used_length < AES_BLOCK_SIZE {
            output[offset] = input[offset] ^ self.keystream_block[self.keystream_used_length];
            self.keystream_used_length += 1;
            offset += 1;
        }
        // Whole blocks in bulk
        let bulk_length = ((length - offset) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        if bulk_length > 0 {
            self.aes.encrypt_ctr_blocks(
                &mut self.counter_block,
                &input[offset..offset + bulk_length],
                &mut output[offset..offset + bulk_length],
            )?;
        }
        offset += bulk_length;
        // Final partial block, from a fresh keystream block (the CTR encryption of zeros)
        if offset < length {
            self.aes.encrypt_ctr_blocks(
                &mut self.counter_block,
                &[0u8; AES_BLOCK_SIZE],
                &mut self.keystream_block,
            )?;
            self.keystream_used_length = 0;
            while offset < length {
                output[offset] = input[offset] ^ self.keystream_block[self.keystream_used_length];
                self.keystream_used_length += 1;
                offset += 1;
            }
        }
        match self.ciphertext_omac.as_mut() {
            Some(ciphertext_omac) => ciphertext_omac.update(&mut self.aes, &output[..length]),
            None => Err(crate::error::ErrorKind::WrongState.into()),
        }
    }

    pub(crate) fn finish(&mut self) -> Result<[u8; AEAD_TAG_SIZE]> {
        let ciphertext_omac = self.ciphertext_omac.take().ok_or(crate::error::ErrorKind::WrongState)?;
        let mut tag = ciphertext_omac.finish(&mut self.aes)?;
        for (tag_byte, omac_byte) in tag.iter_mut().zip(self.nonce_and_header_omacs.iter()) {
            *tag_byte ^= omac_byte;
        }
        Ok(tag)
    }
}

impl<A: Aes256Encryptor> Drop for AesEaxEncryption<A> {
    fn drop(&mut self) {
        self.counter_block.zeroize();
        self.keystream_block.zeroize();
        self.nonce_and_header_omacs.zeroize();
        self.keystream_used_length = 0;
    }
}
