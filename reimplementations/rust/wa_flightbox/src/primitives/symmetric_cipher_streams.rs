// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Symmetric ciphers of the encryptor specification, section 3.4: AES_CBC (PKCS#7), AES_EAX and
//! CHACHA20_POLY1305, without associated data. Streaming contexts (payload cipher layers) and one-shot
//! cipherdicts (symmetric key layers), the latter running the former, so both give exactly the same ciphertext
//! and tag.

use zeroize::Zeroize;

use crate::crypto_backend::{
    AEAD_TAG_SIZE, AES_BLOCK_SIZE, Aes256Encryptor, CHACHA20_POLY1305_NONCE_SIZE, ChaCha20Poly1305Encryptor,
    CryptoBackend,
};
use crate::encoding::value_tree::{Map, Value};
use crate::error::{Error, ErrorKind, Result};
use crate::primitives::aes_cbc_pkcs7_padding::{pkcs7_pad_final_block, pkcs7_padding_length};
use crate::primitives::aes_eax_mode::AesEaxEncryption;
use crate::primitives::symmetric_key_generation::{Symkey, SymmetricCipherAlgo};
use crate::primitives::try_zeroed_vec;

pub(crate) struct AesCbcStream<A: Aes256Encryptor> {
    aes: A,
    chaining_value: [u8; AES_BLOCK_SIZE],
    pending_block: [u8; AES_BLOCK_SIZE],
    /// 0..=15
    pending_length: usize,
}

impl<A: Aes256Encryptor> Drop for AesCbcStream<A> {
    fn drop(&mut self) {
        self.chaining_value.zeroize();
        self.pending_block.zeroize();
    }
}

pub(crate) enum SymmetricCipherStream<B: CryptoBackend> {
    AesCbc(AesCbcStream<B::Aes256>),
    AesEax(AesEaxEncryption<B::Aes256>),
    /// `None` once finished
    ChaCha20Poly1305(Option<B::ChaCha20Poly1305>),
}

impl<B: CryptoBackend> SymmetricCipherStream<B> {
    pub(crate) fn start(symkey: &Symkey) -> Result<Self> {
        match symkey.cipher_algo {
            SymmetricCipherAlgo::AesCbc => {
                let chaining_value: [u8; AES_BLOCK_SIZE] = symkey
                    .iv_or_nonce()
                    .try_into()
                    .map_err(|_| Error::new(ErrorKind::InvalidArgument))?;
                Ok(Self::AesCbc(AesCbcStream {
                    aes: B::Aes256::new(&symkey.key)?,
                    chaining_value,
                    pending_block: [0; AES_BLOCK_SIZE],
                    pending_length: 0,
                }))
            }
            SymmetricCipherAlgo::AesEax => Ok(Self::AesEax(AesEaxEncryption::start(
                &symkey.key,
                symkey.iv_or_nonce(),
            )?)),
            SymmetricCipherAlgo::ChaCha20Poly1305 => {
                let nonce: [u8; CHACHA20_POLY1305_NONCE_SIZE] = symkey
                    .iv_or_nonce()
                    .try_into()
                    .map_err(|_| Error::new(ErrorKind::InvalidArgument))?;
                Ok(Self::ChaCha20Poly1305(Some(B::ChaCha20Poly1305::new(
                    &symkey.key,
                    &nonce,
                    &[],
                )?)))
            }
        }
    }

    /// Encrypt `input` into `output` (capacity: the input length + 15 at least), and return the number of bytes
    /// written: as many as the input for AES_EAX and CHACHA20_POLY1305, whole blocks for AES_CBC.
    pub(crate) fn encrypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        match self {
            Self::AesCbc(stream) => stream.encrypt(input, output),
            Self::AesEax(encryption) => {
                let output = output.get_mut(..input.len()).ok_or(ErrorKind::InternalError)?;
                encryption.update(input, output)?;
                Ok(input.len())
            }
            Self::ChaCha20Poly1305(encryptor) => {
                let output = output.get_mut(..input.len()).ok_or(ErrorKind::InternalError)?;
                encryptor
                    .as_mut()
                    .ok_or(ErrorKind::WrongState)?
                    .encrypt(input, output)?;
                Ok(input.len())
            }
        }
    }

    /// End the encryption: AES_CBC writes its final padded block to `final_output` and has no tag; the others
    /// write nothing there and return a 16-byte tag. Returns the length written to `final_output` (0 or 16).
    pub(crate) fn finish(
        &mut self,
        final_output: &mut [u8; AES_BLOCK_SIZE],
    ) -> Result<(usize, Option<[u8; AEAD_TAG_SIZE]>)> {
        match self {
            Self::AesCbc(stream) => {
                pkcs7_pad_final_block(&mut stream.pending_block, stream.pending_length);
                // Borrowed in place, not copied: the block holds plaintext
                let result =
                    stream
                        .aes
                        .encrypt_cbc_blocks(&mut stream.chaining_value, &stream.pending_block, final_output);
                stream.pending_block.zeroize();
                stream.pending_length = 0;
                result.map(|()| (AES_BLOCK_SIZE, None))
            }
            Self::AesEax(encryption) => Ok((0, Some(encryption.finish()?))),
            Self::ChaCha20Poly1305(encryptor) => {
                Ok((0, Some(encryptor.take().ok_or(ErrorKind::WrongState)?.finish()?)))
            }
        }
    }
}

impl<A: Aes256Encryptor> AesCbcStream<A> {
    fn encrypt(&mut self, mut input: &[u8], output: &mut [u8]) -> Result<usize> {
        let mut output_length = 0;
        // Complete the pending block first
        if self.pending_length > 0 {
            let fill_length = (AES_BLOCK_SIZE - self.pending_length).min(input.len());
            self.pending_block[self.pending_length..self.pending_length + fill_length]
                .copy_from_slice(&input[..fill_length]);
            self.pending_length += fill_length;
            input = &input[fill_length..];
            if self.pending_length < AES_BLOCK_SIZE {
                return Ok(0);
            }
            let block_output = output.get_mut(..AES_BLOCK_SIZE).ok_or(ErrorKind::InternalError)?;
            self.aes
                .encrypt_cbc_blocks(&mut self.chaining_value, &self.pending_block, block_output)?;
            self.pending_length = 0;
            output_length = AES_BLOCK_SIZE;
        }
        // Whole blocks in bulk (PKCS#7 always adds a block, so a full last block needs not be kept back)
        let bulk_length = (input.len() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        let bulk_output = output
            .get_mut(output_length..output_length + bulk_length)
            .ok_or(ErrorKind::InternalError)?;
        if bulk_length > 0 {
            // One backend call per processing slice, whatever its number of blocks
            self.aes
                .encrypt_cbc_blocks(&mut self.chaining_value, &input[..bulk_length], bulk_output)?;
        }
        output_length += bulk_length;
        let rest = &input[bulk_length..];
        self.pending_length = rest.len();
        self.pending_block[..rest.len()].copy_from_slice(rest);
        Ok(output_length)
    }
}

/// One-shot cipherdict: `{"ciphertext": bytes}` for AES_CBC, `{"ciphertext": bytes, "tag": bytes(16)}` otherwise.
pub(crate) fn symmetric_encrypt_to_cipherdict<B: CryptoBackend>(symkey: &Symkey, plaintext: &[u8]) -> Result<Value> {
    // The exact ciphertext length: a fresh stream outputs whole blocks then the padding block for AES_CBC, as
    // many bytes as the input for the others
    let padding_length = if symkey.cipher_algo == SymmetricCipherAlgo::AesCbc {
        pkcs7_padding_length(plaintext.len())
    } else {
        0
    };
    let capacity = plaintext
        .len()
        .checked_add(padding_length)
        .ok_or(ErrorKind::InvalidArgument)?;
    let mut ciphertext = try_zeroed_vec(capacity)?;
    let mut stream = SymmetricCipherStream::<B>::start(symkey)?;
    let result = (|| {
        let ciphertext_length = stream.encrypt(plaintext, &mut ciphertext)?;
        let mut final_output = [0u8; AES_BLOCK_SIZE];
        let (final_length, tag) = stream.finish(&mut final_output)?;
        ciphertext
            .get_mut(ciphertext_length..ciphertext_length + final_length)
            .ok_or(ErrorKind::InternalError)?
            .copy_from_slice(&final_output[..final_length]);
        if ciphertext_length + final_length != capacity {
            return Err(Error::new(ErrorKind::InternalError));
        }
        Ok(tag)
    })();
    let tag = match result {
        Ok(tag) => tag,
        Err(error) => {
            ciphertext.zeroize(); // It may hold plaintext after a failure in the middle
            return Err(error);
        }
    };
    let mut cipherdict = Map::new();
    cipherdict.set("ciphertext", Value::Bytes(ciphertext));
    if let Some(tag) = tag {
        cipherdict.set("tag", Value::Bytes(tag.to_vec()));
    }
    Ok(Value::Map(cipherdict))
}

/// Payload MACs of a payload cipher layer (section 3.4): `{}` for AES_CBC, `{"tag": bytes(16)}` otherwise.
pub(crate) fn build_payload_macs(cipher_algo: SymmetricCipherAlgo, tag: Option<&[u8; AEAD_TAG_SIZE]>) -> Result<Value> {
    let mut payload_macs = Map::new();
    match (cipher_algo.has_tag(), tag) {
        (true, Some(tag)) => {
            payload_macs.set("tag", Value::Bytes(tag.to_vec()));
        }
        (false, None) => {}
        _ => return Err(Error::new(ErrorKind::InvalidArgument)),
    }
    Ok(Value::Map(payload_macs))
}
