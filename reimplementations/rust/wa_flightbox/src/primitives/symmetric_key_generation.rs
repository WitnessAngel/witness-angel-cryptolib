// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Symmetric cipher algorithms and symkeys (encryptor specification, sections 3.3 and 3.4): a 32-byte key and a
//! 16-byte IV (AES_CBC), a 16-byte nonce (AES_EAX) or a 12-byte nonce (CHACHA20_POLY1305), the key being drawn
//! before the IV or nonce.

use zeroize::{Zeroize, Zeroizing};

use crate::encoding::document_serialization::{ResolvedFormat, serialize_to_secret_buffer};
use crate::encoding::secret_byte_buffer::SecretByteBuffer;
use crate::encoding::value_tree::Node;
use crate::error::Result;
use crate::platform_hooks::PlatformHooks;
use crate::primitives::fill_random_bytes;

pub(crate) const SYMKEY_KEY_SIZE: usize = 32;
pub(crate) const SYMKEY_MAXIMUM_IV_OR_NONCE_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SymmetricCipherAlgo {
    AesCbc,
    AesEax,
    ChaCha20Poly1305,
}

impl SymmetricCipherAlgo {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "AES_CBC" => Some(Self::AesCbc),
            "AES_EAX" => Some(Self::AesEax),
            "CHACHA20_POLY1305" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// The name of the symkey field holding the IV or nonce.
    pub(crate) fn iv_or_nonce_field_name(self) -> &'static str {
        match self {
            Self::AesCbc => "iv",
            Self::AesEax | Self::ChaCha20Poly1305 => "nonce",
        }
    }

    pub(crate) fn iv_or_nonce_length(self) -> usize {
        match self {
            Self::AesCbc | Self::AesEax => 16,
            Self::ChaCha20Poly1305 => 12,
        }
    }

    pub(crate) fn has_tag(self) -> bool {
        !matches!(self, Self::AesCbc)
    }
}

/// A symkey, wiped when dropped.
pub(crate) struct Symkey {
    pub(crate) cipher_algo: SymmetricCipherAlgo,
    pub(crate) key: Zeroizing<[u8; SYMKEY_KEY_SIZE]>,
    iv_or_nonce: [u8; SYMKEY_MAXIMUM_IV_OR_NONCE_SIZE],
}

impl Symkey {
    /// Draw a symkey for `cipher_algo` from the random hook: the key, then the IV or nonce.
    pub(crate) fn generate(hooks: &mut dyn PlatformHooks, cipher_algo: SymmetricCipherAlgo) -> Result<Self> {
        let mut symkey = Self {
            cipher_algo,
            key: Zeroizing::new([0; SYMKEY_KEY_SIZE]),
            iv_or_nonce: [0; SYMKEY_MAXIMUM_IV_OR_NONCE_SIZE],
        };
        fill_random_bytes(hooks, &mut symkey.key[..])?;
        fill_random_bytes(hooks, &mut symkey.iv_or_nonce[..cipher_algo.iv_or_nonce_length()])?;
        Ok(symkey)
    }

    /// A symkey from given bytes (test vectors): `None` unless `key` is 32 bytes and `iv_or_nonce` has the length
    /// of the algorithm.
    pub(crate) fn from_parts(cipher_algo: SymmetricCipherAlgo, key: &[u8], iv_or_nonce: &[u8]) -> Option<Self> {
        if key.len() != SYMKEY_KEY_SIZE || iv_or_nonce.len() != cipher_algo.iv_or_nonce_length() {
            return None;
        }
        let mut symkey = Self {
            cipher_algo,
            key: Zeroizing::new([0; SYMKEY_KEY_SIZE]),
            iv_or_nonce: [0; SYMKEY_MAXIMUM_IV_OR_NONCE_SIZE],
        };
        symkey.key.copy_from_slice(key);
        symkey.iv_or_nonce[..iv_or_nonce.len()].copy_from_slice(iv_or_nonce);
        Some(symkey)
    }

    pub(crate) fn iv_or_nonce(&self) -> &[u8] {
        &self.iv_or_nonce[..self.cipher_algo.iv_or_nonce_length()]
    }

    /// `S_F` of the symkey `{"key": ..., "iv" or "nonce": ...}`, into a wiping buffer.
    pub(crate) fn serialize(&self, format: ResolvedFormat) -> Result<SecretByteBuffer> {
        let key = ("key", Node::Bytes(&self.key[..]));
        let iv_or_nonce = (
            self.cipher_algo.iv_or_nonce_field_name(),
            Node::Bytes(self.iv_or_nonce()),
        );
        // Entries sorted by key, like those of owned maps: "iv" < "key" < "nonce"
        let entries = if iv_or_nonce.0 < key.0 {
            [iv_or_nonce, key]
        } else {
            [key, iv_or_nonce]
        };
        serialize_to_secret_buffer(Node::Map(&entries), format)
    }
}

impl Drop for Symkey {
    fn drop(&mut self) {
        self.iv_or_nonce.zeroize();
    }
}
