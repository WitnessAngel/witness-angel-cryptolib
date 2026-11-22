// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Limits applied when device profiles and metadata are loaded, with the defaults of the C library.

use crate::error::{Error, ErrorKind, Result};

/// The largest CBOR nesting depth of WA-CBOR documents.
pub const WA_CBOR_MAXIMUM_NESTING_DEPTH: usize = 64;

/// The largest number of shards of a shared secret (encryptor specification, section 3.7): a format limit,
/// readers rejecting shard indices above it, hence not configurable. Cryptoconf validation enforces it.
pub const MAX_SHARED_SECRET_SHARD_COUNT: usize = 30;

/// Limits of an encryptor: inputs beyond them are rejected with an error when they are loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptorLimits {
    max_key_cipher_nesting_depth: usize,
    max_cbor_nesting_depth: usize,
    max_rsa_modulus_bits: usize,
}

impl EncryptorLimits {
    /// Default key cipher nesting depth: a `key_cipher_layers` list of a payload layer is at depth 1, the list of
    /// a symmetric layer or of a shard one level deeper than the layer holding it.
    pub const DEFAULT_MAX_KEY_CIPHER_NESTING_DEPTH: usize = 8;
    /// Default CBOR item nesting depth, the maximum of WA-CBOR.
    pub const DEFAULT_MAX_CBOR_NESTING_DEPTH: usize = WA_CBOR_MAXIMUM_NESTING_DEPTH;
    /// Default size of the largest RSA modulus, in bits.
    pub const DEFAULT_MAX_RSA_MODULUS_BITS: usize = 4096;

    /// Limits with the given values. `ErrorKind::InvalidArgument` unless:
    /// - the key cipher nesting depth is in 1..=64;
    /// - the CBOR nesting depth is in 8..=64 (WA-CBOR documents never nest deeper than 64);
    /// - the RSA modulus size is a multiple of 8 in 2048..=8192.
    pub const fn new(
        max_key_cipher_nesting_depth: usize,
        max_cbor_nesting_depth: usize,
        max_rsa_modulus_bits: usize,
    ) -> Result<Self> {
        if max_key_cipher_nesting_depth < 1
            || max_key_cipher_nesting_depth > 64
            || max_cbor_nesting_depth < 8
            || max_cbor_nesting_depth > WA_CBOR_MAXIMUM_NESTING_DEPTH
            || max_rsa_modulus_bits < 2048
            || max_rsa_modulus_bits > 8192
            || !max_rsa_modulus_bits.is_multiple_of(8)
        {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        Ok(Self {
            max_key_cipher_nesting_depth,
            max_cbor_nesting_depth,
            max_rsa_modulus_bits,
        })
    }

    /// The largest key cipher nesting depth accepted.
    pub const fn max_key_cipher_nesting_depth(&self) -> usize {
        self.max_key_cipher_nesting_depth
    }

    /// The largest CBOR item nesting depth accepted, for profiles and metadata.
    pub const fn max_cbor_nesting_depth(&self) -> usize {
        self.max_cbor_nesting_depth
    }

    /// The size of the largest RSA modulus accepted, in bits.
    pub const fn max_rsa_modulus_bits(&self) -> usize {
        self.max_rsa_modulus_bits
    }
}

impl Default for EncryptorLimits {
    fn default() -> Self {
        Self {
            max_key_cipher_nesting_depth: Self::DEFAULT_MAX_KEY_CIPHER_NESTING_DEPTH,
            max_cbor_nesting_depth: Self::DEFAULT_MAX_CBOR_NESTING_DEPTH,
            max_rsa_modulus_bits: Self::DEFAULT_MAX_RSA_MODULUS_BITS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_those_of_the_c_library() {
        let limits = EncryptorLimits::default();
        assert_eq!(limits.max_key_cipher_nesting_depth(), 8);
        assert_eq!(limits.max_cbor_nesting_depth(), 64);
        assert_eq!(limits.max_rsa_modulus_bits(), 4096);
        assert_eq!(EncryptorLimits::new(8, 64, 4096), Ok(limits));
    }

    #[test]
    fn a_cbor_depth_of_65_is_refused() {
        assert_eq!(
            EncryptorLimits::new(8, 65, 4096).map_err(|error| error.kind()),
            Err(ErrorKind::InvalidArgument)
        );
        assert!(EncryptorLimits::new(8, 8, 4096).is_ok());
        assert!(EncryptorLimits::new(8, 7, 4096).is_err());
    }

    #[test]
    fn other_bounds_are_checked() {
        assert!(EncryptorLimits::new(0, 64, 4096).is_err());
        assert!(EncryptorLimits::new(65, 64, 4096).is_err());
        assert!(EncryptorLimits::new(1, 64, 2048).is_ok());
        assert!(EncryptorLimits::new(8, 64, 2040).is_err());
        assert!(EncryptorLimits::new(8, 64, 4100).is_err());
        assert!(EncryptorLimits::new(8, 64, 8192).is_ok());
        assert!(EncryptorLimits::new(8, 64, 8200).is_err());
    }
}
