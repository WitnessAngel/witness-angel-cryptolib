// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! The single error set of the library (design D8), named after the status codes of the C library so that the
//! host tools of both implementations report the same status names.

use alloc::string::String;
use core::fmt;

/// Category of an [`Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An argument is invalid (sizes, options, a primitive used outside its contract).
    InvalidArgument,
    /// The device profile format string is missing or unknown.
    UnsupportedFormat,
    /// The bytes are not WA-CBOR.
    DecodingError,
    /// The device profile, its cryptoconf or the cryptainer metadata break a rule.
    InvalidProfile,
    /// A valid WA-CBOR item outside the device profile sub-profile (float, datetime, bignum, decimal, indefinite
    /// length, tag 55799, integer outside the signed 64-bit range).
    UnsupportedType,
    /// A feature that this build does not have, such as a document format that is not compiled in.
    UnsupportedFeature,
    /// The cryptoconf asks for signatures, which this encryptor does not make.
    UnsupportedSignature,
    /// An algorithm that this encryptor does not have.
    UnsupportedAlgorithm,
    /// No trustee public key entry matches an asymmetric key cipher layer.
    MissingPublicKey,
    /// A trustee public key breaks its sanity constraints.
    KeyConstraintViolation,
    /// CBOR items or key cipher layers are nested beyond the configured limits.
    NestingTooDeep,
    /// The allocator refused a buffer whose size depends on caller input.
    OutOfMemory,
    /// The random hook failed.
    RandomnessFailure,
    /// The crypto backend failed.
    CryptoBackendFailure,
    /// An output sink failed.
    SinkWriteFailure,
    /// A call made on a failed encryptor (or, for backends, on a finished stream).
    WrongState,
    /// A bug in the library: an internal consistency check failed.
    InternalError,
}

impl ErrorKind {
    /// Every kind, in the order of the C status codes.
    pub const ALL: [ErrorKind; 17] = [
        ErrorKind::InvalidArgument,
        ErrorKind::UnsupportedFormat,
        ErrorKind::DecodingError,
        ErrorKind::InvalidProfile,
        ErrorKind::UnsupportedType,
        ErrorKind::UnsupportedFeature,
        ErrorKind::UnsupportedSignature,
        ErrorKind::UnsupportedAlgorithm,
        ErrorKind::MissingPublicKey,
        ErrorKind::KeyConstraintViolation,
        ErrorKind::NestingTooDeep,
        ErrorKind::OutOfMemory,
        ErrorKind::RandomnessFailure,
        ErrorKind::CryptoBackendFailure,
        ErrorKind::SinkWriteFailure,
        ErrorKind::WrongState,
        ErrorKind::InternalError,
    ];

    /// The name of the matching C status code, as printed by the host tools.
    pub const fn status_name(self) -> &'static str {
        match self {
            ErrorKind::InvalidArgument => "WA_STATUS_INVALID_ARGUMENT",
            ErrorKind::UnsupportedFormat => "WA_STATUS_UNSUPPORTED_FORMAT",
            ErrorKind::DecodingError => "WA_STATUS_DECODING_ERROR",
            ErrorKind::InvalidProfile => "WA_STATUS_INVALID_PROFILE",
            ErrorKind::UnsupportedType => "WA_STATUS_UNSUPPORTED_TYPE",
            ErrorKind::UnsupportedFeature => "WA_STATUS_UNSUPPORTED_FEATURE",
            ErrorKind::UnsupportedSignature => "WA_STATUS_UNSUPPORTED_SIGNATURE",
            ErrorKind::UnsupportedAlgorithm => "WA_STATUS_UNSUPPORTED_ALGORITHM",
            ErrorKind::MissingPublicKey => "WA_STATUS_MISSING_PUBLIC_KEY",
            ErrorKind::KeyConstraintViolation => "WA_STATUS_KEY_CONSTRAINT_VIOLATION",
            ErrorKind::NestingTooDeep => "WA_STATUS_NESTING_TOO_DEEP",
            ErrorKind::OutOfMemory => "WA_STATUS_OUT_OF_MEMORY",
            ErrorKind::RandomnessFailure => "WA_STATUS_RANDOMNESS_FAILURE",
            ErrorKind::CryptoBackendFailure => "WA_STATUS_CRYPTO_BACKEND_FAILURE",
            ErrorKind::SinkWriteFailure => "WA_STATUS_SINK_WRITE_FAILURE",
            ErrorKind::WrongState => "WA_STATUS_WRONG_STATE",
            ErrorKind::InternalError => "WA_STATUS_INTERNAL_ERROR",
        }
    }

    /// A human-readable description, the same as the C library's.
    pub const fn description(self) -> &'static str {
        match self {
            ErrorKind::InvalidArgument => "invalid argument",
            ErrorKind::UnsupportedFormat => "unsupported or missing device profile format",
            ErrorKind::DecodingError => "invalid WA-CBOR data",
            ErrorKind::InvalidProfile => "invalid device profile, cryptoconf or metadata",
            ErrorKind::UnsupportedType => {
                "unsupported WA-CBOR item (float, datetime, bignum, decimal, indefinite length, tag 55799 or integer \
                 outside int64)"
            }
            ErrorKind::UnsupportedFeature => "unsupported feature (e.g. a document format not compiled in)",
            ErrorKind::UnsupportedSignature => "signatures are not supported by this encryptor",
            ErrorKind::UnsupportedAlgorithm => "unsupported algorithm",
            ErrorKind::MissingPublicKey => "no public key entry matches a key cipher layer",
            ErrorKind::KeyConstraintViolation => "a public key violates its constraints",
            ErrorKind::NestingTooDeep => "nesting too deep",
            ErrorKind::OutOfMemory => "out of memory",
            ErrorKind::RandomnessFailure => "the random generator failed",
            ErrorKind::CryptoBackendFailure => "the crypto backend failed",
            ErrorKind::SinkWriteFailure => "an output sink failed",
            ErrorKind::WrongState => "call made in the wrong encryptor state",
            ErrorKind::InternalError => "internal error",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

/// An error of the library: its kind and, for device profile errors, the location of the faulty item, as a path
/// such as `cryptoconf.payload_cipher_layers[0].key_cipher_layers[1]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    location: String,
}

impl Error {
    /// An error without location.
    pub const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            location: String::new(),
        }
    }

    /// An error at `location` of a device profile.
    pub fn with_location(kind: ErrorKind, location: String) -> Self {
        Self { kind, location }
    }

    /// The category of the error.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The location of the faulty item, empty when there is none.
    pub fn location(&self) -> &str {
        &self.location
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.description())?;
        if !self.location.is_empty() {
            write!(formatter, " (at {})", self.location)?;
        }
        Ok(())
    }
}

impl core::error::Error for Error {}

/// Result of the fallible operations of the library.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn every_kind_has_a_name_and_a_description() {
        for kind in ErrorKind::ALL {
            assert!(kind.status_name().starts_with("WA_STATUS_"));
            assert!(!kind.description().is_empty());
            assert_eq!(kind.to_string(), kind.description());
        }
        let mut names: alloc::vec::Vec<_> = ErrorKind::ALL.iter().map(|kind| kind.status_name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ErrorKind::ALL.len());
    }

    #[test]
    fn display_includes_the_location() {
        let error = Error::with_location(
            ErrorKind::MissingPublicKey,
            "cryptoconf.payload_cipher_layers[0]".into(),
        );
        assert_eq!(
            error.to_string(),
            "no public key entry matches a key cipher layer (at cryptoconf.payload_cipher_layers[0])"
        );
        assert_eq!(Error::new(ErrorKind::OutOfMemory).to_string(), "out of memory");
        assert_eq!(Error::from(ErrorKind::OutOfMemory).location(), "");
    }
}
