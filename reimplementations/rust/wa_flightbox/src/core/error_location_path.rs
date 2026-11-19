// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Location of a fault inside a device profile, for error reports: map keys joined with dots, array indices in
//! brackets, as in `cryptoconf.payload_cipher_layers[0].key_cipher_layers[1].key_cipher_algo`.
//!
//! Validation functions push a component before descending and pop it when the subtree is valid: when one fails,
//! the path is left pointing at the fault.

use alloc::string::String;
use core::fmt::Write;

use crate::error::{Error, ErrorKind};

/// The result of a validation step: on failure, the location path given to the step points at the fault.
pub(crate) type Located<T> = core::result::Result<T, ErrorKind>;

#[derive(Default)]
pub(crate) struct ErrorLocationPath {
    text: String,
}

impl ErrorLocationPath {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Append a map key, and return the previous length of the path, for [`Self::pop`].
    pub(crate) fn push_key(&mut self, key: &str) -> usize {
        let previous_length = self.text.len();
        if previous_length > 0 {
            self.text.push('.');
        }
        self.text.push_str(key);
        previous_length
    }

    /// Append an array index, and return the previous length of the path, for [`Self::pop`].
    pub(crate) fn push_index(&mut self, index: usize) -> usize {
        let previous_length = self.text.len();
        // Writing to a String does not fail
        let _ = write!(self.text, "[{index}]");
        previous_length
    }

    /// Back to a length returned by a push.
    pub(crate) fn pop(&mut self, previous_length: usize) {
        self.text.truncate(previous_length);
    }

    /// `kind` at the pushed `key`.
    pub(crate) fn fail_at_key<T>(&mut self, key: &str, kind: ErrorKind) -> Located<T> {
        self.push_key(key);
        Err(kind)
    }

    /// The error of `kind` at this location.
    pub(crate) fn into_error(self, kind: ErrorKind) -> Error {
        Error::with_location(kind, self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_indices_are_joined() {
        let mut path = ErrorLocationPath::new();
        let root = path.push_key("cryptoconf");
        path.push_key("payload_cipher_layers");
        let index = path.push_index(12);
        path.push_key("key_cipher_algo");
        assert_eq!(path.text, "cryptoconf.payload_cipher_layers[12].key_cipher_algo");
        path.pop(index);
        assert_eq!(path.text, "cryptoconf.payload_cipher_layers");
        path.pop(root);
        assert_eq!(path.text, "");
        path.push_index(0);
        assert_eq!(path.into_error(ErrorKind::InvalidProfile).location(), "[0]");
    }
}
