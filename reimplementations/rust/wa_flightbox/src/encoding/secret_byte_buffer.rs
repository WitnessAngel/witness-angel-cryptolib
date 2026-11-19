// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! A growable byte buffer for secrets (design D9): it grows by allocating a new block, copying, wiping the old
//! block and releasing it, where a `Vec` would leave an unwiped copy behind when it reallocates. Its content is
//! wiped when it is dropped.

use alloc::vec::Vec;

use zeroize::Zeroize;

use crate::error::{Error, ErrorKind, Result};
use crate::platform_hooks::{OutputSink, SinkError};

/// A wiping byte buffer, usable as an output sink.
#[derive(Default)]
pub(crate) struct SecretByteBuffer {
    data: Vec<u8>,
}

impl SecretByteBuffer {
    /// An empty buffer, without allocation.
    pub(crate) const fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// The content.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// The length of the content.
    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    /// Append `bytes`, growing if needed. `ErrorKind::OutOfMemory` when the allocator refuses the new block (the
    /// content is then unchanged).
    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        let needed = self
            .data
            .len()
            .checked_add(bytes.len())
            .ok_or(Error::new(ErrorKind::OutOfMemory))?;
        if needed > self.data.capacity() {
            // Amortized growth, into a new block: the old one is wiped before its release
            let doubled = self.data.capacity().saturating_mul(2);
            let new_capacity = needed.max(doubled).max(64);
            let mut new_data = Vec::new();
            if new_data.try_reserve_exact(new_capacity).is_err() {
                new_data
                    .try_reserve_exact(needed)
                    .map_err(|_| Error::new(ErrorKind::OutOfMemory))?;
            }
            new_data.extend_from_slice(&self.data);
            self.data.zeroize();
            self.data = new_data;
        }
        self.data.extend_from_slice(bytes);
        Ok(())
    }
}

impl Drop for SecretByteBuffer {
    fn drop(&mut self) {
        // Vec::zeroize() wipes the whole capacity
        self.data.zeroize();
    }
}

impl OutputSink for SecretByteBuffer {
    fn write(&mut self, bytes: &[u8]) -> core::result::Result<(), SinkError> {
        self.extend_from_slice(bytes).map_err(|_| SinkError::OutOfMemory)
    }
}

impl core::fmt::Debug for SecretByteBuffer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "SecretByteBuffer({} bytes)", self.data.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // That neither growth nor drop leaves the content behind is checked with a scanning allocator, in
    // tests/allocator_robustness.rs
    #[test]
    fn content_survives_growth() {
        let mut buffer = SecretByteBuffer::new();
        assert_eq!(buffer.len(), 0);
        let mut expected = Vec::new();
        for round in 0..300u32 {
            let piece = [round as u8; 7];
            buffer.extend_from_slice(&piece).unwrap();
            expected.extend_from_slice(&piece);
        }
        assert_eq!(buffer.as_slice(), expected.as_slice());
        assert_eq!(buffer.len(), 2100);
        buffer.write(b"abc").unwrap();
        assert_eq!(buffer.as_slice()[2100..], *b"abc");
    }
}
