// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Small buffer in front of an output sink, for the document writers: they emit many short pieces, which reach
//! the sink in blocks. The first sink error is kept and returned by `finish()`, later writes being dropped. The
//! buffer is wiped when the writer is dropped, since serialized key material goes through it.

use zeroize::Zeroize;

use crate::error::{Error, ErrorKind, Result};
use crate::platform_hooks::{OutputSink, SinkError};

const BUFFER_SIZE: usize = 256;

/// Map a sink failure to the error of the library: out of memory passes through.
pub(crate) fn sink_error_kind(error: SinkError) -> ErrorKind {
    match error {
        SinkError::OutOfMemory => ErrorKind::OutOfMemory,
        SinkError::WriteFailure => ErrorKind::SinkWriteFailure,
    }
}

pub(crate) struct BufferedSinkWriter<'a> {
    sink: &'a mut dyn OutputSink,
    buffer: [u8; BUFFER_SIZE],
    length: usize,
    failure: Option<ErrorKind>,
}

impl<'a> BufferedSinkWriter<'a> {
    pub(crate) fn new(sink: &'a mut dyn OutputSink) -> Self {
        Self {
            sink,
            buffer: [0; BUFFER_SIZE],
            length: 0,
            failure: None,
        }
    }

    fn flush(&mut self) {
        if self.failure.is_none()
            && let Some(pending) = self.buffer.get(..self.length)
            && !pending.is_empty()
            && let Err(error) = self.sink.write(pending)
        {
            self.failure = Some(sink_error_kind(error));
        }
        self.length = 0;
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) {
        if self.failure.is_some() {
            return;
        }
        if bytes.len() >= BUFFER_SIZE {
            // Large strings (an inline ciphertext in WA-CBOR) go straight to the sink
            self.flush();
            if self.failure.is_none()
                && let Err(error) = self.sink.write(bytes)
            {
                self.failure = Some(sink_error_kind(error));
            }
            return;
        }
        let mut rest = bytes;
        while !rest.is_empty() {
            let free = self.buffer.get_mut(self.length..).unwrap_or_default();
            if free.is_empty() {
                self.flush();
                if self.failure.is_some() {
                    return;
                }
                continue;
            }
            let count = free.len().min(rest.len());
            let (head, tail) = rest.split_at(count);
            if let Some(destination) = free.get_mut(..count) {
                destination.copy_from_slice(head);
            }
            self.length = self.length.saturating_add(count);
            rest = tail;
        }
    }

    pub(crate) fn write_byte(&mut self, byte: u8) {
        self.write(&[byte]);
    }

    #[cfg(any(feature = "extended-json", test))]
    pub(crate) fn write_text(&mut self, text: &str) {
        self.write(text.as_bytes());
    }

    /// Flush what remains, and report the first failure if any.
    pub(crate) fn finish(mut self) -> Result<()> {
        self.flush();
        match self.failure {
            None => Ok(()),
            Some(kind) => Err(Error::new(kind)),
        }
    }
}

impl Drop for BufferedSinkWriter<'_> {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    struct FailingSink {
        accepted: Vec<u8>,
        budget: usize,
        error: SinkError,
        calls_after_failure: usize,
        failed: bool,
    }

    impl OutputSink for FailingSink {
        fn write(&mut self, bytes: &[u8]) -> core::result::Result<(), SinkError> {
            if self.failed {
                self.calls_after_failure += 1;
            }
            if self.accepted.len() + bytes.len() > self.budget {
                self.failed = true;
                return Err(self.error);
            }
            self.accepted.extend_from_slice(bytes);
            Ok(())
        }
    }

    #[test]
    fn pieces_of_any_size_arrive_in_order() {
        let mut output = Vec::new();
        let mut expected = Vec::new();
        let mut writer = BufferedSinkWriter::new(&mut output);
        for size in [0usize, 1, 255, 256, 257, 3, 1000, 0, 5] {
            let piece: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
            writer.write(&piece);
            expected.extend_from_slice(&piece);
        }
        writer.write_byte(b'!');
        writer.write_text("end");
        expected.extend_from_slice(b"!end");
        writer.finish().unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn the_first_failure_is_kept_and_the_sink_left_alone() {
        for (error, kind) in [
            (SinkError::WriteFailure, ErrorKind::SinkWriteFailure),
            (SinkError::OutOfMemory, ErrorKind::OutOfMemory),
        ] {
            let mut sink = FailingSink {
                accepted: Vec::new(),
                budget: 300,
                error,
                calls_after_failure: 0,
                failed: false,
            };
            let mut writer = BufferedSinkWriter::new(&mut sink);
            for _ in 0..10 {
                writer.write(&[7u8; 100]);
            }
            assert_eq!(writer.finish().map_err(|error| error.kind()), Err(kind));
            assert_eq!(sink.calls_after_failure, 0);
        }
    }
}
