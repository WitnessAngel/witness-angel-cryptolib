// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! What the library needs from the platform: random bytes, optionally the time, and sinks for its outputs. The
//! library itself makes no operating-system call and has no global state.

use alloc::vec::Vec;

/// Failure of the random hook: the operation in progress is aborted, no other source is tried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomFailure;

/// Hooks given to each encryptor creation.
pub trait PlatformHooks {
    /// Fill `buffer` entirely with random bytes.
    ///
    /// **This must be a cryptographically secure generator**: every secret of a cryptainer comes from it
    /// (symmetric keys, IVs and nonces, Shamir coefficients, HPKE ephemeral keys, ML-KEM encapsulation randomness,
    /// RSA-OAEP seeds, UUID random bits). On a microcontroller, use the hardware TRNG, preferably through a DRBG,
    /// and return an error when it reports a fault. Never use a fixed seed, a counter or a general-purpose
    /// pseudo-random generator.
    fn fill_random(&mut self, buffer: &mut [u8]) -> Result<(), RandomFailure>;

    /// The Unix time in units of 1/10000 second, or `None` without a clock: UUID time prefixes are then zero,
    /// their 80 random bits being kept.
    fn unix_time_in_ten_thousandths_of_second(&mut self) -> Option<u64> {
        None
    }
}

impl<H: PlatformHooks + ?Sized> PlatformHooks for &mut H {
    fn fill_random(&mut self, buffer: &mut [u8]) -> Result<(), RandomFailure> {
        (**self).fill_random(buffer)
    }

    fn unix_time_in_ten_thousandths_of_second(&mut self) -> Option<u64> {
        (**self).unix_time_in_ten_thousandths_of_second()
    }
}

/// Failure of an [`OutputSink`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkError {
    /// The destination refused the bytes: reported as a sink write failure.
    WriteFailure,
    /// The sink could not grow its buffer: reported as an out-of-memory error.
    OutOfMemory,
}

/// A destination for output bytes (a file, a flash region, a radio link, a buffer), written progressively.
pub trait OutputSink {
    /// Take the next bytes of the output. After an error, the sink is not written to anymore.
    fn write(&mut self, bytes: &[u8]) -> Result<(), SinkError>;
}

impl<S: OutputSink + ?Sized> OutputSink for &mut S {
    fn write(&mut self, bytes: &[u8]) -> Result<(), SinkError> {
        (**self).write(bytes)
    }
}

/// Appends to the vector, reporting an allocation refusal as [`SinkError::OutOfMemory`].
impl OutputSink for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), SinkError> {
        self.try_reserve(bytes.len()).map_err(|_| SinkError::OutOfMemory)?;
        self.extend_from_slice(bytes);
        Ok(())
    }
}

/// The payload sink type of encryptors whose ciphertext is inline: it is never written to.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPayloadSink;

impl OutputSink for NoPayloadSink {
    fn write(&mut self, _bytes: &[u8]) -> Result<(), SinkError> {
        Err(SinkError::WriteFailure)
    }
}
