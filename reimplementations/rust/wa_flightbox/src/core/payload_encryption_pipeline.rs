// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Section 7.2 of the encryptor specification: payload chunks go through one cipher stream per payload cipher
//! layer, in internal slices that bound memory use. The CBC remainder of each node lives in its symmetric cipher
//! stream, which outputs whole blocks only; AES_EAX and CHACHA20_POLY1305 output as many bytes as they get.
//!
//! Scratch sizes: with S the slice size (a multiple of 16) and n nodes, a node receives at most S + 15 * n bytes
//! per slice and writes at most its input length + 15 bytes. At finalization, the bytes pending for a node are at
//! most 16 per previous node, and it outputs at most them + 15, then its final block of 16 bytes. Two blocks of
//! S + 16 * n bytes, used alternately as input and output, therefore suffice.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::crypto_backend::{AEAD_TAG_SIZE, AES_BLOCK_SIZE, CryptoBackend};
use crate::encoding::buffered_sink_writer::sink_error_kind;
use crate::error::{Error, ErrorKind, Result};
use crate::platform_hooks::OutputSink;
use crate::primitives::symmetric_cipher_streams::SymmetricCipherStream;
use crate::primitives::symmetric_key_generation::Symkey;
use crate::primitives::try_zeroed_vec;

/// The default size of processing slices.
pub(crate) const DEFAULT_PAYLOAD_PROCESSING_SLICE_SIZE: usize = 4096;

struct PipelineNode<B: CryptoBackend> {
    stream: SymmetricCipherStream<B>,
    /// Set at finalization, `None` for AES_CBC
    tag: Option<[u8; AEAD_TAG_SIZE]>,
}

pub(crate) struct PayloadEncryptionPipeline<B: CryptoBackend> {
    nodes: Vec<PipelineNode<B>>,
    slice_size: usize,
    /// Intermediate ciphertexts, wiped when dropped
    first_scratch_block: Zeroizing<Vec<u8>>,
    second_scratch_block: Zeroizing<Vec<u8>>,
}

fn write_to_sink(sink: &mut dyn OutputSink, bytes: &[u8]) -> Result<()> {
    // Out of memory (e.g. the inline ciphertext buffer) passes through
    sink.write(bytes).map_err(|error| Error::new(sink_error_kind(error)))
}

impl<B: CryptoBackend> PayloadEncryptionPipeline<B> {
    /// One cipher stream per payload symkey, in layer order. `slice_size` must be a multiple of 16, at least 16
    /// (`ErrorKind::InvalidArgument` otherwise).
    pub(crate) fn start(payload_symkeys: &[Symkey], slice_size: usize) -> Result<Self> {
        if payload_symkeys.is_empty() {
            return Err(Error::new(ErrorKind::InternalError));
        }
        if slice_size < AES_BLOCK_SIZE || !slice_size.is_multiple_of(AES_BLOCK_SIZE) {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        let scratch_block_size = payload_symkeys
            .len()
            .checked_mul(AES_BLOCK_SIZE)
            .and_then(|extra_size| extra_size.checked_add(slice_size))
            .ok_or(ErrorKind::OutOfMemory)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(payload_symkeys.len())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        for payload_symkey in payload_symkeys {
            nodes.push(PipelineNode {
                stream: SymmetricCipherStream::start(payload_symkey)?,
                tag: None,
            });
        }
        Ok(Self {
            nodes,
            slice_size,
            first_scratch_block: Zeroizing::new(try_zeroed_vec(scratch_block_size)?),
            second_scratch_block: Zeroizing::new(try_zeroed_vec(scratch_block_size)?),
        })
    }

    /// One slice through every node, then to the sink.
    fn encrypt_slice(&mut self, slice: &[u8], sink: &mut dyn OutputSink) -> Result<()> {
        let mut input_block: &mut [u8] = &mut self.first_scratch_block;
        let mut output_block: &mut [u8] = &mut self.second_scratch_block;
        let mut length = slice.len();
        for (node_index, node) in self.nodes.iter_mut().enumerate() {
            if length == 0 {
                return Ok(()); // An AES_CBC node kept everything in its remainder: nothing to pass on
            }
            if node_index == 0 {
                length = node.stream.encrypt(slice, output_block)?;
            } else {
                core::mem::swap(&mut input_block, &mut output_block);
                let input = input_block.get(..length).ok_or(ErrorKind::InternalError)?;
                length = node.stream.encrypt(input, output_block)?;
            }
        }
        if length == 0 {
            return Ok(());
        }
        write_to_sink(sink, output_block.get(..length).ok_or(ErrorKind::InternalError)?)
    }

    /// Step 2: encrypt a payload chunk of any length, the ciphertext available so far going to `sink`.
    pub(crate) fn encrypt_chunk(&mut self, chunk: &[u8], sink: &mut dyn OutputSink) -> Result<()> {
        for slice in chunk.chunks(self.slice_size) {
            self.encrypt_slice(slice, sink)?;
        }
        Ok(())
    }

    /// End of step 2: `pending = b""; for node in nodes: pending = (node.encrypt(pending) if pending else b"") +
    /// node.finalize()`, then the last pending bytes go to `sink`. The tags of the nodes are kept for step 3.
    pub(crate) fn finalize(&mut self, sink: &mut dyn OutputSink) -> Result<()> {
        let mut pending_block: &mut [u8] = &mut self.first_scratch_block;
        let mut output_block: &mut [u8] = &mut self.second_scratch_block;
        let mut pending_length = 0usize;
        for node in self.nodes.iter_mut() {
            let mut output_length = 0;
            if pending_length > 0 {
                let pending = pending_block.get(..pending_length).ok_or(ErrorKind::InternalError)?;
                output_length = node.stream.encrypt(pending, output_block)?;
            }
            let mut final_block = [0u8; AES_BLOCK_SIZE];
            let (final_length, tag) = node.stream.finish(&mut final_block)?;
            node.tag = tag;
            let total_length = output_length
                .checked_add(final_length)
                .ok_or(ErrorKind::InternalError)?;
            // Excluded by the bound in the module comment
            let final_output = output_block
                .get_mut(output_length..total_length)
                .ok_or(ErrorKind::InternalError)?;
            final_output.copy_from_slice(final_block.get(..final_length).ok_or(ErrorKind::InternalError)?);
            pending_length = total_length;
            core::mem::swap(&mut pending_block, &mut output_block);
        }
        if pending_length == 0 {
            return Ok(());
        }
        write_to_sink(
            sink,
            pending_block.get(..pending_length).ok_or(ErrorKind::InternalError)?,
        )
    }

    /// The tags of the nodes after finalization, in layer order (`None` for AES_CBC).
    pub(crate) fn tags(&self) -> impl ExactSizeIterator<Item = Option<&[u8; AEAD_TAG_SIZE]>> {
        self.nodes.iter().map(|node| node.tag.as_ref())
    }
}
