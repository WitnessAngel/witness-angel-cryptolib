// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Public API and lifecycle of the cryptainer encryptor: steps 1 (creation), 2 (chunks) and 3 (finalization) of
//! the encryptor specification, then serialization in the document format chosen at creation.

use alloc::vec::Vec;

use crate::core::cryptainer_base_generation::generate_cryptainer_base;
use crate::core::cryptainer_finalization::add_authentication_data;
use crate::core::payload_encryption_pipeline::{DEFAULT_PAYLOAD_PROCESSING_SLICE_SIZE, PayloadEncryptionPipeline};
use crate::crypto_backend::{AES_BLOCK_SIZE, CryptoBackend};
use crate::encoding::device_profile::DeviceProfile;
use crate::encoding::document_serialization::{DocumentFormat, ResolvedFormat, serialize_to_sink};
use crate::encoding::document_tree_constraints::check_document_tree_constraints;
use crate::encoding::value_tree::{Node, Value};
use crate::error::{Error, ErrorKind, Result};
use crate::platform_hooks::{NoPayloadSink, OutputSink, PlatformHooks};
use crate::primitives::symmetric_key_generation::SymmetricCipherAlgo;

/// Options of a cryptainer creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptorOptions {
    /// The document format of the cryptainer, and of the structures encrypted inside it.
    pub document_format: DocumentFormat,
    /// Payload chunks are processed in internal slices of at most this many bytes, which bounds memory use: a
    /// multiple of 16, at least 16. A crypto backend receives whole slices in its bulk AES calls.
    pub payload_processing_slice_size: usize,
}

impl EncryptorOptions {
    /// The default size of processing slices.
    pub const DEFAULT_PAYLOAD_PROCESSING_SLICE_SIZE: usize = DEFAULT_PAYLOAD_PROCESSING_SLICE_SIZE;
}

impl Default for EncryptorOptions {
    fn default() -> Self {
        Self {
            document_format: DocumentFormat::BuildDefault,
            payload_processing_slice_size: Self::DEFAULT_PAYLOAD_PROCESSING_SLICE_SIZE,
        }
    }
}

/// Where the payload ciphertext goes.
enum PayloadCiphertextOutput<S: OutputSink> {
    /// Accumulated, to be stored in the cryptainer
    Inline(Vec<u8>),
    /// Streamed to the sink of the caller
    Offloaded(S),
}

impl<S: OutputSink> PayloadCiphertextOutput<S> {
    fn as_sink(&mut self) -> &mut dyn OutputSink {
        match self {
            Self::Inline(inline_ciphertext) => inline_ciphertext,
            Self::Offloaded(payload_ciphertext_sink) => payload_ciphertext_sink,
        }
    }
}

/// An encryptor creating one cryptainer from a device profile, over the crypto backend `B`.
///
/// The lifecycle is enforced by types: [`Self::finalize`] consumes the encryptor and returns the
/// [`FinishedCryptainer`], so a chunk after finalization, or a cryptainer written before it, does not compile:
///
/// ```compile_fail
/// # use wa_flightbox::{CryptainerEncryptor, NoPayloadSink, crypto_backend::CryptoBackend};
/// fn misuse<B: CryptoBackend>(mut encryptor: CryptainerEncryptor<B, NoPayloadSink>) {
///     let _finished = encryptor.finalize();
///     let _ = encryptor.encrypt_payload_chunk(b"too late"); // error[E0382]: borrow of moved value
/// }
/// ```
///
/// After a failed call, an encryptor refuses every operation with `ErrorKind::WrongState`. Dropping an encryptor
/// at any point wipes its secrets.
pub struct CryptainerEncryptor<B: CryptoBackend, S: OutputSink = NoPayloadSink> {
    format: ResolvedFormat,
    /// The cryptainer tree, in STARTED state
    cryptainer: Value,
    /// Of the payload cipher layers, in order: their symkeys only live in the cipher streams
    payload_cipher_algos: Vec<SymmetricCipherAlgo>,
    pipeline: PayloadEncryptionPipeline<B>,
    output: PayloadCiphertextOutput<S>,
    has_failed: bool,
}

/// Metadata goes at depth 2 of cryptainers and key structs: one level less than the CBOR nesting limit.
fn check_cryptainer_metadata(device_profile: &DeviceProfile, cryptainer_metadata: Option<&Value>) -> Result<()> {
    let Some(cryptainer_metadata) = cryptainer_metadata else {
        return Ok(());
    };
    if cryptainer_metadata.as_map().is_none() {
        return Err(Error::new(ErrorKind::InvalidProfile));
    }
    check_document_tree_constraints(
        cryptainer_metadata,
        device_profile.limits().max_cbor_nesting_depth().saturating_sub(1),
    )
}

fn check_options(options: &EncryptorOptions) -> Result<ResolvedFormat> {
    if options.payload_processing_slice_size < AES_BLOCK_SIZE
        || !options.payload_processing_slice_size.is_multiple_of(AES_BLOCK_SIZE)
    {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    options.document_format.resolve()
}

impl<B: CryptoBackend> CryptainerEncryptor<B, NoPayloadSink> {
    /// Step 1, for a cryptainer holding its payload ciphertext (inline location): the ciphertext accumulates in
    /// memory until finalization, so this suits small payloads.
    ///
    /// `cryptainer_metadata`, if any, must be a map without Extended JSON keyword maps. All the randomness of the
    /// cryptainer is drawn here from `hooks`, which are not kept. Errors: `ErrorKind::InvalidArgument` for
    /// invalid options, `ErrorKind::UnsupportedFeature` for a document format that is not built in,
    /// `ErrorKind::InvalidProfile` or `ErrorKind::NestingTooDeep` for unusable metadata (all before any random
    /// draw), then those of the random hook and of the crypto backend.
    pub fn create(
        device_profile: &DeviceProfile,
        cryptainer_metadata: Option<&Value>,
        options: &EncryptorOptions,
        hooks: &mut dyn PlatformHooks,
    ) -> Result<Self> {
        Self::create_with_output(
            device_profile,
            cryptainer_metadata,
            options,
            hooks,
            PayloadCiphertextOutput::Inline(Vec::new()),
        )
    }
}

impl<B: CryptoBackend, S: OutputSink> CryptainerEncryptor<B, S> {
    /// Step 1, for a cryptainer whose payload ciphertext is streamed to `payload_ciphertext_sink` (offloaded
    /// location), typically a file named after the cryptainer with
    /// [`OFFLOADED_PAYLOAD_SUFFIX`](crate::OFFLOADED_PAYLOAD_SUFFIX) appended: memory use does not depend on the
    /// payload size. See [`CryptainerEncryptor::create`] for the other parameters and the errors.
    pub fn create_offloaded(
        device_profile: &DeviceProfile,
        cryptainer_metadata: Option<&Value>,
        options: &EncryptorOptions,
        hooks: &mut dyn PlatformHooks,
        payload_ciphertext_sink: S,
    ) -> Result<Self> {
        Self::create_with_output(
            device_profile,
            cryptainer_metadata,
            options,
            hooks,
            PayloadCiphertextOutput::Offloaded(payload_ciphertext_sink),
        )
    }

    fn create_with_output(
        device_profile: &DeviceProfile,
        cryptainer_metadata: Option<&Value>,
        options: &EncryptorOptions,
        hooks: &mut dyn PlatformHooks,
        output: PayloadCiphertextOutput<S>,
    ) -> Result<Self> {
        let format = check_options(options)?;
        check_cryptainer_metadata(device_profile, cryptainer_metadata)?; // Before any key generation
        let is_offloaded = matches!(output, PayloadCiphertextOutput::Offloaded(_));
        let base = generate_cryptainer_base::<B>(hooks, device_profile, cryptainer_metadata, format, is_offloaded)?;
        let pipeline = PayloadEncryptionPipeline::start(&base.payload_symkeys, options.payload_processing_slice_size)?;
        let mut payload_cipher_algos = Vec::new();
        payload_cipher_algos
            .try_reserve_exact(base.payload_symkeys.len())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        payload_cipher_algos.extend(
            base.payload_symkeys
                .iter()
                .map(|payload_symkey| payload_symkey.cipher_algo),
        );
        // The payload symkeys are wiped here: the cipher streams hold what they need of them
        Ok(Self {
            format,
            cryptainer: base.cryptainer,
            payload_cipher_algos,
            pipeline,
            output,
            has_failed: false,
        })
    }

    /// Step 2: encrypt the next bytes of the payload, of any length (0 allowed), any number of times. With an
    /// offloaded location, the ciphertext available so far is written to the sink before returning.
    ///
    /// Errors: `ErrorKind::SinkWriteFailure` when the sink fails, `ErrorKind::OutOfMemory` when an inline
    /// ciphertext cannot grow, those of the crypto backend, and `ErrorKind::WrongState` after any failed call.
    pub fn encrypt_payload_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        if self.has_failed {
            return Err(Error::new(ErrorKind::WrongState));
        }
        let result = self.pipeline.encrypt_chunk(chunk, self.output.as_sink());
        self.has_failed = result.is_err();
        result
    }

    /// End of step 2 and step 3: flush the cipher streams, store the payload MACs and the inline ciphertext if
    /// any, and return the finished cryptainer. The cipher contexts and scratch buffers are released wiped.
    ///
    /// Errors: as [`Self::encrypt_payload_chunk`]. The encryptor is consumed in any case.
    pub fn finalize(mut self) -> Result<FinishedCryptainer> {
        if self.has_failed {
            return Err(Error::new(ErrorKind::WrongState));
        }
        self.pipeline.finalize(self.output.as_sink())?;
        let inline_ciphertext = match self.output {
            PayloadCiphertextOutput::Inline(inline_ciphertext) => Some(inline_ciphertext),
            PayloadCiphertextOutput::Offloaded(_) => None,
        };
        add_authentication_data(
            &mut self.cryptainer,
            self.payload_cipher_algos.iter().copied(),
            self.pipeline.tags(),
            inline_ciphertext,
        )?;
        Ok(FinishedCryptainer {
            format: self.format,
            cryptainer: self.cryptainer,
        })
    }
}

/// A cryptainer in FINISHED state, ready to be written.
#[derive(Debug)]
pub struct FinishedCryptainer {
    format: ResolvedFormat,
    cryptainer: Value,
}

impl FinishedCryptainer {
    /// Write the cryptainer to `cryptainer_sink`, in the document format chosen at creation. Errors:
    /// `ErrorKind::SinkWriteFailure` when the sink fails.
    pub fn write_cryptainer<W: OutputSink>(&self, cryptainer_sink: &mut W) -> Result<()> {
        serialize_to_sink(Node::Value(&self.cryptainer), self.format, cryptainer_sink)
    }

    /// The cryptainer tree.
    pub fn cryptainer(&self) -> &Value {
        &self.cryptainer
    }

    /// The document format of the cryptainer (never `DocumentFormat::BuildDefault`).
    pub fn document_format(&self) -> DocumentFormat {
        match self.format {
            ResolvedFormat::ExtendedJson => DocumentFormat::ExtendedJson,
            ResolvedFormat::Cbor => DocumentFormat::Cbor,
        }
    }
}

/// Create a cryptainer holding its payload ciphertext from a whole payload, and write it to `cryptainer_sink`:
/// steps 1 to 3 and the serialization in one call.
pub fn encrypt_payload_in_one_call<B: CryptoBackend, W: OutputSink>(
    device_profile: &DeviceProfile,
    cryptainer_metadata: Option<&Value>,
    options: &EncryptorOptions,
    hooks: &mut dyn PlatformHooks,
    payload: &[u8],
    cryptainer_sink: &mut W,
) -> Result<()> {
    let mut encryptor = CryptainerEncryptor::<B>::create(device_profile, cryptainer_metadata, options, hooks)?;
    encryptor.encrypt_payload_chunk(payload)?;
    encryptor.finalize()?.write_cryptainer(cryptainer_sink)
}
