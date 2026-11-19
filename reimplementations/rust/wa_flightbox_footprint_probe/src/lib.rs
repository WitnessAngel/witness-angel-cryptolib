// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Bare-metal build check and code size probe of the flightbox encryptor: a static library for targets without an
//! operating system, whose single entry point loads a device profile and runs the whole encryptor API with the
//! RustCrypto backend. Building it proves that the core crate and its default backend need nothing from `std`;
//! linking it with `--gc-sections` from its entry point gives the flash footprint of an encryptor, the Rust
//! runtime pieces it needs included (see `build_and_test_all_backends.sh`).
//!
//! It is not firmware: its allocator is a small bump arena that never releases, and its random hook is a counter.
//! This is the only crate of the workspace, with the wolfCrypt backend, to contain `unsafe` code: a global
//! allocator, and an entry point taking raw pointers, cannot be written without it.
//!
//! On hosted targets the crate is empty, so that workspace-wide commands still build.

#![cfg_attr(target_os = "none", no_std)]
#![cfg(target_os = "none")]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use wa_flightbox::{
    CryptainerEncryptor, DeviceProfile, DocumentFormat, EncryptorLimits, EncryptorOptions, ErrorKind, OutputSink,
    PlatformHooks, RandomFailure, Result, SinkError, decode_document_from_cbor, encrypt_payload_in_one_call,
};
use wa_flightbox_backend_rustcrypto::RustCryptoBackend;

const ARENA_SIZE: usize = 32 * 1024;

/// A bump arena: enough for one run, nothing is ever released.
struct BumpAllocator {
    arena: UnsafeCell<[u8; ARENA_SIZE]>,
    used_length: AtomicUsize,
}

// SAFETY: the arena is only reached through `alloc`, which hands out disjoint ranges reserved by an atomic update.
unsafe impl Sync for BumpAllocator {}

// SAFETY: `alloc` returns null or a block of `layout.size()` bytes aligned to `layout.align()`, inside the arena
// and disjoint from every other block; `dealloc` does nothing, so blocks stay valid.
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = self.arena.get().cast::<u8>();
        let mut used_length = self.used_length.load(Ordering::Relaxed);
        loop {
            let padding = base.wrapping_add(used_length).align_offset(layout.align());
            let Some(end) = used_length
                .checked_add(padding)
                .and_then(|start| start.checked_add(layout.size()))
            else {
                return core::ptr::null_mut();
            };
            if end > ARENA_SIZE {
                return core::ptr::null_mut();
            }
            match self
                .used_length
                .compare_exchange_weak(used_length, end, Ordering::Relaxed, Ordering::Relaxed)
            {
                // SAFETY: `used_length + padding <= end <= ARENA_SIZE`, so the block is inside the arena
                Ok(_) => return unsafe { base.add(used_length + padding) },
                Err(current_length) => used_length = current_length,
            }
        }
    }

    unsafe fn dealloc(&self, _pointer: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator {
    arena: UnsafeCell::new([0; ARENA_SIZE]),
    used_length: AtomicUsize::new(0),
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Not random at all: a firmware gives its hardware generator here.
struct ProbeHooks {
    counter: u8,
}

impl PlatformHooks for ProbeHooks {
    fn fill_random(&mut self, buffer: &mut [u8]) -> core::result::Result<(), RandomFailure> {
        for byte in buffer {
            self.counter = self.counter.wrapping_add(1);
            *byte = self.counter;
        }
        Ok(())
    }
}

/// Discards what it receives, keeping a checksum so that the writers are not optimized out.
struct ProbeSink {
    checksum: u32,
}

impl OutputSink for ProbeSink {
    fn write(&mut self, bytes: &[u8]) -> core::result::Result<(), SinkError> {
        for byte in bytes {
            self.checksum = self.checksum.rotate_left(5) ^ u32::from(*byte);
        }
        Ok(())
    }
}

fn run(profile: &[u8], metadata: &[u8], payload: &[u8], use_cbor: bool) -> Result<u32> {
    let limits = EncryptorLimits::default();
    let device_profile = DeviceProfile::load_from_cbor(profile, &limits)?;
    let metadata = if metadata.is_empty() {
        None
    } else {
        Some(decode_document_from_cbor(metadata, &limits)?)
    };
    let options = EncryptorOptions {
        document_format: if use_cbor {
            DocumentFormat::Cbor
        } else {
            DocumentFormat::ExtendedJson
        },
        ..EncryptorOptions::default()
    };
    let mut hooks = ProbeHooks { counter: 0 };
    let mut payload_sink = ProbeSink { checksum: 0 };
    let mut cryptainer_sink = ProbeSink { checksum: 0 };

    // Offloaded payload ciphertext, fed in two chunks
    let (first_chunk, second_chunk) = payload.split_at(payload.len() / 2);
    let mut encryptor = CryptainerEncryptor::<RustCryptoBackend, _>::create_offloaded(
        &device_profile,
        metadata.as_ref(),
        &options,
        &mut hooks,
        &mut payload_sink,
    )?;
    encryptor.encrypt_payload_chunk(first_chunk)?;
    encryptor.encrypt_payload_chunk(second_chunk)?;
    encryptor.finalize()?.write_cryptainer(&mut cryptainer_sink)?;

    // Inline payload ciphertext, in one call
    encrypt_payload_in_one_call::<RustCryptoBackend, _>(
        &device_profile,
        metadata.as_ref(),
        &options,
        &mut hooks,
        payload,
        &mut cryptainer_sink,
    )?;
    Ok(payload_sink.checksum ^ cryptainer_sink.checksum)
}

/// Load the device profile and create two cryptainers of the payload, offloaded then inline, in WA-CBOR when
/// `use_cbor` is not 0, else in Extended JSON. Returns a checksum of the outputs, or 0xffffff00 plus the position
/// of the error kind in `ErrorKind::ALL`.
///
/// # Safety
///
/// Each pointer must be valid for reads of the length that follows it, or its length must be 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wa_flightbox_footprint_probe_run(
    profile: *const u8,
    profile_length: usize,
    metadata: *const u8,
    metadata_length: usize,
    payload: *const u8,
    payload_length: usize,
    use_cbor: u32,
) -> u32 {
    // SAFETY: the caller guarantees that a non-empty range is valid for reads
    let as_slice = |pointer: *const u8, length: usize| -> &[u8] {
        if length == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(pointer, length) }
        }
    };
    let result = run(
        as_slice(profile, profile_length),
        as_slice(metadata, metadata_length),
        as_slice(payload, payload_length),
        use_cbor != 0,
    );
    match result {
        Ok(checksum) => checksum,
        Err(error) => {
            let position = ErrorKind::ALL
                .iter()
                .position(|kind| *kind == error.kind())
                .unwrap_or(0xff);
            0xffff_ff00 | u32::try_from(position).unwrap_or(0xff)
        }
    }
}
