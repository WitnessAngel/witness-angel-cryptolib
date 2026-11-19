// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Robustness checked with a test global allocator, over the whole workflow (profile loading, creation with
//! metadata, chunks, finalization, cryptainer writing):
//!
//! - secrets: no released block holds a registered secret pattern (the first 16 bytes of every random output of
//!   32 bytes or more: symkeys, Shamir coefficients, X25519 scalars, ML-KEM coins, OAEP seeds; raw, and as the
//!   base64 text that Extended JSON would hold), after finalization and after aborted creations;
//! - the secret byte buffer leaves nothing behind when it grows or is dropped;
//! - an inline ciphertext beyond what the allocator grants gives the out-of-memory error;
//! - the peak allocation of offloaded encryptions does not depend on the payload size nor on the chunking.
//!
//! The allocator only tracks the thread that asked for it, so the tests of this binary can run in parallel. This
//! file is the only one of the core crate's tests with `unsafe` code: the allocator itself.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use wa_flightbox::{
    CryptainerEncryptor, DeviceProfile, DocumentFormat, EncryptorLimits, EncryptorOptions, ErrorKind, Map, OutputSink,
    SinkError, Value, internals,
};
use wa_flightbox_backend_conformance::test_support::{
    DeterministicHooks, device_profile_sample, enabled_document_formats,
};
use wa_flightbox_backend_rustcrypto::RustCryptoBackend;

thread_local! {
    /// Bytes currently allocated by this thread, since tracking started
    static LIVE_BYTES: Cell<isize> = const { Cell::new(0) };
    static PEAK_LIVE_BYTES: Cell<isize> = const { Cell::new(0) };
    static IS_TRACKING: Cell<bool> = const { Cell::new(false) };
    /// Allocations making the live bytes exceed this are refused
    static LIVE_BYTES_LIMIT: Cell<isize> = const { Cell::new(isize::MAX) };
    static REFUSED_ALLOCATION_COUNT: Cell<usize> = const { Cell::new(0) };
    /// Patterns searched in every released block
    static SECRET_PATTERNS: Cell<&'static [Vec<u8>]> = const { Cell::new(&[]) };
    static RELEASED_SECRET_COUNT: Cell<usize> = const { Cell::new(0) };
    static SCANNED_BLOCK_COUNT: Cell<usize> = const { Cell::new(0) };
}

struct TrackingAllocator;

fn contains(block: &[u8], pattern: &[u8]) -> bool {
    !pattern.is_empty() && block.windows(pattern.len()).any(|window| window == pattern)
}

// SAFETY: every call is forwarded to the system allocator with the layout it was given; the bookkeeping only
// touches thread-local cells without destructors, and reads the block being released, which is still valid.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if IS_TRACKING.get() {
            let live_bytes = LIVE_BYTES.get() + layout.size() as isize;
            if live_bytes > LIVE_BYTES_LIMIT.get() {
                REFUSED_ALLOCATION_COUNT.set(REFUSED_ALLOCATION_COUNT.get() + 1);
                return core::ptr::null_mut();
            }
            LIVE_BYTES.set(live_bytes);
            PEAK_LIVE_BYTES.set(PEAK_LIVE_BYTES.get().max(live_bytes));
            // Zeroed blocks: a block released later only holds what was written to it during the tracked run,
            // not what an earlier run left in the heap (the recording runs of the tests do not wipe)
            return unsafe { System.alloc_zeroed(layout) };
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if IS_TRACKING.get() {
            LIVE_BYTES.set(LIVE_BYTES.get() - layout.size() as isize);
            let patterns = SECRET_PATTERNS.get();
            if !patterns.is_empty() {
                let block = unsafe { core::slice::from_raw_parts(pointer, layout.size()) };
                SCANNED_BLOCK_COUNT.set(SCANNED_BLOCK_COUNT.get() + 1);
                if patterns.iter().any(|pattern| contains(block, pattern)) {
                    RELEASED_SECRET_COUNT.set(RELEASED_SECRET_COUNT.get() + 1);
                }
            }
        }
        unsafe { System.dealloc(pointer, layout) }
    }
    // The default `realloc` allocates, copies and releases through the two functions above: a block moved by a
    // growing `Vec` is scanned like any released block
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

/// Run `workload` with the allocations of this thread tracked: what it returned, the peak of live bytes above
/// the level at the start, and the numbers of released blocks holding a secret pattern and of scanned blocks.
fn track<T>(
    patterns: &'static [Vec<u8>],
    live_bytes_limit: Option<isize>,
    workload: impl FnOnce() -> T,
) -> (T, Tracking) {
    LIVE_BYTES.set(0);
    PEAK_LIVE_BYTES.set(0);
    REFUSED_ALLOCATION_COUNT.set(0);
    RELEASED_SECRET_COUNT.set(0);
    SCANNED_BLOCK_COUNT.set(0);
    SECRET_PATTERNS.set(patterns);
    LIVE_BYTES_LIMIT.set(live_bytes_limit.unwrap_or(isize::MAX));
    IS_TRACKING.set(true);
    let result = workload();
    IS_TRACKING.set(false);
    LIVE_BYTES_LIMIT.set(isize::MAX);
    SECRET_PATTERNS.set(&[]);
    let tracking = Tracking {
        peak_live_bytes: PEAK_LIVE_BYTES.get(),
        leaked_bytes: LIVE_BYTES.get(),
        refused_allocation_count: REFUSED_ALLOCATION_COUNT.get(),
        released_secret_count: RELEASED_SECRET_COUNT.get(),
        scanned_block_count: SCANNED_BLOCK_COUNT.get(),
    };
    (result, tracking)
}

#[derive(Debug)]
struct Tracking {
    peak_live_bytes: isize,
    leaked_bytes: isize,
    refused_allocation_count: usize,
    released_secret_count: usize,
    scanned_block_count: usize,
}

fn encode_base64(bytes: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    assert!(bytes.len().is_multiple_of(3));
    bytes
        .chunks(3)
        .flat_map(|triple| {
            let group = u32::from(triple[0]) << 16 | u32::from(triple[1]) << 8 | u32::from(triple[2]);
            [18, 12, 6, 0].map(|shift| ALPHABET[(group >> shift) as usize & 63])
        })
        .collect()
}

/// The patterns of the secrets of a run: for every random output of 32 bytes or more, its first 16 bytes, and
/// the base64 text of its first 15 bytes (a secret serialized in Extended JSON starts its own base64 string).
fn secret_patterns_of(recorded_outputs: &[Vec<u8>]) -> &'static [Vec<u8>] {
    let mut patterns = Vec::new();
    for output in recorded_outputs.iter().filter(|output| output.len() >= 32) {
        patterns.push(output[..16].to_vec());
        patterns.push(encode_base64(&output[..15]));
    }
    assert!(!patterns.is_empty());
    Box::leak(patterns.into_boxed_slice())
}

fn sample_metadata() -> Value {
    Value::Map(Map::from_entries([("device_id", Value::from("fb-07")), ("sequence", Value::from(42i64))]).unwrap())
}

/// A sink counting what it receives, without allocating.
#[derive(Default)]
struct CountingSink {
    byte_count: usize,
    write_count: usize,
    largest_write: usize,
}

impl OutputSink for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), SinkError> {
        self.byte_count += bytes.len();
        self.write_count += 1;
        self.largest_write = self.largest_write.max(bytes.len());
        Ok(())
    }
}

/// The whole workflow. `failing_random_call_index` aborts the creation at that random call.
fn run_workflow(
    hooks: &mut DeterministicHooks,
    profile_cbor: &[u8],
    format: DocumentFormat,
    is_offloaded: bool,
    payload: &[u8],
) -> wa_flightbox::Result<usize> {
    let device_profile = DeviceProfile::load_from_cbor(profile_cbor, &EncryptorLimits::default())?;
    let metadata = sample_metadata();
    let options = EncryptorOptions {
        document_format: format,
        ..EncryptorOptions::default()
    };
    let mut cryptainer_sink = CountingSink::default();
    if is_offloaded {
        let mut payload_sink = CountingSink::default();
        let mut encryptor = CryptainerEncryptor::<RustCryptoBackend, _>::create_offloaded(
            &device_profile,
            Some(&metadata),
            &options,
            hooks,
            &mut payload_sink,
        )?;
        for chunk in payload.chunks(3000) {
            encryptor.encrypt_payload_chunk(chunk)?;
        }
        encryptor.finalize()?.write_cryptainer(&mut cryptainer_sink)?;
    } else {
        let mut encryptor =
            CryptainerEncryptor::<RustCryptoBackend>::create(&device_profile, Some(&metadata), &options, hooks)?;
        for chunk in payload.chunks(3000) {
            encryptor.encrypt_payload_chunk(chunk)?;
        }
        encryptor.finalize()?.write_cryptainer(&mut cryptainer_sink)?;
    }
    Ok(cryptainer_sink.byte_count)
}

const SAMPLE_NAMES: [&str; 3] = [
    "nested_all_layer_kinds",
    "minimal_rsa_authenticator",
    "corpus_2026_cbor_key_ciphertexts_04",
];

#[test]
fn the_scanning_allocator_sees_unwiped_secrets() {
    // The check of the checker: a plain vector released with a pattern inside is noticed, a wiped one is not
    let patterns: &'static [Vec<u8>] = Box::leak(vec![b"0123456789abcdef".to_vec()].into_boxed_slice());
    let ((), tracking) = track(patterns, None, || {
        let mut plain = Vec::with_capacity(100);
        plain.extend_from_slice(b"....0123456789abcdef....");
        drop(plain);
    });
    assert_eq!((tracking.released_secret_count, tracking.scanned_block_count), (1, 1));
    assert_eq!((tracking.peak_live_bytes, tracking.leaked_bytes), (100, 0));

    // A growing vector leaves its old block behind
    let ((), tracking) = track(patterns, None, || {
        let mut growing = Vec::with_capacity(16);
        growing.extend_from_slice(b"0123456789abcdef");
        growing.extend_from_slice(&[0; 1000]);
        growing.fill(0);
    });
    assert_eq!(tracking.released_secret_count, 1, "{tracking:?}");

    let ((), tracking) = track(patterns, None, || {
        let mut wiped = b"....0123456789abcdef....".to_vec();
        wiped.fill(0);
    });
    assert_eq!((tracking.released_secret_count, tracking.scanned_block_count), (0, 1));

    // Refusals beyond the limit
    let (is_refused, tracking) = track(&[], Some(1000), || {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.try_reserve_exact(500).unwrap();
        let mut more: Vec<u8> = Vec::new();
        more.try_reserve_exact(501).is_err()
    });
    assert!(is_refused);
    assert_eq!(tracking.refused_allocation_count, 1);
}

#[test]
fn the_secret_byte_buffer_leaves_nothing_behind() {
    let secret: Vec<u8> = (0..5000u32).map(|index| (index * 31 + 7) as u8).collect();
    let patterns: &'static [Vec<u8>] = Box::leak(
        vec![
            secret[..16].to_vec(),
            secret[2000..2016].to_vec(),
            secret[4984..].to_vec(),
        ]
        .into_boxed_slice(),
    );
    // Many small pieces (the buffer grows a dozen times), then one large piece
    let small_pieces: Vec<&[u8]> = secret.chunks(7).collect();
    for pieces in [small_pieces.as_slice(), &[&secret[..]], &[&secret[..10], &secret[10..]]] {
        let (length, tracking) = track(patterns, None, || {
            internals::fill_and_drop_secret_byte_buffer(pieces).unwrap()
        });
        assert_eq!(length, secret.len());
        assert!(tracking.scanned_block_count >= 1, "{tracking:?}");
        assert_eq!(tracking.released_secret_count, 0, "{tracking:?}");
        assert_eq!(tracking.leaked_bytes, 0);
    }
    // The serializations of secrets go through such buffers
    for format in enabled_document_formats() {
        let (length, tracking) = track(patterns, None, || {
            let serialized = internals::serialize_key_struct(format, &secret, None).unwrap();
            let length = serialized.len();
            let mut serialized = serialized; // The copy handed to the test is wiped by the test
            serialized.fill(0);
            length
        });
        assert!(length > secret.len());
        assert_eq!(tracking.released_secret_count, 0, "{format:?}: {tracking:?}");
    }
}

#[test]
fn no_released_block_holds_a_secret_after_finalization() {
    let payload: Vec<u8> = (0..10000u32).map(|index| index as u8).collect();
    for sample_name in SAMPLE_NAMES {
        let profile_cbor = device_profile_sample(sample_name);
        for format in enabled_document_formats() {
            for is_offloaded in [false, true] {
                // A first run records the random outputs; the same run is then replayed under the scanner
                let mut hooks = DeterministicHooks::new(90);
                hooks.recorded_outputs = Some(Vec::new());
                let expected_length = run_workflow(&mut hooks, &profile_cbor, format, is_offloaded, &payload).unwrap();
                let patterns = secret_patterns_of(hooks.recorded_outputs.as_deref().unwrap());

                let mut hooks = DeterministicHooks::new(90);
                let (result, tracking) = track(patterns, None, || {
                    run_workflow(&mut hooks, &profile_cbor, format, is_offloaded, &payload)
                });
                let context = format!("{sample_name}, {format:?}, offloaded: {is_offloaded}: {tracking:?}");
                assert_eq!(result.unwrap(), expected_length, "{context}");
                assert!(tracking.scanned_block_count > 20, "{context}");
                assert_eq!(tracking.released_secret_count, 0, "{context}");
                assert_eq!(tracking.leaked_bytes, 0, "{context}");
            }
        }
    }
}

#[test]
fn no_released_block_holds_a_secret_after_an_aborted_creation() {
    for sample_name in SAMPLE_NAMES {
        let profile_cbor = device_profile_sample(sample_name);
        for format in enabled_document_formats() {
            let mut hooks = DeterministicHooks::new(91);
            hooks.recorded_outputs = Some(Vec::new());
            run_workflow(&mut hooks, &profile_cbor, format, true, b"payload").unwrap();
            let patterns = secret_patterns_of(hooks.recorded_outputs.as_deref().unwrap());
            let call_count = hooks.random_call_count;

            // The random hook fails at each of its calls in turn: the secrets drawn before are wiped
            for failing_call_index in 0..call_count {
                let mut hooks = DeterministicHooks::new(91);
                hooks.failing_random_call_index = Some(failing_call_index);
                let (result, tracking) = track(patterns, None, || {
                    run_workflow(&mut hooks, &profile_cbor, format, true, b"payload")
                });
                let context = format!("{sample_name}, {format:?}, failing call {failing_call_index}: {tracking:?}");
                assert_eq!(result.unwrap_err().kind(), ErrorKind::RandomnessFailure, "{context}");
                assert_eq!(tracking.released_secret_count, 0, "{context}");
                assert_eq!(tracking.leaked_bytes, 0, "{context}");
            }

            // An encryptor dropped before finalization, with payload inside its cipher streams
            let mut hooks = DeterministicHooks::new(91);
            let ((), tracking) = track(patterns, None, || {
                let device_profile = DeviceProfile::load_from_cbor(&profile_cbor, &EncryptorLimits::default()).unwrap();
                let options = EncryptorOptions {
                    document_format: format,
                    ..EncryptorOptions::default()
                };
                let mut encryptor =
                    CryptainerEncryptor::<RustCryptoBackend>::create(&device_profile, None, &options, &mut hooks)
                        .unwrap();
                encryptor.encrypt_payload_chunk(&[0x5a; 5001]).unwrap();
            });
            assert_eq!(
                tracking.released_secret_count, 0,
                "{sample_name}, {format:?}, dropped: {tracking:?}"
            );
            assert_eq!(tracking.leaked_bytes, 0);
        }
    }
}

#[test]
fn an_inline_ciphertext_beyond_the_allocator_limit_is_an_out_of_memory_error() {
    let chunk = [0x5au8; 4096];
    for sample_name in ["nested_all_layer_kinds", "minimal_rsa_authenticator"] {
        let device_profile =
            DeviceProfile::load_from_cbor(&device_profile_sample(sample_name), &EncryptorLimits::default()).unwrap();
        let mut hooks = DeterministicHooks::new(92);
        let mut encryptor = CryptainerEncryptor::<RustCryptoBackend>::create(
            &device_profile,
            None,
            &EncryptorOptions::default(),
            &mut hooks,
        )
        .unwrap();
        // 256 KiB more than what the encryptor holds now: the inline ciphertext cannot reach 1 MiB
        let (outcome, tracking) = track(&[], Some(256 * 1024), || {
            for chunk_index in 0..256 {
                if let Err(error) = encryptor.encrypt_payload_chunk(&chunk) {
                    return Some((
                        chunk_index,
                        error.kind(),
                        encryptor.encrypt_payload_chunk(&chunk).unwrap_err().kind(),
                    ));
                }
            }
            None
        });
        let (chunk_index, first_kind, next_kind) = outcome.expect("the allocator limit was not reached");
        assert_eq!(first_kind, ErrorKind::OutOfMemory, "{sample_name}");
        assert_eq!(next_kind, ErrorKind::WrongState);
        assert!(tracking.refused_allocation_count >= 1);
        assert!(
            (16..64).contains(&chunk_index),
            "{sample_name}: refused at chunk {chunk_index}"
        );
        assert_eq!(
            encryptor.finalize().err().map(|error| error.kind()),
            Some(ErrorKind::WrongState)
        );
    }
}

/// The peak of live bytes of an offloaded encryption, from the creation of the encryptor to the written
/// cryptainer, above what the loaded profile and the metadata hold.
fn measure_offloaded_peak(
    device_profile: &DeviceProfile,
    format: DocumentFormat,
    payload_length: usize,
    chunk_length: usize,
) -> isize {
    let payload = vec![0xa5u8; payload_length];
    let metadata = sample_metadata();
    let mut hooks = DeterministicHooks::new(93);
    let options = EncryptorOptions {
        document_format: format,
        ..EncryptorOptions::default()
    };
    let (byte_counts, tracking) = track(&[], None, || {
        let mut payload_sink = CountingSink::default();
        let mut cryptainer_sink = CountingSink::default();
        let mut encryptor = CryptainerEncryptor::<RustCryptoBackend, _>::create_offloaded(
            device_profile,
            Some(&metadata),
            &options,
            &mut hooks,
            &mut payload_sink,
        )
        .unwrap();
        for chunk in payload.chunks(chunk_length) {
            encryptor.encrypt_payload_chunk(chunk).unwrap();
        }
        encryptor
            .finalize()
            .unwrap()
            .write_cryptainer(&mut cryptainer_sink)
            .unwrap();
        (
            payload_sink.byte_count,
            payload_sink.largest_write,
            cryptainer_sink.byte_count,
        )
    });
    let (payload_byte_count, largest_payload_write, cryptainer_byte_count) = byte_counts;
    assert!(payload_byte_count >= payload_length && payload_byte_count <= payload_length + 32);
    assert!(
        largest_payload_write <= 4096 + 32,
        "the sink receives slices, not chunks"
    );
    assert!(cryptainer_byte_count > 100);
    assert_eq!(tracking.leaked_bytes, 0);
    tracking.peak_live_bytes
}

#[test]
fn the_peak_allocation_of_offloaded_encryptions_does_not_depend_on_the_payload() {
    const SMALL_FIXED_MARGIN: isize = 256;
    for sample_name in SAMPLE_NAMES {
        let device_profile =
            DeviceProfile::load_from_cbor(&device_profile_sample(sample_name), &EncryptorLimits::default()).unwrap();
        for format in enabled_document_formats() {
            let peaks: Vec<isize> = [
                (4096usize, 4096usize),
                (4096, usize::MAX),
                (1 << 20, 4096),
                (1 << 20, usize::MAX),
                (1 << 20, 100_000),
            ]
            .into_iter()
            .map(|(payload_length, chunk_length)| {
                measure_offloaded_peak(
                    &device_profile,
                    format,
                    payload_length,
                    chunk_length.min(payload_length),
                )
            })
            .collect();
            let (lowest, highest) = (*peaks.iter().min().unwrap(), *peaks.iter().max().unwrap());
            // Reported with `cargo test -- --nocapture`, for the README
            println!("heap peak of offloaded encryptions, {sample_name}, {format:?}: {highest} bytes");
            assert!(
                highest - lowest <= SMALL_FIXED_MARGIN,
                "{sample_name}, {format:?}: peaks {peaks:?}"
            );
            // The peak is reached at creation, in the nested serializations of the key ciphertexts
            assert!(highest < 256 * 1024, "{sample_name}, {format:?}: peaks {peaks:?}");
        }
    }
}
