// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Safe wrappers over the wolfCrypt functions of the adapter: the only module of the crate with `unsafe` code.
//!
//! Every wrapper is sound for any argument: lengths are checked here before a pointer is handed to wolfCrypt,
//! and lengths beyond what wolfCrypt's 32-bit sizes hold are split into chunks. wolfCrypt structures live in heap
//! blocks that never move, are freed with their wolfCrypt function, then wiped.

#![allow(unsafe_code)]

use alloc::boxed::Box;
use core::ffi::c_int;
use core::mem::{MaybeUninit, size_of};
use core::ptr;

use zeroize::Zeroize;

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    missing_docs,
    unreachable_pub,
    unsafe_op_in_unsafe_fn,
    clippy::all
)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/wolfcrypt_bindings.rs"));
}

/// A wolfCrypt function failed, or was given lengths it cannot take.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WolfCryptFailure;

type FfiResult<T> = Result<T, WolfCryptFailure>;

/// wolfCrypt takes 32-bit lengths: longer inputs are processed in chunks (a multiple of every block size).
const MAXIMUM_CHUNK_LENGTH: usize = 0x4000_0000;

/// The largest RSA modulus that the wolfCrypt build computes with, in bytes.
pub(crate) const MAXIMUM_RSA_MODULUS_LENGTH: usize = bindings::WA_WOLFCRYPT_SP_INT_BITS as usize / 8;

const AES_BLOCK_SIZE: usize = 16;

fn check(result: c_int) -> FfiResult<()> {
    if result == 0 { Ok(()) } else { Err(WolfCryptFailure) }
}

/// The length as wolfCrypt takes it. Callers pass chunks of `MAXIMUM_CHUNK_LENGTH` at most.
fn word32_length(length: usize) -> FfiResult<u32> {
    u32::try_from(length).map_err(|_| WolfCryptFailure)
}

/// A wolfCrypt structure in its own heap block, zero-filled at creation and wiped when dropped. The block never
/// moves, whatever wolfCrypt keeps as pointers into it.
struct WipedBox<T> {
    content: Box<MaybeUninit<T>>,
}

impl<T> WipedBox<T> {
    fn new_zeroed() -> Self {
        let mut content = Box::<T>::new_uninit();
        // SAFETY: the block is valid for writes of one T
        unsafe { ptr::write_bytes(content.as_mut_ptr(), 0, 1) };
        Self { content }
    }

    fn as_mut_ptr(&mut self) -> *mut T {
        self.content.as_mut_ptr()
    }

    fn as_ptr(&self) -> *const T {
        self.content.as_ptr()
    }
}

impl<T> Drop for WipedBox<T> {
    fn drop(&mut self) {
        // SAFETY: the block is valid for writes of size_of::<T>() bytes, and any byte is a valid u8
        let bytes = unsafe { core::slice::from_raw_parts_mut(self.content.as_mut_ptr().cast::<u8>(), size_of::<T>()) };
        bytes.zeroize();
    }
}

// AES-256 //

/// An AES-256 encryption key schedule.
pub(crate) struct Aes256Context {
    aes: WipedBox<bindings::Aes>,
}

impl Aes256Context {
    pub(crate) fn new(key: &[u8; 32]) -> FfiResult<Self> {
        let mut aes = WipedBox::<bindings::Aes>::new_zeroed();
        // SAFETY: `aes` points to a zero-filled Aes, which wc_AesInit initializes
        check(unsafe {
            bindings::wc_AesInit(
                aes.as_mut_ptr(),
                ptr::null_mut(),
                bindings::WA_WOLFCRYPT_INVALID_DEVID as c_int,
            )
        })?;
        // From here on, dropping the context frees the Aes
        let mut context = Self { aes };
        // SAFETY: the Aes is initialized, and `key` is valid for reads of its 32 bytes
        check(unsafe {
            bindings::wc_AesSetKey(
                context.aes.as_mut_ptr(),
                key.as_ptr(),
                32,
                ptr::null(),
                bindings::WA_WOLFCRYPT_AES_ENCRYPTION as c_int,
            )
        })?;
        Ok(context)
    }

    /// CBC or CTR encryption of whole blocks. `aes->reg` is the CBC chaining value and the CTR counter alike: it
    /// is loaded before the call and read back after it. With whole blocks, no CTR keystream is ever left over.
    fn encrypt_blocks(
        &mut self,
        register: &mut [u8; AES_BLOCK_SIZE],
        input: &[u8],
        output: &mut [u8],
        use_counter_mode: bool,
    ) -> FfiResult<()> {
        if input.len() != output.len() || !input.len().is_multiple_of(AES_BLOCK_SIZE) {
            return Err(WolfCryptFailure);
        }
        if input.is_empty() {
            return Ok(());
        }
        let aes = self.aes.as_mut_ptr();
        // SAFETY: the Aes is initialized, and `register` is valid for reads of a block. wc_AesSetIV also discards
        // any leftover keystream.
        check(unsafe { bindings::wc_AesSetIV(aes, register.as_ptr()) })?;
        for (input_chunk, output_chunk) in input
            .chunks(MAXIMUM_CHUNK_LENGTH)
            .zip(output.chunks_mut(MAXIMUM_CHUNK_LENGTH))
        {
            let chunk_length = word32_length(input_chunk.len())?;
            // SAFETY: both chunks are valid for `chunk_length` bytes, and do not overlap (distinct borrows)
            check(unsafe {
                if use_counter_mode {
                    bindings::wc_AesCtrEncrypt(aes, output_chunk.as_mut_ptr(), input_chunk.as_ptr(), chunk_length)
                } else {
                    bindings::wc_AesCbcEncrypt(aes, output_chunk.as_mut_ptr(), input_chunk.as_ptr(), chunk_length)
                }
            })?;
        }
        // SAFETY: `reg` holds a block (16 bytes as 32-bit words), read as bytes into the 16 bytes of `register`
        unsafe {
            ptr::copy_nonoverlapping(
                ptr::addr_of!((*aes).reg).cast::<u8>(),
                register.as_mut_ptr(),
                AES_BLOCK_SIZE,
            );
        }
        Ok(())
    }

    pub(crate) fn encrypt_cbc_blocks(
        &mut self,
        chaining_value: &mut [u8; AES_BLOCK_SIZE],
        input: &[u8],
        output: &mut [u8],
    ) -> FfiResult<()> {
        self.encrypt_blocks(chaining_value, input, output, false)
    }

    /// The counter is incremented as a 128-bit big-endian integer by wolfCrypt.
    pub(crate) fn encrypt_ctr_blocks(
        &mut self,
        counter_block: &mut [u8; AES_BLOCK_SIZE],
        input: &[u8],
        output: &mut [u8],
    ) -> FfiResult<()> {
        self.encrypt_blocks(counter_block, input, output, true)
    }
}

impl Drop for Aes256Context {
    fn drop(&mut self) {
        // SAFETY: the Aes was initialized by wc_AesInit; the block is wiped afterwards by WipedBox
        unsafe { bindings::wc_AesFree(self.aes.as_mut_ptr()) };
    }
}

// CHACHA20 AND POLY1305 //

/// A ChaCha20 keystream and a Poly1305 accumulator: the two halves of RFC 8439, composed by the caller.
pub(crate) struct ChaCha20Poly1305Context {
    chacha: WipedBox<bindings::ChaCha>,
    poly1305: WipedBox<bindings::Poly1305>,
}

impl ChaCha20Poly1305Context {
    /// The Poly1305 key is taken from the keystream block of counter 0, and the keystream is left at counter 1.
    pub(crate) fn new(key: &[u8; 32], nonce: &[u8; 12]) -> FfiResult<Self> {
        let mut context = Self {
            chacha: WipedBox::new_zeroed(),
            poly1305: WipedBox::new_zeroed(),
        };
        let chacha = context.chacha.as_mut_ptr();
        let mut poly1305_key = [0u8; 32];
        // One pointer for both the input and the output of the in-place keystream call: a shared borrow taken
        // beside it would be invalidated by the first write
        let poly1305_key_pointer = poly1305_key.as_mut_ptr();
        // SAFETY: the structures are zero-filled blocks that these functions initialize; `key`, `nonce` and
        // `poly1305_key` are valid for the lengths given. wc_Chacha_Process works in place.
        let result = unsafe {
            check(bindings::wc_Chacha_SetKey(chacha, key.as_ptr(), 32))
                .and_then(|()| check(bindings::wc_Chacha_SetIV(chacha, nonce.as_ptr(), 0)))
                .and_then(|()| {
                    check(bindings::wc_Chacha_Process(
                        chacha,
                        poly1305_key_pointer,
                        poly1305_key_pointer.cast_const(),
                        32,
                    ))
                })
                .and_then(|()| {
                    check(bindings::wc_Poly1305SetKey(
                        context.poly1305.as_mut_ptr(),
                        poly1305_key_pointer.cast_const(),
                        32,
                    ))
                })
                // Also drops the rest of block 0
                .and_then(|()| check(bindings::wc_Chacha_SetIV(chacha, nonce.as_ptr(), 1)))
        };
        poly1305_key.zeroize();
        result.map(|()| context)
    }

    /// Add bytes to the authenticated data. wolfCrypt keeps incomplete Poly1305 blocks itself.
    pub(crate) fn authenticate(&mut self, bytes: &[u8]) -> FfiResult<()> {
        for chunk in bytes.chunks(MAXIMUM_CHUNK_LENGTH) {
            // SAFETY: the Poly1305 is initialized, and `chunk` is valid for reads of its length
            check(unsafe {
                bindings::wc_Poly1305Update(self.poly1305.as_mut_ptr(), chunk.as_ptr(), word32_length(chunk.len())?)
            })?;
        }
        Ok(())
    }

    /// Zero padding of the authenticated data up to a Poly1305 block, for a part of `length` bytes.
    pub(crate) fn pad_authenticated_data(&mut self, length: u64) -> FfiResult<()> {
        // SAFETY: the Poly1305 is initialized
        check(unsafe { bindings::wc_Poly1305_Pad(self.poly1305.as_mut_ptr(), (length % 16) as u32) })
    }

    /// Encrypt `input` into `output`, of the same length, and authenticate the ciphertext.
    pub(crate) fn encrypt(&mut self, input: &[u8], output: &mut [u8]) -> FfiResult<()> {
        if input.len() != output.len() {
            return Err(WolfCryptFailure);
        }
        for (input_chunk, output_chunk) in input
            .chunks(MAXIMUM_CHUNK_LENGTH)
            .zip(output.chunks_mut(MAXIMUM_CHUNK_LENGTH))
        {
            // SAFETY: the ChaCha is initialized, and both chunks are valid for the length given
            check(unsafe {
                bindings::wc_Chacha_Process(
                    self.chacha.as_mut_ptr(),
                    output_chunk.as_mut_ptr(),
                    input_chunk.as_ptr(),
                    word32_length(input_chunk.len())?,
                )
            })?;
            self.authenticate(output_chunk)?;
        }
        Ok(())
    }

    pub(crate) fn compute_tag(&mut self) -> FfiResult<[u8; 16]> {
        let mut tag = [0u8; 16];
        // SAFETY: the Poly1305 is initialized, and `tag` is valid for writes of the 16 bytes of a tag
        check(unsafe { bindings::wc_Poly1305Final(self.poly1305.as_mut_ptr(), tag.as_mut_ptr()) })?;
        Ok(tag)
    }
}

// HASHES AND HMAC //

pub(crate) fn compute_sha256(parts: &[&[u8]]) -> FfiResult<[u8; 32]> {
    let mut sha256 = WipedBox::<bindings::wc_Sha256>::new_zeroed();
    let mut digest = [0u8; 32];
    // SAFETY: the structure is a zero-filled block that wc_InitSha256_ex initializes
    check(unsafe {
        bindings::wc_InitSha256_ex(
            sha256.as_mut_ptr(),
            ptr::null_mut(),
            bindings::WA_WOLFCRYPT_INVALID_DEVID as c_int,
        )
    })?;
    let mut result = Ok(());
    for chunk in parts.iter().flat_map(|part| part.chunks(MAXIMUM_CHUNK_LENGTH)) {
        // SAFETY: the hash is initialized, and `chunk` is valid for reads of its length
        result = result.and_then(|()| {
            check(unsafe {
                bindings::wc_Sha256Update(sha256.as_mut_ptr(), chunk.as_ptr(), word32_length(chunk.len())?)
            })
        });
    }
    // SAFETY: the hash is initialized, and `digest` is valid for writes of the 32 bytes of a digest
    result = result.and_then(|()| check(unsafe { bindings::wc_Sha256Final(sha256.as_mut_ptr(), digest.as_mut_ptr()) }));
    // SAFETY: the hash was initialized by wc_InitSha256_ex
    unsafe { bindings::wc_Sha256Free(sha256.as_mut_ptr()) };
    result.map(|()| digest)
}

pub(crate) fn compute_sha512(parts: &[&[u8]]) -> FfiResult<[u8; 64]> {
    let mut sha512 = WipedBox::<bindings::wc_Sha512>::new_zeroed();
    let mut digest = [0u8; 64];
    // SAFETY: the structure is a zero-filled block that wc_InitSha512_ex initializes
    check(unsafe {
        bindings::wc_InitSha512_ex(
            sha512.as_mut_ptr(),
            ptr::null_mut(),
            bindings::WA_WOLFCRYPT_INVALID_DEVID as c_int,
        )
    })?;
    let mut result = Ok(());
    for chunk in parts.iter().flat_map(|part| part.chunks(MAXIMUM_CHUNK_LENGTH)) {
        // SAFETY: the hash is initialized, and `chunk` is valid for reads of its length
        result = result.and_then(|()| {
            check(unsafe {
                bindings::wc_Sha512Update(sha512.as_mut_ptr(), chunk.as_ptr(), word32_length(chunk.len())?)
            })
        });
    }
    // SAFETY: the hash is initialized, and `digest` is valid for writes of the 64 bytes of a digest
    result = result.and_then(|()| check(unsafe { bindings::wc_Sha512Final(sha512.as_mut_ptr(), digest.as_mut_ptr()) }));
    // SAFETY: the hash was initialized by wc_InitSha512_ex
    unsafe { bindings::wc_Sha512Free(sha512.as_mut_ptr()) };
    result.map(|()| digest)
}

pub(crate) fn compute_hmac_sha256(key: &[u8], parts: &[&[u8]]) -> FfiResult<[u8; 32]> {
    let key_length = word32_length(key.len())?;
    // Wiped when dropped: the pads hold the key
    let mut hmac = WipedBox::<bindings::Hmac>::new_zeroed();
    let mut mac = [0u8; 32];
    // SAFETY: the structure is a zero-filled block that wc_HmacInit initializes
    check(unsafe {
        bindings::wc_HmacInit(
            hmac.as_mut_ptr(),
            ptr::null_mut(),
            bindings::WA_WOLFCRYPT_INVALID_DEVID as c_int,
        )
    })?;
    // SAFETY: the Hmac is initialized, and `key` is valid for reads of its length (not read when empty)
    let mut result = check(unsafe {
        bindings::wc_HmacSetKey(
            hmac.as_mut_ptr(),
            bindings::WA_WOLFCRYPT_HMAC_SHA256 as c_int,
            key.as_ptr(),
            key_length,
        )
    });
    for chunk in parts.iter().flat_map(|part| part.chunks(MAXIMUM_CHUNK_LENGTH)) {
        // SAFETY: the Hmac is initialized, and `chunk` is valid for reads of its length
        result = result.and_then(|()| {
            check(unsafe { bindings::wc_HmacUpdate(hmac.as_mut_ptr(), chunk.as_ptr(), word32_length(chunk.len())?) })
        });
    }
    // SAFETY: the Hmac is initialized, and `mac` is valid for writes of the 32 bytes of a SHA-256 digest
    result = result.and_then(|()| check(unsafe { bindings::wc_HmacFinal(hmac.as_mut_ptr(), mac.as_mut_ptr()) }));
    // SAFETY: the Hmac was initialized by wc_HmacInit
    unsafe { bindings::wc_HmacFree(hmac.as_mut_ptr()) };
    result.map(|()| mac)
}

// X25519 //

/// The X25519 function on a scalar already clamped and a u-coordinate whose top bit is already masked, which is
/// what wc_curve25519_generic() takes.
pub(crate) fn x25519_multiply(clamped_scalar: &[u8; 32], masked_point: &[u8; 32]) -> FfiResult<[u8; 32]> {
    let mut output = [0u8; 32];
    // SAFETY: the three buffers are valid for the 32 bytes given as their sizes
    check(unsafe {
        bindings::wc_curve25519_generic(
            32,
            output.as_mut_ptr(),
            32,
            clamped_scalar.as_ptr(),
            32,
            masked_point.as_ptr(),
        )
    })?;
    Ok(output)
}

// RAW RSA //

/// `output = input^e mod n` on big-endian byte strings, `input` and `output` having the length of the modulus.
/// wc_RsaDirect() does not check that the input is below the modulus: the caller does.
pub(crate) fn rsa_compute_public_operation(
    modulus: &[u8],
    public_exponent: &[u8],
    input: &[u8],
    output: &mut [u8],
) -> FfiResult<()> {
    if modulus.is_empty()
        || modulus.len() > MAXIMUM_RSA_MODULUS_LENGTH
        || public_exponent.is_empty()
        || public_exponent.len() > modulus.len()
        || input.len() != modulus.len()
        || output.len() != modulus.len()
    {
        return Err(WolfCryptFailure);
    }
    let modulus_length = word32_length(modulus.len())?;
    let public_exponent_length = word32_length(public_exponent.len())?;
    let mut output_length = modulus_length;
    // Public material only, wiped all the same
    let mut rsa_key = WipedBox::<bindings::RsaKey>::new_zeroed();
    // SAFETY: the structure is a zero-filled block that wc_InitRsaKey_ex initializes
    check(unsafe {
        bindings::wc_InitRsaKey_ex(
            rsa_key.as_mut_ptr(),
            ptr::null_mut(),
            bindings::WA_WOLFCRYPT_INVALID_DEVID as c_int,
        )
    })?;
    // SAFETY: the key is initialized; every buffer is valid for the length given with it, `output` for writes of
    // `output_length` bytes; a null RNG is what the public operation takes
    let result = unsafe {
        check(bindings::wc_RsaPublicKeyDecodeRaw(
            modulus.as_ptr(),
            modulus_length,
            public_exponent.as_ptr(),
            public_exponent_length,
            rsa_key.as_mut_ptr(),
        ))
        .and_then(|()| {
            if i64::from(bindings::wc_RsaEncryptSize(rsa_key.as_ptr())) == i64::from(modulus_length) {
                Ok(())
            } else {
                Err(WolfCryptFailure)
            }
        })
        .and_then(|()| {
            let written_length = bindings::wc_RsaDirect(
                input.as_ptr(),
                modulus_length,
                output.as_mut_ptr(),
                &mut output_length,
                rsa_key.as_mut_ptr(),
                bindings::WA_WOLFCRYPT_RSA_PUBLIC_ENCRYPT as c_int,
                ptr::null_mut(),
            );
            if i64::from(written_length) == i64::from(modulus_length) && output_length == modulus_length {
                Ok(())
            } else {
                Err(WolfCryptFailure)
            }
        })
    };
    // SAFETY: the key was initialized by wc_InitRsaKey_ex
    unsafe { bindings::wc_FreeRsaKey(rsa_key.as_mut_ptr()) };
    result
}

// ML-KEM-768 //

pub(crate) fn ml_kem_768_encapsulate_derandomized(
    public_key: &[u8; 1184],
    coins: &[u8; 32],
    ciphertext: &mut [u8; 1088],
    shared_secret: &mut [u8; 32],
) -> FfiResult<()> {
    let mut ml_kem_key = WipedBox::<bindings::MlKemKey>::new_zeroed();
    // SAFETY: the structure is a zero-filled block that wc_MlKemKey_Init initializes
    check(unsafe {
        bindings::wc_MlKemKey_Init(
            ml_kem_key.as_mut_ptr(),
            bindings::WA_WOLFCRYPT_ML_KEM_768 as c_int,
            ptr::null_mut(),
            bindings::WA_WOLFCRYPT_INVALID_DEVID as c_int,
        )
    })?;
    // SAFETY: the key is initialized as an ML-KEM-768 key, whose encapsulation key, ciphertext, shared secret and
    // randomness have the sizes of these arrays
    let result = unsafe {
        check(bindings::wc_MlKemKey_DecodePublicKey(
            ml_kem_key.as_mut_ptr(),
            public_key.as_ptr(),
            1184,
        ))
        .and_then(|()| {
            check(bindings::wc_MlKemKey_EncapsulateWithRandom(
                ml_kem_key.as_mut_ptr(),
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
                coins.as_ptr(),
                32,
            ))
        })
    };
    // SAFETY: the key was initialized by wc_MlKemKey_Init
    unsafe { bindings::wc_MlKemKey_Free(ml_kem_key.as_mut_ptr()) };
    result
}
