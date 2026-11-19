// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! DHKEM(X25519, HKDF-SHA256) of RFC 9180 (KEM id 0x0020), encapsulation side: the KEM of ECIES_X25519.

use zeroize::Zeroizing;

use crate::crypto_backend::{CryptoBackend, X25519_KEY_SIZE};
use crate::error::{Error, ErrorKind, Result};
use crate::platform_hooks::PlatformHooks;
use crate::primitives::fill_random_bytes;
use crate::primitives::hpke_base_mode_seal::{HPKE_SHARED_SECRET_SIZE, hpke_labeled_expand, hpke_labeled_extract};

/// "KEM" || I2OSP(0x0020, 2)
const KEM_SUITE_ID: [u8; 5] = *b"KEM\x00\x20";

/// Draw a 32-byte ephemeral scalar from the random hook, write its public key to `enc` (32 bytes) and return the
/// shared secret with the 32-byte `public_key`. An all-zero Diffie-Hellman output (low-order public key) is
/// `ErrorKind::KeyConstraintViolation`.
pub(crate) fn encapsulate<B: CryptoBackend>(
    hooks: &mut dyn PlatformHooks,
    public_key: &[u8],
    enc: &mut [u8],
) -> Result<Zeroizing<[u8; HPKE_SHARED_SECRET_SIZE]>> {
    let public_key: &[u8; X25519_KEY_SIZE] = public_key
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidArgument))?;
    if enc.len() != X25519_KEY_SIZE {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let mut ephemeral_scalar = Zeroizing::new([0u8; X25519_KEY_SIZE]);
    fill_random_bytes(hooks, &mut ephemeral_scalar[..])?;
    let ephemeral_public_key = B::x25519_compute_public_key(&ephemeral_scalar)?;
    enc.copy_from_slice(&ephemeral_public_key);
    let dh = Zeroizing::new(B::x25519_compute_shared_secret(&ephemeral_scalar, public_key)?);
    drop(ephemeral_scalar);
    // Without early exit, although the outcome is public as soon as it is an error
    if dh.iter().fold(0u8, |accumulator, byte| accumulator | byte) == 0 {
        return Err(Error::new(ErrorKind::KeyConstraintViolation));
    }
    // kem_context = enc || pkRm
    let mut kem_context = [0u8; 2 * X25519_KEY_SIZE];
    kem_context[..X25519_KEY_SIZE].copy_from_slice(&ephemeral_public_key);
    kem_context[X25519_KEY_SIZE..].copy_from_slice(public_key);
    let eae_prk = Zeroizing::new(hpke_labeled_extract::<B>(&KEM_SUITE_ID, &[], "eae_prk", &dh[..])?);
    let mut shared_secret = Zeroizing::new([0u8; HPKE_SHARED_SECRET_SIZE]);
    hpke_labeled_expand::<B>(
        &KEM_SUITE_ID,
        &eae_prk,
        "shared_secret",
        &kem_context,
        &mut shared_secret[..],
    )?;
    Ok(shared_secret)
}
