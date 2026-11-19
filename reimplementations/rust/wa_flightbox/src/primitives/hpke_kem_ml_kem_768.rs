// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! ML-KEM-768 as an HPKE KEM (KEM id 0x0041), encapsulation side: the KEM of the ML_KEM_768 key cipher. The
//! shared secret of FIPS 203 is used as is.

use zeroize::Zeroizing;

use crate::crypto_backend::{
    CryptoBackend, ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_COINS_SIZE, ML_KEM_768_PUBLIC_KEY_SIZE,
};
use crate::error::{Error, ErrorKind, Result};
use crate::platform_hooks::PlatformHooks;
use crate::primitives::fill_random_bytes;
use crate::primitives::hpke_base_mode_seal::HPKE_SHARED_SECRET_SIZE;

/// Draw the 32 bytes of encapsulation randomness from the random hook, write the 1088-byte ciphertext to `enc`
/// and return the shared secret with the 1184-byte `public_key`.
pub(crate) fn encapsulate<B: CryptoBackend>(
    hooks: &mut dyn PlatformHooks,
    public_key: &[u8],
    enc: &mut [u8],
) -> Result<Zeroizing<[u8; HPKE_SHARED_SECRET_SIZE]>> {
    let public_key: &[u8; ML_KEM_768_PUBLIC_KEY_SIZE] = public_key
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidArgument))?;
    let enc: &mut [u8; ML_KEM_768_CIPHERTEXT_SIZE] =
        enc.try_into().map_err(|_| Error::new(ErrorKind::InvalidArgument))?;
    let mut coins = Zeroizing::new([0u8; ML_KEM_768_COINS_SIZE]);
    fill_random_bytes(hooks, &mut coins[..])?;
    let mut shared_secret = Zeroizing::new([0u8; HPKE_SHARED_SECRET_SIZE]);
    B::ml_kem_768_encapsulate_derandomized(public_key, &coins, enc, &mut shared_secret)?;
    Ok(shared_secret)
}
