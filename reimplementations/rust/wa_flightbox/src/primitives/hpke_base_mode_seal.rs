// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! HPKE (RFC 9180) Base mode, single-shot seal, KDF HKDF-SHA256 (0x0001), AEAD ChaCha20-Poly1305 (0x0003): the
//! ECIES_X25519 and ML_KEM_768 key ciphers of the encryptor specification, section 3.5. The KEM is a parameter;
//! info and AAD are empty in cryptainers, and only settable here for the RFC 9180 test vectors.

use zeroize::{Zeroize, Zeroizing};

use crate::crypto_backend::{
    AEAD_TAG_SIZE, CHACHA20_POLY1305_KEY_SIZE, CHACHA20_POLY1305_NONCE_SIZE, ChaCha20Poly1305Encryptor, CryptoBackend,
    ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_PUBLIC_KEY_SIZE, X25519_KEY_SIZE,
};
use crate::encoding::value_tree::{Map, Value};
use crate::error::{Error, ErrorKind, Result};
use crate::platform_hooks::PlatformHooks;
use crate::primitives::hkdf_sha256::{HKDF_SHA256_PRK_SIZE, hkdf_sha256_expand, hkdf_sha256_extract};
use crate::primitives::try_zeroed_vec;
use crate::primitives::{hpke_kem_dhkem_x25519, hpke_kem_ml_kem_768};

const HPKE_KDF_ID_HKDF_SHA256: u16 = 0x0001;
const HPKE_AEAD_ID_CHACHA20_POLY1305: u16 = 0x0003;
const HPKE_MODE_BASE: u8 = 0x00;
const HPKE_VERSION_LABEL: &[u8; 7] = b"HPKE-v1";
pub(crate) const HPKE_SHARED_SECRET_SIZE: usize = 32;
pub(crate) const HPKE_KEY_SIZE: usize = CHACHA20_POLY1305_KEY_SIZE;
pub(crate) const HPKE_NONCE_SIZE: usize = CHACHA20_POLY1305_NONCE_SIZE;

/// The KEMs of the two HPKE-based key ciphers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HpkeKem {
    /// DHKEM(X25519, HKDF-SHA256), KEM id 0x0020
    DhkemX25519,
    /// ML-KEM-768, KEM id 0x0041
    MlKem768,
}

impl HpkeKem {
    pub(crate) fn kem_id(self) -> u16 {
        match self {
            Self::DhkemX25519 => 0x0020,
            Self::MlKem768 => 0x0041,
        }
    }

    pub(crate) fn public_key_length(self) -> usize {
        match self {
            Self::DhkemX25519 => X25519_KEY_SIZE,
            Self::MlKem768 => ML_KEM_768_PUBLIC_KEY_SIZE,
        }
    }

    /// The length of the encapsulated key `enc`.
    pub(crate) fn enc_length(self) -> usize {
        match self {
            Self::DhkemX25519 => X25519_KEY_SIZE,
            Self::MlKem768 => ML_KEM_768_CIPHERTEXT_SIZE,
        }
    }

    /// Encapsulate to `public_key`, drawing the randomness from the random hook: writes `enc` and returns the
    /// shared secret.
    fn encapsulate<B: CryptoBackend>(
        self,
        hooks: &mut dyn PlatformHooks,
        public_key: &[u8],
        enc: &mut [u8],
    ) -> Result<Zeroizing<[u8; HPKE_SHARED_SECRET_SIZE]>> {
        match self {
            Self::DhkemX25519 => hpke_kem_dhkem_x25519::encapsulate::<B>(hooks, public_key, enc),
            Self::MlKem768 => hpke_kem_ml_kem_768::encapsulate::<B>(hooks, public_key, enc),
        }
    }
}

/// LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm)
pub(crate) fn hpke_labeled_extract<B: CryptoBackend>(
    suite_id: &[u8],
    salt: &[u8],
    label: &str,
    ikm: &[u8],
) -> Result<[u8; HKDF_SHA256_PRK_SIZE]> {
    hkdf_sha256_extract::<B>(salt, &[HPKE_VERSION_LABEL, suite_id, label.as_bytes(), ikm])
}

/// LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L)
pub(crate) fn hpke_labeled_expand<B: CryptoBackend>(
    suite_id: &[u8],
    prk: &[u8; HKDF_SHA256_PRK_SIZE],
    label: &str,
    info: &[u8],
    output: &mut [u8],
) -> Result<()> {
    let length = u16::try_from(output.len()).map_err(|_| Error::new(ErrorKind::InvalidArgument))?;
    hkdf_sha256_expand::<B>(
        prk,
        &[
            &length.to_be_bytes(),
            HPKE_VERSION_LABEL,
            suite_id,
            label.as_bytes(),
            info,
        ],
        output,
    )
}

/// The AEAD key and base nonce of a key schedule.
type HpkeKeyAndBaseNonce = (Zeroizing<[u8; HPKE_KEY_SIZE]>, Zeroizing<[u8; HPKE_NONCE_SIZE]>);

/// KeySchedule for mode Base (empty psk and psk_id): the AEAD key and base nonce.
fn hpke_base_mode_key_schedule<B: CryptoBackend>(
    kem_id: u16,
    shared_secret: &[u8; HPKE_SHARED_SECRET_SIZE],
    info: &[u8],
) -> Result<HpkeKeyAndBaseNonce> {
    let mut suite_id = *b"HPKE\0\0\0\0\0\0";
    suite_id[4..6].copy_from_slice(&kem_id.to_be_bytes());
    suite_id[6..8].copy_from_slice(&HPKE_KDF_ID_HKDF_SHA256.to_be_bytes());
    suite_id[8..10].copy_from_slice(&HPKE_AEAD_ID_CHACHA20_POLY1305.to_be_bytes());
    // key_schedule_context = mode || psk_id_hash || info_hash
    let mut key_schedule_context = [0u8; 1 + 2 * HKDF_SHA256_PRK_SIZE];
    key_schedule_context[0] = HPKE_MODE_BASE;
    key_schedule_context[1..1 + HKDF_SHA256_PRK_SIZE].copy_from_slice(&hpke_labeled_extract::<B>(
        &suite_id,
        &[],
        "psk_id_hash",
        &[],
    )?);
    key_schedule_context[1 + HKDF_SHA256_PRK_SIZE..].copy_from_slice(&hpke_labeled_extract::<B>(
        &suite_id,
        &[],
        "info_hash",
        info,
    )?);
    // secret = LabeledExtract(shared_secret, "secret", psk = "")
    let secret = Zeroizing::new(hpke_labeled_extract::<B>(&suite_id, shared_secret, "secret", &[])?);
    let mut key = Zeroizing::new([0u8; HPKE_KEY_SIZE]);
    let mut base_nonce = Zeroizing::new([0u8; HPKE_NONCE_SIZE]);
    hpke_labeled_expand::<B>(&suite_id, &secret, "key", &key_schedule_context, &mut key[..])?;
    hpke_labeled_expand::<B>(
        &suite_id,
        &secret,
        "base_nonce",
        &key_schedule_context,
        &mut base_nonce[..],
    )?;
    Ok((key, base_nonce))
}

/// Encapsulate to `public_key` (of the length of the KEM's public keys), then seal `plaintext` at sequence number
/// 0: `enc` receives `kem.enc_length()` bytes, `sealed` the plaintext length + 16 bytes (ciphertext || tag).
#[allow(clippy::too_many_arguments)] // The parameters of RFC 9180 SetupBaseS and Seal, and the two outputs
pub(crate) fn hpke_base_mode_seal<B: CryptoBackend>(
    hooks: &mut dyn PlatformHooks,
    kem: HpkeKem,
    public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    enc: &mut [u8],
    sealed: &mut [u8],
) -> Result<()> {
    if public_key.len() != kem.public_key_length()
        || enc.len() != kem.enc_length()
        || sealed.len().checked_sub(AEAD_TAG_SIZE) != Some(plaintext.len())
    {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let shared_secret = kem.encapsulate::<B>(hooks, public_key, enc)?;
    let (key, base_nonce) = hpke_base_mode_key_schedule::<B>(kem.kem_id(), &shared_secret, info)?;
    drop(shared_secret);
    // Sequence number 0: the nonce is the base nonce
    let mut aead = B::ChaCha20Poly1305::new(&key, &base_nonce, aad)?;
    let (ciphertext, tag) = sealed.split_at_mut(plaintext.len());
    aead.encrypt(plaintext, ciphertext)?;
    tag.copy_from_slice(&aead.finish()?);
    Ok(())
}

/// Cipherdict `{"kem_ciphertext": enc, "ciphertext": sealed}` with empty info and AAD.
pub(crate) fn hpke_base_mode_seal_to_cipherdict<B: CryptoBackend>(
    hooks: &mut dyn PlatformHooks,
    kem: HpkeKem,
    public_key: &[u8],
    plaintext: &[u8],
) -> Result<Value> {
    let sealed_length = plaintext
        .len()
        .checked_add(AEAD_TAG_SIZE)
        .ok_or(ErrorKind::InvalidArgument)?;
    let mut enc = try_zeroed_vec(kem.enc_length())?;
    let mut sealed = try_zeroed_vec(sealed_length)?;
    if let Err(error) = hpke_base_mode_seal::<B>(hooks, kem, public_key, &[], &[], plaintext, &mut enc, &mut sealed) {
        sealed.zeroize(); // It may hold plaintext after a failure in the middle of the AEAD
        return Err(error);
    }
    let mut cipherdict = Map::new();
    cipherdict.set("kem_ciphertext", Value::Bytes(enc));
    cipherdict.set("ciphertext", Value::Bytes(sealed));
    Ok(Value::Map(cipherdict))
}
