// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Entry points into the internal modules, for the test driver and the tests of this workspace, which exercise
//! the portable primitives one by one against vectors. **Not part of the public API**: hidden from the
//! documentation, without any stability guarantee, and of no use to an encryptor.

#![allow(missing_docs)]

use alloc::vec::Vec;

use crate::core::cryptoconf_validation;
use crate::core::error_location_path::ErrorLocationPath;
use crate::core::key_cipher_layers_encryption;
use crate::core::payload_encryption_pipeline::PayloadEncryptionPipeline;
use crate::crypto_backend::{AEAD_TAG_SIZE, AES_256_KEY_SIZE, Aes256Encryptor, CryptoBackend};
use crate::encoding::document_serialization::DocumentFormat;
use crate::encoding::secret_byte_buffer::SecretByteBuffer;
use crate::encoding::value_tree::{UUID_SIZE, Value};
use crate::error::{Error, ErrorKind, Result};
use crate::limits::EncryptorLimits;
use crate::platform_hooks::PlatformHooks;
use crate::primitives::aes_cmac_omac1::AesCmac;
use crate::primitives::asymmetric_key_wrapping::{self, AsymmetricCipherAlgo, AsymmetricPublicKey};
use crate::primitives::hpke_base_mode_seal::{self, HpkeKem};
use crate::primitives::symmetric_cipher_streams::{self, SymmetricCipherStream};
use crate::primitives::symmetric_key_generation::{Symkey, SymmetricCipherAlgo};
use crate::primitives::{
    hkdf_sha256, public_key_constraints, rsa_oaep_chunked_encryption, rsa_oaep_sha512_padding,
    shamir_secret_sharing_gf128, try_zeroed_vec, uuid0_generation,
};

fn invalid_argument() -> Error {
    Error::new(ErrorKind::InvalidArgument)
}

fn parse_symkey(cipher_algo: &str, key: &[u8], iv_or_nonce: &[u8]) -> Result<Symkey> {
    let cipher_algo = SymmetricCipherAlgo::from_name(cipher_algo).ok_or_else(invalid_argument)?;
    Symkey::from_parts(cipher_algo, key, iv_or_nonce).ok_or_else(invalid_argument)
}

/// The length of the IV or nonce of a payload cipher algorithm, `None` for an unknown name.
pub fn symmetric_iv_or_nonce_length(cipher_algo: &str) -> Option<usize> {
    SymmetricCipherAlgo::from_name(cipher_algo).map(SymmetricCipherAlgo::iv_or_nonce_length)
}

/// A symkey drawn from the hooks: its key, then its IV or nonce.
pub fn generate_symkey(hooks: &mut dyn PlatformHooks, cipher_algo: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher_algo = SymmetricCipherAlgo::from_name(cipher_algo).ok_or_else(invalid_argument)?;
    let symkey = Symkey::generate(hooks, cipher_algo)?;
    Ok((symkey.key.to_vec(), symkey.iv_or_nonce().to_vec()))
}

/// The one-shot cipherdict of a given symkey.
pub fn symmetric_encrypt_to_cipherdict<B: CryptoBackend>(
    cipher_algo: &str,
    key: &[u8],
    iv_or_nonce: &[u8],
    plaintext: &[u8],
) -> Result<Value> {
    let symkey = parse_symkey(cipher_algo, key, iv_or_nonce)?;
    symmetric_cipher_streams::symmetric_encrypt_to_cipherdict::<B>(&symkey, plaintext)
}

/// A streamed encryption, the plaintext being fed in pieces of `piece_length` bytes: the ciphertext and the tag.
pub fn symmetric_encrypt_in_pieces<B: CryptoBackend>(
    cipher_algo: &str,
    key: &[u8],
    iv_or_nonce: &[u8],
    plaintext: &[u8],
    piece_length: usize,
) -> Result<(Vec<u8>, Option<[u8; AEAD_TAG_SIZE]>)> {
    let symkey = parse_symkey(cipher_algo, key, iv_or_nonce)?;
    let mut stream = SymmetricCipherStream::<B>::start(&symkey)?;
    let mut ciphertext = Vec::new();
    for piece in plaintext.chunks(piece_length.max(1)) {
        let mut output = try_zeroed_vec(piece.len().checked_add(16).ok_or_else(invalid_argument)?)?;
        let written_length = stream.encrypt(piece, &mut output)?;
        ciphertext.extend_from_slice(output.get(..written_length).ok_or(ErrorKind::InternalError)?);
    }
    let mut final_block = [0u8; 16];
    let (written_length, tag) = stream.finish(&mut final_block)?;
    ciphertext.extend_from_slice(final_block.get(..written_length).ok_or(ErrorKind::InternalError)?);
    Ok((ciphertext, tag))
}

/// AES-256 CMAC of a message fed in the given pieces.
pub fn compute_aes_cmac<B: CryptoBackend>(key: &[u8; AES_256_KEY_SIZE], message_pieces: &[&[u8]]) -> Result<[u8; 16]> {
    let mut aes = B::Aes256::new(key)?;
    let mut cmac = AesCmac::start(&mut aes)?;
    for piece in message_pieces {
        cmac.update(&mut aes, piece)?;
    }
    cmac.finish(&mut aes)
}

pub fn hkdf_sha256_extract<B: CryptoBackend>(salt: &[u8], ikm: &[u8]) -> Result<[u8; 32]> {
    hkdf_sha256::hkdf_sha256_extract::<B>(salt, &[ikm])
}

pub fn hkdf_sha256_expand<B: CryptoBackend>(prk: &[u8; 32], info: &[u8], length: usize) -> Result<Vec<u8>> {
    let mut okm = try_zeroed_vec(length)?;
    hkdf_sha256::hkdf_sha256_expand::<B>(prk, &[info], &mut okm)?;
    Ok(okm)
}

fn parse_hpke_kem(kem_name: &str) -> Option<HpkeKem> {
    match kem_name {
        "x25519" => Some(HpkeKem::DhkemX25519),
        "ml-kem-768" => Some(HpkeKem::MlKem768),
        _ => None,
    }
}

/// The length of the public keys of an HPKE KEM (`x25519` or `ml-kem-768`), `None` for an unknown name.
pub fn hpke_kem_public_key_length(kem_name: &str) -> Option<usize> {
    parse_hpke_kem(kem_name).map(HpkeKem::public_key_length)
}

/// HPKE base mode seal, the KEM drawing its randomness from the hooks: `enc`, then the sealed bytes.
pub fn hpke_base_mode_seal<B: CryptoBackend>(
    hooks: &mut dyn PlatformHooks,
    kem_name: &str,
    public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let kem = parse_hpke_kem(kem_name).ok_or_else(invalid_argument)?;
    let mut enc = try_zeroed_vec(kem.enc_length())?;
    let mut sealed = try_zeroed_vec(
        plaintext
            .len()
            .checked_add(AEAD_TAG_SIZE)
            .ok_or_else(invalid_argument)?,
    )?;
    hpke_base_mode_seal::hpke_base_mode_seal::<B>(hooks, kem, public_key, info, aad, plaintext, &mut enc, &mut sealed)?;
    Ok((enc, sealed))
}

/// The OAEP encoding of `message` with a given seed, for a modulus of `modulus_length` bytes.
pub fn rsa_oaep_sha512_encode_padding<B: CryptoBackend>(
    message: &[u8],
    seed: &[u8; 64],
    modulus_length: usize,
) -> Result<Vec<u8>> {
    let mut encoded_message = try_zeroed_vec(modulus_length)?;
    rsa_oaep_sha512_padding::rsa_oaep_sha512_encode_padding::<B>(message, seed, &mut encoded_message)?;
    Ok(encoded_message)
}

/// The cipherdict `{"ciphertext_chunks": [...]}` of an RSA-OAEP encryption.
pub fn rsa_oaep_encrypt_into_chunks<B: CryptoBackend>(
    hooks: &mut dyn PlatformHooks,
    modulus: &[u8],
    public_exponent: &[u8],
    plaintext: &[u8],
) -> Result<Value> {
    rsa_oaep_chunked_encryption::rsa_oaep_encrypt_into_chunks::<B>(hooks, modulus, public_exponent, plaintext)
}

/// The shards of a secret, in index order (the first one has index 1).
pub fn shamir_split_secret_into_shards(
    hooks: &mut dyn PlatformHooks,
    secret: &[u8],
    shard_count: usize,
    threshold_count: usize,
) -> Result<Vec<Vec<u8>>> {
    let shards =
        shamir_secret_sharing_gf128::shamir_split_secret_into_shards(hooks, secret, shard_count, threshold_count)?;
    Ok(shards.iter().map(<[u8]>::to_vec).collect())
}

pub fn gf128_multiply(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    shamir_secret_sharing_gf128::gf128_multiply(a, b)
}

pub fn generate_uuid0(hooks: &mut dyn PlatformHooks) -> Result<[u8; UUID_SIZE]> {
    uuid0_generation::generate_uuid0(hooks)
}

/// A public key given by its parts: the modulus and the exponent for `RSA_OAEP`, else the key bytes and nothing.
fn parse_public_key<'a>(
    cipher_algo: &str,
    modulus_or_key_bytes: &'a [u8],
    public_exponent: &'a [u8],
) -> Result<AsymmetricPublicKey<'a>> {
    Ok(
        match AsymmetricCipherAlgo::from_name(cipher_algo).ok_or_else(invalid_argument)? {
            AsymmetricCipherAlgo::RsaOaep => AsymmetricPublicKey::RsaOaep {
                modulus: modulus_or_key_bytes,
                public_exponent,
            },
            AsymmetricCipherAlgo::EciesX25519 => AsymmetricPublicKey::EciesX25519(modulus_or_key_bytes),
            AsymmetricCipherAlgo::MlKem768 => AsymmetricPublicKey::MlKem768(modulus_or_key_bytes),
        },
    )
}

/// Whether the name is one of the asymmetric key cipher algorithms.
pub fn is_asymmetric_cipher_algo(cipher_algo: &str) -> bool {
    AsymmetricCipherAlgo::from_name(cipher_algo).is_some()
}

/// The key constraints of profile loading.
pub fn check_public_key(
    cipher_algo: &str,
    modulus_or_key_bytes: &[u8],
    public_exponent: &[u8],
    limits: &EncryptorLimits,
) -> Result<()> {
    match parse_public_key(cipher_algo, modulus_or_key_bytes, public_exponent)? {
        AsymmetricPublicKey::RsaOaep {
            modulus,
            public_exponent,
        } => public_key_constraints::check_rsa_public_key(modulus, public_exponent, limits.max_rsa_modulus_bits()),
        AsymmetricPublicKey::EciesX25519(key_bytes) => public_key_constraints::check_x25519_public_key(key_bytes),
        AsymmetricPublicKey::MlKem768(key_bytes) => public_key_constraints::check_ml_kem_768_public_key(key_bytes),
    }
}

/// `S_F` of a symkey.
pub fn serialize_symkey(format: DocumentFormat, cipher_algo: &str, key: &[u8], iv_or_nonce: &[u8]) -> Result<Vec<u8>> {
    let symkey = parse_symkey(cipher_algo, key, iv_or_nonce)?;
    Ok(symkey.serialize(format.resolve()?)?.as_slice().to_vec())
}

/// `S_F` of the shard of 0-based index `shard_index`.
pub fn serialize_shard(format: DocumentFormat, shard_index: usize, shard: &[u8]) -> Result<Vec<u8>> {
    Ok(
        key_cipher_layers_encryption::serialize_shard(format.resolve()?, shard_index, shard)?
            .as_slice()
            .to_vec(),
    )
}

/// `S_F` of a key struct.
pub fn serialize_key_struct(format: DocumentFormat, key_bytes: &[u8], metadata: Option<&Value>) -> Result<Vec<u8>> {
    Ok(
        asymmetric_key_wrapping::serialize_key_struct(format.resolve()?, key_bytes, metadata)?
            .as_slice()
            .to_vec(),
    )
}

/// The cipherdict of the key struct of `key_bytes` and `metadata`, the key being given as for [`check_public_key`]
/// (and not checked here).
pub fn asymmetric_wrap_key_struct<B: CryptoBackend>(
    hooks: &mut dyn PlatformHooks,
    format: DocumentFormat,
    cipher_algo: &str,
    modulus_or_key_bytes: &[u8],
    public_exponent: &[u8],
    key_bytes: &[u8],
    metadata: Option<&Value>,
) -> Result<Value> {
    let public_key = parse_public_key(cipher_algo, modulus_or_key_bytes, public_exponent)?;
    asymmetric_key_wrapping::asymmetric_wrap_key_struct::<B>(hooks, public_key, format.resolve()?, key_bytes, metadata)
}

/// The cryptoconf validation of profile loading, on its own: errors are located from `cryptoconf`, as those of
/// profile loading.
pub fn validate_cryptoconf(cryptoconf: &Value, limits: &EncryptorLimits) -> Result<()> {
    let mut location = ErrorLocationPath::new();
    location.push_key("cryptoconf");
    match cryptoconf_validation::validate_cryptoconf(cryptoconf, limits, &mut location) {
        Ok(()) => Ok(()),
        Err(kind) => Err(location.into_error(kind)),
    }
}

/// The validation of a trustee, on its own: errors are located from the trustee.
pub fn validate_trustee(trustee: &Value) -> Result<()> {
    let mut location = ErrorLocationPath::new();
    match cryptoconf_validation::validate_trustee(trustee, &mut location) {
        Ok(()) => Ok(()),
        Err(kind) => Err(location.into_error(kind)),
    }
}

/// Whether two valid trustees designate the same one (the keystore owner being ignored).
pub fn trustee_identities_are_equal(trustee_a: &Value, trustee_b: &Value) -> bool {
    cryptoconf_validation::trustee_identities_are_equal(trustee_a, trustee_b)
}

/// A payload ciphertext, and the tag of each of its layers (none for the ones without authentication).
pub type CiphertextAndLayerTags = (Vec<u8>, Vec<Option<[u8; AEAD_TAG_SIZE]>>);

/// The payload encryption pipeline over given symkeys (`(cipher_algo, key, iv_or_nonce)`, in layer order), the
/// payload being fed in chunks of `chunk_length` bytes and processed in slices of `slice_size` bytes: the
/// ciphertext, and the tag of each layer.
pub fn encrypt_payload_through_layers<B: CryptoBackend>(
    symkeys: &[(&str, &[u8], &[u8])],
    payload: &[u8],
    chunk_length: usize,
    slice_size: usize,
) -> Result<CiphertextAndLayerTags> {
    let mut parsed_symkeys = Vec::new();
    for (cipher_algo, key, iv_or_nonce) in symkeys {
        parsed_symkeys.push(parse_symkey(cipher_algo, key, iv_or_nonce)?);
    }
    let mut pipeline = PayloadEncryptionPipeline::<B>::start(&parsed_symkeys, slice_size)?;
    let mut ciphertext = Vec::new();
    for chunk in payload.chunks(chunk_length.max(1)) {
        pipeline.encrypt_chunk(chunk, &mut ciphertext)?;
    }
    pipeline.finalize(&mut ciphertext)?;
    let tags = pipeline.tags().map(|tag| tag.copied()).collect();
    Ok((ciphertext, tags))
}

/// Append `pieces` to a secret byte buffer, then drop it: the length it reached. For the tests checking, with an
/// allocator scanning released blocks, that neither its growth nor its drop leaves the content behind.
pub fn fill_and_drop_secret_byte_buffer(pieces: &[&[u8]]) -> Result<usize> {
    let mut buffer = SecretByteBuffer::new();
    for piece in pieces {
        buffer.extend_from_slice(piece)?;
    }
    Ok(buffer.len())
}
