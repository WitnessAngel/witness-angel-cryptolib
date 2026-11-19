// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Asymmetric key wrapping (encryptor specification, sections 3.5 and 6.5): the key struct
//! `{"key_bytes": ..., "cryptainer_metadata": ... or null}` is serialized in the document format of the
//! cryptainer, then encrypted with RSA_OAEP, ECIES_X25519 or ML_KEM_768 into a cipherdict.

use crate::crypto_backend::CryptoBackend;
use crate::encoding::document_serialization::{ResolvedFormat, serialize_to_secret_buffer};
use crate::encoding::secret_byte_buffer::SecretByteBuffer;
use crate::encoding::value_tree::{Node, Value};
use crate::error::{Error, ErrorKind, Result};
use crate::platform_hooks::PlatformHooks;
use crate::primitives::hpke_base_mode_seal::{HpkeKem, hpke_base_mode_seal_to_cipherdict};
use crate::primitives::rsa_oaep_chunked_encryption::rsa_oaep_encrypt_into_chunks;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AsymmetricCipherAlgo {
    RsaOaep,
    EciesX25519,
    MlKem768,
}

impl AsymmetricCipherAlgo {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "RSA_OAEP" => Some(Self::RsaOaep),
            "ECIES_X25519" => Some(Self::EciesX25519),
            "ML_KEM_768" => Some(Self::MlKem768),
            _ => None,
        }
    }
}

/// A public key, borrowing the bytes of its device profile entry. Constraints are checked at profile loading.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AsymmetricPublicKey<'a> {
    RsaOaep {
        modulus: &'a [u8],
        public_exponent: &'a [u8],
    },
    /// 32 bytes
    EciesX25519(&'a [u8]),
    /// 1184 bytes
    MlKem768(&'a [u8]),
}

/// Encrypt raw bytes: `{"ciphertext_chunks": [...]}` for RSA_OAEP, `{"kem_ciphertext", "ciphertext"}` otherwise.
pub(crate) fn asymmetric_encrypt_to_cipherdict<B: CryptoBackend>(
    hooks: &mut dyn PlatformHooks,
    public_key: AsymmetricPublicKey<'_>,
    plaintext: &[u8],
) -> Result<Value> {
    match public_key {
        AsymmetricPublicKey::RsaOaep {
            modulus,
            public_exponent,
        } => rsa_oaep_encrypt_into_chunks::<B>(hooks, modulus, public_exponent, plaintext),
        AsymmetricPublicKey::EciesX25519(key_bytes) => {
            hpke_base_mode_seal_to_cipherdict::<B>(hooks, HpkeKem::DhkemX25519, key_bytes, plaintext)
        }
        AsymmetricPublicKey::MlKem768(key_bytes) => {
            hpke_base_mode_seal_to_cipherdict::<B>(hooks, HpkeKem::MlKem768, key_bytes, plaintext)
        }
    }
}

/// `S_F` of the key struct `{"key_bytes": ..., "cryptainer_metadata": map or null}` (section 6.5), into a wiping
/// buffer: the key bytes never enter an owned tree.
pub(crate) fn serialize_key_struct(
    format: ResolvedFormat,
    key_bytes: &[u8],
    cryptainer_metadata: Option<&Value>,
) -> Result<SecretByteBuffer> {
    let metadata_node = match cryptainer_metadata {
        Some(metadata @ Value::Map(_)) => Node::Value(metadata),
        Some(_) => return Err(Error::new(ErrorKind::InvalidArgument)),
        None => Node::Null,
    };
    // Entries sorted by key, like those of owned maps
    let entries = [
        ("cryptainer_metadata", metadata_node),
        ("key_bytes", Node::Bytes(key_bytes)),
    ];
    serialize_to_secret_buffer(Node::Map(&entries), format)
}

/// Serialize the key struct of `key_bytes` and `cryptainer_metadata` (a map satisfying the document tree
/// constraints, or none), and encrypt it.
pub(crate) fn asymmetric_wrap_key_struct<B: CryptoBackend>(
    hooks: &mut dyn PlatformHooks,
    public_key: AsymmetricPublicKey<'_>,
    format: ResolvedFormat,
    key_bytes: &[u8],
    cryptainer_metadata: Option<&Value>,
) -> Result<Value> {
    let serialized_key_struct = serialize_key_struct(format, key_bytes, cryptainer_metadata)?;
    asymmetric_encrypt_to_cipherdict::<B>(hooks, public_key, serialized_key_struct.as_slice())
}
