// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Sections 6.2 to 6.5 of the encryptor specification (Python: `_flightbox.py`,
//! `_encrypt_key_through_multiple_layers`, `_encrypt_key_through_single_layer` and
//! `_encrypt_key_with_asymmetric_cipher`). The cryptoconf was validated at profile load: layers are well-formed,
//! and every asymmetric layer resolves to a public key.

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::core::cryptoconf_validation::KeyCipherLayerKind;
use crate::crypto_backend::CryptoBackend;
use crate::encoding::device_profile::DeviceProfile;
use crate::encoding::document_serialization::{ResolvedFormat, serialize_to_secret_buffer};
use crate::encoding::secret_byte_buffer::SecretByteBuffer;
use crate::encoding::value_tree::{Node, Value};
use crate::error::{Error, ErrorKind, Result};
use crate::limits::MAX_SHARED_SECRET_SHARD_COUNT;
use crate::platform_hooks::PlatformHooks;
use crate::primitives::asymmetric_key_wrapping::asymmetric_wrap_key_struct;
use crate::primitives::shamir_secret_sharing_gf128::shamir_split_secret_into_shards;
use crate::primitives::symmetric_cipher_streams::symmetric_encrypt_to_cipherdict;
use crate::primitives::symmetric_key_generation::{Symkey, SymmetricCipherAlgo};
use crate::primitives::try_zeroed_vec;

/// The value of `key_ciphertext_format` in CBOR cryptainers; an absent field means "json" (section 2).
const KEY_CIPHERTEXT_FORMAT_CBOR: &str = "cbor";

/// What the encryption of keys needs, all along a cryptainer creation.
pub(crate) struct KeyCipherContext<'a, B: CryptoBackend> {
    pub(crate) hooks: &'a mut dyn PlatformHooks,
    pub(crate) device_profile: &'a DeviceProfile,
    pub(crate) format: ResolvedFormat,
    /// The metadata copy of the cryptainer, which goes into every key struct
    pub(crate) cryptainer_metadata: Option<&'a Value>,
    pub(crate) backend: PhantomData<B>,
}

/// `S_F((index, shard_bytes))`: a two-item array, built from borrowed nodes. Indices start at 1.
pub(crate) fn serialize_shard(format: ResolvedFormat, shard_index: usize, shard: &[u8]) -> Result<SecretByteBuffer> {
    let index = shard_index.checked_add(1).and_then(|index| i64::try_from(index).ok());
    let items = [
        Node::Integer(index.ok_or(ErrorKind::InvalidArgument)?),
        Node::Bytes(shard),
    ];
    serialize_to_secret_buffer(Node::Array(&items), format)
}

/// Store the ciphertext of the key of `layer` in it, with its format when it is not the default one.
pub(crate) fn store_key_ciphertext(
    format: ResolvedFormat,
    layer: &mut Value,
    key_ciphertext: &SecretByteBuffer,
) -> Result<()> {
    let mut key_ciphertext_bytes = try_zeroed_vec(key_ciphertext.len())?;
    key_ciphertext_bytes.copy_from_slice(key_ciphertext.as_slice());
    let layer = layer.as_map_mut().ok_or(ErrorKind::InternalError)?;
    layer.insert("key_ciphertext", Value::Bytes(key_ciphertext_bytes))?;
    if matches!(format, ResolvedFormat::Cbor) {
        layer.insert("key_ciphertext_format", KEY_CIPHERTEXT_FORMAT_CBOR)?;
    }
    Ok(())
}

impl<B: CryptoBackend> KeyCipherContext<'_, B> {
    /// Section 6.2: encrypt `key_bytes` through the `key_cipher_layers` of `layer_owner` (a payload cipher layer,
    /// a symmetric key cipher layer or a shard conf), chained: the k-th layer encrypts `S_F` of the cipherdict of
    /// the (k-1)-th one, and the result is `S_F` of the last cipherdict. Symmetric layers of the chain receive
    /// their own key ciphertext in place.
    pub(crate) fn encrypt_key(&mut self, layer_owner: &mut Value, key_bytes: &[u8]) -> Result<SecretByteBuffer> {
        let key_cipher_layers = layer_owner
            .as_map_mut()
            .and_then(|map| map.get_mut("key_cipher_layers"))
            .and_then(Value::as_array_mut)
            .ok_or(ErrorKind::InvalidProfile)?;
        let mut key_ciphertext: Option<SecretByteBuffer> = None;
        for layer in key_cipher_layers.iter_mut() {
            // Key bytes stay bytes all along
            let current_bytes = key_ciphertext.as_ref().map_or(key_bytes, SecretByteBuffer::as_slice);
            let key_cipherdict = self.encrypt_key_through_single_layer(layer, current_bytes)?;
            key_ciphertext = Some(serialize_to_secret_buffer(Node::Value(&key_cipherdict), self.format)?);
        }
        // Section 5.2: the core checks again that there is a layer
        let key_ciphertext = key_ciphertext.ok_or(ErrorKind::InvalidProfile)?;
        // Safety net of the reference: the output differs from the input
        if key_ciphertext.as_slice() == key_bytes {
            return Err(Error::new(ErrorKind::InternalError));
        }
        Ok(key_ciphertext)
    }

    /// Section 6.3: the cipherdict of `key_bytes` under one layer.
    fn encrypt_key_through_single_layer(&mut self, layer: &mut Value, key_bytes: &[u8]) -> Result<Value> {
        let algo_name = layer
            .get("key_cipher_algo")
            .and_then(Value::as_text)
            .ok_or(ErrorKind::InvalidProfile)?;
        match KeyCipherLayerKind::from_algo_name(algo_name) {
            Some(KeyCipherLayerKind::SharedSecret) => self.encrypt_key_with_shared_secret(layer, key_bytes),
            Some(KeyCipherLayerKind::Symmetric(cipher_algo)) => {
                self.encrypt_key_with_symmetric_sub_key(layer, cipher_algo, key_bytes)
            }
            Some(KeyCipherLayerKind::Asymmetric(_)) => {
                // Section 6.5: the key struct {"key_bytes", "cryptainer_metadata"}, serialized with S_F, then
                // wrapped
                let public_key = self.device_profile.find_layer_public_key(layer)?;
                asymmetric_wrap_key_struct::<B>(
                    self.hooks,
                    public_key,
                    self.format,
                    key_bytes,
                    self.cryptainer_metadata,
                )
            }
            None => Err(Error::new(ErrorKind::UnsupportedAlgorithm)),
        }
    }

    /// Section 6.4, shared secret: the key is split into shards, the i-th one going through the i-th shard conf,
    /// recursively, with the same document format.
    fn encrypt_key_with_shared_secret(&mut self, layer: &mut Value, key_bytes: &[u8]) -> Result<Value> {
        let threshold_count = layer.get("key_shared_secret_threshold").and_then(Value::as_integer);
        let shard_confs = layer
            .as_map_mut()
            .and_then(|map| map.get_mut("key_shared_secret_shards"))
            .and_then(Value::as_array_mut)
            .ok_or(ErrorKind::InvalidProfile)?;
        // Section 5.2: the core checks the threshold and the shard count (section 3.7) again
        if shard_confs.len() > MAX_SHARED_SECRET_SHARD_COUNT {
            return Err(Error::new(ErrorKind::InvalidProfile));
        }
        let threshold_count = threshold_count
            .and_then(|threshold_count| usize::try_from(threshold_count).ok())
            .filter(|threshold_count| (1..=shard_confs.len()).contains(threshold_count))
            .ok_or(ErrorKind::InvalidProfile)?;
        let shards = shamir_split_secret_into_shards(self.hooks, key_bytes, shard_confs.len(), threshold_count)?;
        let mut shard_ciphertexts = Vec::new();
        shard_ciphertexts
            .try_reserve_exact(shard_confs.len())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        for (shard_index, (shard, shard_conf)) in shards.iter().zip(shard_confs.iter_mut()).enumerate() {
            let serialized_shard = serialize_shard(self.format, shard_index, shard)?;
            let shard_ciphertext = self.encrypt_key(shard_conf, serialized_shard.as_slice())?;
            drop(serialized_shard);
            let mut shard_ciphertext_bytes = try_zeroed_vec(shard_ciphertext.len())?;
            shard_ciphertext_bytes.copy_from_slice(shard_ciphertext.as_slice());
            shard_ciphertexts.push(Value::Bytes(shard_ciphertext_bytes));
        }
        let mut cipherdict = crate::encoding::value_tree::Map::new();
        cipherdict.set("shard_ciphertexts", Value::Array(shard_ciphertexts));
        Ok(Value::Map(cipherdict))
    }

    /// Section 6.4, symmetric sub-key: a new symkey encrypts the key, and is itself protected by the layer's own
    /// key cipher layers, its ciphertext being stored in the layer.
    fn encrypt_key_with_symmetric_sub_key(
        &mut self,
        layer: &mut Value,
        cipher_algo: SymmetricCipherAlgo,
        key_bytes: &[u8],
    ) -> Result<Value> {
        let sub_symkey = Symkey::generate(self.hooks, cipher_algo)?;
        let serialized_sub_symkey = sub_symkey.serialize(self.format)?;
        let sub_key_ciphertext = self.encrypt_key(layer, serialized_sub_symkey.as_slice())?;
        drop(serialized_sub_symkey);
        store_key_ciphertext(self.format, layer, &sub_key_ciphertext)?;
        symmetric_encrypt_to_cipherdict::<B>(&sub_symkey, key_bytes)
    }
}
