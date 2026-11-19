// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Sections 7.1, 8 and 9.2 of the encryptor specification. The signature lists are empty (or the plaintext one
//! absent), so `inject_digests_and_signatures()` has nothing to inject: no digest is computed nor stored.

use alloc::vec::Vec;

use crate::core::cryptainer_base_generation::{CIPHERTEXT_LOCATION_INLINE_NAME, CRYPTAINER_STATE_FINISHED};
use crate::crypto_backend::AEAD_TAG_SIZE;
use crate::encoding::value_tree::{Map, Value};
use crate::error::{Error, ErrorKind, Result};
use crate::primitives::symmetric_cipher_streams::build_payload_macs;
use crate::primitives::symmetric_key_generation::SymmetricCipherAlgo;

/// Step 3: store the payload MACs of each payload cipher layer (`cipher_algos` and `tags` in layer order), the
/// inline ciphertext if any, and mark the cryptainer FINISHED.
pub(crate) fn add_authentication_data<'a>(
    cryptainer: &mut Value,
    cipher_algos: impl ExactSizeIterator<Item = SymmetricCipherAlgo>,
    tags: impl ExactSizeIterator<Item = Option<&'a [u8; AEAD_TAG_SIZE]>>,
    inline_ciphertext: Option<Vec<u8>>,
) -> Result<()> {
    let root = cryptainer.as_map_mut().ok_or(ErrorKind::InternalError)?;
    let payload_layers = root
        .get_mut("payload_cipher_layers")
        .and_then(Value::as_array_mut)
        .ok_or(ErrorKind::InternalError)?;
    if cipher_algos.len() != payload_layers.len() || tags.len() != payload_layers.len() {
        return Err(Error::new(ErrorKind::InternalError));
    }
    for ((payload_layer, cipher_algo), tag) in payload_layers.iter_mut().zip(cipher_algos).zip(tags) {
        let payload_layer = payload_layer.as_map_mut().ok_or(ErrorKind::InternalError)?;
        // assert layer["payload_macs"] is null
        if !payload_layer.get("payload_macs").is_some_and(Value::is_null) {
            return Err(Error::new(ErrorKind::InternalError));
        }
        payload_layer.set("payload_macs", build_payload_macs(cipher_algo, tag)?);
    }
    if let Some(inline_ciphertext) = inline_ciphertext {
        let mut ciphertext_struct = Map::new();
        ciphertext_struct.set("ciphertext_location", CIPHERTEXT_LOCATION_INLINE_NAME);
        ciphertext_struct.set("ciphertext_value", Value::Bytes(inline_ciphertext));
        root.set("payload_ciphertext_struct", ciphertext_struct);
    }
    root.set("cryptainer_state", CRYPTAINER_STATE_FINISHED);
    Ok(())
}
