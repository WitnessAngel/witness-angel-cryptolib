// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Section 6.1 of the encryptor specification (Python: `_flightbox.py`, `generate_cryptainer_base_and_secrets` and
//! `_encrypt_payload_symkey`). Random draws follow the reference order: the cryptainer uid, then for each payload
//! layer its symkey and its key cipher chain. The root keychain uid is mandatory in device profiles, so no second
//! UUID0 is ever drawn for it.

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::core::key_cipher_layers_encryption::{KeyCipherContext, store_key_ciphertext};
use crate::crypto_backend::CryptoBackend;
use crate::encoding::device_profile::DeviceProfile;
use crate::encoding::document_serialization::ResolvedFormat;
use crate::encoding::value_tree::{Map, Value};
use crate::error::{ErrorKind, Result};
use crate::platform_hooks::PlatformHooks;
use crate::primitives::symmetric_key_generation::{Symkey, SymmetricCipherAlgo};
use crate::primitives::uuid0_generation::generate_uuid0;

pub(crate) const CRYPTAINER_FORMAT: &str = "cryptainer_1.0";
pub(crate) const CRYPTAINER_STATE_STARTED: &str = "STARTED";
pub(crate) const CRYPTAINER_STATE_FINISHED: &str = "FINISHED";
pub(crate) const CIPHERTEXT_LOCATION_INLINE_NAME: &str = "inline";
pub(crate) const CIPHERTEXT_LOCATION_OFFLOADED_NAME: &str = "offloaded";

/// The cryptainer tree in its STARTED state, and the symkeys of its payload cipher layers, in layer order.
pub(crate) struct CryptainerBase {
    pub(crate) cryptainer: Value,
    pub(crate) payload_symkeys: Vec<Symkey>,
}

/// Legacy naming of old cryptoconfs: `payload_signatures` becomes `payload_ciphertext_signatures` (the validation
/// allows only one of both names, so the new name never has precedence to apply here).
fn rename_legacy_payload_signatures(payload_layer: &mut Map) {
    let Some(legacy_payload_signatures) = payload_layer.remove("payload_signatures") else {
        return;
    };
    // Never both after validation: kept as in the C library, which drops the legacy value then
    if !payload_layer.contains_key("payload_ciphertext_signatures") {
        payload_layer.set("payload_ciphertext_signatures", legacy_payload_signatures);
    }
}

fn prepare_payload_cipher_layer<B: CryptoBackend>(
    context: &mut KeyCipherContext<'_, B>,
    payload_layer: &mut Value,
) -> Result<Symkey> {
    let cipher_algo = payload_layer
        .get("payload_cipher_algo")
        .and_then(Value::as_text)
        .and_then(SymmetricCipherAlgo::from_name)
        .ok_or(ErrorKind::InvalidProfile)?;
    let payload_layer_map = payload_layer.as_map_mut().ok_or(ErrorKind::InvalidProfile)?;
    rename_legacy_payload_signatures(payload_layer_map);
    payload_layer_map.set("payload_macs", Value::Null); // Filled at step 3
    let payload_symkey = Symkey::generate(context.hooks, cipher_algo)?;
    let serialized_symkey = payload_symkey.serialize(context.format)?;
    let key_ciphertext = context.encrypt_key(payload_layer, serialized_symkey.as_slice())?;
    drop(serialized_symkey);
    store_key_ciphertext(context.format, payload_layer, &key_ciphertext)?;
    Ok(payload_symkey)
}

/// Step 1: a copy of the cryptoconf of the profile, completed into a cryptainer whose payload symkeys are
/// generated and encrypted through their key cipher layers.
pub(crate) fn generate_cryptainer_base<B: CryptoBackend>(
    hooks: &mut dyn PlatformHooks,
    device_profile: &DeviceProfile,
    cryptainer_metadata: Option<&Value>,
    format: ResolvedFormat,
    is_offloaded: bool,
) -> Result<CryptainerBase> {
    let cryptainer_uid = generate_uuid0(hooks)?; // ALWAYS UNIQUE, drawn first
    let mut cryptainer = device_profile.cryptoconf().clone();
    let metadata_copy = cryptainer_metadata.cloned();
    let mut context = KeyCipherContext::<B> {
        hooks,
        device_profile,
        format,
        cryptainer_metadata: metadata_copy.as_ref(),
        backend: PhantomData,
    };

    let payload_layers = cryptainer
        .as_map_mut()
        .and_then(|map| map.get_mut("payload_cipher_layers"))
        .and_then(Value::as_array_mut)
        .filter(|payload_layers| !payload_layers.is_empty())
        .ok_or(ErrorKind::InvalidProfile)?; // Rejected at profile load already
    let mut payload_symkeys = Vec::new();
    payload_symkeys
        .try_reserve_exact(payload_layers.len())
        .map_err(|_| ErrorKind::OutOfMemory)?;
    for payload_layer in payload_layers.iter_mut() {
        payload_symkeys.push(prepare_payload_cipher_layer(&mut context, payload_layer)?);
    }

    let root = cryptainer.as_map_mut().ok_or(ErrorKind::InvalidProfile)?;
    root.set("cryptainer_metadata", metadata_copy.unwrap_or(Value::Null));
    root.set("cryptainer_state", CRYPTAINER_STATE_STARTED);
    root.set("cryptainer_format", CRYPTAINER_FORMAT);
    root.set("cryptainer_uid", Value::Uuid(cryptainer_uid));
    root.set("keychain_uid", Value::Uuid(*device_profile.root_keychain_uid()));
    if is_offloaded {
        // Streaming mode: the offloaded marker right away (section 7.2)
        let mut marker = Map::new();
        marker.set("ciphertext_location", CIPHERTEXT_LOCATION_OFFLOADED_NAME);
        root.set("payload_ciphertext_struct", marker);
    } else {
        root.set("payload_ciphertext_struct", Value::Null);
    }
    Ok(CryptainerBase {
        cryptainer,
        payload_symkeys,
    })
}
