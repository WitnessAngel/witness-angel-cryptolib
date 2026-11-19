// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Device profile loading (device profile specification): decode the WA-CBOR sub-profile, check the root
//! structure and format string, validate the cryptoconf and the public key entries, check key constraints, then
//! resolve every asymmetric layer to its entry. A loaded profile is immutable, and serves any number of
//! encryptors.

use alloc::vec::Vec;

use crate::core::cryptoconf_validation::{
    KeyCipherLayerKind, check_allowed_keys, trustee_identities_are_equal, validate_cryptoconf, validate_trustee,
};
use crate::core::error_location_path::{ErrorLocationPath, Located};
use crate::crypto_backend::{ML_KEM_768_PUBLIC_KEY_SIZE, X25519_KEY_SIZE};
use crate::encoding::value_tree::{UUID_SIZE, Value};
use crate::encoding::wacbor_subprofile_decoder::decode_wacbor_subprofile_document;
use crate::error::{Error, ErrorKind, Result};
use crate::limits::EncryptorLimits;
use crate::primitives::asymmetric_key_wrapping::{AsymmetricCipherAlgo, AsymmetricPublicKey};
use crate::primitives::public_key_constraints::{
    check_ml_kem_768_public_key, check_rsa_public_key, check_x25519_public_key,
};

/// The `device_profile_format` of the profiles this library loads.
pub const DEVICE_PROFILE_FORMAT: &str = "flightbox_device_profile_1.0";

/// The lookup key of an entry of `trustee_public_keys`, at the same index: its trustee and key bytes stay in the
/// document.
struct KeyEntry {
    keychain_uid: [u8; UUID_SIZE],
    cipher_algo: AsymmetricCipherAlgo,
}

/// A loaded device profile: a validated cryptoconf and the trustee public keys it needs.
pub struct DeviceProfile {
    document: Value,
    root_keychain_uid: [u8; UUID_SIZE],
    key_entries: Vec<KeyEntry>,
    limits: EncryptorLimits,
}

impl core::fmt::Debug for DeviceProfile {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DeviceProfile")
            .field("key_entry_count", &self.key_entries.len())
            .finish()
    }
}

impl DeviceProfile {
    /// Load a device profile from its WA-CBOR bytes. Errors carry the location of the fault in the document, e.g.
    /// `cryptoconf.payload_cipher_layers[0].key_cipher_layers[1].key_cipher_algo`.
    pub fn load_from_cbor(cbor: &[u8], limits: &EncryptorLimits) -> Result<Self> {
        let document = decode_wacbor_subprofile_document(cbor, limits.max_cbor_nesting_depth())?;
        let mut device_profile = Self {
            document,
            root_keychain_uid: [0; UUID_SIZE],
            key_entries: Vec::new(),
            limits: *limits,
        };
        let mut location = ErrorLocationPath::new();
        match device_profile.check_document(&mut location) {
            Ok(()) => Ok(device_profile),
            Err(kind) => Err(location.into_error(kind)),
        }
    }

    /// The cryptoconf of the profile.
    pub fn cryptoconf(&self) -> &Value {
        // Present in loaded profiles
        self.document.get("cryptoconf").unwrap_or(&Value::Null)
    }

    /// The limits the profile was loaded with, which also apply to the encryptors using it.
    pub fn limits(&self) -> &EncryptorLimits {
        &self.limits
    }

    /// The root keychain uid of the cryptoconf.
    pub fn root_keychain_uid(&self) -> &[u8; UUID_SIZE] {
        &self.root_keychain_uid
    }

    /// The number of trustee public keys of the profile.
    pub fn trustee_public_key_count(&self) -> usize {
        self.key_entries.len()
    }

    fn key_entry_maps(&self) -> &[Value] {
        self.document
            .get("trustee_public_keys")
            .and_then(Value::as_array)
            .unwrap_or(&[])
    }

    fn check_document(&mut self, location: &mut ErrorLocationPath) -> Located<()> {
        check_root_structure(&self.document, location)?;
        let previous_length = location.push_key("cryptoconf");
        let cryptoconf = self.document.get("cryptoconf").ok_or(ErrorKind::InvalidProfile)?;
        validate_cryptoconf(cryptoconf, &self.limits, location)?;
        location.pop(previous_length);
        // Checked by the cryptoconf validation
        self.root_keychain_uid = *cryptoconf
            .get("keychain_uid")
            .and_then(Value::as_uuid)
            .ok_or(ErrorKind::InternalError)?;
        self.key_entries = self.decode_key_entries(location)?;
        self.resolve_all_layers(location)
    }

    /// Decode every entry and check their uniqueness, then their key constraints.
    fn decode_key_entries(&self, location: &mut ErrorLocationPath) -> Located<Vec<KeyEntry>> {
        let previous_length = location.push_key("trustee_public_keys");
        let key_entry_maps = self
            .document
            .get("trustee_public_keys")
            .and_then(Value::as_array)
            .ok_or(ErrorKind::InvalidProfile)?;
        let mut key_entries: Vec<KeyEntry> = Vec::new();
        key_entries
            .try_reserve_exact(key_entry_maps.len())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        for (entry_index, key_entry_map) in key_entry_maps.iter().enumerate() {
            let entry_previous_length = location.push_index(entry_index);
            let key_entry = decode_key_entry(key_entry_map, location)?;
            let trustee = key_entry_map.get("trustee").ok_or(ErrorKind::InternalError)?;
            if find_key_entry(
                key_entry_maps,
                &key_entries,
                trustee,
                &key_entry.keychain_uid,
                key_entry.cipher_algo,
            )
            .is_some()
            {
                return Err(ErrorKind::InvalidProfile); // Duplicate (trustee identity, keychain uid, key algo)
            }
            key_entries.push(key_entry);
            location.pop(entry_previous_length);
        }
        for (entry_index, (key_entry_map, key_entry)) in key_entry_maps.iter().zip(key_entries.iter()).enumerate() {
            let entry_previous_length = location.push_index(entry_index);
            let public_key = borrow_public_key(key_entry_map, key_entry.cipher_algo).ok_or(ErrorKind::InternalError)?;
            check_public_key_constraints(public_key, &self.limits).map_err(|error| error.kind())?;
            location.pop(entry_previous_length);
        }
        location.pop(previous_length);
        Ok(key_entries)
    }

    /// The public key of a validated asymmetric key cipher layer: the entry of its trustee, of its keychain uid
    /// (the root one unless the layer has its own) and of its algorithm. `ErrorKind::MissingPublicKey` when the
    /// profile has none.
    pub(crate) fn find_layer_public_key(&self, key_cipher_layer: &Value) -> Result<AsymmetricPublicKey<'_>> {
        // Layers are validated at load time
        let Some(KeyCipherLayerKind::Asymmetric(cipher_algo)) = KeyCipherLayerKind::of_layer(key_cipher_layer) else {
            return Err(Error::new(ErrorKind::InternalError));
        };
        let keychain_uid = match key_cipher_layer.get("keychain_uid") {
            Some(layer_keychain_uid) => layer_keychain_uid.as_uuid().ok_or(ErrorKind::InternalError)?,
            None => &self.root_keychain_uid,
        };
        let trustee = key_cipher_layer
            .get("key_cipher_trustee")
            .ok_or(ErrorKind::InternalError)?;
        let key_entry_maps = self.key_entry_maps();
        let entry_index = find_key_entry(key_entry_maps, &self.key_entries, trustee, keychain_uid, cipher_algo)
            .ok_or(ErrorKind::MissingPublicKey)?;
        let public_key = key_entry_maps
            .get(entry_index)
            .and_then(|map| borrow_public_key(map, cipher_algo));
        Ok(public_key.ok_or(ErrorKind::InternalError)?)
    }

    fn resolve_all_layers(&self, location: &mut ErrorLocationPath) -> Located<()> {
        let previous_length = location.push_key("cryptoconf");
        let list_previous_length = location.push_key("payload_cipher_layers");
        let payload_cipher_layers = self
            .cryptoconf()
            .get("payload_cipher_layers")
            .and_then(Value::as_array)
            .ok_or(ErrorKind::InternalError)?;
        for (layer_index, payload_cipher_layer) in payload_cipher_layers.iter().enumerate() {
            let layer_previous_length = location.push_index(layer_index);
            self.resolve_key_cipher_layers(payload_cipher_layer, location)?;
            location.pop(layer_previous_length);
        }
        location.pop(list_previous_length);
        location.pop(previous_length);
        Ok(())
    }

    fn resolve_key_cipher_layers(&self, map: &Value, location: &mut ErrorLocationPath) -> Located<()> {
        let previous_length = location.push_key("key_cipher_layers");
        let key_cipher_layers = map
            .get("key_cipher_layers")
            .and_then(Value::as_array)
            .ok_or(ErrorKind::InternalError)?;
        for (layer_index, key_cipher_layer) in key_cipher_layers.iter().enumerate() {
            let layer_previous_length = location.push_index(layer_index);
            self.resolve_key_cipher_layer(key_cipher_layer, location)?;
            location.pop(layer_previous_length);
        }
        location.pop(previous_length);
        Ok(())
    }

    fn resolve_key_cipher_layer(&self, key_cipher_layer: &Value, location: &mut ErrorLocationPath) -> Located<()> {
        if let Some(shards) = key_cipher_layer.get("key_shared_secret_shards") {
            let previous_length = location.push_key("key_shared_secret_shards");
            for (shard_index, shard) in shards.as_array().unwrap_or(&[]).iter().enumerate() {
                let shard_previous_length = location.push_index(shard_index);
                self.resolve_key_cipher_layers(shard, location)?;
                location.pop(shard_previous_length);
            }
            location.pop(previous_length);
            return Ok(());
        }
        if key_cipher_layer.get("key_cipher_layers").is_some() {
            return self.resolve_key_cipher_layers(key_cipher_layer, location);
        }
        self.find_layer_public_key(key_cipher_layer)
            .map(|_| ())
            .map_err(|error| error.kind())
    }
}

fn check_root_structure(document: &Value, location: &mut ErrorLocationPath) -> Located<()> {
    let Some(root) = document.as_map() else {
        return Err(ErrorKind::InvalidProfile);
    };
    // The format comes first: another version may have other root keys
    if root.get("device_profile_format").and_then(Value::as_text) != Some(DEVICE_PROFILE_FORMAT) {
        return location.fail_at_key("device_profile_format", ErrorKind::UnsupportedFormat);
    }
    check_allowed_keys(
        document,
        &["device_profile_format", "cryptoconf", "trustee_public_keys"],
        location,
    )
}

/// The index of the entry of this trustee identity, keychain uid and algorithm, among the decoded ones.
fn find_key_entry(
    key_entry_maps: &[Value],
    key_entries: &[KeyEntry],
    trustee: &Value,
    keychain_uid: &[u8; UUID_SIZE],
    cipher_algo: AsymmetricCipherAlgo,
) -> Option<usize> {
    key_entries
        .iter()
        .zip(key_entry_maps.iter())
        .position(|(key_entry, key_entry_map)| {
            key_entry.cipher_algo == cipher_algo
                && key_entry.keychain_uid == *keychain_uid
                && key_entry_map
                    .get("trustee")
                    .is_some_and(|entry_trustee| trustee_identities_are_equal(entry_trustee, trustee))
        })
}

/// Structure of one entry: exactly `trustee`, `keychain_uid`, `key_algo` and `public_key`.
fn decode_key_entry(key_entry_map: &Value, location: &mut ErrorLocationPath) -> Located<KeyEntry> {
    let Some(entries) = key_entry_map.as_map() else {
        return Err(ErrorKind::InvalidProfile);
    };
    check_allowed_keys(
        key_entry_map,
        &["trustee", "keychain_uid", "key_algo", "public_key"],
        location,
    )?;
    let previous_length = location.push_key("trustee");
    let trustee = entries.get("trustee").ok_or(ErrorKind::InvalidProfile)?;
    validate_trustee(trustee, location)?;
    location.pop(previous_length);
    let Some(keychain_uid) = entries.get("keychain_uid").and_then(Value::as_uuid) else {
        return location.fail_at_key("keychain_uid", ErrorKind::InvalidProfile);
    };
    let Some(cipher_algo) = entries
        .get("key_algo")
        .and_then(Value::as_text)
        .and_then(AsymmetricCipherAlgo::from_name)
    else {
        return location.fail_at_key("key_algo", ErrorKind::InvalidProfile);
    };
    check_public_key_structure(key_entry_map, cipher_algo, location)?;
    Ok(KeyEntry {
        keychain_uid: *keychain_uid,
        cipher_algo,
    })
}

/// `public_key`: a map with exactly the byte strings `modulus` and `public_exponent` for RSA_OAEP, a byte string
/// of the key size for the others.
fn check_public_key_structure(
    key_entry_map: &Value,
    cipher_algo: AsymmetricCipherAlgo,
    location: &mut ErrorLocationPath,
) -> Located<()> {
    let previous_length = location.push_key("public_key");
    let public_key = key_entry_map.get("public_key").ok_or(ErrorKind::InvalidProfile)?;
    match cipher_algo {
        AsymmetricCipherAlgo::RsaOaep => {
            let entries = public_key.as_map().ok_or(ErrorKind::InvalidProfile)?;
            check_allowed_keys(public_key, &["modulus", "public_exponent"], location)?;
            for key in ["modulus", "public_exponent"] {
                if entries.get(key).and_then(Value::as_bytes).is_none() {
                    return location.fail_at_key(key, ErrorKind::InvalidProfile);
                }
            }
        }
        AsymmetricCipherAlgo::EciesX25519 | AsymmetricCipherAlgo::MlKem768 => {
            let expected_length = if cipher_algo == AsymmetricCipherAlgo::EciesX25519 {
                X25519_KEY_SIZE
            } else {
                ML_KEM_768_PUBLIC_KEY_SIZE
            };
            if public_key.as_bytes().map(<[u8]>::len) != Some(expected_length) {
                return Err(ErrorKind::InvalidProfile);
            }
        }
    }
    location.pop(previous_length);
    Ok(())
}

/// The public key of an entry whose structure was checked.
fn borrow_public_key(key_entry_map: &Value, cipher_algo: AsymmetricCipherAlgo) -> Option<AsymmetricPublicKey<'_>> {
    let public_key = key_entry_map.get("public_key")?;
    Some(match cipher_algo {
        AsymmetricCipherAlgo::RsaOaep => AsymmetricPublicKey::RsaOaep {
            modulus: public_key.get("modulus")?.as_bytes()?,
            public_exponent: public_key.get("public_exponent")?.as_bytes()?,
        },
        AsymmetricCipherAlgo::EciesX25519 => AsymmetricPublicKey::EciesX25519(public_key.as_bytes()?),
        AsymmetricCipherAlgo::MlKem768 => AsymmetricPublicKey::MlKem768(public_key.as_bytes()?),
    })
}

fn check_public_key_constraints(public_key: AsymmetricPublicKey<'_>, limits: &EncryptorLimits) -> Result<()> {
    match public_key {
        AsymmetricPublicKey::RsaOaep {
            modulus,
            public_exponent,
        } => check_rsa_public_key(modulus, public_exponent, limits.max_rsa_modulus_bits()),
        AsymmetricPublicKey::EciesX25519(key_bytes) => check_x25519_public_key(key_bytes),
        AsymmetricPublicKey::MlKem768(key_bytes) => check_ml_kem_768_public_key(key_bytes),
    }
}
