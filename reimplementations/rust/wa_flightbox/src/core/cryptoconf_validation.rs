// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Cryptoconf validation: a mirror of `CRYPTOCONF_SCHEMA_PYTHON` of wacryptolib (closed maps, known algorithms,
//! trustee grammar), plus the rules of devices: a mandatory root keychain uid, no signature, and a cap on the
//! nesting of key cipher layers. Checks run in the order of the C library, so that both report the same fault at
//! the same location.

use crate::core::error_location_path::{ErrorLocationPath, Located};
use crate::encoding::value_tree::Value;
use crate::error::ErrorKind;
use crate::limits::EncryptorLimits;
use crate::primitives::asymmetric_key_wrapping::AsymmetricCipherAlgo;
use crate::primitives::symmetric_key_generation::SymmetricCipherAlgo;

/// The `key_cipher_algo` of shared secret layers.
pub(crate) const SHARED_SECRET_ALGO_MARKER: &str = "[SHARED_SECRET]";

/// SUPPORTED_HASH_ALGOS and SUPPORTED_SIGNATURE_ALGOS of wacryptolib, for the signature conf grammar
const HASH_ALGO_NAMES: [&str; 4] = ["SHA256", "SHA512", "SHA3_256", "SHA3_512"];
const SIGNATURE_ALGO_NAMES: [&str; 4] = ["DSA_DSS", "ECC_DSS", "ML_DSA_65", "RSA_PSS"];

/// What a key cipher layer is, by its `key_cipher_algo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyCipherLayerKind {
    SharedSecret,
    Symmetric(SymmetricCipherAlgo),
    Asymmetric(AsymmetricCipherAlgo),
}

impl KeyCipherLayerKind {
    pub(crate) fn from_algo_name(name: &str) -> Option<Self> {
        if name == SHARED_SECRET_ALGO_MARKER {
            return Some(Self::SharedSecret);
        }
        if let Some(algo) = SymmetricCipherAlgo::from_name(name) {
            return Some(Self::Symmetric(algo));
        }
        AsymmetricCipherAlgo::from_name(name).map(Self::Asymmetric)
    }

    /// The kind of a validated layer.
    pub(crate) fn of_layer(layer: &Value) -> Option<Self> {
        Self::from_algo_name(layer.get("key_cipher_algo")?.as_text()?)
    }
}

fn text_is_one_of(value: Option<&Value>, names: &[&str]) -> bool {
    value.and_then(Value::as_text).is_some_and(|text| names.contains(&text))
}

fn text_is(value: Option<&Value>, expected: &str) -> bool {
    value.and_then(Value::as_text) == Some(expected)
}

fn check_map(value: &Value) -> Located<()> {
    if value.as_map().is_some() {
        Ok(())
    } else {
        Err(ErrorKind::InvalidProfile)
    }
}

/// `ErrorKind::InvalidProfile` at the first key of `map`, in key order, that is not in `allowed_keys`.
pub(crate) fn check_allowed_keys(map: &Value, allowed_keys: &[&str], location: &mut ErrorLocationPath) -> Located<()> {
    let Some(map) = map.as_map() else {
        return Err(ErrorKind::InvalidProfile);
    };
    for (key, _) in map.iter() {
        if !allowed_keys.contains(&key) {
            return location.fail_at_key(key, ErrorKind::InvalidProfile);
        }
    }
    Ok(())
}

/// `ErrorKind::InvalidProfile` at `key` unless its value is present (or optional and absent) and accepted by
/// `has_expected_type`.
fn check_typed_value(
    map: &Value,
    key: &str,
    is_required: bool,
    has_expected_type: fn(&Value) -> bool,
    location: &mut ErrorLocationPath,
) -> Located<()> {
    match map.get(key) {
        None if !is_required => Ok(()),
        Some(value) if has_expected_type(value) => Ok(()),
        _ => location.fail_at_key(key, ErrorKind::InvalidProfile),
    }
}

fn is_uuid(value: &Value) -> bool {
    value.as_uuid().is_some()
}

fn is_text(value: &Value) -> bool {
    value.as_text().is_some()
}

fn is_array(value: &Value) -> bool {
    value.as_array().is_some()
}

/// A trustee: `local_keyfactory`, `authenticator` (with its keystore uid and optional owner) or `jsonrpc_api`
/// (with its URL), without any other key.
pub(crate) fn validate_trustee(trustee: &Value, location: &mut ErrorLocationPath) -> Located<()> {
    check_map(trustee)?;
    match trustee.get("trustee_type").and_then(Value::as_text) {
        Some("local_keyfactory") => check_allowed_keys(trustee, &["trustee_type"], location),
        Some("authenticator") => {
            check_allowed_keys(trustee, &["trustee_type", "keystore_uid", "keystore_owner"], location)?;
            check_typed_value(trustee, "keystore_uid", true, is_uuid, location)?;
            check_typed_value(trustee, "keystore_owner", false, is_text, location)
        }
        Some("jsonrpc_api") => {
            check_allowed_keys(trustee, &["trustee_type", "jsonrpc_url"], location)?;
            check_typed_value(trustee, "jsonrpc_url", true, is_text, location)
        }
        _ => location.fail_at_key("trustee_type", ErrorKind::InvalidProfile),
    }
}

/// Equality of two UUID leaves or of two text leaves, both absent counting as equal.
fn leaves_are_equal(value_a: Option<&Value>, value_b: Option<&Value>) -> bool {
    match (value_a, value_b) {
        (None, None) => true,
        (Some(Value::Uuid(uuid_a)), Some(Value::Uuid(uuid_b))) => uuid_a == uuid_b,
        (Some(Value::Text(text_a)), Some(Value::Text(text_b))) => text_a == text_b,
        _ => false,
    }
}

/// Whether two validated trustees designate the same one: same type, and same keystore uid (authenticators) or
/// same URL (JSON-RPC APIs). The keystore owner is a label, not part of the identity.
pub(crate) fn trustee_identities_are_equal(trustee_a: &Value, trustee_b: &Value) -> bool {
    let trustee_type = trustee_a.get("trustee_type");
    if !leaves_are_equal(trustee_type, trustee_b.get("trustee_type")) {
        return false;
    }
    if text_is(trustee_type, "authenticator") {
        return leaves_are_equal(trustee_a.get("keystore_uid"), trustee_b.get("keystore_uid"));
    }
    if text_is(trustee_type, "jsonrpc_api") {
        return leaves_are_equal(trustee_a.get("jsonrpc_url"), trustee_b.get("jsonrpc_url"));
    }
    true
}

/// A signature conf of a signature list: `payload_digest_algo`, `payload_signature_algo`,
/// `payload_signature_trustee` and an optional `keychain_uid`.
fn validate_signature_conf(signature_conf: &Value, location: &mut ErrorLocationPath) -> Located<()> {
    check_map(signature_conf)?;
    check_allowed_keys(
        signature_conf,
        &[
            "payload_digest_algo",
            "payload_signature_algo",
            "payload_signature_trustee",
            "keychain_uid",
        ],
        location,
    )?;
    if !text_is_one_of(signature_conf.get("payload_digest_algo"), &HASH_ALGO_NAMES) {
        return location.fail_at_key("payload_digest_algo", ErrorKind::InvalidProfile);
    }
    if !text_is_one_of(signature_conf.get("payload_signature_algo"), &SIGNATURE_ALGO_NAMES) {
        return location.fail_at_key("payload_signature_algo", ErrorKind::InvalidProfile);
    }
    let previous_length = location.push_key("payload_signature_trustee");
    let trustee = signature_conf
        .get("payload_signature_trustee")
        .ok_or(ErrorKind::InvalidProfile)?;
    validate_trustee(trustee, location)?;
    location.pop(previous_length);
    check_typed_value(signature_conf, "keychain_uid", false, is_uuid, location)
}

/// A signature list, validated item by item, then refused if non-empty (signatures are not supported yet).
fn validate_signature_list(map: &Value, key: &str, location: &mut ErrorLocationPath) -> Located<()> {
    let previous_length = location.push_key(key);
    let signature_list = map
        .get(key)
        .and_then(Value::as_array)
        .ok_or(ErrorKind::InvalidProfile)?;
    for (item_index, signature_conf) in signature_list.iter().enumerate() {
        let item_previous_length = location.push_index(item_index);
        validate_signature_conf(signature_conf, location)?;
        location.pop(item_previous_length);
    }
    if !signature_list.is_empty() {
        return Err(ErrorKind::UnsupportedSignature);
    }
    location.pop(previous_length);
    Ok(())
}

fn validate_shared_secret_layer(
    layer: &Value,
    nesting_level: usize,
    limits: &EncryptorLimits,
    location: &mut ErrorLocationPath,
) -> Located<()> {
    check_allowed_keys(
        layer,
        &[
            "key_cipher_algo",
            "key_shared_secret_shards",
            "key_shared_secret_threshold",
        ],
        location,
    )?;
    check_typed_value(layer, "key_shared_secret_shards", true, is_array, location)?;
    let shards = layer
        .get("key_shared_secret_shards")
        .and_then(Value::as_array)
        .ok_or(ErrorKind::InternalError)?;
    let previous_length = location.push_key("key_shared_secret_shards");
    for (shard_index, shard) in shards.iter().enumerate() {
        let shard_previous_length = location.push_index(shard_index);
        check_map(shard)?;
        check_allowed_keys(shard, &["key_cipher_layers"], location)?;
        validate_key_cipher_layers(shard, nesting_level.saturating_add(1), limits, location)?;
        location.pop(shard_previous_length);
    }
    location.pop(previous_length);
    let threshold = layer.get("key_shared_secret_threshold").and_then(Value::as_integer);
    match threshold.map(u64::try_from) {
        Some(Ok(threshold)) if threshold >= 1 && threshold <= shards.len() as u64 => Ok(()),
        _ => location.fail_at_key("key_shared_secret_threshold", ErrorKind::InvalidProfile),
    }
}

fn validate_key_cipher_layer(
    layer: &Value,
    nesting_level: usize,
    limits: &EncryptorLimits,
    location: &mut ErrorLocationPath,
) -> Located<()> {
    check_map(layer)?;
    let Some(algo_name) = layer.get("key_cipher_algo").and_then(Value::as_text) else {
        return location.fail_at_key("key_cipher_algo", ErrorKind::InvalidProfile);
    };
    match KeyCipherLayerKind::from_algo_name(algo_name) {
        Some(KeyCipherLayerKind::SharedSecret) => validate_shared_secret_layer(layer, nesting_level, limits, location),
        Some(KeyCipherLayerKind::Symmetric(_)) => {
            check_allowed_keys(layer, &["key_cipher_algo", "key_cipher_layers"], location)?;
            validate_key_cipher_layers(layer, nesting_level.saturating_add(1), limits, location)
        }
        Some(KeyCipherLayerKind::Asymmetric(_)) => {
            check_allowed_keys(
                layer,
                &["key_cipher_algo", "key_cipher_trustee", "keychain_uid"],
                location,
            )?;
            let previous_length = location.push_key("key_cipher_trustee");
            let trustee = layer.get("key_cipher_trustee").ok_or(ErrorKind::InvalidProfile)?;
            validate_trustee(trustee, location)?;
            location.pop(previous_length);
            check_typed_value(layer, "keychain_uid", false, is_uuid, location)
        }
        None => location.fail_at_key("key_cipher_algo", ErrorKind::InvalidProfile),
    }
}

/// The non-empty `key_cipher_layers` list of `map`, at `nesting_level` (1 for those of payload cipher layers).
fn validate_key_cipher_layers(
    map: &Value,
    nesting_level: usize,
    limits: &EncryptorLimits,
    location: &mut ErrorLocationPath,
) -> Located<()> {
    let previous_length = location.push_key("key_cipher_layers");
    let layers = map
        .get("key_cipher_layers")
        .and_then(Value::as_array)
        .ok_or(ErrorKind::InvalidProfile)?;
    if layers.is_empty() {
        return Err(ErrorKind::InvalidProfile);
    }
    if nesting_level > limits.max_key_cipher_nesting_depth() {
        return Err(ErrorKind::NestingTooDeep);
    }
    for (layer_index, layer) in layers.iter().enumerate() {
        let layer_previous_length = location.push_index(layer_index);
        validate_key_cipher_layer(layer, nesting_level, limits, location)?;
        location.pop(layer_previous_length);
    }
    location.pop(previous_length);
    Ok(())
}

fn validate_payload_cipher_layer(
    layer: &Value,
    limits: &EncryptorLimits,
    location: &mut ErrorLocationPath,
) -> Located<()> {
    check_map(layer)?;
    check_allowed_keys(
        layer,
        &[
            "payload_cipher_algo",
            "payload_ciphertext_signatures",
            "payload_signatures",
            "key_cipher_layers",
        ],
        location,
    )?;
    let payload_cipher_algo = layer.get("payload_cipher_algo").and_then(Value::as_text);
    if payload_cipher_algo.and_then(SymmetricCipherAlgo::from_name).is_none() {
        return location.fail_at_key("payload_cipher_algo", ErrorKind::InvalidProfile);
    }
    // The Python schema is an Or of two closed schemas, one per signature list name: exactly one is required
    let has_signatures = layer.get("payload_ciphertext_signatures").is_some();
    let has_legacy_signatures = layer.get("payload_signatures").is_some();
    if has_signatures && has_legacy_signatures {
        return Err(ErrorKind::InvalidProfile);
    }
    validate_signature_list(
        layer,
        if has_legacy_signatures {
            "payload_signatures"
        } else {
            "payload_ciphertext_signatures"
        },
        location,
    )?;
    validate_key_cipher_layers(layer, 1, limits, location)
}

/// Validate a cryptoconf. On failure, `location` points at the fault, relative to its value on entry.
pub(crate) fn validate_cryptoconf(
    cryptoconf: &Value,
    limits: &EncryptorLimits,
    location: &mut ErrorLocationPath,
) -> Located<()> {
    check_map(cryptoconf)?;
    check_allowed_keys(
        cryptoconf,
        &["payload_cipher_layers", "payload_plaintext_signatures", "keychain_uid"],
        location,
    )?;
    if cryptoconf.get("payload_plaintext_signatures").is_some() {
        validate_signature_list(cryptoconf, "payload_plaintext_signatures", location)?;
    }
    let previous_length = location.push_key("payload_cipher_layers");
    let payload_cipher_layers = cryptoconf
        .get("payload_cipher_layers")
        .and_then(Value::as_array)
        .ok_or(ErrorKind::InvalidProfile)?;
    if payload_cipher_layers.is_empty() {
        return Err(ErrorKind::InvalidProfile);
    }
    for (layer_index, layer) in payload_cipher_layers.iter().enumerate() {
        let layer_previous_length = location.push_index(layer_index);
        validate_payload_cipher_layer(layer, limits, location)?;
        location.pop(layer_previous_length);
    }
    location.pop(previous_length);
    // Optional in wacryptolib, mandatory here
    check_typed_value(cryptoconf, "keychain_uid", true, is_uuid, location)
}
