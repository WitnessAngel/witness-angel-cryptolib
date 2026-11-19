// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Cryptainer creation, steps 1 to 3: the nesting of key ciphertexts (encryptor specification, section 6.7), the
//! root and layer fields in each format, the payload pipeline fed in chunks against one-shot encryptions, and the
//! lifecycle of the encryptor (options, metadata checks, failed state, hook and sink failures).
//!
//! Cryptainers are read back with the test-only reader, and their key ciphertexts are checked by their shapes and
//! sizes: decrypting them is the job of the interoperability suite, with wacryptolib.

use wa_flightbox::{
    CryptainerEncryptor, DeviceProfile, DocumentFormat, EncryptorLimits, EncryptorOptions, ErrorKind, Map,
    NoPayloadSink, OFFLOADED_PAYLOAD_SUFFIX, OutputSink, Result, SinkError, Value, encrypt_payload_in_one_call,
    internals, write_document,
};
use wa_flightbox_backend_conformance::test_support::{
    DeterministicHooks, device_profile_sample, enabled_document_formats, read_document,
};
use wa_flightbox_backend_rustcrypto::RustCryptoBackend;

type Encryptor<S = NoPayloadSink> = CryptainerEncryptor<RustCryptoBackend, S>;

/// The root keychain uid of the synthetic device profile samples.
const SAMPLES_ROOT_KEYCHAIN_UID: [u8; 16] = [0x0d, 0x0d, 0x0d, 0x0d, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
const RSA_MODULUS_LENGTH: usize = 256;

fn load_sample(name: &str) -> DeviceProfile {
    DeviceProfile::load_from_cbor(&device_profile_sample(name), &EncryptorLimits::default())
        .unwrap_or_else(|error| panic!("sample {name}: {error}"))
}

fn build_payload(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index * 7 + 3) as u8).collect()
}

/// `{"device_id": "fb-07", "sequence": 42}`
fn sample_metadata() -> Value {
    Value::Map(Map::from_entries([("device_id", Value::from("fb-07")), ("sequence", Value::from(42i64))]).unwrap())
}

fn options_for(format: DocumentFormat) -> EncryptorOptions {
    EncryptorOptions {
        document_format: format,
        ..EncryptorOptions::default()
    }
}

/// A value by its path, such as `payload_cipher_layers[1].key_cipher_layers[0]`.
fn get_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut node = root;
    for step in path.split('.') {
        let (key, indices) = step.split_once('[').map_or((step, ""), |(key, indices)| (key, indices));
        if !key.is_empty() {
            node = node.get(key)?;
        }
        for index in indices.split('[').filter(|index| !index.is_empty()) {
            node = node
                .as_array()?
                .get(index.trim_end_matches(']').parse::<usize>().unwrap())?;
        }
    }
    Some(node)
}

fn path<'a>(root: &'a Value, path_text: &str) -> &'a Value {
    get_path(root, path_text).unwrap_or_else(|| panic!("no {path_text} in {root:?}"))
}

fn item_count(value: &Value) -> usize {
    value
        .as_map()
        .map(Map::len)
        .or_else(|| value.as_array().map(<[Value]>::len))
        .expect("a map or an array")
}

fn bytes_length(value: &Value) -> usize {
    value.as_bytes().expect("a byte string").len()
}

/// What an encryption gave: the cryptainer bytes, the tree read back from them, and the offloaded payload.
struct Encryption {
    cryptainer_bytes: Vec<u8>,
    cryptainer: Value,
    offloaded_ciphertext: Option<Vec<u8>>,
}

/// Encrypt `payload` in chunks of `chunk_length` bytes, write the cryptainer and read it back.
fn encrypt_payload(
    hooks: &mut DeterministicHooks,
    device_profile: &DeviceProfile,
    metadata: Option<&Value>,
    options: &EncryptorOptions,
    is_offloaded: bool,
    payload: &[u8],
    chunk_length: usize,
) -> Result<Encryption> {
    let mut offloaded_ciphertext = Vec::new();
    let mut cryptainer_bytes = Vec::new();
    let finished = if is_offloaded {
        let mut encryptor =
            Encryptor::create_offloaded(device_profile, metadata, options, hooks, &mut offloaded_ciphertext)?;
        for chunk in payload.chunks(chunk_length.max(1)) {
            encryptor.encrypt_payload_chunk(chunk)?;
        }
        encryptor.finalize()?
    } else {
        let mut encryptor = Encryptor::create(device_profile, metadata, options, hooks)?;
        for chunk in payload.chunks(chunk_length.max(1)) {
            encryptor.encrypt_payload_chunk(chunk)?;
        }
        encryptor.finalize()?
    };
    finished.write_cryptainer(&mut cryptainer_bytes)?;
    let format = finished.document_format();
    assert_ne!(format, DocumentFormat::BuildDefault);
    let cryptainer = read_document(format, &cryptainer_bytes);
    assert_eq!(
        &cryptainer,
        finished.cryptainer(),
        "the cryptainer read back equals the tree of the encryptor"
    );
    Ok(Encryption {
        cryptainer_bytes,
        cryptainer,
        offloaded_ciphertext: is_offloaded.then_some(offloaded_ciphertext),
    })
}

// Lengths of the structures serialized in key ciphertexts: they only depend on the lengths of their bytes

fn symkey_length(format: DocumentFormat, cipher_algo: &str) -> usize {
    let iv_or_nonce = vec![0u8; internals::symmetric_iv_or_nonce_length(cipher_algo).unwrap()];
    internals::serialize_symkey(format, cipher_algo, &[0; 32], &iv_or_nonce)
        .unwrap()
        .len()
}

fn key_struct_length(format: DocumentFormat, key_bytes_length: usize, metadata: Option<&Value>) -> usize {
    internals::serialize_key_struct(format, &vec![0; key_bytes_length], metadata)
        .unwrap()
        .len()
}

fn shard_length(format: DocumentFormat, shard_index: usize, shard_bytes_length: usize) -> usize {
    internals::serialize_shard(format, shard_index, &vec![0; shard_bytes_length])
        .unwrap()
        .len()
}

/// `S_F({"ciphertext_chunks": [bytes(modulus_length)] * ceil(plaintext_length / 60)})`
fn rsa_cipherdict_length(format: DocumentFormat, plaintext_length: usize) -> usize {
    let chunks = vec![Value::Bytes(vec![0; RSA_MODULUS_LENGTH]); plaintext_length.div_ceil(60)];
    let cipherdict = Value::Map(Map::from_entries([("ciphertext_chunks", Value::Array(chunks))]).unwrap());
    let mut serialized = Vec::new();
    write_document(&cipherdict, format, &mut serialized).unwrap();
    serialized.len()
}

/// Check an asymmetric cipherdict read back from a key ciphertext, wrapping a key struct of `key_bytes_length`
/// bytes.
fn check_asymmetric_cipherdict(
    format: DocumentFormat,
    cipherdict: &Value,
    cipher_algo: &str,
    key_bytes_length: usize,
    metadata: Option<&Value>,
) {
    let key_struct_length = key_struct_length(format, key_bytes_length, metadata);
    if cipher_algo == "RSA_OAEP" {
        assert_eq!(item_count(cipherdict), 1);
        let chunks = path(cipherdict, "ciphertext_chunks").as_array().unwrap();
        assert_eq!(chunks.len(), key_struct_length.div_ceil(60));
        assert!(chunks.iter().all(|chunk| bytes_length(chunk) == RSA_MODULUS_LENGTH));
    } else {
        assert_eq!(item_count(cipherdict), 2);
        let kem_ciphertext_length = if cipher_algo == "ECIES_X25519" { 32 } else { 1088 };
        assert_eq!(bytes_length(path(cipherdict, "kem_ciphertext")), kem_ciphertext_length);
        assert_eq!(bytes_length(path(cipherdict, "ciphertext")), key_struct_length + 16);
    }
}

fn read_key_ciphertext(format: DocumentFormat, key_ciphertext: &Value) -> Value {
    read_document(format, key_ciphertext.as_bytes().expect("a key ciphertext"))
}

/// `nested_all_layer_kinds`:
///   payload layer 0: AES_EAX, key through [ECIES_X25519 local]
///   payload layer 1: CHACHA20_POLY1305, key through [RSA_OAEP authenticator, SHARED_SECRET 2 of 3:
///       shard 1: [ECIES_X25519 other authenticator], shard 2: [ML_KEM_768 jsonrpc],
///       shard 3: [CHACHA20_POLY1305 symmetric layer, its sub-key through [RSA_OAEP local, layer keychain uid]]]
#[test]
fn nested_cryptainer_has_the_nesting_of_the_specification_in_each_format() {
    for (format_index, format) in enabled_document_formats().into_iter().enumerate() {
        let is_cbor = format == DocumentFormat::Cbor;
        let device_profile = load_sample("nested_all_layer_kinds");
        let metadata = sample_metadata();
        let mut hooks = DeterministicHooks::new(71 + format_index as u64);
        let payload = build_payload(4099);
        let encryption = encrypt_payload(
            &mut hooks,
            &device_profile,
            Some(&metadata),
            &options_for(format),
            false,
            &payload,
            1000,
        )
        .unwrap();
        let cryptainer = &encryption.cryptainer;
        assert!(encryption.offloaded_ciphertext.is_none());

        let payload_layer_0 = path(cryptainer, "payload_cipher_layers[0]");
        let payload_layer_1 = path(cryptainer, "payload_cipher_layers[1]");
        let rsa_layer = path(payload_layer_1, "key_cipher_layers[0]");
        let shared_secret_layer = path(payload_layer_1, "key_cipher_layers[1]");
        let symmetric_layer = path(shared_secret_layer, "key_shared_secret_shards[2].key_cipher_layers[0]");
        let rsa_local_layer = path(symmetric_layer, "key_cipher_layers[0]");

        // Root fields (section 9.1): nothing else than the cryptoconf's fields and the 5 added ones
        assert_eq!(item_count(cryptainer), 7);
        assert_eq!(path(cryptainer, "cryptainer_state").as_text(), Some("FINISHED"));
        assert_eq!(path(cryptainer, "cryptainer_format").as_text(), Some("cryptainer_1.0"));
        let cryptainer_uid = path(cryptainer, "cryptainer_uid").as_uuid().expect("a UUID");
        assert_eq!(
            cryptainer_uid[..6],
            DeterministicHooks::DEFAULT_TIME.to_be_bytes()[2..],
            "a UUID0"
        );
        assert_eq!(
            path(cryptainer, "keychain_uid").as_uuid(),
            Some(&SAMPLES_ROOT_KEYCHAIN_UID)
        );
        assert_eq!(path(cryptainer, "cryptainer_metadata"), &metadata);
        assert_eq!(item_count(path(cryptainer, "payload_ciphertext_struct")), 2);
        assert_eq!(
            path(cryptainer, "payload_ciphertext_struct.ciphertext_location").as_text(),
            Some("inline")
        );
        // AES_EAX then CHACHA20_POLY1305: no padding
        assert_eq!(
            bytes_length(path(cryptainer, "payload_ciphertext_struct.ciphertext_value")),
            payload.len()
        );

        // Payload layer fields: MACs, signature lists, format fields
        for payload_layer in [payload_layer_0, payload_layer_1] {
            assert_eq!(item_count(path(payload_layer, "payload_macs")), 1);
            assert_eq!(bytes_length(path(payload_layer, "payload_macs.tag")), 16);
            assert_eq!(
                path(payload_layer, "payload_ciphertext_signatures")
                    .as_array()
                    .map(<[Value]>::len),
                Some(0)
            );
            assert_eq!(item_count(payload_layer), if is_cbor { 6 } else { 5 });
            assert_eq!(
                get_path(payload_layer, "key_ciphertext_format").and_then(Value::as_text),
                is_cbor.then_some("cbor")
            );
        }

        // Only symmetric key layers receive fields: asymmetric layers, shared secrets and shard confs are unchanged
        assert_eq!(item_count(rsa_layer), 2);
        assert_eq!(item_count(shared_secret_layer), 3);
        assert_eq!(item_count(path(shared_secret_layer, "key_shared_secret_shards[0]")), 1);
        assert_eq!(item_count(rsa_local_layer), 3, "its own keychain uid only");
        assert_eq!(item_count(symmetric_layer), if is_cbor { 4 } else { 3 });
        assert_eq!(
            get_path(symmetric_layer, "key_ciphertext_format").and_then(Value::as_text),
            is_cbor.then_some("cbor")
        );

        // Payload layer 0: ECIES_X25519(S_F(key struct of S_F(AES_EAX symkey)))
        let cipherdict = read_key_ciphertext(format, path(payload_layer_0, "key_ciphertext"));
        check_asymmetric_cipherdict(
            format,
            &cipherdict,
            "ECIES_X25519",
            symkey_length(format, "AES_EAX"),
            Some(&metadata),
        );

        // Symmetric layer: its sub-symkey through RSA_OAEP (local)
        let chacha_symkey_length = symkey_length(format, "CHACHA20_POLY1305");
        let cipherdict = read_key_ciphertext(format, path(symmetric_layer, "key_ciphertext"));
        check_asymmetric_cipherdict(format, &cipherdict, "RSA_OAEP", chacha_symkey_length, Some(&metadata));

        // Payload layer 1: the last layer is the shared secret, whose shards split S_F(RSA_OAEP cipherdict)
        let shard_ciphertexts_dict = read_key_ciphertext(format, path(payload_layer_1, "key_ciphertext"));
        assert_eq!(item_count(&shard_ciphertexts_dict), 1);
        let shard_ciphertexts = path(&shard_ciphertexts_dict, "shard_ciphertexts").as_array().unwrap();
        assert_eq!(shard_ciphertexts.len(), 3);
        let secret_length =
            rsa_cipherdict_length(format, key_struct_length(format, chacha_symkey_length, Some(&metadata)));
        let shard_bytes_length = secret_length / 16 * 16 + 16; // PKCS#7 padded
        for (shard_index, shard_ciphertext) in shard_ciphertexts.iter().enumerate() {
            let serialized_shard_length = shard_length(format, shard_index, shard_bytes_length);
            let cipherdict = read_key_ciphertext(format, shard_ciphertext);
            match shard_index {
                0 => check_asymmetric_cipherdict(
                    format,
                    &cipherdict,
                    "ECIES_X25519",
                    serialized_shard_length,
                    Some(&metadata),
                ),
                1 => check_asymmetric_cipherdict(
                    format,
                    &cipherdict,
                    "ML_KEM_768",
                    serialized_shard_length,
                    Some(&metadata),
                ),
                _ => {
                    // One-shot cipherdict of the symmetric layer over S_F([3, shard3])
                    assert_eq!(item_count(&cipherdict), 2);
                    assert_eq!(bytes_length(path(&cipherdict, "ciphertext")), serialized_shard_length);
                    assert_eq!(bytes_length(path(&cipherdict, "tag")), 16);
                }
            }
        }
    }
}

/// Minimal profile (AES_CBC, RSA_OAEP), no metadata: `payload_macs` is `{}`, the ciphertext is padded, and the
/// metadata are null everywhere.
#[test]
fn minimal_cryptainer_without_metadata() {
    for format in enabled_document_formats() {
        let device_profile = load_sample("minimal_rsa_authenticator");
        let mut hooks = DeterministicHooks::new(72);
        for payload_length in [0usize, 1, 15, 16, 17, 4096, 10000] {
            let payload = build_payload(payload_length);
            let encryption = encrypt_payload(
                &mut hooks,
                &device_profile,
                None,
                &options_for(format),
                false,
                &payload,
                7,
            )
            .unwrap();
            let cryptainer = &encryption.cryptainer;
            assert!(path(cryptainer, "cryptainer_metadata").is_null());
            assert_eq!(
                path(cryptainer, "payload_cipher_layers[0].payload_macs"),
                &Value::Map(Map::new())
            );
            assert_eq!(item_count(path(cryptainer, "payload_ciphertext_struct")), 2);
            assert_eq!(
                bytes_length(path(cryptainer, "payload_ciphertext_struct.ciphertext_value")),
                (payload_length / 16 + 1) * 16
            );
            let cipherdict = read_key_ciphertext(format, path(cryptainer, "payload_cipher_layers[0].key_ciphertext"));
            check_asymmetric_cipherdict(format, &cipherdict, "RSA_OAEP", symkey_length(format, "AES_CBC"), None);
            // 2 RSA-OAEP chunks in WA-CBOR, against 6 in Extended JSON
            let expected_chunk_count = if format == DocumentFormat::Cbor { 2 } else { 6 };
            assert_eq!(item_count(path(&cipherdict, "ciphertext_chunks")), expected_chunk_count);
        }
    }
}

#[test]
fn every_cryptainer_has_fresh_secrets() {
    let format = enabled_document_formats()[0];
    let device_profile = load_sample("nested_all_layer_kinds");
    let mut hooks = DeterministicHooks::new(73);
    let payload = build_payload(100);
    let encrypt = |hooks: &mut DeterministicHooks| {
        encrypt_payload(hooks, &device_profile, None, &options_for(format), false, &payload, 100)
            .unwrap()
            .cryptainer
    };
    let (first, second) = (encrypt(&mut hooks), encrypt(&mut hooks));
    for different_field in [
        "cryptainer_uid",
        "payload_cipher_layers[1].key_ciphertext",
        "payload_ciphertext_struct",
    ] {
        assert_ne!(
            path(&first, different_field),
            path(&second, different_field),
            "{different_field}"
        );
    }
    assert_eq!(path(&first, "keychain_uid"), path(&second, "keychain_uid"));
    // The same generator state gives the same cryptainer: nothing else than the hooks is a source of randomness
    let (mut hooks_a, mut hooks_b) = (DeterministicHooks::new(5), DeterministicHooks::new(5));
    assert_eq!(encrypt(&mut hooks_a), encrypt(&mut hooks_b));
}

#[test]
fn root_and_layer_fields_of_each_sample_location_and_format() {
    for format in enabled_document_formats() {
        let is_cbor = format == DocumentFormat::Cbor;
        for (sample_name, layer_algos) in [
            ("nested_all_layer_kinds", &["AES_EAX", "CHACHA20_POLY1305"][..]),
            // payload_signatures: [] becomes payload_ciphertext_signatures
            ("legacy_payload_signatures_alias", &["AES_CBC"]),
            ("empty_plaintext_signatures", &["AES_CBC"]),
            ("minimal_rsa_authenticator", &["AES_CBC"]),
        ] {
            for is_offloaded in [false, true] {
                let device_profile = load_sample(sample_name);
                let cryptoconf = device_profile.cryptoconf();
                let mut hooks = DeterministicHooks::new(74);
                let payload = build_payload(50);
                let encryption = encrypt_payload(
                    &mut hooks,
                    &device_profile,
                    None,
                    &options_for(format),
                    is_offloaded,
                    &payload,
                    50,
                )
                .unwrap();
                let cryptainer = &encryption.cryptainer;

                // The cryptoconf fields, and the 5 added ones (the keychain uid was in the cryptoconf)
                assert_eq!(item_count(cryptainer), item_count(cryptoconf) + 5, "{sample_name}");
                assert_eq!(path(cryptainer, "cryptainer_state").as_text(), Some("FINISHED"));
                assert_eq!(path(cryptainer, "cryptainer_format").as_text(), Some("cryptainer_1.0"));
                assert!(path(cryptainer, "cryptainer_uid").as_uuid().is_some());
                assert_eq!(
                    path(cryptainer, "keychain_uid").as_uuid(),
                    Some(&SAMPLES_ROOT_KEYCHAIN_UID)
                );
                assert!(path(cryptainer, "cryptainer_metadata").is_null());
                assert_eq!(
                    get_path(cryptainer, "payload_plaintext_signatures"),
                    get_path(cryptoconf, "payload_plaintext_signatures")
                );
                let ciphertext_struct = path(cryptainer, "payload_ciphertext_struct");
                let is_padded = layer_algos.contains(&"AES_CBC");
                let expected_ciphertext_length = if is_padded { 64 } else { 50 };
                if is_offloaded {
                    assert_eq!(item_count(ciphertext_struct), 1);
                    assert_eq!(
                        path(ciphertext_struct, "ciphertext_location").as_text(),
                        Some("offloaded")
                    );
                    assert_eq!(
                        encryption.offloaded_ciphertext.as_ref().map(Vec::len),
                        Some(expected_ciphertext_length)
                    );
                } else {
                    assert_eq!(item_count(ciphertext_struct), 2);
                    assert_eq!(path(ciphertext_struct, "ciphertext_location").as_text(), Some("inline"));
                    assert_eq!(
                        bytes_length(path(ciphertext_struct, "ciphertext_value")),
                        expected_ciphertext_length
                    );
                }

                let payload_layers = path(cryptainer, "payload_cipher_layers").as_array().unwrap();
                assert_eq!(payload_layers.len(), layer_algos.len());
                for (layer_index, (payload_layer, layer_algo)) in payload_layers.iter().zip(layer_algos).enumerate() {
                    let conf_layer = path(cryptoconf, &format!("payload_cipher_layers[{layer_index}]"));
                    assert_eq!(path(payload_layer, "payload_cipher_algo").as_text(), Some(*layer_algo));
                    // key_ciphertext and payload_macs are added, key_ciphertext_format in WA-CBOR only; the legacy
                    // alias is renamed, not duplicated
                    assert_eq!(
                        item_count(payload_layer),
                        item_count(conf_layer) + if is_cbor { 3 } else { 2 }
                    );
                    assert!(bytes_length(path(payload_layer, "key_ciphertext")) > 0);
                    assert_eq!(
                        get_path(payload_layer, "key_ciphertext_format").and_then(Value::as_text),
                        is_cbor.then_some("cbor")
                    );
                    assert_eq!(
                        path(payload_layer, "payload_ciphertext_signatures"),
                        &Value::Array(Vec::new())
                    );
                    assert!(get_path(payload_layer, "payload_signatures").is_none());
                    let payload_macs = path(payload_layer, "payload_macs");
                    if *layer_algo == "AES_CBC" {
                        assert_eq!(item_count(payload_macs), 0);
                    } else {
                        assert_eq!(item_count(payload_macs), 1);
                        assert_eq!(bytes_length(path(payload_macs, "tag")), 16);
                    }
                    assert_eq!(
                        path(payload_layer, "key_cipher_layers[0].key_cipher_algo"),
                        path(conf_layer, "key_cipher_layers[0].key_cipher_algo")
                    );
                }
                // The profile itself is untouched, and reusable
                assert!(get_path(cryptoconf, "cryptainer_uid").is_none());
                assert!(get_path(cryptoconf, "payload_cipher_layers[0].key_ciphertext").is_none());
            }
        }
    }
    // The legacy sample does hold the legacy key
    let legacy_profile = load_sample("legacy_payload_signatures_alias");
    assert!(
        get_path(
            legacy_profile.cryptoconf(),
            "payload_cipher_layers[0].payload_signatures"
        )
        .is_some()
    );
    assert!(
        get_path(
            legacy_profile.cryptoconf(),
            "payload_cipher_layers[0].payload_ciphertext_signatures"
        )
        .is_none()
    );
}

/// The chained one-shot encryptions of section 7: each layer encrypts the whole ciphertext of the previous one.
fn encrypt_in_one_shot(symkeys: &[(&str, &[u8], &[u8])], payload: &[u8]) -> (Vec<u8>, Vec<Option<Vec<u8>>>) {
    let mut data = payload.to_vec();
    let mut tags = Vec::new();
    for (cipher_algo, key, iv_or_nonce) in symkeys {
        let cipherdict =
            internals::symmetric_encrypt_to_cipherdict::<RustCryptoBackend>(cipher_algo, key, iv_or_nonce, &data)
                .unwrap();
        data = path(&cipherdict, "ciphertext").as_bytes().unwrap().to_vec();
        tags.push(cipherdict.get("tag").map(|tag| tag.as_bytes().unwrap().to_vec()));
    }
    (data, tags)
}

#[test]
fn payload_pipeline_fed_in_chunks_equals_one_shot_encryptions() {
    let key_material: Vec<(Vec<u8>, Vec<u8>)> = (0u8..3)
        .map(|index| {
            (
                vec![0x10 + index; 32],
                (0u8..16).map(|byte| byte ^ (index << 4)).collect(),
            )
        })
        .collect();
    let layer_stacks: [&[&str]; 9] = [
        &["AES_CBC"],
        &["AES_EAX"],
        &["CHACHA20_POLY1305"],
        &["AES_CBC", "AES_CBC"],
        &["AES_EAX", "AES_CBC"],
        &["AES_CBC", "CHACHA20_POLY1305"],
        &["AES_CBC", "AES_EAX", "CHACHA20_POLY1305"],
        &["CHACHA20_POLY1305", "AES_CBC", "AES_CBC"],
        &["AES_CBC", "AES_CBC", "AES_CBC"],
    ];
    for layer_stack in layer_stacks {
        let symkeys: Vec<(&str, &[u8], &[u8])> = layer_stack
            .iter()
            .zip(&key_material)
            .map(|(cipher_algo, (key, iv))| {
                (
                    *cipher_algo,
                    key.as_slice(),
                    &iv[..internals::symmetric_iv_or_nonce_length(cipher_algo).unwrap()],
                )
            })
            .collect();
        for payload_length in [0usize, 1, 15, 16, 17, 31, 32, 33, 100, 4095, 4096, 4097, 10000] {
            let payload = build_payload(payload_length);
            let (expected_ciphertext, expected_tags) = encrypt_in_one_shot(&symkeys, &payload);
            let padded_layer_count = layer_stack
                .iter()
                .filter(|cipher_algo| **cipher_algo == "AES_CBC")
                .count();
            assert!(expected_ciphertext.len() > payload_length || padded_layer_count == 0);
            for (chunk_length, slice_size) in [
                (1usize, 16usize),
                (7, 16),
                (15, 32),
                (16, 16),
                (17, 48),
                (1000, 4096),
                (4096, 4096),
                (usize::MAX, 4096),
                (usize::MAX, 16),
                (5000, 1024),
            ] {
                if chunk_length == 1 && payload_length > 4097 {
                    continue; // Slow, and no different
                }
                let (ciphertext, tags) = internals::encrypt_payload_through_layers::<RustCryptoBackend>(
                    &symkeys,
                    &payload,
                    chunk_length,
                    slice_size,
                )
                .unwrap();
                let context = format!(
                    "{layer_stack:?}, {payload_length} bytes in chunks of {chunk_length}, slices of {slice_size}"
                );
                assert!(ciphertext == expected_ciphertext, "ciphertext of {context}");
                let tags: Vec<Option<Vec<u8>>> = tags.iter().map(|tag| tag.map(|tag| tag.to_vec())).collect();
                assert_eq!(tags, expected_tags, "tags of {context}");
            }
        }
    }
    let symkey = [("AES_CBC", &[0u8; 32][..], &[0u8; 16][..])];
    for invalid_slice_size in [0usize, 8, 15, 17, 24, 4095] {
        let error =
            internals::encrypt_payload_through_layers::<RustCryptoBackend>(&symkey, b"abc", 1, invalid_slice_size)
                .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    }
}

/// Through the public API: the way the payload is cut in chunks, the slice size and the ciphertext location do
/// not change a byte of the outputs.
#[test]
fn cryptainers_do_not_depend_on_chunking_slicing_nor_location() {
    for format in enabled_document_formats() {
        for sample_name in [
            "nested_all_layer_kinds",
            "minimal_rsa_authenticator",
            "corpus_2026_cbor_key_ciphertexts_02",
        ] {
            let device_profile = load_sample(sample_name);
            for payload_length in [0usize, 1, 16, 5000] {
                let payload = build_payload(payload_length);
                let encrypt = |is_offloaded: bool, chunk_length: usize, slice_size: usize| {
                    let options = EncryptorOptions {
                        document_format: format,
                        payload_processing_slice_size: slice_size,
                    };
                    let mut hooks = DeterministicHooks::new(75);
                    encrypt_payload(
                        &mut hooks,
                        &device_profile,
                        None,
                        &options,
                        is_offloaded,
                        &payload,
                        chunk_length,
                    )
                    .unwrap()
                };
                let reference = encrypt(false, usize::MAX, 4096);
                let inline_ciphertext = path(&reference.cryptainer, "payload_ciphertext_struct.ciphertext_value");
                let offloaded_reference = encrypt(true, usize::MAX, 4096);
                assert_eq!(
                    offloaded_reference.offloaded_ciphertext.as_deref(),
                    inline_ciphertext.as_bytes()
                );
                for (chunk_length, slice_size) in [(1usize, 16usize), (17, 16), (1000, 64), (4096, 4096), (3, 65536)] {
                    let inline = encrypt(false, chunk_length, slice_size);
                    assert!(
                        inline.cryptainer_bytes == reference.cryptainer_bytes,
                        "inline, chunks of {chunk_length}"
                    );
                    let offloaded = encrypt(true, chunk_length, slice_size);
                    assert!(offloaded.cryptainer_bytes == offloaded_reference.cryptainer_bytes);
                    assert_eq!(offloaded.offloaded_ciphertext, offloaded_reference.offloaded_ciphertext);
                }
                // Apart from the payload ciphertext struct, both locations give the same cryptainer
                let mut inline_tree = reference.cryptainer.clone();
                let mut offloaded_tree = offloaded_reference.cryptainer.clone();
                inline_tree.as_map_mut().unwrap().remove("payload_ciphertext_struct");
                offloaded_tree.as_map_mut().unwrap().remove("payload_ciphertext_struct");
                assert_eq!(inline_tree, offloaded_tree);
            }
        }
    }
}

#[test]
fn options_are_checked_before_any_random_draw() {
    let device_profile = load_sample("minimal_rsa_authenticator");
    let mut hooks = DeterministicHooks::new(76);
    assert_eq!(EncryptorOptions::default().payload_processing_slice_size, 4096);
    assert_eq!(EncryptorOptions::DEFAULT_PAYLOAD_PROCESSING_SLICE_SIZE, 4096);
    assert_eq!(
        EncryptorOptions::default().document_format,
        DocumentFormat::BuildDefault
    );
    for invalid_slice_size in [0usize, 1, 15, 17, 4095, 4097] {
        let options = EncryptorOptions {
            payload_processing_slice_size: invalid_slice_size,
            ..EncryptorOptions::default()
        };
        let error = Encryptor::create(&device_profile, None, &options, &mut hooks)
            .err()
            .expect("a refused slice size");
        assert_eq!(error.kind(), ErrorKind::InvalidArgument);
        let mut sink = Vec::new();
        let error = Encryptor::create_offloaded(&device_profile, None, &options, &mut hooks, &mut sink)
            .err()
            .expect("a refused slice size");
        assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    }
    for format in [DocumentFormat::ExtendedJson, DocumentFormat::Cbor] {
        if !format.is_enabled() {
            // A build without this format: explicit refusal, in both entry points
            let error = Encryptor::create(&device_profile, None, &options_for(format), &mut hooks)
                .err()
                .unwrap();
            assert_eq!(error.kind(), ErrorKind::UnsupportedFeature);
            let mut cryptainer_sink = Vec::new();
            let error = encrypt_payload_in_one_call::<RustCryptoBackend, _>(
                &device_profile,
                None,
                &options_for(format),
                &mut hooks,
                b"payload",
                &mut cryptainer_sink,
            )
            .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::UnsupportedFeature);
            assert!(cryptainer_sink.is_empty());
            assert_eq!(format.cryptainer_suffix(), None);
        }
    }
    assert_eq!(hooks.random_call_count, 0);

    // The build default format: the only enabled one, or Extended JSON when both are
    let expected_default = if DocumentFormat::ExtendedJson.is_enabled() {
        DocumentFormat::ExtendedJson
    } else {
        DocumentFormat::Cbor
    };
    assert!(DocumentFormat::BuildDefault.is_enabled());
    let finished = Encryptor::create(&device_profile, None, &EncryptorOptions::default(), &mut hooks)
        .unwrap()
        .finalize()
        .unwrap();
    assert_eq!(finished.document_format(), expected_default);
    assert_eq!(
        DocumentFormat::BuildDefault.cryptainer_suffix(),
        expected_default.cryptainer_suffix()
    );
}

/// Nested maps `{"a": {"a": ... {}}}` of `level_count` levels.
fn nested_metadata(level_count: usize) -> Value {
    let mut metadata = Value::Map(Map::new());
    for _ in 1..level_count {
        metadata = Value::Map(Map::from_entries([("a", metadata)]).unwrap());
    }
    metadata
}

#[test]
fn metadata_are_checked_before_any_random_draw() {
    let device_profile = load_sample("minimal_rsa_authenticator");
    let options = EncryptorOptions::default();
    let mut hooks = DeterministicHooks::new(78);
    let mut refused = |metadata: &Value| {
        Encryptor::create(&device_profile, Some(metadata), &options, &mut hooks)
            .err()
            .expect("refused metadata")
            .kind()
    };

    // Not a map
    assert_eq!(refused(&Value::from("x")), ErrorKind::InvalidProfile);
    assert_eq!(refused(&Value::Array(Vec::new())), ErrorKind::InvalidProfile);
    assert_eq!(refused(&Value::Null), ErrorKind::InvalidProfile);
    // An Extended JSON keyword map, at any depth
    let keyword_map = Value::Map(Map::from_entries([("$uuid", "0123")]).unwrap());
    assert_eq!(refused(&keyword_map), ErrorKind::InvalidProfile);
    let outer = Value::Map(Map::from_entries([("inner", keyword_map.clone())]).unwrap());
    assert_eq!(refused(&outer), ErrorKind::InvalidProfile);
    let in_array =
        Value::Map(Map::from_entries([("items", Value::Array(vec![Value::from(1i64), keyword_map]))]).unwrap());
    assert_eq!(refused(&in_array), ErrorKind::InvalidProfile);
    // Depth: 63 levels pass, 64 do not (metadata sit at depth 2 of cryptainers and key structs)
    assert_eq!(refused(&nested_metadata(64)), ErrorKind::NestingTooDeep);
    assert_eq!(hooks.random_call_count, 0, "before any key generation");

    // Floats and datetimes never get into a tree: {"k": 1.0} (half float) and {"k": tag 0 datetime}
    let limits = EncryptorLimits::default();
    let float_metadata = [0xa1, 0x61, 0x6b, 0xf9, 0x3c, 0x00];
    let mut datetime_metadata = vec![0xa1, 0x61, 0x6b, 0xc0, 0x74];
    datetime_metadata.extend_from_slice(b"2026-01-01T00:00:00Z");
    for unsupported in [&float_metadata[..], &datetime_metadata] {
        let error = wa_flightbox::decode_document_from_cbor(unsupported, &limits).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnsupportedType);
    }

    for format in enabled_document_formats() {
        let metadata = nested_metadata(63);
        let mut hooks = DeterministicHooks::new(78);
        let encryption = encrypt_payload(
            &mut hooks,
            &device_profile,
            Some(&metadata),
            &options_for(format),
            false,
            b"abc",
            3,
        )
        .unwrap();
        assert_eq!(path(&encryption.cryptainer, "cryptainer_metadata"), &metadata);

        // A lower configured depth applies to metadata too
        let limits = EncryptorLimits::new(8, 16, 4096).unwrap();
        let shallow_profile =
            DeviceProfile::load_from_cbor(&device_profile_sample("minimal_rsa_authenticator"), &limits).unwrap();
        let create = |metadata: &Value| {
            let mut hooks = DeterministicHooks::new(78);
            Encryptor::create(&shallow_profile, Some(metadata), &options_for(format), &mut hooks).map(|_| ())
        };
        assert!(create(&nested_metadata(15)).is_ok());
        assert_eq!(
            create(&nested_metadata(16)).unwrap_err().kind(),
            ErrorKind::NestingTooDeep
        );
    }

    if DocumentFormat::ExtendedJson.is_enabled() {
        // Non-ASCII metadata are escaped in Extended JSON
        let metadata = Value::Map(Map::from_entries([("label", "Café ☕")]).unwrap());
        let mut hooks = DeterministicHooks::new(78);
        let options = options_for(DocumentFormat::ExtendedJson);
        let encryption =
            encrypt_payload(&mut hooks, &device_profile, Some(&metadata), &options, false, b"abc", 3).unwrap();
        let text = core::str::from_utf8(&encryption.cryptainer_bytes).unwrap();
        assert!(text.is_ascii());
        assert!(text.contains("\"Caf\\u00e9 \\u2615\""), "{text}");
        assert_eq!(
            path(&encryption.cryptainer, "cryptainer_metadata.label").as_text(),
            Some("Café ☕")
        );
    }
}

/// The caller's metadata are copied at creation: changing or dropping them afterwards changes nothing.
#[test]
fn metadata_are_copied_at_creation() {
    let device_profile = load_sample("minimal_rsa_authenticator");
    let mut hooks = DeterministicHooks::new(79);
    let mut metadata = sample_metadata();
    let encryptor = Encryptor::create(
        &device_profile,
        Some(&metadata),
        &EncryptorOptions::default(),
        &mut hooks,
    )
    .unwrap();
    metadata.as_map_mut().unwrap().set("device_id", "changed");
    drop(metadata);
    let finished = encryptor.finalize().unwrap();
    assert_eq!(
        finished.cryptainer().get("cryptainer_metadata"),
        Some(&sample_metadata())
    );
}

/// A sink accepting a given number of bytes, then failing.
struct LimitedSink {
    bytes: Vec<u8>,
    capacity: usize,
    error: SinkError,
    write_count_after_failure: usize,
    has_failed: bool,
}

impl LimitedSink {
    fn new(capacity: usize, error: SinkError) -> Self {
        Self {
            bytes: Vec::new(),
            capacity,
            error,
            write_count_after_failure: 0,
            has_failed: false,
        }
    }
}

impl OutputSink for LimitedSink {
    fn write(&mut self, bytes: &[u8]) -> core::result::Result<(), SinkError> {
        if self.has_failed {
            self.write_count_after_failure += 1;
        }
        if self.bytes.len() + bytes.len() > self.capacity {
            self.has_failed = true;
            return Err(self.error);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

#[test]
fn an_encryptor_is_unusable_after_a_failed_call() {
    let device_profile = load_sample("nested_all_layer_kinds");
    let options = EncryptorOptions {
        payload_processing_slice_size: 16,
        ..EncryptorOptions::default()
    };
    let payload = build_payload(200);

    for (sink_error, expected_kind) in [
        (SinkError::WriteFailure, ErrorKind::SinkWriteFailure),
        (SinkError::OutOfMemory, ErrorKind::OutOfMemory),
    ] {
        // The payload sink fails in the middle of a chunk
        let mut hooks = DeterministicHooks::new(80);
        let mut sink = LimitedSink::new(100, sink_error);
        let mut encryptor =
            Encryptor::create_offloaded(&device_profile, None, &options, &mut hooks, &mut sink).unwrap();
        encryptor.encrypt_payload_chunk(&payload[..64]).unwrap();
        assert_eq!(
            encryptor.encrypt_payload_chunk(&payload[64..]).unwrap_err().kind(),
            expected_kind
        );
        // Every later call is refused, without touching the sink
        assert_eq!(
            encryptor.encrypt_payload_chunk(b"more").unwrap_err().kind(),
            ErrorKind::WrongState
        );
        assert_eq!(
            encryptor.encrypt_payload_chunk(b"").unwrap_err().kind(),
            ErrorKind::WrongState
        );
        assert_eq!(
            encryptor.finalize().err().map(|error| error.kind()),
            Some(ErrorKind::WrongState)
        );
        assert_eq!(sink.write_count_after_failure, 0);
        assert_eq!(sink.bytes.len(), 96, "whole slices before the failure");

        // The payload sink fails at finalization (the last bytes and tags do not fit)
        let mut hooks = DeterministicHooks::new(80);
        let mut sink = LimitedSink::new(16, sink_error);
        let cbc_profile = load_sample("minimal_rsa_authenticator");
        let mut encryptor = Encryptor::create_offloaded(&cbc_profile, None, &options, &mut hooks, &mut sink).unwrap();
        encryptor.encrypt_payload_chunk(&payload[..17]).unwrap();
        assert_eq!(
            encryptor.finalize().err().map(|error| error.kind()),
            Some(expected_kind)
        );

        // The cryptainer sink fails: the finished cryptainer stays writable elsewhere
        let mut hooks = DeterministicHooks::new(80);
        let mut encryptor = Encryptor::create(&device_profile, None, &options, &mut hooks).unwrap();
        encryptor.encrypt_payload_chunk(&payload).unwrap();
        let finished = encryptor.finalize().unwrap();
        let mut failing_sink = LimitedSink::new(300, sink_error);
        assert_eq!(
            finished.write_cryptainer(&mut failing_sink).unwrap_err().kind(),
            expected_kind
        );
        let (mut first_copy, mut second_copy) = (Vec::new(), Vec::new());
        finished.write_cryptainer(&mut first_copy).unwrap();
        finished.write_cryptainer(&mut second_copy).unwrap();
        assert!(first_copy == second_copy && first_copy.len() > 300);
        assert_eq!(
            failing_sink.bytes[..],
            first_copy[..failing_sink.bytes.len()],
            "a prefix was written"
        );
    }
}

/// A failure of the random hook, at each of its calls: the creation fails with the randomness error, and nothing
/// was written anywhere.
#[test]
fn a_random_hook_failure_at_any_call_aborts_the_creation() {
    for format in enabled_document_formats() {
        for sample_name in [
            "nested_all_layer_kinds",
            "minimal_rsa_authenticator",
            "corpus_2026_cbor_key_ciphertexts_04",
        ] {
            let device_profile = load_sample(sample_name);
            let metadata = sample_metadata();
            let options = options_for(format);
            let mut hooks = DeterministicHooks::new(81);
            let mut sink = Vec::new();
            Encryptor::create_offloaded(&device_profile, Some(&metadata), &options, &mut hooks, &mut sink).unwrap();
            let call_count = hooks.random_call_count;
            assert!(
                call_count >= 4,
                "{sample_name}: a UUID, a symkey and a wrapping at least"
            );

            for failing_call_index in 0..call_count {
                let mut hooks = DeterministicHooks::new(81);
                hooks.failing_random_call_index = Some(failing_call_index);
                let mut sink = Vec::new();
                let error =
                    Encryptor::create_offloaded(&device_profile, Some(&metadata), &options, &mut hooks, &mut sink)
                        .err()
                        .unwrap_or_else(|| {
                            panic!("{sample_name}: creation despite a failure of call {failing_call_index}")
                        });
                assert_eq!(error.kind(), ErrorKind::RandomnessFailure, "call {failing_call_index}");
                assert_eq!(
                    hooks.random_call_count,
                    failing_call_index + 1,
                    "no draw after the failure"
                );
                assert!(sink.is_empty());

                let mut hooks = DeterministicHooks::new(81);
                hooks.failing_random_call_index = Some(failing_call_index);
                let mut cryptainer_sink = Vec::new();
                let error = encrypt_payload_in_one_call::<RustCryptoBackend, _>(
                    &device_profile,
                    Some(&metadata),
                    &options,
                    &mut hooks,
                    b"payload",
                    &mut cryptainer_sink,
                )
                .unwrap_err();
                assert_eq!(error.kind(), ErrorKind::RandomnessFailure);
                assert!(cryptainer_sink.is_empty(), "nothing written");
            }
            // All the randomness is drawn at creation: steps 2 and 3 draw nothing
            let mut hooks = DeterministicHooks::new(81);
            let encryption = encrypt_payload(
                &mut hooks,
                &device_profile,
                Some(&metadata),
                &options,
                false,
                &[1; 100],
                9,
            );
            assert!(encryption.is_ok());
            assert_eq!(hooks.random_call_count, call_count);
        }
    }
}

#[test]
fn one_call_helper_and_file_suffixes() {
    assert_eq!(OFFLOADED_PAYLOAD_SUFFIX, ".payload");
    let device_profile = load_sample("nested_all_layer_kinds");
    let metadata = sample_metadata();
    let payload = build_payload(1234);
    for format in enabled_document_formats() {
        let expected_suffix = if format == DocumentFormat::Cbor {
            ".crypt.cbor"
        } else {
            ".crypt.json"
        };
        assert_eq!(format.cryptainer_suffix(), Some(expected_suffix));

        let mut hooks = DeterministicHooks::new(82);
        let mut cryptainer_bytes = Vec::new();
        encrypt_payload_in_one_call::<RustCryptoBackend, _>(
            &device_profile,
            Some(&metadata),
            &options_for(format),
            &mut hooks,
            &payload,
            &mut cryptainer_bytes,
        )
        .unwrap();
        // The same bytes as the three steps, fed in chunks
        let mut hooks = DeterministicHooks::new(82);
        let encryption = encrypt_payload(
            &mut hooks,
            &device_profile,
            Some(&metadata),
            &options_for(format),
            false,
            &payload,
            100,
        )
        .unwrap();
        assert!(cryptainer_bytes == encryption.cryptainer_bytes);
        let first_byte = cryptainer_bytes[0];
        assert!(if format == DocumentFormat::Cbor {
            first_byte >> 5 == 5
        } else {
            first_byte == b'{'
        });
    }
}

/// An empty payload, without any chunk call or with empty chunks, gives the same valid cryptainer.
#[test]
fn empty_payloads_and_empty_chunks() {
    for format in enabled_document_formats() {
        for (sample_name, expected_ciphertext_length) in
            [("nested_all_layer_kinds", 0usize), ("minimal_rsa_authenticator", 16)]
        {
            let device_profile = load_sample(sample_name);
            let options = options_for(format);
            let mut hooks = DeterministicHooks::new(83);
            let without_chunk = Encryptor::create(&device_profile, None, &options, &mut hooks)
                .unwrap()
                .finalize()
                .unwrap();
            let mut hooks = DeterministicHooks::new(83);
            let mut encryptor = Encryptor::create(&device_profile, None, &options, &mut hooks).unwrap();
            for _ in 0..3 {
                encryptor.encrypt_payload_chunk(b"").unwrap();
            }
            let with_empty_chunks = encryptor.finalize().unwrap();
            assert_eq!(without_chunk.cryptainer(), with_empty_chunks.cryptainer());
            let ciphertext = path(without_chunk.cryptainer(), "payload_ciphertext_struct.ciphertext_value");
            assert_eq!(bytes_length(ciphertext), expected_ciphertext_length);

            // Empty chunks between others change nothing either
            let mut hooks = DeterministicHooks::new(83);
            let mut encryptor = Encryptor::create(&device_profile, None, &options, &mut hooks).unwrap();
            for chunk in [&b"ab"[..], b"", b"cdefgh", b""] {
                encryptor.encrypt_payload_chunk(chunk).unwrap();
            }
            let in_pieces = encryptor.finalize().unwrap();
            let mut hooks = DeterministicHooks::new(83);
            let whole = encrypt_payload(&mut hooks, &device_profile, None, &options, false, b"abcdefgh", 8).unwrap();
            assert_eq!(in_pieces.cryptainer(), &whole.cryptainer);
        }
    }
}

/// Every valid sample profile gives a cryptainer, in each format and location.
#[test]
fn every_valid_sample_profile_gives_a_cryptainer() {
    let samples = wa_flightbox_backend_conformance::test_support::vectors::device_profile_samples();
    let mut valid_sample_count = 0;
    for sample in samples.as_array().unwrap() {
        if sample["expected_status"] != "WA_STATUS_OK" {
            continue;
        }
        valid_sample_count += 1;
        let sample_name = sample["name"].as_str().unwrap();
        let device_profile = load_sample(sample_name);
        for format in enabled_document_formats() {
            for is_offloaded in [false, true] {
                let mut hooks = DeterministicHooks::new(84);
                let encryption = encrypt_payload(
                    &mut hooks,
                    &device_profile,
                    Some(&sample_metadata()),
                    &options_for(format),
                    is_offloaded,
                    &build_payload(333),
                    64,
                )
                .unwrap_or_else(|error| panic!("{sample_name}: {error}"));
                assert_eq!(
                    path(&encryption.cryptainer, "cryptainer_state").as_text(),
                    Some("FINISHED")
                );
                assert_eq!(
                    path(&encryption.cryptainer, "keychain_uid").as_uuid(),
                    Some(device_profile.root_keychain_uid())
                );
            }
        }
    }
    assert!(valid_sample_count >= 19);
}
