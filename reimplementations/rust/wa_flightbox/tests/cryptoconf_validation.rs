// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Cryptoconf validation: hand-built trees for each rule, with the expected error kind and location path (those
//! that the tests of the C library expect); the key cipher nesting depth; trustee identities.

use wa_flightbox::{EncryptorLimits, ErrorKind, Map, Value, internals};

/// Build a value tree from a compact notation: `{'key': value}`, `[items]`, `'text'`, integers, `null`, `true`,
/// `false`, `b'hex'` for bytes and `u'hex'` for UUIDs. Panics on a notation error.
fn build_tree(notation: &str) -> Value {
    struct Parser<'a> {
        characters: core::iter::Peekable<core::str::Chars<'a>>,
    }
    impl Parser<'_> {
        fn skip_spaces(&mut self) {
            while self.characters.next_if(|character| character.is_whitespace()).is_some() {}
        }
        fn expect(&mut self, expected: char) {
            self.skip_spaces();
            assert_eq!(self.characters.next(), Some(expected), "notation error");
        }
        fn quoted(&mut self) -> String {
            self.expect('\'');
            let mut text = String::new();
            loop {
                match self.characters.next().expect("an unterminated string") {
                    '\'' => return text,
                    character => text.push(character),
                }
            }
        }
        fn hex(&mut self) -> Vec<u8> {
            let text = self.quoted();
            assert!(text.len() % 2 == 0);
            (0..text.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
                .collect()
        }
        fn value(&mut self) -> Value {
            self.skip_spaces();
            match *self.characters.peek().expect("a value") {
                '{' => {
                    self.characters.next();
                    let mut map = Map::new();
                    loop {
                        self.skip_spaces();
                        if self.characters.next_if_eq(&'}').is_some() {
                            return Value::Map(map);
                        }
                        if !map.is_empty() {
                            self.characters.next_if_eq(&',').expect("a comma between entries");
                        }
                        let key = self.quoted();
                        self.expect(':');
                        let value = self.value();
                        map.insert(key, value).expect("no duplicate key");
                    }
                }
                '[' => {
                    self.characters.next();
                    let mut items = Vec::new();
                    loop {
                        self.skip_spaces();
                        if self.characters.next_if_eq(&']').is_some() {
                            return Value::Array(items);
                        }
                        if !items.is_empty() {
                            self.characters.next_if_eq(&',').expect("a comma between items");
                        }
                        items.push(self.value());
                    }
                }
                '\'' => Value::Text(self.quoted()),
                'b' => {
                    self.characters.next();
                    Value::Bytes(self.hex())
                }
                'u' => {
                    self.characters.next();
                    Value::Uuid(self.hex().try_into().expect("16 bytes"))
                }
                _ => {
                    let mut word = String::new();
                    while let Some(character) = self
                        .characters
                        .next_if(|character| character.is_ascii_alphanumeric() || *character == '-')
                    {
                        word.push(character);
                    }
                    match word.as_str() {
                        "null" => Value::Null,
                        "true" => Value::Bool(true),
                        "false" => Value::Bool(false),
                        integer => {
                            Value::Integer(integer.parse().unwrap_or_else(|_| panic!("notation error: {integer}")))
                        }
                    }
                }
            }
        }
    }
    let mut parser = Parser {
        characters: notation.chars().peekable(),
    };
    let tree = parser.value();
    parser.skip_spaces();
    assert_eq!(parser.characters.next(), None, "notation error: trailing characters");
    tree
}

#[test]
fn notation_builder_builds_every_type() {
    let tree =
        build_tree(" { 'a' : [ -12, null, false, b'00ff', u'000102030405060708090a0b0c0d0e0f' ], 'b': {} , 'c': '' } ");
    assert_eq!(tree.as_map().map(Map::len), Some(3));
    let items = tree.get("a").and_then(Value::as_array).unwrap();
    assert_eq!(items[0].as_integer(), Some(-12));
    assert!(items[1].is_null());
    assert_eq!(items[2].as_bool(), Some(false));
    assert_eq!(items[3].as_bytes(), Some(&[0x00, 0xff][..]));
    assert_eq!(items[4].as_uuid().map(|uuid| uuid[15]), Some(0x0f));
    assert_eq!(tree.get("b"), Some(&Value::Map(Map::new())));
    assert_eq!(tree.get("c").and_then(Value::as_text), Some(""));
}

// Notation snippets

const UID: &str = "u'0123456789abcdef0123456789abcdef'";
const OTHER_UID: &str = "u'fedcba9876543210fedcba9876543210'";
const LOCAL_TRUSTEE: &str = "{'trustee_type': 'local_keyfactory'}";
const JSONRPC_TRUSTEE: &str = "{'trustee_type': 'jsonrpc_api', 'jsonrpc_url': 'https://example.com/jsonrpc'}";
const PAYLOAD_0: &str = "cryptoconf.payload_cipher_layers[0]";
const KEY_LAYER_0: &str = "cryptoconf.payload_cipher_layers[0].key_cipher_layers[0]";

fn authenticator_trustee() -> String {
    format!("{{'trustee_type': 'authenticator', 'keystore_uid': {UID}, 'keystore_owner': 'Jane'}}")
}

fn rsa_layer() -> String {
    trustee_layer(LOCAL_TRUSTEE)
}

fn layer_with(extra: &str) -> String {
    format!("{{'key_cipher_algo': 'RSA_OAEP', 'key_cipher_trustee': {LOCAL_TRUSTEE}, {extra}}}")
}

fn trustee_layer(trustee: &str) -> String {
    format!("{{'key_cipher_algo': 'RSA_OAEP', 'key_cipher_trustee': {trustee}}}")
}

fn payload_layer_with(extra: &str, key_layers: &str) -> String {
    format!(
        "{{'payload_cipher_algo': 'AES_CBC', 'payload_ciphertext_signatures': [], {extra}'key_cipher_layers': \
         [{key_layers}]}}"
    )
}

fn payload_layer(key_layers: &str) -> String {
    payload_layer_with("", key_layers)
}

fn cryptoconf(payload_layers: &str) -> String {
    format!("{{'payload_cipher_layers': [{payload_layers}], 'keychain_uid': {UID}}}")
}

fn simple_cryptoconf(key_layer: &str) -> String {
    cryptoconf(&payload_layer(key_layer))
}

fn signature_conf() -> String {
    format!(
        "{{'payload_digest_algo': 'SHA256', 'payload_signature_algo': 'ECC_DSS', 'payload_signature_trustee': \
         {LOCAL_TRUSTEE}, 'keychain_uid': {OTHER_UID}}}"
    )
}

fn shared_secret_layer(threshold: &str, shards: &str) -> String {
    format!(
        "{{'key_cipher_algo': '[SHARED_SECRET]', 'key_shared_secret_threshold': {threshold}, \
         'key_shared_secret_shards': [{shards}]}}"
    )
}

fn shard(key_layers: &str) -> String {
    format!("{{'key_cipher_layers': [{key_layers}]}}")
}

/// A payload layer with given signatures under a given key: `payload_ciphertext_signatures` or the legacy one.
fn signed_payload_layer(signatures_key: &str, signatures: &str) -> String {
    let rsa = rsa_layer();
    format!("{{'payload_cipher_algo': 'AES_CBC', '{signatures_key}': {signatures}, 'key_cipher_layers': [{rsa}]}}")
}

fn cryptoconf_cases() -> Vec<(String, Option<ErrorKind>, String)> {
    use ErrorKind::{InvalidProfile, UnsupportedSignature};
    let rsa = rsa_layer();
    let rsa = rsa.as_str();
    let payload_rsa = payload_layer(rsa);
    let signature = signature_conf();
    let mut cases: Vec<(String, Option<ErrorKind>, String)> = Vec::new();
    let mut valid = |notation: String| cases.push((notation, None, String::new()));
    // Valid cryptoconfs
    valid(simple_cryptoconf(rsa));
    valid(format!(
        "{{'keychain_uid': {UID}, 'payload_plaintext_signatures': [], 'payload_cipher_layers': [\
         {{'payload_cipher_algo': 'AES_EAX', 'payload_signatures': [], 'key_cipher_layers': [\
         {{'key_cipher_algo': 'ECIES_X25519', 'key_cipher_trustee': {authenticator}, 'keychain_uid': {OTHER_UID}}}, \
         {{'key_cipher_algo': 'ML_KEM_768', 'key_cipher_trustee': {JSONRPC_TRUSTEE}}}]}}, \
         {{'payload_cipher_algo': 'CHACHA20_POLY1305', 'payload_ciphertext_signatures': [], 'key_cipher_layers': [\
         {{'key_cipher_algo': 'AES_CBC', 'key_cipher_layers': [{rsa}]}}, {shared_secret}]}}]}}",
        authenticator = authenticator_trustee(),
        shared_secret = shared_secret_layer(
            "2",
            &format!(
                "{}, {}, {}",
                shard(rsa),
                shard(&format!(
                    "{{'key_cipher_algo': 'CHACHA20_POLY1305', 'key_cipher_layers': [{rsa}]}}"
                )),
                shard(rsa)
            )
        ),
    ));
    valid(simple_cryptoconf(&shared_secret_layer("1", &shard(rsa))));

    let mut invalid =
        |notation: String, kind: ErrorKind, location: String| cases.push((notation, Some(kind), location));
    let at = |base: &str, suffix: &str| format!("{base}{suffix}");

    // Root
    invalid("[]".into(), InvalidProfile, "cryptoconf".into());
    invalid(
        format!("{{'payload_cipher_layers': [{payload_rsa}], 'keychain_uid': {UID}, 'foo': 1}}"),
        InvalidProfile,
        "cryptoconf.foo".into(),
    );
    invalid(
        format!("{{'payload_cipher_layers': [{payload_rsa}]}}"),
        InvalidProfile,
        "cryptoconf.keychain_uid".into(),
    );
    invalid(
        format!(
            "{{'payload_cipher_layers': [{}]}}",
            payload_layer(&layer_with(&format!("'keychain_uid': {UID}")))
        ),
        InvalidProfile,
        "cryptoconf.keychain_uid".into(),
    );
    invalid(
        format!("{{'payload_cipher_layers': [{payload_rsa}], 'keychain_uid': '0123456789abcdef0123456789abcdef'}}"),
        InvalidProfile,
        "cryptoconf.keychain_uid".into(),
    );
    for payload_layers in ["'payload_cipher_layers': [], ", "", "'payload_cipher_layers': {}, "] {
        invalid(
            format!("{{{payload_layers}'keychain_uid': {UID}}}"),
            InvalidProfile,
            "cryptoconf.payload_cipher_layers".into(),
        );
    }
    invalid(cryptoconf("'AES_CBC'"), InvalidProfile, PAYLOAD_0.into());

    // Payload layers
    for payload_cipher_algo in [
        "'payload_cipher_algo': 'AES_XTS', ",
        "'payload_cipher_algo': 'RSA_OAEP', ",
        "",
    ] {
        invalid(
            cryptoconf(&format!(
                "{{{payload_cipher_algo}'payload_ciphertext_signatures': [], 'key_cipher_layers': [{rsa}]}}"
            )),
            InvalidProfile,
            at(PAYLOAD_0, ".payload_cipher_algo"),
        );
    }
    invalid(
        cryptoconf(&payload_layer_with("'key_ciphertext_format': 'cbor', ", rsa)),
        InvalidProfile,
        at(PAYLOAD_0, ".key_ciphertext_format"),
    );
    invalid(
        cryptoconf(&payload_layer_with("'payload_macs': null, ", rsa)),
        InvalidProfile,
        at(PAYLOAD_0, ".payload_macs"),
    );
    // Both the legacy key and the current one
    invalid(
        cryptoconf(&payload_layer_with("'payload_signatures': [], ", rsa)),
        InvalidProfile,
        PAYLOAD_0.into(),
    );
    invalid(
        cryptoconf(&format!(
            "{{'payload_cipher_algo': 'AES_CBC', 'key_cipher_layers': [{rsa}]}}"
        )),
        InvalidProfile,
        at(PAYLOAD_0, ".payload_ciphertext_signatures"),
    );
    invalid(
        cryptoconf(&signed_payload_layer("payload_signatures", "{}")),
        InvalidProfile,
        at(PAYLOAD_0, ".payload_signatures"),
    );
    invalid(
        cryptoconf("{'payload_cipher_algo': 'AES_CBC', 'payload_ciphertext_signatures': []}"),
        InvalidProfile,
        at(PAYLOAD_0, ".key_cipher_layers"),
    );
    invalid(
        cryptoconf(&payload_layer("")),
        InvalidProfile,
        at(PAYLOAD_0, ".key_cipher_layers"),
    );
    invalid(
        cryptoconf(&format!("{payload_rsa}, {}", payload_layer(""))),
        InvalidProfile,
        "cryptoconf.payload_cipher_layers[1].key_cipher_layers".into(),
    );

    // Signatures: well-formed but unsupported, or malformed
    invalid(
        cryptoconf(&signed_payload_layer(
            "payload_ciphertext_signatures",
            &format!("[{signature}]"),
        )),
        UnsupportedSignature,
        at(PAYLOAD_0, ".payload_ciphertext_signatures"),
    );
    invalid(
        cryptoconf(&signed_payload_layer("payload_signatures", &format!("[{signature}]"))),
        UnsupportedSignature,
        at(PAYLOAD_0, ".payload_signatures"),
    );
    invalid(
        format!(
            "{{'payload_cipher_layers': [{payload_rsa}], 'keychain_uid': {UID}, 'payload_plaintext_signatures': [{signature}]}}"
        ),
        UnsupportedSignature,
        "cryptoconf.payload_plaintext_signatures".into(),
    );
    invalid(
        format!(
            "{{'payload_cipher_layers': [{payload_rsa}], 'keychain_uid': {UID}, 'payload_plaintext_signatures': {signature}}}"
        ),
        InvalidProfile,
        "cryptoconf.payload_plaintext_signatures".into(),
    );
    let malformed_signatures: [(String, &str); 7] = [
        (
            format!(
                "[{signature}, {{'payload_digest_algo': 'MD5', 'payload_signature_algo': 'ECC_DSS', \
                 'payload_signature_trustee': {LOCAL_TRUSTEE}}}]"
            ),
            "[1].payload_digest_algo",
        ),
        (
            format!(
                "[{{'payload_digest_algo': 'SHA512', 'payload_signature_algo': 'RSA_OAEP', \
                 'payload_signature_trustee': {LOCAL_TRUSTEE}}}]"
            ),
            "[0].payload_signature_algo",
        ),
        (
            "[{'payload_digest_algo': 'SHA3_256', 'payload_signature_algo': 'DSA_DSS', 'payload_signature_trustee': \
             {'trustee_type': 'authenticator'}}]"
                .into(),
            "[0].payload_signature_trustee.keystore_uid",
        ),
        (
            "[{'payload_digest_algo': 'SHA3_512', 'payload_signature_algo': 'ML_DSA_65'}]".into(),
            "[0].payload_signature_trustee",
        ),
        (
            format!(
                "[{{'payload_digest_algo': 'SHA256', 'payload_signature_algo': 'RSA_PSS', \
                 'payload_signature_trustee': {LOCAL_TRUSTEE}, 'keychain_uid': 'abc'}}]"
            ),
            "[0].keychain_uid",
        ),
        (
            format!(
                "[{{'payload_digest_algo': 'SHA256', 'payload_signature_algo': 'RSA_PSS', \
                 'payload_signature_trustee': {LOCAL_TRUSTEE}, 'signature_value': b'00'}}]"
            ),
            "[0].signature_value",
        ),
        ("[[]]".into(), "[0]"),
    ];
    for (signatures, location_suffix) in malformed_signatures {
        invalid(
            cryptoconf(&signed_payload_layer("payload_ciphertext_signatures", &signatures)),
            InvalidProfile,
            format!("{PAYLOAD_0}.payload_ciphertext_signatures{location_suffix}"),
        );
    }

    // Key cipher layers
    let key_layer_cases: [(String, &str); 13] = [
        ("'RSA_OAEP'".into(), ""),
        (format!("{{'key_cipher_trustee': {LOCAL_TRUSTEE}}}"), ".key_cipher_algo"),
        (
            format!("{{'key_cipher_algo': 'DSA_DSS', 'key_cipher_trustee': {LOCAL_TRUSTEE}}}"),
            ".key_cipher_algo",
        ),
        (
            format!("{{'key_cipher_algo': 7, 'key_cipher_trustee': {LOCAL_TRUSTEE}}}"),
            ".key_cipher_algo",
        ),
        (layer_with("'key_ciphertext': b'00'"), ".key_ciphertext"),
        (layer_with("'key_ciphertext_format': 'cbor'"), ".key_ciphertext_format"),
        (
            layer_with(&format!("'key_cipher_layers': [{rsa}]")),
            ".key_cipher_layers",
        ),
        (layer_with("'keychain_uid': 'abc'"), ".keychain_uid"),
        ("{'key_cipher_algo': 'ECIES_X25519'}".into(), ".key_cipher_trustee"),
        ("{'key_cipher_algo': 'AES_EAX'}".into(), ".key_cipher_layers"),
        (
            format!(
                "{{'key_cipher_algo': 'AES_EAX', 'key_cipher_layers': [{rsa}], 'key_cipher_trustee': {LOCAL_TRUSTEE}}}"
            ),
            ".key_cipher_trustee",
        ),
        (
            format!(
                "{{'key_cipher_algo': 'AES_EAX', 'key_cipher_layers': [{rsa}, {}]}}",
                layer_with("'foo': null")
            ),
            ".key_cipher_layers[1].foo",
        ),
        // Trustees
        (trustee_layer("'local_keyfactory'"), ".key_cipher_trustee"),
    ];
    for (key_layer, location_suffix) in key_layer_cases {
        invalid(
            simple_cryptoconf(&key_layer),
            InvalidProfile,
            at(KEY_LAYER_0, location_suffix),
        );
    }
    invalid(
        simple_cryptoconf(&format!(
            "{rsa}, {{'key_cipher_algo': 'AES_EAX', 'key_cipher_layers': []}}"
        )),
        InvalidProfile,
        at(PAYLOAD_0, ".key_cipher_layers[1].key_cipher_layers"),
    );
    let trustee_cases: [(String, &str); 9] = [
        ("{'trustee_type': 'local'}".into(), "trustee_type"),
        ("{}".into(), "trustee_type"),
        (
            format!("{{'trustee_type': 'local_keyfactory', 'keystore_uid': {UID}}}"),
            "keystore_uid",
        ),
        (
            "{'trustee_type': 'authenticator', 'keystore_owner': 'Jane'}".into(),
            "keystore_uid",
        ),
        (
            "{'trustee_type': 'authenticator', 'keystore_uid': '0123456789abcdef0123456789abcdef'}".into(),
            "keystore_uid",
        ),
        (
            format!("{{'trustee_type': 'authenticator', 'keystore_uid': {UID}, 'keystore_owner': 3}}"),
            "keystore_owner",
        ),
        (
            format!("{{'trustee_type': 'authenticator', 'keystore_uid': {UID}, 'jsonrpc_url': 'x'}}"),
            "jsonrpc_url",
        ),
        ("{'trustee_type': 'jsonrpc_api'}".into(), "jsonrpc_url"),
        (
            "{'trustee_type': 'jsonrpc_api', 'jsonrpc_url': b'00'}".into(),
            "jsonrpc_url",
        ),
    ];
    for (trustee, faulty_key) in trustee_cases {
        invalid(
            simple_cryptoconf(&trustee_layer(&trustee)),
            InvalidProfile,
            format!("{KEY_LAYER_0}.key_cipher_trustee.{faulty_key}"),
        );
    }

    // Shared secrets
    let two_shards = format!("{}, {}", shard(rsa), shard(rsa));
    let shared_secret_cases: [(String, &str); 12] = [
        (shared_secret_layer("0", &shard(rsa)), ".key_shared_secret_threshold"),
        (shared_secret_layer("-1", &shard(rsa)), ".key_shared_secret_threshold"),
        (shared_secret_layer("3", &two_shards), ".key_shared_secret_threshold"),
        (shared_secret_layer("'1'", &shard(rsa)), ".key_shared_secret_threshold"),
        (shared_secret_layer("1", ""), ".key_shared_secret_threshold"),
        (
            format!(
                "{{'key_cipher_algo': '[SHARED_SECRET]', 'key_shared_secret_shards': [{}]}}",
                shard(rsa)
            ),
            ".key_shared_secret_threshold",
        ),
        (
            "{'key_cipher_algo': '[SHARED_SECRET]', 'key_shared_secret_threshold': 1}".into(),
            ".key_shared_secret_shards",
        ),
        (
            format!(
                "{{'key_cipher_algo': '[SHARED_SECRET]', 'key_shared_secret_threshold': 1, \
                 'key_shared_secret_shards': [{}], 'key_cipher_layers': [{rsa}]}}",
                shard(rsa)
            ),
            ".key_cipher_layers",
        ),
        (
            shared_secret_layer(
                "1",
                &format!(
                    "{}, {{'key_cipher_layers': [{rsa}], 'key_cipher_algo': 'AES_CBC'}}",
                    shard(rsa)
                ),
            ),
            ".key_shared_secret_shards[1].key_cipher_algo",
        ),
        (
            shared_secret_layer("1", &format!("{}, {}", shard(rsa), shard(""))),
            ".key_shared_secret_shards[1].key_cipher_layers",
        ),
        (shared_secret_layer("1", "[]"), ".key_shared_secret_shards[0]"),
        (
            shared_secret_layer("1", &shard(&layer_with("'keychain_uid': 5"))),
            ".key_shared_secret_shards[0].key_cipher_layers[0].keychain_uid",
        ),
    ];
    for (key_layer, location_suffix) in shared_secret_cases {
        invalid(
            simple_cryptoconf(&key_layer),
            InvalidProfile,
            at(KEY_LAYER_0, location_suffix),
        );
    }
    cases
}

#[test]
fn each_rule_gives_its_error_kind_and_location() {
    let limits = EncryptorLimits::default();
    let cases = cryptoconf_cases();
    assert_eq!(cases.len(), 69);
    for (case_index, (notation, expected_kind, expected_location)) in cases.iter().enumerate() {
        let result = internals::validate_cryptoconf(&build_tree(notation), &limits);
        let actual = result
            .as_ref()
            .err()
            .map(|error| (error.kind(), error.location().to_owned()));
        let expected = expected_kind.map(|kind| (kind, expected_location.clone()));
        assert_eq!(actual, expected, "case {case_index}: {notation}");
    }
}

/// A cryptoconf whose single payload layer nests `level_count` `key_cipher_layers` lists (level 1 being the
/// payload layer's own), alternating symmetric key layers and shared secret shards, and the location of the
/// deepest list.
fn nested_cryptoconf(level_count: usize) -> (String, String) {
    let mut notation = format!(
        "{{'keychain_uid': {UID}, 'payload_cipher_layers': [{{'payload_cipher_algo': 'AES_CBC', \
         'payload_ciphertext_signatures': [], 'key_cipher_layers': ["
    );
    let mut deepest_list = format!("{PAYLOAD_0}.key_cipher_layers");
    let mut closings = Vec::new();
    for level in 2..=level_count {
        if level % 2 == 0 {
            notation.push_str("{'key_cipher_algo': 'AES_EAX', 'key_cipher_layers': [");
            deepest_list.push_str("[0].key_cipher_layers");
            closings.push("]}");
        } else {
            notation.push_str(
                "{'key_cipher_algo': '[SHARED_SECRET]', 'key_shared_secret_threshold': 1, \
                 'key_shared_secret_shards': [{'key_cipher_layers': [",
            );
            deepest_list.push_str("[0].key_shared_secret_shards[0].key_cipher_layers");
            closings.push("]}]}");
        }
    }
    notation.push_str(&rsa_layer());
    for closing in closings.iter().rev() {
        notation.push_str(closing);
    }
    notation.push_str("]}]}");
    (notation, deepest_list)
}

#[test]
fn key_cipher_nesting_depth_is_limited() {
    for (maximum_depth, limits) in [
        (8usize, EncryptorLimits::default()),
        (1, EncryptorLimits::new(1, 64, 4096).unwrap()),
        (3, EncryptorLimits::new(3, 64, 4096).unwrap()),
        // The CBOR limit of 64 levels is what stops deeper profiles from being decoded at all
        (12, EncryptorLimits::new(12, 64, 4096).unwrap()),
    ] {
        assert_eq!(limits.max_key_cipher_nesting_depth(), maximum_depth);
        for level_count in 1..=maximum_depth + 2 {
            let (notation, deepest_list) = nested_cryptoconf(level_count);
            let result = internals::validate_cryptoconf(&build_tree(&notation), &limits);
            if level_count <= maximum_depth {
                assert!(
                    result.is_ok(),
                    "{level_count} levels under a limit of {maximum_depth}: {result:?}"
                );
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), ErrorKind::NestingTooDeep);
                if level_count == maximum_depth + 1 {
                    // The first list beyond the limit is named, in full
                    assert_eq!(error.location(), deepest_list);
                } else {
                    assert!(deepest_list.starts_with(error.location()));
                }
            }
        }
    }
}

#[test]
fn shared_secrets_have_at_most_30_shards() {
    assert_eq!(wa_flightbox::MAX_SHARED_SECRET_SHARD_COUNT, 30);
    let rsa = rsa_layer();
    let limits = EncryptorLimits::default();
    // The shared secret layer as the key layer of the payload layer, in a shard of another shared secret, or under
    // a symmetric key layer: (prefix, suffix, location of its shard list)
    let placements = [
        (String::new(), "", format!("{KEY_LAYER_0}.key_shared_secret_shards")),
        (
            format!(
                "{{'key_cipher_algo': '[SHARED_SECRET]', 'key_shared_secret_threshold': 1, \
                 'key_shared_secret_shards': [{}, {{'key_cipher_layers': [",
                shard(&rsa)
            ),
            "]}]}",
            format!("{KEY_LAYER_0}.key_shared_secret_shards[1].key_cipher_layers[0].key_shared_secret_shards"),
        ),
        (
            format!("{{'key_cipher_algo': 'AES_EAX', 'key_cipher_layers': [{rsa}, "),
            "]}",
            format!("{KEY_LAYER_0}.key_cipher_layers[1].key_shared_secret_shards"),
        ),
    ];
    // (threshold, shard count, accepted); the shard count is checked first, and 300 shards would give indices
    // above 255
    let shard_lists = [
        ("1", 30usize, true),
        ("30", 30, true),
        ("2", 31, false),
        ("31", 31, false),
        ("0", 31, false),
        ("2", 300, false),
    ];
    for (prefix, suffix, shard_list_location) in &placements {
        for (threshold, shard_count, is_accepted) in shard_lists {
            let shards = vec![shard(&rsa); shard_count].join(", ");
            let notation = simple_cryptoconf(&format!("{prefix}{}{suffix}", shared_secret_layer(threshold, &shards)));
            let result = internals::validate_cryptoconf(&build_tree(&notation), &limits);
            let actual = result.err().map(|error| (error.kind(), error.location().to_owned()));
            let expected = (!is_accepted).then(|| (ErrorKind::InvalidProfile, shard_list_location.clone()));
            assert_eq!(
                actual, expected,
                "{shard_count} shards, threshold {threshold}, at {shard_list_location}"
            );
        }
    }
}

#[test]
fn trustees_are_validated_and_compared_by_identity() {
    let authenticator = authenticator_trustee();
    let trustees: [(String, u8); 7] = [
        (LOCAL_TRUSTEE.into(), 0),
        (authenticator, 1),
        (format!("{{'trustee_type': 'authenticator', 'keystore_uid': {UID}}}"), 1),
        (
            format!("{{'keystore_owner': 'John', 'keystore_uid': {UID}, 'trustee_type': 'authenticator'}}"),
            1,
        ),
        (
            format!("{{'trustee_type': 'authenticator', 'keystore_uid': {OTHER_UID}, 'keystore_owner': 'Jane'}}"),
            2,
        ),
        (JSONRPC_TRUSTEE.into(), 3),
        (
            "{'trustee_type': 'jsonrpc_api', 'jsonrpc_url': 'https://example.com/jsonrpc/'}".into(),
            4,
        ),
    ];
    let trees: Vec<(Value, u8)> = trustees
        .iter()
        .map(|(notation, class)| (build_tree(notation), *class))
        .collect();
    for (trustee, _) in &trees {
        assert!(internals::validate_trustee(trustee).is_ok(), "{trustee:?}");
    }
    for (trustee_a, class_a) in &trees {
        for (trustee_b, class_b) in &trees {
            assert_eq!(
                internals::trustee_identities_are_equal(trustee_a, trustee_b),
                class_a == class_b,
                "{trustee_a:?} and {trustee_b:?}"
            );
        }
    }
    let error = internals::validate_trustee(&build_tree("{'trustee_type': 'jsonrpc_api'}")).unwrap_err();
    assert_eq!(
        (error.kind(), error.location()),
        (ErrorKind::InvalidProfile, "jsonrpc_url")
    );
}
