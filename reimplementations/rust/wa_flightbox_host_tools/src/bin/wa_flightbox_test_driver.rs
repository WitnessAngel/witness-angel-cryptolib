// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Test driver for the pytest interoperability tests (`reimplementations/c-language/tests/interop`), with the
//! command-line protocol of the C driver of the same name: each subcommand runs one library function on hex
//! arguments (or `@FILE` for the raw bytes of a file, beyond command line limits) and prints one JSON object on
//! stdout, with byte strings in lowercase hex, and `status` holding the status name. Trees are printed as their
//! serialization by every writer of the build (`json` and/or `cbor`).
//! Exit code: 0 when the subcommand ran (whatever its status), 2 on usage errors, 1 on driver failures.
//!
//! Subcommands:
//!
//! ```text
//! build-info                                                implementation, crypto backend, document formats
//! symmetric-encrypt ALGO KEY IV_OR_NONCE PLAINTEXT          one-shot cipherdict of a given symkey
//! hpke-seal x25519|ml-kem-768 PK RANDOMNESS INFO AAD PLAINTEXT
//!                                                           HPKE base mode seal, the KEM drawing RANDOMNESS
//! ml-kem-encapsulate PK COINS                               ML-KEM-768 derandomized encapsulation
//! cbor-decode CBOR                                          decode a WA-CBOR document, print it back
//! serialize FORMAT symkey ALGO KEY IV_OR_NONCE              intermediate structures, serialized with S_F
//! serialize FORMAT shard WRITTEN_INDEX SHARD                (WRITTEN_INDEX is the 1-based index of the shard)
//! serialize FORMAT key-struct KEY_BYTES [METADATA_CBOR]
//! wrap-key FORMAT ALGO PUBLIC_KEY KEY_BYTES [METADATA_CBOR] key struct wrap with system randomness; PUBLIC_KEY
//!                                                           is MODULUS:EXPONENT for RSA_OAEP
//! load-profile PROFILE_FILE                                 profile loading status and error location
//! encrypt-cryptainer --profile FILE --input FILE --output-cryptainer FILE [--output-payload FILE]
//!                    [--format json|cbor] [--metadata FILE] [--chunk-size N] [--seed N] [--time T]
//!                                                           deterministic cryptainer (seeded random, clock T in
//!                                                           1/10000 s incremented per call); offloaded when
//!                                                           --output-payload is given; N = 0 for one chunk
//! ```
//!
//! Unlike the C driver, `encrypt-cryptainer` does not report allocator figures (`peak_allocated_bytes`,
//! `leaked_block_count`, `unwiped_secret_release_count`): measuring them takes a global allocator, hence `unsafe`
//! code, which this crate forbids. The allocator robustness tests of the core crate cover them.

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

use wa_flightbox::crypto_backend::{
    CryptoBackend, ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_COINS_SIZE, ML_KEM_768_PUBLIC_KEY_SIZE,
    ML_KEM_768_SHARED_SECRET_SIZE,
};
use wa_flightbox::{
    CryptainerEncryptor, DeviceProfile, DocumentFormat, EncryptorLimits, EncryptorOptions, OutputSink, Value,
    decode_document_from_cbor, internals, write_document,
};
use wa_flightbox_backend_conformance::test_support::{DeterministicHooks, ReplayedRandomHooks};
use wa_flightbox_host_tools::{
    BACKEND_NAME, HostPlatformHooks, ToolBackend, command_line_arguments, decode_hex, enabled_document_format_names,
    encode_hex, open_output_file, parse_document_format, read_file,
};

const SYMKEY_KEY_SIZE: usize = 32;
const STATUS_OK: &str = "WA_STATUS_OK";

/// How a subcommand ended, when it did not print its JSON object.
enum DriverError {
    /// Exit code 2, after the usage
    Usage,
    /// Exit code 1
    Failure,
}

type DriverResult = Result<JsonOutput, DriverError>;

fn usage_error(message: &str) -> DriverError {
    eprintln!("Error: {message}");
    DriverError::Usage
}

/* JSON OUTPUT */

/// The JSON object printed by a subcommand, with the separators of Python's `json.dumps()`.
#[derive(Default)]
struct JsonOutput {
    text: String,
}

fn push_json_string(output: &mut String, text: &str) {
    output.push('"');
    for character in text.chars() {
        match character {
            '"' | '\\' => {
                output.push('\\');
                output.push(character);
            }
            control if u32::from(control) < 0x20 => output.push_str(&format!("\\u{:04x}", u32::from(control))),
            other => output.push(other),
        }
    }
    output.push('"');
}

impl JsonOutput {
    fn begin_field(&mut self, name: &str) {
        self.text.push_str(if self.text.is_empty() { "{" } else { ", " });
        push_json_string(&mut self.text, name);
        self.text.push_str(": ");
    }

    fn text_field(&mut self, name: &str, text: &str) {
        self.begin_field(name);
        push_json_string(&mut self.text, text);
    }

    fn integer_field(&mut self, name: &str, integer: u64) {
        self.begin_field(name);
        self.text.push_str(&integer.to_string());
    }

    fn hex_field(&mut self, name: &str, bytes: &[u8]) {
        self.begin_field(name);
        self.text.push('"');
        self.text.push_str(&encode_hex(bytes));
        self.text.push('"');
    }

    fn raw_field(&mut self, name: &str, json: &str) {
        self.begin_field(name);
        self.text.push_str(json);
    }

    fn status_field<T>(&mut self, result: &wa_flightbox::Result<T>) {
        self.text_field("status", status_name(result));
    }

    /// Fields `json` and/or `cbor`: the tree serialized by each writer of the build, up to the first failure.
    fn tree_fields(&mut self, tree: &Value) -> wa_flightbox::Result<()> {
        for (name, format) in [("json", DocumentFormat::ExtendedJson), ("cbor", DocumentFormat::Cbor)] {
            if !format.is_enabled() {
                continue;
            }
            let mut serialized = Vec::new();
            write_document(tree, format, &mut serialized)?;
            self.hex_field(name, &serialized);
        }
        Ok(())
    }

    fn print(mut self) -> Result<(), DriverError> {
        self.text.push_str(if self.text.is_empty() { "{}\n" } else { "}\n" });
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(self.text.as_bytes())
            .and_then(|()| stdout.flush())
            .map_err(|_| DriverError::Failure)
    }
}

fn status_name<T>(result: &wa_flightbox::Result<T>) -> &'static str {
    match result {
        Ok(_) => STATUS_OK,
        Err(error) => error.kind().status_name(),
    }
}

/* ARGUMENT HELPERS */

/// Bytes given in hex, or `@FILE` for the content of a file.
fn decode_hex_argument(name: &str, hex: &str) -> Result<Vec<u8>, DriverError> {
    if let Some(path) = hex.strip_prefix('@') {
        return read_file(path).map_err(|_| usage_error(&format!("cannot read {path} for {name}")));
    }
    decode_hex(hex).ok_or_else(|| usage_error(&format!("invalid hex for {name}")))
}

/// The key and the IV or nonce of a symkey of this algorithm, with the sizes of section 3.3.
fn parse_symkey(algo_name: &str, key_hex: &str, iv_or_nonce_hex: &str) -> Result<(Vec<u8>, Vec<u8>), DriverError> {
    let Some(expected_iv_or_nonce_length) = internals::symmetric_iv_or_nonce_length(algo_name) else {
        return Err(usage_error(&format!("unknown symmetric algo {algo_name}")));
    };
    let key = decode_hex_argument("KEY", key_hex)?;
    let iv_or_nonce = decode_hex_argument("IV_OR_NONCE", iv_or_nonce_hex)?;
    if key.len() != SYMKEY_KEY_SIZE || iv_or_nonce.len() != expected_iv_or_nonce_length {
        return Err(usage_error(&format!(
            "a {SYMKEY_KEY_SIZE}-byte key and a {expected_iv_or_nonce_length}-byte IV or nonce are expected"
        )));
    }
    Ok((key, iv_or_nonce))
}

/// Optional WA-CBOR metadata (`""` or a missing argument: none), with the status of its decoding.
fn decode_metadata(hex: Option<&String>) -> Result<wa_flightbox::Result<Option<Value>>, DriverError> {
    let Some(hex) = hex.filter(|hex| !hex.is_empty()) else {
        return Ok(Ok(None));
    };
    let cbor = decode_hex_argument("METADATA_CBOR", hex)?;
    Ok(decode_document_from_cbor(&cbor, &EncryptorLimits::default()).map(Some))
}

fn parse_format(name: &str) -> Result<DocumentFormat, DriverError> {
    let Some(format) = parse_document_format(name) else {
        return Err(usage_error(&format!("unknown format {name} (json or cbor)")));
    };
    if !format.is_enabled() {
        return Err(usage_error(&format!("this build does not support the {name} format")));
    }
    Ok(format)
}

fn parse_unsigned(name: &str, text: &str) -> Result<u64, DriverError> {
    if text.is_empty() || !text.bytes().all(|character| character.is_ascii_digit()) {
        return Err(usage_error(&format!("invalid {name} {text}")));
    }
    text.parse::<u64>()
        .map_err(|_| usage_error(&format!("invalid {name} {text}")))
}

/* SUBCOMMANDS */

fn symmetric_encrypt(arguments: &[String]) -> DriverResult {
    let [algo_name, key_hex, iv_or_nonce_hex, plaintext_hex] = arguments else {
        return Err(DriverError::Usage);
    };
    let (key, iv_or_nonce) = parse_symkey(algo_name, key_hex, iv_or_nonce_hex)?;
    let plaintext = decode_hex_argument("PLAINTEXT", plaintext_hex)?;
    let mut output = JsonOutput::default();
    let result = internals::symmetric_encrypt_to_cipherdict::<ToolBackend>(algo_name, &key, &iv_or_nonce, &plaintext)
        .and_then(|cipherdict| output.tree_fields(&cipherdict));
    output.status_field(&result);
    Ok(output)
}

fn hpke_seal(arguments: &[String]) -> DriverResult {
    let [kem_name, values @ ..] = arguments else {
        return Err(DriverError::Usage);
    };
    if values.len() != 5 {
        return Err(DriverError::Usage);
    }
    let Some(public_key_length) = internals::hpke_kem_public_key_length(kem_name) else {
        return Err(usage_error(&format!("unknown KEM {kem_name} (x25519 or ml-kem-768)")));
    };
    let mut decoded_values = Vec::new();
    for (name, value) in ["PK", "RANDOMNESS", "INFO", "AAD", "PLAINTEXT"].into_iter().zip(values) {
        decoded_values.push(decode_hex_argument(name, value)?);
    }
    let [public_key, randomness, info, aad, plaintext] = decoded_values.as_slice() else {
        return Err(DriverError::Failure);
    };
    if public_key.len() != public_key_length {
        return Err(usage_error(&format!(
            "a {public_key_length}-byte public key is expected"
        )));
    }
    // The KEM draws its ephemeral randomness from the random hook: replay RANDOMNESS
    let mut hooks = ReplayedRandomHooks::new(randomness);
    let result = internals::hpke_base_mode_seal::<ToolBackend>(&mut hooks, kem_name, public_key, info, aad, plaintext);
    let mut output = JsonOutput::default();
    if let Ok((enc, sealed)) = &result {
        output.hex_field("enc", enc);
        output.hex_field("sealed", sealed);
    }
    output.integer_field(
        "consumed_randomness_length",
        u64::try_from(hooks.offset).unwrap_or(u64::MAX),
    );
    output.status_field(&result);
    Ok(output)
}

fn ml_kem_encapsulate(arguments: &[String]) -> DriverResult {
    let [public_key_hex, coins_hex] = arguments else {
        return Err(DriverError::Usage);
    };
    let public_key = decode_hex_argument("PK", public_key_hex)?;
    let coins = decode_hex_argument("COINS", coins_hex)?;
    let (Ok(public_key), Ok(coins)) = (
        <[u8; ML_KEM_768_PUBLIC_KEY_SIZE]>::try_from(public_key.as_slice()),
        <[u8; ML_KEM_768_COINS_SIZE]>::try_from(coins.as_slice()),
    ) else {
        return Err(usage_error(&format!(
            "a {ML_KEM_768_PUBLIC_KEY_SIZE}-byte public key and {ML_KEM_768_COINS_SIZE}-byte coins are expected"
        )));
    };
    let mut kem_ciphertext = [0u8; ML_KEM_768_CIPHERTEXT_SIZE];
    let mut shared_secret = [0u8; ML_KEM_768_SHARED_SECRET_SIZE];
    // The modulus check of profile loading first, as the library does
    let result =
        internals::check_public_key("ML_KEM_768", &public_key, &[], &EncryptorLimits::default()).and_then(|()| {
            ToolBackend::ml_kem_768_encapsulate_derandomized(
                &public_key,
                &coins,
                &mut kem_ciphertext,
                &mut shared_secret,
            )
        });
    let mut output = JsonOutput::default();
    if result.is_ok() {
        output.hex_field("kem_ciphertext", &kem_ciphertext);
        output.hex_field("shared_secret", &shared_secret);
    }
    output.status_field(&result);
    Ok(output)
}

fn cbor_decode(arguments: &[String]) -> DriverResult {
    let [cbor_hex] = arguments else {
        return Err(DriverError::Usage);
    };
    let cbor = decode_hex_argument("CBOR", cbor_hex)?;
    let mut output = JsonOutput::default();
    let result =
        decode_document_from_cbor(&cbor, &EncryptorLimits::default()).and_then(|tree| output.tree_fields(&tree));
    output.status_field(&result);
    Ok(output)
}

fn serialize(arguments: &[String]) -> DriverResult {
    let [format_name, structure_name, values @ ..] = arguments else {
        return Err(DriverError::Usage);
    };
    let format = parse_format(format_name)?;
    let result = match (structure_name.as_str(), values) {
        ("symkey", [algo_name, key_hex, iv_or_nonce_hex]) => {
            let (key, iv_or_nonce) = parse_symkey(algo_name, key_hex, iv_or_nonce_hex)?;
            internals::serialize_symkey(format, algo_name, &key, &iv_or_nonce)
        }
        ("shard", [written_index, shard_hex]) => {
            let written_index = parse_unsigned("WRITTEN_INDEX", written_index)?;
            let shard_index = match usize::try_from(written_index) {
                Ok(written_index @ 1..=255) => written_index - 1,
                _ => return Err(DriverError::Usage),
            };
            let shard = decode_hex_argument("SHARD", shard_hex)?;
            internals::serialize_shard(format, shard_index, &shard)
        }
        ("key-struct", [key_bytes_hex, metadata_hex @ ..]) if metadata_hex.len() <= 1 => {
            let key_bytes = decode_hex_argument("KEY_BYTES", key_bytes_hex)?;
            decode_metadata(metadata_hex.first())?
                .and_then(|metadata| internals::serialize_key_struct(format, &key_bytes, metadata.as_ref()))
        }
        ("symkey" | "shard" | "key-struct", _) => return Err(DriverError::Usage),
        _ => {
            return Err(usage_error(&format!(
                "unknown structure {structure_name} (symkey, shard or key-struct)"
            )));
        }
    };
    let mut output = JsonOutput::default();
    if let Ok(serialized) = &result {
        output.hex_field("serialized", serialized);
    }
    output.status_field(&result);
    Ok(output)
}

fn wrap_key(arguments: &[String]) -> DriverResult {
    let [
        format_name,
        algo_name,
        public_key_text,
        key_bytes_hex,
        metadata_hex @ ..,
    ] = arguments
    else {
        return Err(DriverError::Usage);
    };
    if metadata_hex.len() > 1 {
        return Err(DriverError::Usage);
    }
    let format = parse_format(format_name)?;
    if !internals::is_asymmetric_cipher_algo(algo_name) {
        return Err(usage_error(&format!("unknown asymmetric algo {algo_name}")));
    }
    let (modulus_or_key_bytes, public_exponent) = if algo_name == "RSA_OAEP" {
        let Some((modulus_hex, exponent_hex)) = public_key_text.split_once(':') else {
            return Err(usage_error("an RSA_OAEP public key is given as MODULUS:EXPONENT"));
        };
        (
            decode_hex_argument("MODULUS", modulus_hex)?,
            decode_hex_argument("EXPONENT", exponent_hex)?,
        )
    } else {
        (decode_hex_argument("PUBLIC_KEY", public_key_text)?, Vec::new())
    };
    let key_bytes = decode_hex_argument("KEY_BYTES", key_bytes_hex)?;
    let metadata = decode_metadata(metadata_hex.first())?;
    let mut hooks = HostPlatformHooks;
    let mut output = JsonOutput::default();
    // The key constraints of profile loading first, as the library does
    let result = metadata
        .and_then(|metadata| {
            internals::check_public_key(
                algo_name,
                &modulus_or_key_bytes,
                &public_exponent,
                &EncryptorLimits::default(),
            )?;
            internals::asymmetric_wrap_key_struct::<ToolBackend>(
                &mut hooks,
                format,
                algo_name,
                &modulus_or_key_bytes,
                &public_exponent,
                &key_bytes,
                metadata.as_ref(),
            )
        })
        .and_then(|cipherdict| output.tree_fields(&cipherdict));
    output.status_field(&result);
    Ok(output)
}

fn load_profile(arguments: &[String]) -> DriverResult {
    let [profile_path] = arguments else {
        return Err(DriverError::Usage);
    };
    let Ok(profile_bytes) = read_file(profile_path) else {
        eprintln!("Error: cannot read {profile_path}");
        return Err(DriverError::Failure);
    };
    let result = DeviceProfile::load_from_cbor(&profile_bytes, &EncryptorLimits::default());
    let mut output = JsonOutput::default();
    output.status_field(&result);
    output.text_field("location", result.as_ref().err().map_or("", |error| error.location()));
    Ok(output)
}

struct EncryptionArguments {
    profile_path: String,
    input_path: String,
    cryptainer_path: String,
    payload_path: Option<String>,
    metadata_path: Option<String>,
    document_format: DocumentFormat,
    /// 0: one chunk
    chunk_size: u64,
    seed: u64,
    time: u64,
}

fn parse_encryption_arguments(arguments: &[String]) -> Result<EncryptionArguments, DriverError> {
    let mut profile_path = None;
    let mut input_path = None;
    let mut cryptainer_path = None;
    let mut payload_path = None;
    let mut metadata_path = None;
    let mut document_format = DocumentFormat::BuildDefault;
    let mut chunk_size = 0;
    let mut seed = 1;
    let mut time = DeterministicHooks::DEFAULT_TIME;
    let pairs = arguments.chunks_exact(2);
    let has_unpaired_argument = !pairs.remainder().is_empty();
    for pair in pairs {
        let [name, value] = pair else {
            return Err(DriverError::Failure);
        };
        match name.as_str() {
            "--profile" => profile_path = Some(value.clone()),
            "--input" => input_path = Some(value.clone()),
            "--output-cryptainer" => cryptainer_path = Some(value.clone()),
            "--output-payload" => payload_path = Some(value.clone()),
            "--metadata" => metadata_path = Some(value.clone()),
            "--format" => document_format = parse_format(value)?,
            "--chunk-size" => chunk_size = parse_unsigned("chunk size", value)?,
            "--seed" => seed = parse_unsigned("seed", value)?,
            "--time" => time = parse_unsigned("time", value)?,
            _ => return Err(usage_error(&format!("unknown option {name}"))),
        }
    }
    match (has_unpaired_argument, profile_path, input_path, cryptainer_path) {
        (false, Some(profile_path), Some(input_path), Some(cryptainer_path)) => Ok(EncryptionArguments {
            profile_path,
            input_path,
            cryptainer_path,
            payload_path,
            metadata_path,
            document_format,
            chunk_size,
            seed,
            time,
        }),
        _ => Err(usage_error(
            "--profile, --input and --output-cryptainer are required, options taking a value",
        )),
    }
}

/// Steps 2 and 3: the serialized cryptainer of the chunks of a payload, or of one empty chunk if there is none.
fn encrypt_chunks<S: OutputSink>(
    mut encryptor: CryptainerEncryptor<ToolBackend, S>,
    mut chunks: std::slice::Chunks<'_, u8>,
) -> wa_flightbox::Result<Vec<u8>> {
    encryptor.encrypt_payload_chunk(chunks.next().unwrap_or(&[]))?;
    for chunk in chunks {
        encryptor.encrypt_payload_chunk(chunk)?;
    }
    let mut cryptainer = Vec::new();
    encryptor.finalize()?.write_cryptainer(&mut cryptainer)?;
    Ok(cryptainer)
}

/// The cryptainer and, when offloaded, the payload ciphertext; a profile loading error keeps its location.
fn encrypt_deterministically(
    arguments: &EncryptionArguments,
    hooks: &mut DeterministicHooks,
    profile_bytes: &[u8],
    metadata_bytes: Option<&[u8]>,
    payload: &[u8],
    error_location: &mut String,
) -> wa_flightbox::Result<(Vec<u8>, Option<Vec<u8>>)> {
    let limits = EncryptorLimits::default();
    let device_profile = DeviceProfile::load_from_cbor(profile_bytes, &limits).inspect_err(|error| {
        error_location.push_str(error.location());
    })?;
    let metadata = metadata_bytes
        .map(|bytes| decode_document_from_cbor(bytes, &limits))
        .transpose()?;
    let options = EncryptorOptions {
        document_format: arguments.document_format,
        ..EncryptorOptions::default()
    };
    // At least one chunk, even for an empty payload
    let chunk_size = match usize::try_from(arguments.chunk_size) {
        Ok(chunk_size) if chunk_size != 0 && chunk_size <= payload.len() => chunk_size,
        _ => payload.len().max(1),
    };
    let chunks = payload.chunks(chunk_size);
    if arguments.payload_path.is_some() {
        let mut payload_ciphertext = Vec::new();
        let encryptor = CryptainerEncryptor::<ToolBackend, _>::create_offloaded(
            &device_profile,
            metadata.as_ref(),
            &options,
            hooks,
            &mut payload_ciphertext,
        )?;
        let cryptainer = encrypt_chunks(encryptor, chunks)?;
        Ok((cryptainer, Some(payload_ciphertext)))
    } else {
        let encryptor =
            CryptainerEncryptor::<ToolBackend>::create(&device_profile, metadata.as_ref(), &options, hooks)?;
        Ok((encrypt_chunks(encryptor, chunks)?, None))
    }
}

fn write_file(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = open_output_file(path, true)?;
    file.write_all(bytes)?;
    file.flush()
}

fn encrypt_cryptainer(arguments: &[String]) -> DriverResult {
    let arguments = parse_encryption_arguments(arguments)?;
    let profile_bytes = read_file(&arguments.profile_path);
    let payload = read_file(&arguments.input_path);
    let metadata_bytes = arguments.metadata_path.as_deref().map(read_file).transpose();
    let (Ok(profile_bytes), Ok(payload), Ok(metadata_bytes)) = (profile_bytes, payload, metadata_bytes) else {
        eprintln!("Error: cannot read an input file, or out of memory");
        return Err(DriverError::Failure);
    };
    let mut hooks = DeterministicHooks::new(arguments.seed);
    hooks.unix_time_in_ten_thousandths_of_second = Some(arguments.time);

    let mut error_location = String::new();
    let result = encrypt_deterministically(
        &arguments,
        &mut hooks,
        &profile_bytes,
        metadata_bytes.as_deref(),
        &payload,
        &mut error_location,
    );
    if let Ok((cryptainer, payload_ciphertext)) = &result {
        let payload_written = match (&arguments.payload_path, payload_ciphertext) {
            (Some(payload_path), Some(payload_ciphertext)) => write_file(payload_path, payload_ciphertext),
            _ => Ok(()),
        };
        if payload_written
            .and_then(|()| write_file(&arguments.cryptainer_path, cryptainer))
            .is_err()
        {
            eprintln!("Error: cannot write the output files");
            return Err(DriverError::Failure);
        }
    }
    let mut output = JsonOutput::default();
    output.status_field(&result);
    output.text_field("location", &error_location);
    output.integer_field("random_call_count", hooks.random_call_count);
    Ok(output)
}

fn build_info(arguments: &[String]) -> DriverResult {
    if !arguments.is_empty() {
        return Err(DriverError::Usage);
    }
    let mut output = JsonOutput::default();
    output.text_field("implementation", "rust");
    output.text_field("backend", BACKEND_NAME);
    let format_names: Vec<String> = enabled_document_format_names()
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect();
    output.raw_field("document_formats", &format!("[{}]", format_names.join(", ")));
    output.text_field("status", STATUS_OK);
    Ok(output)
}

fn print_usage() {
    eprint!(
        "Usage: wa_flightbox_test_driver SUBCOMMAND ARGUMENTS... (byte strings in hex, or @FILE)\n\
         \x20 build-info\n\
         \x20 symmetric-encrypt ALGO KEY IV_OR_NONCE PLAINTEXT\n\
         \x20 hpke-seal x25519|ml-kem-768 PK RANDOMNESS INFO AAD PLAINTEXT\n\
         \x20 ml-kem-encapsulate PK COINS\n\
         \x20 cbor-decode CBOR\n\
         \x20 serialize json|cbor symkey ALGO KEY IV_OR_NONCE\n\
         \x20 serialize json|cbor shard WRITTEN_INDEX SHARD\n\
         \x20 serialize json|cbor key-struct KEY_BYTES [METADATA_CBOR]\n\
         \x20 wrap-key json|cbor ALGO PUBLIC_KEY KEY_BYTES [METADATA_CBOR]   (RSA_OAEP: PUBLIC_KEY = MODULUS:EXPONENT)\n\
         \x20 load-profile PROFILE_FILE\n\
         \x20 encrypt-cryptainer --profile FILE --input FILE --output-cryptainer FILE [--output-payload FILE]\n\
         \x20                    [--format json|cbor] [--metadata FILE] [--chunk-size N] [--seed N] [--time T]\n"
    );
}

fn main() -> ExitCode {
    let command_line = command_line_arguments().unwrap_or_default();
    let result = match command_line.split_first() {
        None => Err(DriverError::Usage),
        Some((subcommand, arguments)) => match subcommand.as_str() {
            "build-info" => build_info(arguments),
            "symmetric-encrypt" => symmetric_encrypt(arguments),
            "hpke-seal" => hpke_seal(arguments),
            "ml-kem-encapsulate" => ml_kem_encapsulate(arguments),
            "cbor-decode" => cbor_decode(arguments),
            "serialize" => serialize(arguments),
            "wrap-key" => wrap_key(arguments),
            "load-profile" => load_profile(arguments),
            "encrypt-cryptainer" => encrypt_cryptainer(arguments),
            _ => Err(DriverError::Usage),
        },
    };
    match result.and_then(JsonOutput::print) {
        Ok(()) => ExitCode::SUCCESS,
        Err(DriverError::Usage) => {
            print_usage();
            ExitCode::from(2)
        }
        Err(DriverError::Failure) => ExitCode::from(1),
    }
}
