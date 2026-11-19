// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Host command-line tool: encrypt a file into a cryptainer with a device profile, like `flightbox encrypt` does
//! with a cryptoconf (encryptor specification, section 9), with the arguments, messages and exit statuses of the C
//! tool of the same name. The payload ciphertext is offloaded into `<cryptainer file>.payload` unless `--bundle`
//! is given; the payload file is written first and the cryptainer last, so that a cryptainer never refers to a
//! missing payload, and the files created are deleted on failure. With `--force`, existing output files are only
//! replaced (by renaming) once their new versions are complete; output files that are one of the input files are
//! always refused.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::process::ExitCode;

use wa_flightbox::{
    CryptainerEncryptor, DeviceProfile, DocumentFormat, EncryptorLimits, EncryptorOptions, Error, ErrorKind,
    FinishedCryptainer, OutputSink, PlatformHooks, Value, decode_document_from_cbor,
};
use wa_flightbox_host_tools::{
    FileSink, HostPlatformHooks, ToolBackend, build_cryptainer_path, build_payload_path, command_line_arguments,
    enabled_document_format_names, file_exists, files_are_same, open_output_file, open_temporary_output_file,
    parse_document_format, read_file, replace_file,
};

const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
const MAXIMUM_CHUNK_SIZE: usize = 1024 * 1024 * 1024;

const EXIT_FAILURE: u8 = 1;
const EXIT_USAGE_ERROR: u8 = 2;

struct CliArguments {
    input_path: String,
    profile_path: String,
    metadata_path: Option<String>,
    /// `None`: the input path
    output_basename: Option<String>,
    document_format: DocumentFormat,
    is_bundle: bool,
    is_forced: bool,
    chunk_size: usize,
}

enum ParsedCommandLine {
    Arguments(CliArguments),
    Help,
    UsageError,
}

fn usage() -> String {
    let format_names = enabled_document_format_names();
    format!(
        "Usage: wa_flightbox_encrypt_file_cli -p PROFILE [options] INPUT_FILE\n\
         \n\
         Encrypt INPUT_FILE (or '-' for stdin) into a cryptainer, with a WA-CBOR device profile.\n\
         \n\
         Options:\n\
         \x20 -p, --profile FILE          device profile (WA-CBOR), required\n\
         \x20 -o, --output-basename NAME  basename of the output files (default: INPUT_FILE); a trailing\n\
         \x20                             .crypt, .crypt.json or .crypt.cbor suffix, in any case, is stripped\n\
         \x20 -m, --metadata FILE         cryptainer metadata, a WA-CBOR map (default: none)\n\
         \x20 --format json|cbor          cryptainer format, also used for its key ciphertexts (default: {})\n\
         \x20 --bundle                    embed the payload ciphertext in the cryptainer (default: offloaded\n\
         \x20                             into <cryptainer file>.payload)\n\
         \x20 --chunk-size N              bytes read from the input at a time, at most 1 GiB (default: {})\n\
         \x20 --force                     replace existing output files, once the new ones are complete\n\
         \x20 -h, --help                  show this help\n\
         \n\
         Formats of this build:{}\n",
        format_names.first().copied().unwrap_or(""),
        DEFAULT_CHUNK_SIZE,
        format_names.iter().map(|name| format!(" {name}")).collect::<String>(),
    )
}

/// Digits only, from 1 to 1 GiB.
fn parse_chunk_size(value: &str) -> Option<usize> {
    if value.is_empty() || !value.bytes().all(|character| character.is_ascii_digit()) {
        return None;
    }
    let chunk_size = value.parse::<usize>().ok()?;
    (1..=MAXIMUM_CHUNK_SIZE).contains(&chunk_size).then_some(chunk_size)
}

fn parse_command_line(arguments: &[String]) -> ParsedCommandLine {
    let mut input_path = None;
    let mut profile_path = None;
    let mut metadata_path = None;
    let mut output_basename = None;
    let mut document_format = DocumentFormat::BuildDefault;
    let mut is_bundle = false;
    let mut is_forced = false;
    let mut chunk_size = DEFAULT_CHUNK_SIZE;

    let mut remaining = arguments.iter();
    while let Some(argument) = remaining.next() {
        match argument.as_str() {
            "-h" | "--help" => return ParsedCommandLine::Help,
            "--bundle" => is_bundle = true,
            "--force" => is_forced = true,
            "-p" | "--profile" | "-o" | "--output-basename" | "-m" | "--metadata" | "--format" | "--chunk-size" => {
                let Some(value) = remaining.next() else {
                    eprintln!("Error: option {argument} needs a value");
                    return ParsedCommandLine::UsageError;
                };
                match argument.as_str() {
                    "-p" | "--profile" => profile_path = Some(value.clone()),
                    "-o" | "--output-basename" => output_basename = Some(value.clone()),
                    "-m" | "--metadata" => metadata_path = Some(value.clone()),
                    "--format" => match parse_document_format(value) {
                        Some(format) => document_format = format,
                        None => {
                            eprintln!("Error: unknown format {value} (json or cbor)");
                            return ParsedCommandLine::UsageError;
                        }
                    },
                    _ => match parse_chunk_size(value) {
                        Some(size) => chunk_size = size,
                        None => {
                            eprintln!("Error: invalid chunk size {value}");
                            return ParsedCommandLine::UsageError;
                        }
                    },
                }
            }
            option if option.starts_with('-') && option.len() > 1 => {
                eprintln!("Error: unknown option {option}");
                return ParsedCommandLine::UsageError;
            }
            _ if input_path.is_none() => input_path = Some(argument.clone()),
            _ => {
                eprintln!("Error: unexpected argument {argument}");
                return ParsedCommandLine::UsageError;
            }
        }
    }
    let (Some(input_path), Some(profile_path)) = (input_path, profile_path) else {
        eprintln!("Error: an input file and a profile (-p) are required");
        return ParsedCommandLine::UsageError;
    };
    let stdin_use_count = [Some(&input_path), Some(&profile_path), metadata_path.as_ref()]
        .into_iter()
        .flatten()
        .filter(|path| *path == "-")
        .count();
    if stdin_use_count > 1 {
        eprintln!("Error: stdin ('-') can only be one of the input file, the profile and the metadata");
        return ParsedCommandLine::UsageError;
    }
    if input_path == "-" && output_basename.is_none() {
        eprintln!("Error: an output basename (-o) is required when the input is stdin");
        return ParsedCommandLine::UsageError;
    }
    ParsedCommandLine::Arguments(CliArguments {
        input_path,
        profile_path,
        metadata_path,
        output_basename,
        document_format,
        is_bundle,
        is_forced,
        chunk_size,
    })
}

fn print_status_error(context: &str, error: &Error, location: Option<&str>) {
    let kind = error.kind();
    let mut message = format!("Error: {context}: {} [{}]", kind.description(), kind.status_name());
    if let Some(location) = location.filter(|location| !location.is_empty()) {
        message.push_str(" at ");
        message.push_str(location);
    }
    eprintln!("{message}");
}

/// An output file. Without `--force` it is created exclusively at its final path; with `--force` it is written to
/// a new temporary file next to it, renamed over the final path only once complete, so that a failure never loses
/// the existing file.
struct CliOutput {
    final_path: String,
    /// With `--force` only
    temporary_path: Option<String>,
    sink: Option<FileSink>,
    /// The file at the write path was created by this run, and is deleted on failure
    is_created: bool,
}

impl CliOutput {
    fn new(final_path: String) -> Self {
        Self {
            final_path,
            temporary_path: None,
            sink: None,
            is_created: false,
        }
    }

    fn write_path(&self) -> &str {
        self.temporary_path.as_deref().unwrap_or(&self.final_path)
    }

    fn open(&mut self, is_forced: bool) -> bool {
        let file = if is_forced {
            open_temporary_output_file(&self.final_path).map(|(file, temporary_path)| {
                self.temporary_path = Some(temporary_path);
                file
            })
        } else {
            open_output_file(&self.final_path, false).ok()
        };
        let Some(file) = file else {
            let reason = if is_forced {
                " (temporary file)"
            } else {
                " (existing file?)"
            };
            eprintln!("Error: cannot create {}{reason}", self.final_path);
            return false;
        };
        self.sink = Some(FileSink::new(file));
        self.is_created = true;
        true
    }

    fn close(&mut self) -> bool {
        self.sink.take().is_none_or(|sink| sink.close().is_ok())
    }

    /// Keep a complete output: move its temporary file to its final path (already there without `--force`).
    fn commit(&mut self) -> bool {
        if let Some(temporary_path) = self.temporary_path.take() {
            if replace_file(&temporary_path, &self.final_path).is_err() {
                eprintln!("Error: cannot replace {}", self.final_path);
                self.temporary_path = Some(temporary_path);
                return false;
            }
        }
        // Now at its final path, where it may have replaced an existing file
        self.is_created = false;
        true
    }

    /// Close, and delete if created by this run and not committed.
    fn discard(&mut self) {
        self.sink = None;
        if self.is_created {
            let _ = std::fs::remove_file(self.write_path());
            self.is_created = false;
        }
        self.temporary_path = None;
    }
}

/// Fill `buffer` from the input, short only at its end.
fn read_chunk(input: &mut dyn Read, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut length = 0;
    while length < buffer.len() {
        match input.read(&mut buffer[length..]) {
            Ok(0) => break,
            Ok(read_count) => length += read_count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(length)
}

/// Step 2 over the whole input, and its end; `None` after an error, already reported.
fn encrypt_payload<S: OutputSink>(
    created_encryptor: wa_flightbox::Result<CryptainerEncryptor<ToolBackend, S>>,
    input: &mut dyn Read,
    chunk: &mut [u8],
    input_path: &str,
) -> Option<FinishedCryptainer> {
    let mut encryptor = match created_encryptor {
        Ok(encryptor) => encryptor,
        Err(error) => {
            print_status_error("cryptainer creation failed", &error, None);
            return None;
        }
    };
    loop {
        let Ok(read_count) = read_chunk(input, chunk) else {
            eprintln!("Error: cannot read the input file {input_path}");
            return None;
        };
        if read_count > 0 {
            if let Err(error) = encryptor.encrypt_payload_chunk(&chunk[..read_count]) {
                print_status_error("payload encryption failed", &error, None);
                return None;
            }
        }
        if read_count < chunk.len() {
            break;
        }
    }
    match encryptor.finalize() {
        Ok(finished) => Some(finished),
        Err(error) => {
            print_status_error("finalization failed", &error, None);
            None
        }
    }
}

/// Run the encryption proper: the payload file first and the cryptainer last (also renamed in that order with
/// `--force`), so that a new cryptainer never refers to a missing payload. Whether it succeeded.
fn encrypt(
    arguments: &CliArguments,
    hooks: &mut dyn PlatformHooks,
    device_profile: &DeviceProfile,
    metadata: Option<&Value>,
    cryptainer_output: &mut CliOutput,
    mut payload_output: Option<&mut CliOutput>,
) -> bool {
    let mut input: Box<dyn Read> = if arguments.input_path == "-" {
        Box::new(std::io::stdin().lock())
    } else {
        match File::open(&arguments.input_path) {
            Ok(file) => Box::new(file),
            Err(_) => {
                eprintln!("Error: cannot open the input file {}", arguments.input_path);
                return false;
            }
        }
    };
    let mut chunk = Vec::new();
    if chunk.try_reserve_exact(arguments.chunk_size).is_err() {
        eprintln!("Error: out of memory");
        return false;
    }
    chunk.resize(arguments.chunk_size, 0u8);

    let options = EncryptorOptions {
        document_format: arguments.document_format,
        ..EncryptorOptions::default()
    };
    let finished = if let Some(payload_output) = payload_output.as_deref_mut() {
        if !payload_output.open(arguments.is_forced) {
            return false;
        }
        let Some(payload_sink) = payload_output.sink.as_mut() else {
            return false;
        };
        let created_encryptor = CryptainerEncryptor::<ToolBackend, _>::create_offloaded(
            device_profile,
            metadata,
            &options,
            hooks,
            payload_sink,
        );
        encrypt_payload(created_encryptor, &mut *input, &mut chunk, &arguments.input_path)
    } else {
        let created_encryptor = CryptainerEncryptor::<ToolBackend>::create(device_profile, metadata, &options, hooks);
        encrypt_payload(created_encryptor, &mut *input, &mut chunk, &arguments.input_path)
    };
    let Some(finished) = finished else {
        return false;
    };
    if let Some(payload_output) = payload_output.as_deref_mut() {
        if !payload_output.close() {
            eprintln!("Error: cannot write {}", payload_output.write_path());
            return false;
        }
    }

    if !cryptainer_output.open(arguments.is_forced) {
        return false;
    }
    let Some(cryptainer_sink) = cryptainer_output.sink.as_mut() else {
        return false;
    };
    let mut written = finished.write_cryptainer(cryptainer_sink);
    if !cryptainer_output.close() && written.is_ok() {
        written = Err(Error::new(ErrorKind::SinkWriteFailure));
    }
    if let Err(error) = written {
        print_status_error("cryptainer writing failed", &error, None);
        return false;
    }
    if let Some(payload_output) = payload_output.as_deref_mut() {
        if !payload_output.commit() {
            return false;
        }
    }
    if !cryptainer_output.commit() {
        return false;
    }
    println!("{}", cryptainer_output.final_path);
    if let Some(payload_output) = payload_output {
        println!("{}", payload_output.final_path);
    }
    true
}

/// Refuse an output path that is one of the input files: with `--force`, that input would be replaced (and the
/// input file read while being replaced). Only an existing output can be such a file.
fn check_output_is_not_an_input(arguments: &CliArguments, output_path: &str) -> bool {
    let inputs = [
        ("input file", Some(&arguments.input_path)),
        ("profile", Some(&arguments.profile_path)),
        ("metadata file", arguments.metadata_path.as_ref()),
    ];
    for (input_name, input_path) in inputs {
        if let Some(input_path) = input_path {
            if input_path != "-" && files_are_same(output_path, input_path) {
                eprintln!("Error: the output file {output_path} is the {input_name}");
                return false;
            }
        }
    }
    true
}

/// Everything after the parsing of the command line; whether it succeeded.
fn run(arguments: &CliArguments, cryptainer_output: &mut CliOutput, payload_output: &mut Option<CliOutput>) -> bool {
    let limits = EncryptorLimits::default();
    let mut hooks = HostPlatformHooks;

    // Output names, refused early (nothing is generated then) when existing, or when one of the input files
    if !check_output_is_not_an_input(arguments, &cryptainer_output.final_path) {
        return false;
    }
    if let Some(payload_output) = payload_output.as_ref() {
        if !check_output_is_not_an_input(arguments, &payload_output.final_path) {
            return false;
        }
    }
    if !arguments.is_forced {
        let existing_path = [Some(&*cryptainer_output), payload_output.as_ref()]
            .into_iter()
            .flatten()
            .map(|output| output.final_path.as_str())
            .find(|path| file_exists(path));
        if let Some(existing_path) = existing_path {
            eprintln!("Error: {existing_path} already exists (use --force to overwrite it)");
            return false;
        }
    }

    // Profile and metadata
    let Ok(profile_bytes) = read_file(&arguments.profile_path) else {
        eprintln!("Error: cannot read the profile {}", arguments.profile_path);
        return false;
    };
    let device_profile = match DeviceProfile::load_from_cbor(&profile_bytes, &limits) {
        Ok(device_profile) => device_profile,
        Err(error) => {
            print_status_error("invalid device profile", &error, Some(error.location()));
            return false;
        }
    };
    drop(profile_bytes);
    let mut metadata = None;
    if let Some(metadata_path) = &arguments.metadata_path {
        let Ok(metadata_bytes) = read_file(metadata_path) else {
            eprintln!("Error: cannot read the metadata {metadata_path}");
            return false;
        };
        match decode_document_from_cbor(&metadata_bytes, &limits) {
            Ok(tree) => metadata = Some(tree),
            Err(error) => {
                print_status_error("invalid metadata", &error, None);
                return false;
            }
        }
    }

    encrypt(
        arguments,
        &mut hooks,
        &device_profile,
        metadata.as_ref(),
        cryptainer_output,
        payload_output.as_mut(),
    )
}

fn main() -> ExitCode {
    let Some(command_line) = command_line_arguments() else {
        eprintln!("Error: the arguments are not valid Unicode");
        eprint!("{}", usage());
        return ExitCode::from(EXIT_USAGE_ERROR);
    };
    let arguments = match parse_command_line(&command_line) {
        ParsedCommandLine::Arguments(arguments) => arguments,
        ParsedCommandLine::Help => {
            print!("{}", usage());
            return ExitCode::SUCCESS;
        }
        ParsedCommandLine::UsageError => {
            eprint!("{}", usage());
            return ExitCode::from(EXIT_USAGE_ERROR);
        }
    };
    if !arguments.document_format.is_enabled() {
        let name = if arguments.document_format == DocumentFormat::Cbor {
            "cbor"
        } else {
            "json"
        };
        eprintln!("Error: this build does not support the {name} format");
        return ExitCode::from(EXIT_FAILURE);
    }
    let basename = arguments.output_basename.as_deref().unwrap_or(&arguments.input_path);
    let Some(cryptainer_path) = build_cryptainer_path(basename, arguments.document_format) else {
        eprintln!("Error: invalid output basename");
        return ExitCode::from(EXIT_FAILURE);
    };
    let mut payload_output = (!arguments.is_bundle).then(|| CliOutput::new(build_payload_path(&cryptainer_path)));
    let mut cryptainer_output = CliOutput::new(cryptainer_path);

    let is_successful = run(&arguments, &mut cryptainer_output, &mut payload_output);
    // On failure, delete what this run created and did not move to a final path, cryptainer first
    cryptainer_output.discard();
    if let Some(payload_output) = payload_output.as_mut() {
        payload_output.discard();
    }
    if is_successful {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}
