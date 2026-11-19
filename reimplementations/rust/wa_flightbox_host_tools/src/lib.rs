// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Host side of the Witness Angel flightbox encryptor: platform hooks over the operating system, and what the two
//! tools of this crate share. The tools take the arguments, write the outputs and return the exit statuses of the
//! C tools of `reimplementations/c-language/tools`, so that the same interoperability tests drive both:
//!
//! - `wa_flightbox_encrypt_file_cli` encrypts a file into a cryptainer with a device profile;
//! - `wa_flightbox_test_driver` runs one library function per subcommand, and prints a JSON object.
//!
//! The crypto backend is chosen by a cargo feature, `backend-rustcrypto` (default) or `backend-wolfcrypt`, and
//! the document formats by `extended-json` and `wa-cbor` (both default).

#![forbid(unsafe_code)]

#[cfg(all(feature = "backend-rustcrypto", feature = "backend-wolfcrypt"))]
compile_error!(
    "wa_flightbox_host_tools: the features backend-rustcrypto and backend-wolfcrypt are exclusive \
     (use --no-default-features to choose backend-wolfcrypt)"
);
#[cfg(not(any(feature = "backend-rustcrypto", feature = "backend-wolfcrypt")))]
compile_error!("wa_flightbox_host_tools: enable one crypto backend feature, backend-rustcrypto or backend-wolfcrypt");
#[cfg(not(any(feature = "extended-json", feature = "wa-cbor")))]
compile_error!("wa_flightbox_host_tools: enable at least one document format feature, extended-json or wa-cbor");

/// The examples of the workspace README, compiled and run as documentation tests.
#[cfg(all(doctest, feature = "backend-rustcrypto"))]
#[doc = include_str!("../../README.md")]
pub struct ReadmeDoctests;

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use wa_flightbox::{DocumentFormat, OFFLOADED_PAYLOAD_SUFFIX, OutputSink, PlatformHooks, RandomFailure, SinkError};

/// The crypto backend of this build.
#[cfg(feature = "backend-rustcrypto")]
pub use wa_flightbox_backend_rustcrypto::RustCryptoBackend as ToolBackend;
/// The crypto backend of this build.
#[cfg(all(feature = "backend-wolfcrypt", not(feature = "backend-rustcrypto")))]
pub use wa_flightbox_backend_wolfcrypt::WolfCryptBackend as ToolBackend;

/// The name of the crypto backend of this build, as the test driver reports it.
#[cfg(feature = "backend-rustcrypto")]
pub const BACKEND_NAME: &str = "RUSTCRYPTO";
/// The name of the crypto backend of this build, as the test driver reports it.
#[cfg(all(feature = "backend-wolfcrypt", not(feature = "backend-rustcrypto")))]
pub const BACKEND_NAME: &str = "WOLFCRYPT";

/// Platform hooks of a host: the random generator of the operating system, and the system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostPlatformHooks;

impl PlatformHooks for HostPlatformHooks {
    fn fill_random(&mut self, buffer: &mut [u8]) -> Result<(), RandomFailure> {
        getrandom::fill(buffer).map_err(|_| RandomFailure)
    }

    fn unix_time_in_ten_thousandths_of_second(&mut self) -> Option<u64> {
        let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        since_epoch
            .as_secs()
            .checked_mul(10_000)?
            .checked_add(u64::from(since_epoch.subsec_nanos() / 100_000))
    }
}

/// The whole content of a file, or of the standard input for `-`.
pub fn read_file(path: &str) -> std::io::Result<Vec<u8>> {
    if path == "-" {
        let mut content = Vec::new();
        std::io::stdin().lock().read_to_end(&mut content)?;
        Ok(content)
    } else {
        std::fs::read(path)
    }
}

/// Whether something exists at this path (symbolic links being followed).
pub fn file_exists(path: &str) -> bool {
    std::fs::metadata(path).is_ok()
}

/// Whether both paths lead to the same existing file, under any name (relative paths, links).
pub fn files_are_same(path_a: &str, path_b: &str) -> bool {
    same_file::is_same_file(path_a, path_b).unwrap_or(false)
}

/// Create an output file: only if nothing exists at this path, unless `force` is set (the file is then truncated).
pub fn open_output_file(path: &str, force: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    options.open(path)
}

/// Create a new file next to `final_path`, named after it with `label` and a number: the file and its path.
fn open_new_sibling_file(final_path: &str, label: &str) -> Option<(File, String)> {
    for attempt in 0..1000u32 {
        let sibling_path = format!("{final_path}.{label}-{attempt:03}");
        match open_output_file(&sibling_path, false) {
            Ok(file) => return Some((file, sibling_path)),
            // Not a name clash: the directory is not writable
            Err(_) if !file_exists(&sibling_path) => return None,
            Err(_) => {}
        }
    }
    None
}

/// Create a new file next to `final_path`, to be renamed over it once complete: the file and its path.
pub fn open_temporary_output_file(final_path: &str) -> Option<(File, String)> {
    open_new_sibling_file(final_path, "tmp")
}

/// Move a complete file to its final path, replacing what is there.
pub fn replace_file(source_path: &str, destination_path: &str) -> std::io::Result<()> {
    std::fs::rename(source_path, destination_path)
}

/// Move the file at `path` to a new name next to it (`path.old-NNN`), leaving nothing at `path`: the new path, to
/// be given to [`replace_file`] to put the file back.
pub fn move_file_aside(path: &str) -> std::io::Result<String> {
    // The name is reserved by an empty file, which the renaming replaces
    let Some((reserving_file, backup_path)) = open_new_sibling_file(path, "old") else {
        return Err(std::io::ErrorKind::AlreadyExists.into());
    };
    drop(reserving_file);
    if let Err(error) = replace_file(path, &backup_path) {
        let _ = std::fs::remove_file(&backup_path);
        return Err(error);
    }
    Ok(backup_path)
}

/// A buffered file, as an output sink of the library.
#[derive(Debug)]
pub struct FileSink {
    writer: BufWriter<File>,
}

impl FileSink {
    /// A sink writing to `file`.
    pub fn new(file: File) -> Self {
        Self {
            writer: BufWriter::new(file),
        }
    }

    /// Write what is still buffered, have the operating system write the file to its storage device, and close
    /// it: after a success, the content survives a power loss, and so does a renaming of the file made afterwards.
    pub fn close(self) -> std::io::Result<()> {
        let file = self.writer.into_inner().map_err(std::io::IntoInnerError::into_error)?;
        file.sync_all()
    }
}

impl OutputSink for FileSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), SinkError> {
        self.writer.write_all(bytes).map_err(|_| SinkError::WriteFailure)
    }
}

fn ends_with_ignoring_case(text: &str, suffix: &str) -> bool {
    let (text, suffix) = (text.as_bytes(), suffix.as_bytes());
    text.len() >= suffix.len() && text[text.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// The path of the cryptainer file of an output basename (encryptor specification, section 9): a trailing
/// `.crypt`, `.crypt.json` or `.crypt.cbor`, in any case, is replaced by the lowercase suffix of the format.
/// `None` when nothing is left to name the file, or when the format is not enabled.
pub fn build_cryptainer_path(basename: &str, document_format: DocumentFormat) -> Option<String> {
    let suffix = document_format.cryptainer_suffix()?;
    let mut stem = basename;
    for typed_suffix in [".crypt.json", ".crypt.cbor", ".crypt"] {
        if ends_with_ignoring_case(stem, typed_suffix) {
            stem = &stem[..stem.len() - typed_suffix.len()];
            break;
        }
    }
    if stem.is_empty() || stem.ends_with('/') || stem.ends_with('\\') {
        return None;
    }
    Some(format!("{stem}{suffix}"))
}

/// The path of the offloaded payload file of a cryptainer file.
pub fn build_payload_path(cryptainer_path: &str) -> String {
    format!("{cryptainer_path}{OFFLOADED_PAYLOAD_SUFFIX}")
}

/// `json` or `cbor`, in any case.
pub fn parse_document_format(name: &str) -> Option<DocumentFormat> {
    if name.eq_ignore_ascii_case("json") {
        Some(DocumentFormat::ExtendedJson)
    } else if name.eq_ignore_ascii_case("cbor") {
        Some(DocumentFormat::Cbor)
    } else {
        None
    }
}

/// The names of the document formats of this build, `json` first.
pub fn enabled_document_format_names() -> Vec<&'static str> {
    let mut names = Vec::new();
    if DocumentFormat::ExtendedJson.is_enabled() {
        names.push("json");
    }
    if DocumentFormat::Cbor.is_enabled() {
        names.push("cbor");
    }
    names
}

/// Bytes from hexadecimal digits of any case, `None` for anything else.
pub fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    let digits = hex.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    let digit_value = |digit: u8| {
        char::from(digit)
            .to_digit(16)
            .and_then(|value| u8::try_from(value).ok())
    };
    digits
        .chunks_exact(2)
        .map(|pair| Some((digit_value(pair[0])? << 4) | digit_value(pair[1])?))
        .collect()
}

/// Lowercase hexadecimal digits.
pub fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The command line arguments after the program name, `None` if one of them is not valid Unicode.
pub fn command_line_arguments() -> Option<Vec<String>> {
    std::env::args_os()
        .skip(1)
        .map(|argument| argument.into_string().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cryptainer_paths_follow_the_naming_of_the_specification() {
        for format in [DocumentFormat::ExtendedJson, DocumentFormat::Cbor] {
            let Some(suffix) = format.cryptainer_suffix() else {
                assert_eq!(build_cryptainer_path("clip.mp4", format), None);
                continue;
            };
            for (basename, stem) in [
                ("clip.mp4", "clip.mp4"),
                ("Clip.CRYPT", "Clip"),
                ("dir/clip.crypt.json", "dir/clip"),
                ("clip.Crypt.CBOR", "clip"),
                ("clip.crypt.crypt", "clip.crypt"),
                ("clip.json", "clip.json"),
            ] {
                assert_eq!(
                    build_cryptainer_path(basename, format),
                    Some(format!("{stem}{suffix}")),
                    "{basename}"
                );
            }
            for basename in ["", ".crypt", "dir/", "dir\\", "dir/.crypt.cbor"] {
                assert_eq!(build_cryptainer_path(basename, format), None, "{basename}");
            }
        }
        assert_eq!(build_payload_path("clip.crypt.cbor"), "clip.crypt.cbor.payload");
    }

    #[test]
    fn formats_and_hex_are_parsed_as_the_c_tools_do() {
        assert_eq!(parse_document_format("JSON"), Some(DocumentFormat::ExtendedJson));
        assert_eq!(parse_document_format("cbor"), Some(DocumentFormat::Cbor));
        assert_eq!(parse_document_format("yaml"), None);
        assert_eq!(parse_document_format("json "), None);
        assert_eq!(decode_hex("00fFa5"), Some(vec![0x00, 0xff, 0xa5]));
        assert_eq!(decode_hex(""), Some(Vec::new()));
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("0g"), None);
        assert_eq!(decode_hex("+1"), None);
        assert_eq!(encode_hex(&[0x00, 0xff, 0xa5]), "00ffa5");
    }

    #[test]
    fn host_hooks_give_randomness_and_a_plausible_time() {
        let mut hooks = HostPlatformHooks;
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        hooks.fill_random(&mut first).unwrap();
        hooks.fill_random(&mut second).unwrap();
        assert_ne!(first, second);
        // Between 2025 and 2100, in 1/10000 s
        let time = hooks.unix_time_in_ten_thousandths_of_second().unwrap();
        assert!((17_356_896_000_000..41_024_448_000_000).contains(&time), "{time}");
    }

    #[test]
    fn output_files_are_created_exclusively_unless_forced() {
        let directory = std::env::temp_dir().join(format!("wa_flightbox_host_tools_{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("output.bin").to_str().unwrap().to_owned();
        let _ = std::fs::remove_file(&path);
        assert!(!file_exists(&path));
        let mut sink = FileSink::new(open_output_file(&path, false).unwrap());
        sink.write(b"first").unwrap();
        sink.close().unwrap();
        assert!(open_output_file(&path, false).is_err());
        assert_eq!(read_file(&path).unwrap(), b"first");

        let (file, temporary_path) = open_temporary_output_file(&path).unwrap();
        assert_eq!(temporary_path, format!("{path}.tmp-000"));
        let (_second_file, second_temporary_path) = open_temporary_output_file(&path).unwrap();
        assert_eq!(second_temporary_path, format!("{path}.tmp-001"));
        let mut sink = FileSink::new(file);
        sink.write(b"second").unwrap();
        sink.close().unwrap();
        assert!(files_are_same(&path, &path));
        assert!(!files_are_same(&path, &temporary_path));
        assert!(!files_are_same(&path, &format!("{path}.missing")));
        replace_file(&temporary_path, &path).unwrap();
        assert_eq!(read_file(&path).unwrap(), b"second");

        // Moved aside under a new name, and back
        let backup_path = move_file_aside(&path).unwrap();
        assert_eq!(backup_path, format!("{path}.old-000"));
        assert!(!file_exists(&path));
        assert_eq!(read_file(&backup_path).unwrap(), b"second");
        std::fs::write(&path, b"third").unwrap();
        assert_eq!(move_file_aside(&path).unwrap(), format!("{path}.old-001"));
        replace_file(&backup_path, &path).unwrap();
        assert_eq!(read_file(&path).unwrap(), b"second");
        assert!(!file_exists(&backup_path));
        // Nothing to move: no name stays reserved
        assert!(move_file_aside(&format!("{path}.missing")).is_err());
        assert!(!file_exists(&format!("{path}.missing.old-000")));
        drop(_second_file);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
