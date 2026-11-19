// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Output file handling of `wa_flightbox_encrypt_file_cli`, run as a process: with `--force`, a failure at any
//! point keeps the existing cryptainer and payload files together; an inline cryptainer never sits next to the
//! payload file of a previous offloaded one; no output file is created for rejected metadata.
//!
//! A replacement failure is provoked with a directory at the path of the cryptainer file, which no file can be
//! renamed over, and on Windows with a read-only cryptainer file too.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use wa_flightbox_backend_conformance::test_support::device_profile_sample;
use wa_flightbox_host_tools::{
    build_cryptainer_path, build_payload_path, enabled_document_format_names, parse_document_format,
};

const PROFILE_FILENAME: &str = "profile.cbor";
const INPUT_FILENAME: &str = "input.bin";
const FIRST_RECORDING: &[u8] = b"first recording ";
const SECOND_RECORDING: &[u8] = b"second recording, longer ";

/// A new directory holding a profile and an input file, deleted when dropped.
struct WorkDirectory {
    path: PathBuf,
}

impl WorkDirectory {
    fn new(test_name: &str, format_name: &str) -> Self {
        let directory_name = format!(
            "wa_flightbox_encrypt_file_cli_{}_{test_name}_{format_name}",
            std::process::id()
        );
        let path = std::env::temp_dir().join(directory_name);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        let directory = Self { path };
        directory.write(PROFILE_FILENAME, &device_profile_sample("minimal_rsa_authenticator"));
        directory.write(INPUT_FILENAME, &FIRST_RECORDING.repeat(100));
        directory
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn write(&self, name: &str, content: &[u8]) {
        std::fs::write(self.file(name), content).unwrap();
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.file(name)).unwrap()
    }

    /// The names of its entries, sorted.
    fn list(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    /// Run the CLI in this directory, with the profile and the output basename `out`.
    fn encrypt(&self, format_name: &str, input_name: &str, extra_arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_wa_flightbox_encrypt_file_cli"))
            .args([input_name, "-p", PROFILE_FILENAME, "--format", format_name, "-o", "out"])
            .args(extra_arguments)
            .current_dir(&self.path)
            .output()
            .unwrap()
    }
}

impl Drop for WorkDirectory {
    fn drop(&mut self) {
        let _ = set_read_only_recursively(&self.path, false);
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn set_read_only(path: &Path, is_read_only: bool) -> std::io::Result<()> {
    let mut permissions = std::fs::metadata(path)?.permissions();
    // Only used on Windows, where this is the read-only attribute of the file
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(is_read_only);
    std::fs::set_permissions(path, permissions)
}

fn set_read_only_recursively(directory: &Path, is_read_only: bool) -> std::io::Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_file() {
            set_read_only(&path, is_read_only)?;
        }
    }
    Ok(())
}

/// The names of the cryptainer file and of the payload file of the output basename `out`.
fn output_names(format_name: &str) -> (String, String) {
    let cryptainer_name = build_cryptainer_path("out", parse_document_format(format_name).unwrap()).unwrap();
    let payload_name = build_payload_path(&cryptainer_name);
    (cryptainer_name, payload_name)
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout_lines_of(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

fn sorted(names: &[&str]) -> Vec<String> {
    let mut names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
    names.sort();
    names
}

#[test]
fn forced_run_replaces_both_outputs_and_leaves_nothing_else() {
    for format_name in enabled_document_format_names() {
        let directory = WorkDirectory::new("forced_success", format_name);
        let (cryptainer_name, payload_name) = output_names(format_name);
        assert!(directory.encrypt(format_name, INPUT_FILENAME, &[]).status.success());
        let old_cryptainer = directory.read(&cryptainer_name);
        let old_payload = directory.read(&payload_name);

        directory.write(INPUT_FILENAME, &SECOND_RECORDING.repeat(300));
        let output = directory.encrypt(format_name, INPUT_FILENAME, &["--force"]);
        assert!(output.status.success(), "{}", stderr_of(&output));
        assert_eq!(stderr_of(&output), "");
        assert_eq!(
            stdout_lines_of(&output),
            [cryptainer_name.clone(), payload_name.clone()]
        );
        assert_ne!(directory.read(&cryptainer_name), old_cryptainer);
        assert!(directory.read(&payload_name).len() > old_payload.len());
        assert_eq!(
            directory.list(),
            sorted(&[INPUT_FILENAME, PROFILE_FILENAME, &cryptainer_name, &payload_name])
        );
    }
}

/// RS-1: the payload file was replaced before the cryptainer file, and stayed replaced when the latter failed.
#[test]
fn forced_run_failing_to_replace_the_cryptainer_keeps_the_existing_payload() {
    for format_name in enabled_document_format_names() {
        let directory = WorkDirectory::new("forced_failure_directory", format_name);
        let (cryptainer_name, payload_name) = output_names(format_name);
        // A directory where the cryptainer file goes: nothing can be renamed over it
        std::fs::create_dir(directory.file(&cryptainer_name)).unwrap();
        std::fs::write(directory.file(&cryptainer_name).join("kept.txt"), b"kept").unwrap();
        directory.write(&payload_name, b"existing payload");
        let files_before = directory.list();

        let output = directory.encrypt(format_name, INPUT_FILENAME, &["--force"]);
        let stderr = stderr_of(&output);
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains(&format!("Error: cannot replace {cryptainer_name}")),
            "{stderr}"
        );
        assert_eq!(stdout_lines_of(&output), Vec::<String>::new());
        assert_eq!(directory.read(&payload_name), b"existing payload");
        // Neither temporary nor backup file left
        assert_eq!(directory.list(), files_before);

        // Without an existing payload file: the new one does not stay next to what could not be replaced
        std::fs::remove_file(directory.file(&payload_name)).unwrap();
        let output = directory.encrypt(format_name, INPUT_FILENAME, &["--force"]);
        assert_eq!(output.status.code(), Some(1), "{}", stderr_of(&output));
        assert_eq!(
            directory.list(),
            sorted(&[INPUT_FILENAME, PROFILE_FILENAME, &cryptainer_name])
        );
    }
}

/// RS-1 as it happens on Windows: a read-only cryptainer file cannot be replaced, its payload file can.
#[cfg(windows)]
#[test]
fn forced_run_over_a_read_only_cryptainer_keeps_the_existing_pair() {
    for format_name in enabled_document_format_names() {
        let directory = WorkDirectory::new("forced_failure_read_only", format_name);
        let (cryptainer_name, payload_name) = output_names(format_name);
        assert!(directory.encrypt(format_name, INPUT_FILENAME, &[]).status.success());
        let old_cryptainer = directory.read(&cryptainer_name);
        let old_payload = directory.read(&payload_name);
        let files_before = directory.list();
        set_read_only(&directory.file(&cryptainer_name), true).unwrap();

        directory.write(INPUT_FILENAME, &SECOND_RECORDING.repeat(300));
        for extra_arguments in [&["--force"][..], &["--force", "--bundle"]] {
            let output = directory.encrypt(format_name, INPUT_FILENAME, extra_arguments);
            let stderr = stderr_of(&output);
            assert_eq!(output.status.code(), Some(1), "{stderr}");
            assert!(
                stderr.contains(&format!("Error: cannot replace {cryptainer_name}")),
                "{stderr}"
            );
            assert_eq!(directory.read(&cryptainer_name), old_cryptainer);
            assert_eq!(directory.read(&payload_name), old_payload, "{extra_arguments:?}");
            assert_eq!(directory.list(), files_before);
        }
    }
}

/// RS-20: an inline cryptainer was written next to the payload file of a previous offloaded cryptainer.
#[test]
fn bundle_run_refuses_or_removes_an_existing_payload_file() {
    for format_name in enabled_document_format_names() {
        let directory = WorkDirectory::new("bundle_stale_payload", format_name);
        let (cryptainer_name, payload_name) = output_names(format_name);
        assert!(directory.encrypt(format_name, INPUT_FILENAME, &[]).status.success());
        let old_cryptainer = directory.read(&cryptainer_name);
        let old_payload = directory.read(&payload_name);

        // Without --force: refused, whether the cryptainer file is still there or not
        for is_cryptainer_removed in [false, true] {
            if is_cryptainer_removed {
                std::fs::remove_file(directory.file(&cryptainer_name)).unwrap();
            }
            let output = directory.encrypt(format_name, INPUT_FILENAME, &["--bundle"]);
            let stderr = stderr_of(&output);
            assert_eq!(output.status.code(), Some(1), "{stderr}");
            assert!(stderr.contains("already exists (use --force"), "{stderr}");
            assert_eq!(directory.read(&payload_name), old_payload);
            assert_eq!(directory.file(&cryptainer_name).exists(), !is_cryptainer_removed);
        }
        directory.write(&cryptainer_name, &old_cryptainer);

        // The payload file of the previous cryptainer is not deleted when it is the input file
        let output = directory.encrypt(format_name, &payload_name, &["--bundle", "--force"]);
        let stderr = stderr_of(&output);
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("is the input file"), "{stderr}");
        assert_eq!(directory.read(&payload_name), old_payload);
        assert_eq!(directory.read(&cryptainer_name), old_cryptainer);

        // With --force: the payload file goes with the cryptainer it belonged to
        let output = directory.encrypt(format_name, INPUT_FILENAME, &["--bundle", "--force"]);
        assert!(output.status.success(), "{}", stderr_of(&output));
        assert_eq!(stdout_lines_of(&output), std::slice::from_ref(&cryptainer_name));
        assert_ne!(directory.read(&cryptainer_name), old_cryptainer);
        assert_eq!(
            directory.list(),
            sorted(&[INPUT_FILENAME, PROFILE_FILENAME, &cryptainer_name])
        );
    }
}

/// RS-20: the payload file of the previous cryptainer stays when the inline cryptainer cannot replace it.
#[test]
fn bundle_run_failing_to_replace_the_cryptainer_keeps_the_existing_payload() {
    for format_name in enabled_document_format_names() {
        let directory = WorkDirectory::new("bundle_failure_directory", format_name);
        let (cryptainer_name, payload_name) = output_names(format_name);
        std::fs::create_dir(directory.file(&cryptainer_name)).unwrap();
        directory.write(&payload_name, b"existing payload");
        let files_before = directory.list();

        let output = directory.encrypt(format_name, INPUT_FILENAME, &["--bundle", "--force"]);
        let stderr = stderr_of(&output);
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains(&format!("Error: cannot replace {cryptainer_name}")),
            "{stderr}"
        );
        assert_eq!(directory.read(&payload_name), b"existing payload");
        assert_eq!(directory.list(), files_before);
    }
}

/// RS-6: the payload file was created before the metadata was checked. The outputs going to a missing directory,
/// their creation fails: the error reported tells what was done first.
#[test]
fn rejected_metadata_is_reported_before_any_output_is_created() {
    for format_name in enabled_document_format_names() {
        let directory = WorkDirectory::new("rejected_metadata", format_name);
        // An empty array: well-formed WA-CBOR, but not a map
        directory.write("metadata.cbor", &[0x80]);
        let files_before = directory.list();
        for force_arguments in [&[][..], &["--force"]] {
            for output_basename in ["out", "missing_directory/out"] {
                let mut arguments = vec!["-m", "metadata.cbor", "-o", output_basename];
                arguments.extend_from_slice(force_arguments);
                let output = directory.encrypt(format_name, INPUT_FILENAME, &arguments);
                let stderr = stderr_of(&output);
                assert_eq!(output.status.code(), Some(1), "{stderr}");
                assert!(
                    stderr.contains("Error: cryptainer creation failed")
                        && stderr.contains("[WA_STATUS_INVALID_PROFILE]"),
                    "{output_basename}: {stderr}"
                );
                assert!(!stderr.contains("cannot create"), "{output_basename}: {stderr}");
                assert_eq!(directory.list(), files_before);
            }
        }

        // Valid metadata: the outputs that cannot be created are reported
        directory.write("metadata.cbor", &[0xa0]);
        let output = directory.encrypt(
            format_name,
            INPUT_FILENAME,
            &["-m", "metadata.cbor", "-o", "missing_directory/out"],
        );
        let stderr = stderr_of(&output);
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains("Error: cannot create missing_directory/out"),
            "{stderr}"
        );
        assert_eq!(directory.list(), files_before);
    }
}

/// An empty input gives an empty payload file with some ciphers: the file is created all the same.
#[test]
fn empty_input_gives_both_output_files() {
    for format_name in enabled_document_format_names() {
        let directory = WorkDirectory::new("empty_input", format_name);
        let (cryptainer_name, payload_name) = output_names(format_name);
        directory.write(INPUT_FILENAME, b"");
        for extra_arguments in [&[][..], &["--force"]] {
            let output = directory.encrypt(format_name, INPUT_FILENAME, extra_arguments);
            assert!(output.status.success(), "{}", stderr_of(&output));
            assert_eq!(
                directory.list(),
                sorted(&[INPUT_FILENAME, PROFILE_FILENAME, &cryptainer_name, &payload_name])
            );
        }
    }
}
