// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Compiles wolfCrypt from its sources and generates the bindings of the adapter (design D4).
//!
//! - `WA_WOLFSSL_SOURCE_DIR` (required): a wolfSSL 5.8.x source tree, the version pinned by the C tree.
//! - `WA_WOLFSSL_USER_SETTINGS_DIR` (optional): a directory holding the `user_settings.h` to build wolfCrypt with.
//!   By default, the settings of the C tree (`config/wa_wolfssl_user_settings_for_flightbox.h`).
//!
//! `bindgen` needs libclang (`LIBCLANG_PATH`), and, when cross-compiling, the include paths of the target's C
//! library in `BINDGEN_EXTRA_CLANG_ARGS`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;

/// The wolfCrypt sources that the adapter needs, as in the CMake build of the C tree.
const WOLFCRYPT_SOURCE_NAMES: [&str; 23] = [
    "aes.c",
    "asn.c",
    "chacha.c",
    "chacha20_poly1305.c",
    "coding.c",
    "curve25519.c",
    "error.c",
    "fe_operations.c",
    "hash.c",
    "hmac.c",
    "logging.c",
    "memory.c",
    "poly1305.c",
    "rsa.c",
    "sha.c",
    "sha256.c",
    "sha3.c",
    "sha512.c",
    "sp_int.c",
    "wc_mlkem.c",
    "wc_mlkem_poly.c",
    "wc_port.c",
    "wolfmath.c",
];

const BOUND_FUNCTIONS: [&str; 36] = [
    "wc_AesInit",
    "wc_AesSetKey",
    "wc_AesSetIV",
    "wc_AesCbcEncrypt",
    "wc_AesCtrEncrypt",
    "wc_AesFree",
    "wc_Chacha_SetKey",
    "wc_Chacha_SetIV",
    "wc_Chacha_Process",
    "wc_Poly1305SetKey",
    "wc_Poly1305Update",
    "wc_Poly1305_Pad",
    "wc_Poly1305Final",
    "wc_InitSha256_ex",
    "wc_Sha256Update",
    "wc_Sha256Final",
    "wc_Sha256Free",
    "wc_InitSha512_ex",
    "wc_Sha512Update",
    "wc_Sha512Final",
    "wc_Sha512Free",
    "wc_HmacInit",
    "wc_HmacSetKey",
    "wc_HmacUpdate",
    "wc_HmacFinal",
    "wc_HmacFree",
    "wc_curve25519_generic",
    "wc_InitRsaKey_ex",
    "wc_RsaPublicKeyDecodeRaw",
    "wc_RsaEncryptSize",
    "wc_RsaDirect",
    "wc_FreeRsaKey",
    "wc_MlKemKey_Init",
    "wc_MlKemKey_DecodePublicKey",
    "wc_MlKemKey_EncapsulateWithRandom",
    "wc_MlKemKey_Free",
];

fn fail(message: &str) -> ! {
    eprintln!("error: wa_flightbox_backend_wolfcrypt: {message}");
    exit(1);
}

fn directory_from_environment(name: &str) -> Option<PathBuf> {
    println!("cargo:rerun-if-env-changed={name}");
    let value = env::var_os(name).filter(|value| !value.is_empty())?;
    let path = PathBuf::from(value);
    if !path.is_dir() {
        fail(&format!("{name} is not a directory: {}", path.display()));
    }
    Some(path)
}

/// The path with forward slashes, for a C `#include` line and for clang arguments.
fn to_c_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

/// A canonical path as C compilers take it: Windows canonical paths start with `\\?\` (`\\?\C:\...`, or
/// `\\?\UNC\server\share\...` for a network share), which they do not understand.
fn to_c_include_path(canonical_path: &Path) -> String {
    let path = to_c_path(canonical_path);
    if let Some(share_path) = path.strip_prefix("//?/UNC/") {
        format!("//{share_path}")
    } else if let Some(local_path) = path.strip_prefix("//?/") {
        local_path.to_owned()
    } else {
        path
    }
}

fn main() {
    let manifest_directory = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let output_directory = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/wolfcrypt_bindings.h");
    println!("cargo:rerun-if-changed=src/wolfcrypt_option_checks.c");

    let Some(wolfssl_directory) = directory_from_environment("WA_WOLFSSL_SOURCE_DIR") else {
        fail(
            "set WA_WOLFSSL_SOURCE_DIR to a wolfSSL 5.8.x source tree (the wolfCrypt backend compiles it; \
             see reimplementations/rust/README.md)",
        );
    };
    let wolfcrypt_source_directory = wolfssl_directory.join("wolfcrypt").join("src");
    if !wolfcrypt_source_directory.join("aes.c").is_file()
        || !wolfssl_directory
            .join("wolfssl")
            .join("wolfcrypt")
            .join("settings.h")
            .is_file()
    {
        fail(&format!(
            "WA_WOLFSSL_SOURCE_DIR is not a wolfSSL source tree (no wolfcrypt/src/aes.c or \
             wolfssl/wolfcrypt/settings.h): {}",
            wolfssl_directory.display()
        ));
    }

    // wolfSSL includes "user_settings.h": the integrator's, or a shim forwarding to the settings of the C tree
    let settings_directory = match directory_from_environment("WA_WOLFSSL_USER_SETTINGS_DIR") {
        Some(directory) => {
            if !directory.join("user_settings.h").is_file() {
                fail(&format!(
                    "WA_WOLFSSL_USER_SETTINGS_DIR holds no user_settings.h: {}",
                    directory.display()
                ));
            }
            println!("cargo:rerun-if-changed={}", directory.join("user_settings.h").display());
            directory
        }
        None => {
            let default_settings = manifest_directory
                .join("..")
                .join("..")
                .join("c-language")
                .join("config")
                .join("wa_wolfssl_user_settings_for_flightbox.h");
            let Ok(default_settings) = default_settings.canonicalize() else {
                fail(&format!(
                    "the default wolfSSL settings are missing ({}): set WA_WOLFSSL_USER_SETTINGS_DIR",
                    default_settings.display()
                ));
            };
            println!("cargo:rerun-if-changed={}", default_settings.display());
            let directory = output_directory.join("wa_wolfssl_settings");
            fs::create_dir_all(&directory).expect("creating the settings directory");
            let include_path = to_c_include_path(&default_settings);
            fs::write(
                directory.join("user_settings.h"),
                format!(
                    "/* Generated by build.rs: wolfSSL settings of the flightbox encryptor */\n#include \"{include_path}\"\n"
                ),
            )
            .expect("writing user_settings.h");
            directory
        }
    };

    // The option checks first: a missing option is reported by name
    let mut option_checks = cc::Build::new();
    option_checks
        .file("src/wolfcrypt_option_checks.c")
        .define("WOLFSSL_USER_SETTINGS", None)
        .include(&wolfssl_directory)
        .include(&settings_directory)
        .cargo_metadata(false);
    if option_checks
        .try_compile("wa_flightbox_wolfcrypt_option_checks")
        .is_err()
    {
        fail(
            "the wolfSSL settings lack an option that the backend requires: see the #error message of \
             src/wolfcrypt_option_checks.c above",
        );
    }

    // Rebuilt when the wolfSSL tree changes, once any rerun-if-changed is printed: its headers, and its sources,
    // including those that the compiled ones include (misc.c)
    println!("cargo:rerun-if-changed={}", wolfssl_directory.join("wolfssl").display());
    println!("cargo:rerun-if-changed={}", wolfcrypt_source_directory.display());
    let mut wolfcrypt = cc::Build::new();
    wolfcrypt
        .define("WOLFSSL_USER_SETTINGS", None)
        .include(&wolfssl_directory)
        .include(&settings_directory)
        .warnings(false);
    for source_name in WOLFCRYPT_SOURCE_NAMES {
        wolfcrypt.file(wolfcrypt_source_directory.join(source_name));
    }
    wolfcrypt.compile("wa_flightbox_wolfcrypt");

    let mut bindings = bindgen::Builder::default()
        .header("src/wolfcrypt_bindings.h")
        .clang_arg("-DWOLFSSL_USER_SETTINGS")
        .clang_arg(format!("-I{}", to_c_path(&wolfssl_directory)))
        .clang_arg(format!("-I{}", to_c_path(&settings_directory)))
        .use_core()
        .layout_tests(false)
        .generate_comments(false)
        .derive_debug(false)
        .derive_copy(false)
        .prepend_enum_name(false)
        .default_enum_style(bindgen::EnumVariation::Consts)
        .allowlist_var("WA_WOLFCRYPT_.*");
    for function_name in BOUND_FUNCTIONS {
        bindings = bindings.allowlist_function(function_name);
    }
    let Ok(bindings) = bindings.generate() else {
        fail("bindgen could not read the wolfCrypt headers (see the clang diagnostics above)");
    };
    bindings
        .write_to_file(output_directory.join("wolfcrypt_bindings.rs"))
        .expect("writing the bindings");
}
