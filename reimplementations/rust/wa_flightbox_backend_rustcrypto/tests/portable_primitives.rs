// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! The portable primitives of the core crate give their expected results over the RustCrypto backend.

use wa_flightbox_backend_conformance::portable_primitive_checks as checks;
use wa_flightbox_backend_rustcrypto::RustCryptoBackend;

#[test]
fn aes_cmac() {
    checks::check_aes_cmac::<RustCryptoBackend>();
}

#[test]
fn aes_eax() {
    checks::check_aes_eax::<RustCryptoBackend>();
}

#[test]
fn symmetric_cipherdicts_and_streams() {
    checks::check_symmetric_cipherdicts_and_streams::<RustCryptoBackend>();
}

#[test]
fn hkdf_sha256() {
    checks::check_hkdf_sha256::<RustCryptoBackend>();
}

#[test]
fn hpke_base_mode_seal() {
    checks::check_hpke_base_mode_seal::<RustCryptoBackend>();
}

#[test]
fn rsa_oaep() {
    checks::check_rsa_oaep::<RustCryptoBackend>();
}

#[test]
fn key_struct_wrapping() {
    checks::check_key_struct_wrapping::<RustCryptoBackend>();
}

#[test]
fn whole_suite() {
    checks::check_all::<RustCryptoBackend>();
}
