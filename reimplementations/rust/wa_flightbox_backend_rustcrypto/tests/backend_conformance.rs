// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! The RustCrypto backend passes the backend conformance suite.

use wa_flightbox_backend_conformance as conformance;
use wa_flightbox_backend_rustcrypto::RustCryptoBackend;

#[test]
fn aes_256_cbc() {
    conformance::check_aes_256_cbc::<RustCryptoBackend>();
}

#[test]
fn aes_256_ctr() {
    conformance::check_aes_256_ctr::<RustCryptoBackend>();
}

#[test]
fn chacha20_poly1305() {
    conformance::check_chacha20_poly1305::<RustCryptoBackend>();
}

#[test]
fn sha256_and_sha512() {
    conformance::check_sha256_and_sha512::<RustCryptoBackend>();
}

#[test]
fn hmac_sha256() {
    conformance::check_hmac_sha256::<RustCryptoBackend>();
}

#[test]
fn x25519() {
    conformance::check_x25519::<RustCryptoBackend>();
}

#[test]
fn rsa_public_operation() {
    conformance::check_rsa_public_operation::<RustCryptoBackend>();
}

#[test]
fn maximum_rsa_modulus_size() {
    conformance::check_maximum_rsa_modulus_size::<RustCryptoBackend>();
}

#[test]
fn ml_kem_768_encapsulation() {
    conformance::check_ml_kem_768_encapsulation::<RustCryptoBackend>();
}

#[test]
fn whole_suite() {
    conformance::check_all::<RustCryptoBackend>();
}
