// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! The flightbox algorithm (encryptor specification, sections 6 to 9), without any cryptographic code: it runs
//! the composite constructions of `primitives`, on the trees and codecs of `encoding`.

pub(crate) mod cryptainer_base_generation;
pub(crate) mod cryptainer_encryptor;
pub(crate) mod cryptainer_finalization;
pub(crate) mod cryptoconf_validation;
pub(crate) mod error_location_path;
pub(crate) mod key_cipher_layers_encryption;
pub(crate) mod payload_encryption_pipeline;
