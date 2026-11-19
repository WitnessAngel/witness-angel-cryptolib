// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Data model and serializations: value trees, the WA-CBOR sub-profile decoder, the two document writers, and
//! device profiles.

#[cfg(feature = "extended-json")]
pub(crate) mod base64_encoder;
pub(crate) mod buffered_sink_writer;
pub(crate) mod device_profile;
pub(crate) mod document_serialization;
pub(crate) mod document_tree_constraints;
#[cfg(feature = "extended-json")]
pub(crate) mod extended_json_writer;
pub(crate) mod secret_byte_buffer;
pub(crate) mod value_tree;
#[cfg(feature = "wa-cbor")]
pub(crate) mod wacbor_deterministic_writer;
pub(crate) mod wacbor_subprofile_decoder;
