// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Document formats, and the only dispatch point between the two writers: `S_F` of the encryptor specification
//! (section 2) for intermediate structures, and the serialization of cryptainers.

use crate::encoding::secret_byte_buffer::SecretByteBuffer;
use crate::encoding::value_tree::{Node, Value};
use crate::error::{Error, ErrorKind, Result};
use crate::platform_hooks::OutputSink;

/// The serialization of a cryptainer and of every structure encrypted inside it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum DocumentFormat {
    /// The only enabled format, or Extended JSON when both are.
    #[default]
    BuildDefault,
    /// Relaxed Extended JSON (cargo feature `extended-json`).
    ExtendedJson,
    /// WA-CBOR, core deterministic encoding (cargo feature `wa-cbor`).
    Cbor,
}

/// A format that this build can write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResolvedFormat {
    #[cfg_attr(not(feature = "extended-json"), allow(dead_code))]
    ExtendedJson,
    #[cfg_attr(not(feature = "wa-cbor"), allow(dead_code))]
    Cbor,
}

impl DocumentFormat {
    /// `ErrorKind::UnsupportedFeature` for a format that is not compiled in.
    pub(crate) fn resolve(self) -> Result<ResolvedFormat> {
        match self {
            #[cfg(feature = "extended-json")]
            DocumentFormat::BuildDefault | DocumentFormat::ExtendedJson => Ok(ResolvedFormat::ExtendedJson),
            #[cfg(all(not(feature = "extended-json"), feature = "wa-cbor"))]
            DocumentFormat::BuildDefault => Ok(ResolvedFormat::Cbor),
            #[cfg(feature = "wa-cbor")]
            DocumentFormat::Cbor => Ok(ResolvedFormat::Cbor),
            #[allow(unreachable_patterns)]
            _ => Err(Error::new(ErrorKind::UnsupportedFeature)),
        }
    }

    /// Whether this build can write the format.
    pub fn is_enabled(self) -> bool {
        self.resolve().is_ok()
    }

    /// The lowercase suffix of cryptainer file names in this format (`.crypt.json` or `.crypt.cbor`, encryptor
    /// specification, section 9), or `None` when the format is not enabled. An offloaded payload goes to a sibling
    /// file named after the cryptainer file, plus [`OFFLOADED_PAYLOAD_SUFFIX`].
    pub fn cryptainer_suffix(self) -> Option<&'static str> {
        match self.resolve() {
            Ok(ResolvedFormat::ExtendedJson) => Some(".crypt.json"),
            Ok(ResolvedFormat::Cbor) => Some(".crypt.cbor"),
            Err(_) => None,
        }
    }
}

/// Suffix appended to a cryptainer file name to name its offloaded payload file.
pub const OFFLOADED_PAYLOAD_SUFFIX: &str = ".payload";

/// Write `tree` to `sink` in `format`.
pub(crate) fn serialize_to_sink(tree: Node<'_>, format: ResolvedFormat, sink: &mut dyn OutputSink) -> Result<()> {
    match format {
        #[cfg(feature = "extended-json")]
        ResolvedFormat::ExtendedJson => crate::encoding::extended_json_writer::write_extended_json_document(tree, sink),
        #[cfg(feature = "wa-cbor")]
        ResolvedFormat::Cbor => crate::encoding::wacbor_deterministic_writer::write_wacbor_document(tree, sink),
        #[allow(unreachable_patterns)]
        _ => {
            let _ = (tree, sink);
            Err(Error::new(ErrorKind::UnsupportedFeature))
        }
    }
}

/// `S_F(tree)` into a new wiping buffer.
pub(crate) fn serialize_to_secret_buffer(tree: Node<'_>, format: ResolvedFormat) -> Result<SecretByteBuffer> {
    let mut buffer = SecretByteBuffer::new();
    serialize_to_sink(tree, format, &mut buffer)?;
    Ok(buffer)
}

/// Write a value tree to `sink` in `format`, with the exact bytes of wacryptolib's default writer of that format.
/// `ErrorKind::UnsupportedFeature` for a format that is not compiled in.
///
/// The tree is written as it is, without the checks applied to cryptainer metadata: a single-key map whose key is
/// an Extended JSON keyword (`{"$uuid": ...}`) is written as a map, which readers of either format then refuse or
/// read back as another type, and its nesting is not checked (the writers recurse once per level).
pub fn write_document<S: OutputSink>(tree: &Value, format: DocumentFormat, sink: &mut S) -> Result<()> {
    serialize_to_sink(Node::Value(tree), format.resolve()?, sink)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::value_tree::Map;
    use alloc::vec::Vec;

    fn sample() -> Value {
        Value::Map(Map::from_entries([("key", Value::Bytes(b"f".to_vec())), ("iv", Value::Integer(1))]).unwrap())
    }

    #[cfg(feature = "extended-json")]
    #[test]
    fn extended_json_is_the_default_when_enabled() {
        assert_eq!(DocumentFormat::BuildDefault.resolve(), Ok(ResolvedFormat::ExtendedJson));
        assert_eq!(DocumentFormat::BuildDefault.cryptainer_suffix(), Some(".crypt.json"));
        assert_eq!(DocumentFormat::ExtendedJson.cryptainer_suffix(), Some(".crypt.json"));
        let mut output = Vec::new();
        write_document(&sample(), DocumentFormat::ExtendedJson, &mut output).unwrap();
        assert_eq!(
            output,
            b"{\"iv\": 1, \"key\": {\"$binary\": {\"base64\": \"Zg==\", \"subType\": \"00\"}}}"
        );
    }

    #[cfg(feature = "wa-cbor")]
    #[test]
    fn wa_cbor_when_enabled() {
        assert!(DocumentFormat::Cbor.is_enabled());
        assert_eq!(DocumentFormat::Cbor.cryptainer_suffix(), Some(".crypt.cbor"));
        let buffer = serialize_to_secret_buffer(Node::Value(&sample()), ResolvedFormat::Cbor).unwrap();
        assert_eq!(buffer.as_slice(), b"\xA2\x62iv\x01\x63key\x41f");
    }

    #[cfg(not(feature = "extended-json"))]
    #[test]
    fn extended_json_disabled() {
        assert_eq!(DocumentFormat::BuildDefault.resolve(), Ok(ResolvedFormat::Cbor));
        assert_eq!(DocumentFormat::BuildDefault.cryptainer_suffix(), Some(".crypt.cbor"));
        assert!(!DocumentFormat::ExtendedJson.is_enabled());
        assert_eq!(DocumentFormat::ExtendedJson.cryptainer_suffix(), None);
        let mut output = Vec::new();
        assert_eq!(
            write_document(&sample(), DocumentFormat::ExtendedJson, &mut output).map_err(|error| error.kind()),
            Err(ErrorKind::UnsupportedFeature)
        );
        assert_eq!(
            serialize_to_sink(Node::Null, ResolvedFormat::ExtendedJson, &mut output).map_err(|error| error.kind()),
            Err(ErrorKind::UnsupportedFeature)
        );
        assert!(output.is_empty());
    }

    #[cfg(not(feature = "wa-cbor"))]
    #[test]
    fn wa_cbor_disabled() {
        assert_eq!(DocumentFormat::BuildDefault.resolve(), Ok(ResolvedFormat::ExtendedJson));
        assert!(!DocumentFormat::Cbor.is_enabled());
        assert_eq!(DocumentFormat::Cbor.cryptainer_suffix(), None);
        let mut output = Vec::new();
        assert_eq!(
            write_document(&sample(), DocumentFormat::Cbor, &mut output).map_err(|error| error.kind()),
            Err(ErrorKind::UnsupportedFeature)
        );
        assert!(output.is_empty());
    }
}
