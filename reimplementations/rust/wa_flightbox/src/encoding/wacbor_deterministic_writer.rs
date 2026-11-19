// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! WA-CBOR writer in the core deterministic encoding (`docs/specifications/wa_cbor_document_format.md`),
//! byte-identical to wacryptolib's `dump_to_cbor_bytes()`: shortest heads, definite lengths, map keys sorted by
//! their encoded bytes, UUIDs as tag 37 around a 16-byte string.

use crate::encoding::buffered_sink_writer::BufferedSinkWriter;
use crate::encoding::value_tree::{MapEntries, Node, UUID_SIZE, Value};
use crate::error::Result;
use crate::platform_hooks::OutputSink;

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const UUID_TAG: u64 = 37;

fn write_head(writer: &mut BufferedSinkWriter<'_>, major_type: u8, argument: u64) {
    let initial = major_type << 5;
    let bytes = argument.to_be_bytes();
    if argument < 24 {
        writer.write_byte(initial | (argument as u8));
    } else if argument <= 0xFF {
        writer.write_byte(initial | 24);
        writer.write(bytes.get(7..).unwrap_or_default());
    } else if argument <= 0xFFFF {
        writer.write_byte(initial | 25);
        writer.write(bytes.get(6..).unwrap_or_default());
    } else if argument <= 0xFFFF_FFFF {
        writer.write_byte(initial | 26);
        writer.write(bytes.get(4..).unwrap_or_default());
    } else {
        writer.write_byte(initial | 27);
        writer.write(&bytes);
    }
}

fn write_integer(writer: &mut BufferedSinkWriter<'_>, integer: i64) {
    if integer >= 0 {
        write_head(writer, MAJOR_UNSIGNED, integer.unsigned_abs());
    } else {
        // -1 - n, without overflow for i64::MIN
        write_head(writer, MAJOR_NEGATIVE, integer.unsigned_abs().saturating_sub(1));
    }
}

fn write_string(writer: &mut BufferedSinkWriter<'_>, major_type: u8, content: &[u8]) {
    write_head(writer, major_type, content.len() as u64);
    writer.write(content);
}

fn write_map(writer: &mut BufferedSinkWriter<'_>, entries: MapEntries<'_>) {
    // Canonical order: by encoded key, that is by key length, then bytewise. Entries are kept sorted bytewise, so
    // the keys of each length are written in their stored order, one pass per distinct key length (no allocation).
    write_head(writer, MAJOR_MAP, entries.len() as u64);
    let mut written_count = 0usize;
    let mut previous_length: Option<usize> = None;
    while written_count < entries.len() {
        let current_length = entries
            .iter()
            .map(|(key, _)| key.len())
            .filter(|length| previous_length.is_none_or(|previous| *length > previous))
            .min();
        let Some(current_length) = current_length else {
            break;
        };
        for (key, value) in entries.iter().filter(|(key, _)| key.len() == current_length) {
            write_string(writer, MAJOR_TEXT, key.as_bytes());
            write_node(writer, value);
            written_count = written_count.saturating_add(1);
        }
        previous_length = Some(current_length);
    }
}

fn write_node(writer: &mut BufferedSinkWriter<'_>, node: Node<'_>) {
    match node {
        Node::Null | Node::Value(Value::Null) => writer.write_byte(0xF6),
        Node::Value(Value::Bool(boolean)) => writer.write_byte(if *boolean { 0xF5 } else { 0xF4 }),
        Node::Integer(integer) => write_integer(writer, integer),
        Node::Value(Value::Integer(integer)) => write_integer(writer, *integer),
        Node::Value(Value::Text(text)) => write_string(writer, MAJOR_TEXT, text.as_bytes()),
        Node::Bytes(bytes) => write_string(writer, MAJOR_BYTES, bytes),
        Node::Value(Value::Bytes(bytes)) => write_string(writer, MAJOR_BYTES, bytes),
        Node::Value(Value::Uuid(uuid)) => {
            write_head(writer, MAJOR_TAG, UUID_TAG);
            write_head(writer, MAJOR_BYTES, UUID_SIZE as u64);
            writer.write(uuid);
        }
        Node::Array(items) => {
            write_head(writer, MAJOR_ARRAY, items.len() as u64);
            for item in items {
                write_node(writer, *item);
            }
        }
        Node::Value(Value::Array(items)) => {
            write_head(writer, MAJOR_ARRAY, items.len() as u64);
            for item in items {
                write_node(writer, Node::Value(item));
            }
        }
        Node::Map(entries) => write_map(writer, MapEntries::Borrowed(entries)),
        Node::Value(Value::Map(map)) => write_map(writer, MapEntries::Owned(map)),
    }
}

/// Write `tree` to `sink` in the WA-CBOR core deterministic encoding.
pub(crate) fn write_wacbor_document(tree: Node<'_>, sink: &mut dyn OutputSink) -> Result<()> {
    let mut writer = BufferedSinkWriter::new(sink);
    write_node(&mut writer, tree);
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::value_tree::Map;
    use alloc::vec;
    use alloc::vec::Vec;

    fn to_cbor(tree: Node<'_>) -> Vec<u8> {
        let mut output = Vec::new();
        write_wacbor_document(tree, &mut output).unwrap();
        output
    }

    #[test]
    fn integers_use_the_shortest_head() {
        let vectors: [(i64, &[u8]); 13] = [
            (0, &[0x00]),
            (23, &[0x17]),
            (24, &[0x18, 0x18]),
            (255, &[0x18, 0xFF]),
            (256, &[0x19, 0x01, 0x00]),
            (65535, &[0x19, 0xFF, 0xFF]),
            (65536, &[0x1A, 0x00, 0x01, 0x00, 0x00]),
            (4294967296, &[0x1B, 0, 0, 0, 1, 0, 0, 0, 0]),
            (i64::MAX, &[0x1B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            (-1, &[0x20]),
            (-24, &[0x37]),
            (-25, &[0x38, 0x18]),
            (i64::MIN, &[0x3B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        ];
        for (integer, expected) in vectors {
            assert_eq!(to_cbor(Node::Integer(integer)), expected, "{integer}");
        }
    }

    #[test]
    fn scalars_and_strings() {
        assert_eq!(to_cbor(Node::Null), [0xF6]);
        assert_eq!(to_cbor(Node::Value(&Value::Bool(false))), [0xF4]);
        assert_eq!(to_cbor(Node::Value(&Value::Bool(true))), [0xF5]);
        assert_eq!(to_cbor(Node::Bytes(b"")), [0x40]);
        assert_eq!(to_cbor(Node::Bytes(b"ab")), [0x42, b'a', b'b']);
        assert_eq!(to_cbor(Node::Value(&Value::Text("\u{e9}".into()))), [0x62, 0xC3, 0xA9]);
        let mut expected = vec![0xD8, 0x25, 0x50];
        expected.extend_from_slice(&[7u8; 16]);
        assert_eq!(to_cbor(Node::Value(&Value::Uuid([7; 16]))), expected);
        let long_bytes = vec![1u8; 300];
        let encoded = to_cbor(Node::Bytes(&long_bytes));
        assert_eq!(&encoded[..3], [0x59, 0x01, 0x2C]);
        assert_eq!(encoded.len(), 303);
    }

    #[test]
    fn map_keys_are_ordered_by_length_then_bytes() {
        let map = Map::from_entries([
            ("bb", Value::Integer(1)),
            ("a", Value::Integer(2)),
            ("c", Value::Integer(3)),
            ("aaa", Value::Integer(4)),
            ("", Value::Integer(5)),
            ("ab", Value::Integer(6)),
        ])
        .unwrap();
        let expected: &[u8] = &[
            0xA6, 0x60, 0x05, 0x61, b'a', 0x02, 0x61, b'c', 0x03, 0x62, b'a', b'b', 0x06, 0x62, b'b', b'b', 0x01, 0x63,
            b'a', b'a', b'a', 0x04,
        ];
        assert_eq!(to_cbor(Node::Value(&Value::Map(map))), expected);
        // "nonce" sorts after "key" bytewise and by length; "cryptainer_metadata" before "key_bytes" bytewise, but
        // after it by length
        let key_struct = [("cryptainer_metadata", Node::Null), ("key_bytes", Node::Bytes(b"k"))];
        let encoded = to_cbor(Node::Map(&key_struct));
        assert_eq!(&encoded[..11], b"\xA2\x69key_bytes");
        assert_eq!(
            to_cbor(Node::Array(&[Node::Integer(1), Node::Bytes(b"x")])),
            [0x82, 0x01, 0x41, b'x']
        );
        assert_eq!(to_cbor(Node::Value(&Value::Array(vec![]))), [0x80]);
    }
}
