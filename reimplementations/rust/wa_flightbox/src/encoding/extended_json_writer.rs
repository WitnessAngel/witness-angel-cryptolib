// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Relaxed Extended JSON writer, byte-identical to wacryptolib's `dump_to_json_bytes()` (encryptor specification,
//! section 2): keys sorted by code point, `", "` and `": "` separators, ASCII-only output with lowercase `\uXXXX`
//! escapes, bytes as `$binary` (base64, subtype 00) and UUIDs as `$uuid` (32 hexadecimal digits).

use crate::encoding::base64_encoder::write_base64;
use crate::encoding::buffered_sink_writer::BufferedSinkWriter;
use crate::encoding::value_tree::{MapEntries, Node, Value};
use crate::error::Result;
use crate::platform_hooks::OutputSink;

const HEXADECIMAL_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn hexadecimal_digit(nibble: u32) -> u8 {
    HEXADECIMAL_DIGITS.get((nibble & 0xF) as usize).copied().unwrap_or(b'0')
}

fn write_unicode_escape(writer: &mut BufferedSinkWriter<'_>, code_unit: u32) {
    writer.write(&[
        b'\\',
        b'u',
        hexadecimal_digit(code_unit >> 12),
        hexadecimal_digit(code_unit >> 8),
        hexadecimal_digit(code_unit >> 4),
        hexadecimal_digit(code_unit),
    ]);
}

fn write_string(writer: &mut BufferedSinkWriter<'_>, text: &str) {
    writer.write_byte(b'"');
    for character in text.chars() {
        match character {
            '"' => writer.write_text("\\\""),
            '\\' => writer.write_text("\\\\"),
            '\u{8}' => writer.write_text("\\b"),
            '\u{c}' => writer.write_text("\\f"),
            '\n' => writer.write_text("\\n"),
            '\r' => writer.write_text("\\r"),
            '\t' => writer.write_text("\\t"),
            ' '..='~' => writer.write_byte(character as u8),
            _ => {
                // Surrogate pair beyond the BMP
                let mut code_units = [0u16; 2];
                for code_unit in character.encode_utf16(&mut code_units) {
                    write_unicode_escape(writer, u32::from(*code_unit));
                }
            }
        }
    }
    writer.write_byte(b'"');
}

fn write_integer(writer: &mut BufferedSinkWriter<'_>, integer: i64) {
    let mut digits = [0u8; 20];
    let mut position = digits.len();
    let mut magnitude = integer.unsigned_abs();
    loop {
        position = position.saturating_sub(1);
        if let Some(digit) = digits.get_mut(position) {
            *digit = b'0'.saturating_add((magnitude % 10) as u8);
        }
        magnitude /= 10;
        if magnitude == 0 {
            break;
        }
    }
    if integer < 0 {
        writer.write_byte(b'-');
    }
    writer.write(digits.get(position..).unwrap_or_default());
}

fn write_bytes(writer: &mut BufferedSinkWriter<'_>, bytes: &[u8]) {
    writer.write_text("{\"$binary\": {\"base64\": \"");
    write_base64(writer, bytes);
    writer.write_text("\", \"subType\": \"00\"}}");
}

fn write_map(writer: &mut BufferedSinkWriter<'_>, entries: MapEntries<'_>) {
    // Entries are kept sorted bytewise, which is the code point order of sort_keys
    writer.write_byte(b'{');
    for (index, (key, value)) in entries.iter().enumerate() {
        if index != 0 {
            writer.write_text(", ");
        }
        write_string(writer, key);
        writer.write_text(": ");
        write_node(writer, value);
    }
    writer.write_byte(b'}');
}

fn write_array<'a>(writer: &mut BufferedSinkWriter<'_>, items: impl Iterator<Item = Node<'a>>) {
    writer.write_byte(b'[');
    for (index, item) in items.enumerate() {
        if index != 0 {
            writer.write_text(", ");
        }
        write_node(writer, item);
    }
    writer.write_byte(b']');
}

fn write_node(writer: &mut BufferedSinkWriter<'_>, node: Node<'_>) {
    match node {
        Node::Null | Node::Value(Value::Null) => writer.write_text("null"),
        Node::Value(Value::Bool(boolean)) => writer.write_text(if *boolean { "true" } else { "false" }),
        Node::Integer(integer) => write_integer(writer, integer),
        Node::Value(Value::Integer(integer)) => write_integer(writer, *integer),
        Node::Value(Value::Text(text)) => write_string(writer, text),
        Node::Bytes(bytes) => write_bytes(writer, bytes),
        Node::Value(Value::Bytes(bytes)) => write_bytes(writer, bytes),
        Node::Value(Value::Uuid(uuid)) => {
            writer.write_text("{\"$uuid\": \"");
            for byte in uuid {
                writer.write(&[
                    hexadecimal_digit(u32::from(*byte) >> 4),
                    hexadecimal_digit(u32::from(*byte)),
                ]);
            }
            writer.write_text("\"}");
        }
        Node::Array(items) => write_array(writer, items.iter().copied()),
        Node::Value(Value::Array(items)) => write_array(writer, items.iter().map(Node::Value)),
        Node::Map(entries) => write_map(writer, MapEntries::Borrowed(entries)),
        Node::Value(Value::Map(map)) => write_map(writer, MapEntries::Owned(map)),
    }
}

/// Write `tree` to `sink` as relaxed Extended JSON.
pub(crate) fn write_extended_json_document(tree: Node<'_>, sink: &mut dyn OutputSink) -> Result<()> {
    let mut writer = BufferedSinkWriter::new(sink);
    write_node(&mut writer, tree);
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::value_tree::Map;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    fn to_json(tree: Node<'_>) -> String {
        let mut output = Vec::new();
        write_extended_json_document(tree, &mut output).unwrap();
        String::from_utf8(output).unwrap()
    }

    #[test]
    fn scalars() {
        assert_eq!(to_json(Node::Null), "null");
        assert_eq!(to_json(Node::Value(&Value::Bool(true))), "true");
        assert_eq!(to_json(Node::Value(&Value::Bool(false))), "false");
        assert_eq!(to_json(Node::Integer(0)), "0");
        assert_eq!(to_json(Node::Integer(-1)), "-1");
        assert_eq!(to_json(Node::Integer(i64::MAX)), "9223372036854775807");
        assert_eq!(to_json(Node::Integer(i64::MIN)), "-9223372036854775808");
        assert_eq!(
            to_json(Node::Bytes(b"")),
            "{\"$binary\": {\"base64\": \"\", \"subType\": \"00\"}}"
        );
        assert_eq!(
            to_json(Node::Bytes(b"fo")),
            "{\"$binary\": {\"base64\": \"Zm8=\", \"subType\": \"00\"}}"
        );
        let uuid = Value::Uuid([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0, 1, 2, 3, 4, 5, 6, 0xFF,
        ]);
        assert_eq!(
            to_json(Node::Value(&uuid)),
            "{\"$uuid\": \"0123456789abcdef00010203040506ff\"}"
        );
    }

    #[test]
    fn strings_are_ascii_only() {
        let text = Value::Text("Caf\u{e9} \u{2615}".into());
        assert_eq!(to_json(Node::Value(&text)), "\"Caf\\u00e9 \\u2615\"");
        let non_bmp = Value::Text("\u{1F600}".into());
        assert_eq!(to_json(Node::Value(&non_bmp)), "\"\\ud83d\\ude00\"");
        let controls = Value::Text("\"\\\u{8}\u{c}\n\r\t\u{0}\u{1f}\u{7f}/ ~".into());
        assert_eq!(
            to_json(Node::Value(&controls)),
            "\"\\\"\\\\\\b\\f\\n\\r\\t\\u0000\\u001f\\u007f/ ~\""
        );
    }

    #[test]
    fn containers_and_key_order() {
        let map = Map::from_entries([
            ("b", Value::Array(vec![Value::Integer(1), Value::Null])),
            ("a", Value::Map(Map::new())),
            ("\u{e9}", Value::Array(vec![])),
            ("B", Value::Text("x".into())),
        ])
        .unwrap();
        assert_eq!(
            to_json(Node::Value(&Value::Map(map))),
            "{\"B\": \"x\", \"a\": {}, \"b\": [1, null], \"\\u00e9\": []}"
        );
        let borrowed = [("iv", Node::Bytes(b"f")), ("key", Node::Integer(3))];
        assert_eq!(
            to_json(Node::Map(&borrowed)),
            "{\"iv\": {\"$binary\": {\"base64\": \"Zg==\", \"subType\": \"00\"}}, \"key\": 3}"
        );
        assert_eq!(
            to_json(Node::Array(&[Node::Integer(1), Node::Bytes(b"")])),
            "[1, {\"$binary\": {\"base64\": \"\", \"subType\": \"00\"}}]"
        );
    }
}
