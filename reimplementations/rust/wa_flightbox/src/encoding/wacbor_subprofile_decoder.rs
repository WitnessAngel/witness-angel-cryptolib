// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Decoder of the device profile sub-profile of WA-CBOR (`docs/flightbox_specifications/
//! flightbox_device_profile_specification.md`), into a value tree. Its verdicts are those of the C decoder
//! (`wa_wacbor_subprofile_decoder.c`), checks being made in the same order:
//! - accepted: null, booleans, integers within int64, text, bytes, UUIDs (tag 37), definite-length arrays and
//!   maps with text keys, in any valid encoding (non-shortest heads and unsorted keys included);
//! - `ErrorKind::UnsupportedType`: valid WA-CBOR outside the sub-profile (floats, datetimes, bignums, decimals,
//!   indefinite lengths, tag 55799 around the document, integers outside int64);
//! - `ErrorKind::NestingTooDeep`: arrays and maps nested beyond the limit;
//! - `ErrorKind::DecodingError`: everything else.
//!
//! No input makes it panic: every read is bounds-checked, and the recursion is bounded by the depth limit.

use alloc::string::String;
use alloc::vec::Vec;

use crate::encoding::document_tree_constraints::is_extended_json_keyword;
use crate::encoding::value_tree::{Map, UUID_SIZE, Value};
use crate::error::{Error, ErrorKind, Result};

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const BREAK_BYTE: u8 = 0xFF;
const INDEFINITE_LENGTH: u8 = 31;
const DATETIME_TEXT_TAG: u64 = 0;
const POSITIVE_BIGNUM_TAG: u64 = 2;
const NEGATIVE_BIGNUM_TAG: u64 = 3;
const DECIMAL_FRACTION_TAG: u64 = 4;
const UUID_TAG: u64 = 37;
const SELF_DESCRIBED_TAG: u64 = 55799;

fn decoding_error() -> Error {
    Error::new(ErrorKind::DecodingError)
}

fn unsupported_type() -> Error {
    Error::new(ErrorKind::UnsupportedType)
}

#[derive(Clone, Copy)]
struct Head {
    major_type: u8,
    additional_information: u8,
    /// Meaningless for indefinite lengths
    argument: u64,
}

#[derive(Clone, Copy)]
struct Decoder<'a> {
    /// What remains to decode
    data: &'a [u8],
    maximum_depth: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let (taken, rest) = self.data.split_at_checked(length).ok_or_else(decoding_error)?;
        self.data = rest;
        Ok(taken)
    }

    fn read_head(&mut self) -> Result<Head> {
        let initial = *self.take(1)?.first().ok_or_else(decoding_error)?; // Truncated
        let major_type = initial >> 5;
        let additional_information = initial & 0x1F;
        let mut argument = 0u64;
        if additional_information < 24 {
            argument = u64::from(additional_information);
        } else if additional_information <= 27 {
            let argument_size = 1usize << (additional_information.saturating_sub(24));
            for byte in self.take(argument_size)? {
                argument = (argument << 8) | u64::from(*byte);
            }
        } else if additional_information != INDEFINITE_LENGTH {
            return Err(decoding_error()); // Reserved additional information 28..30
        }
        Ok(Head {
            major_type,
            additional_information,
            argument,
        })
    }

    fn peek_head(&self) -> Result<Head> {
        let mut probe = *self;
        probe.read_head()
    }

    /// Definite-length byte or text string content, bounds-checked
    fn read_string_content(&mut self, head: &Head) -> Result<&'a [u8]> {
        if head.additional_information == INDEFINITE_LENGTH {
            return Err(unsupported_type());
        }
        let length = usize::try_from(head.argument).map_err(|_| decoding_error())?;
        let content = self.take(length)?;
        if head.major_type == MAJOR_TEXT && core::str::from_utf8(content).is_err() {
            return Err(decoding_error());
        }
        Ok(content)
    }

    fn read_text(&mut self, head: &Head) -> Result<String> {
        let content = self.read_string_content(head)?;
        let text = core::str::from_utf8(content).map_err(|_| decoding_error())?;
        let mut owned = String::new();
        owned
            .try_reserve_exact(text.len())
            .map_err(|_| Error::new(ErrorKind::OutOfMemory))?;
        owned.push_str(text);
        Ok(owned)
    }

    fn decode_array(&mut self, head: &Head, depth: usize) -> Result<Value> {
        if head.additional_information == INDEFINITE_LENGTH {
            return Err(unsupported_type());
        }
        if depth > self.maximum_depth {
            return Err(Error::new(ErrorKind::NestingTooDeep));
        }
        // Each item takes at least one byte
        let count = usize::try_from(head.argument)
            .ok()
            .filter(|count| *count <= self.data.len());
        let count = count.ok_or_else(decoding_error)?;
        let mut items = Vec::new();
        items
            .try_reserve_exact(count)
            .map_err(|_| Error::new(ErrorKind::OutOfMemory))?;
        for _ in 0..count {
            items.push(self.decode_item(depth)?);
        }
        Ok(Value::Array(items))
    }

    fn decode_map_entry(&mut self, map: &mut Map, depth: usize) -> Result<()> {
        let key_head = self.peek_head()?;
        if key_head.major_type != MAJOR_TEXT {
            return Err(decoding_error()); // Map key is not a text string
        }
        let key_head = self.read_head()?;
        let key = self.read_text(&key_head)?;
        if map.contains_key(&key) {
            return Err(decoding_error()); // Duplicate map key
        }
        let value = self.decode_item(depth)?;
        map.insert(key, value).map_err(|_| Error::new(ErrorKind::InternalError))
    }

    fn decode_map(&mut self, head: &Head, depth: usize) -> Result<Value> {
        if head.additional_information == INDEFINITE_LENGTH {
            return Err(unsupported_type());
        }
        if depth > self.maximum_depth {
            return Err(Error::new(ErrorKind::NestingTooDeep));
        }
        // Each entry takes at least two bytes
        let count = usize::try_from(head.argument)
            .ok()
            .filter(|count| *count <= self.data.len() / 2);
        let count = count.ok_or_else(decoding_error)?;
        let mut map = Map::new();
        for _ in 0..count {
            self.decode_map_entry(&mut map, depth)?;
        }
        if map.len() == 1 && map.iter().any(|(key, _)| is_extended_json_keyword(key)) {
            return Err(decoding_error()); // Extended JSON keyword map
        }
        Ok(Value::Map(map))
    }

    fn decode_tagged_item(&mut self, head: &Head) -> Result<Value> {
        match head.argument {
            // Valid WA-CBOR tags, outside the sub-profile
            DATETIME_TEXT_TAG | POSITIVE_BIGNUM_TAG | NEGATIVE_BIGNUM_TAG | DECIMAL_FRACTION_TAG => {
                Err(unsupported_type())
            }
            UUID_TAG => {
                let content_head = self.peek_head()?;
                if content_head.major_type != MAJOR_BYTES {
                    return Err(decoding_error());
                }
                let content_head = self.read_head()?;
                let content = self.read_string_content(&content_head)?;
                let uuid: [u8; UUID_SIZE] = content.try_into().map_err(|_| decoding_error())?;
                Ok(Value::Uuid(uuid))
            }
            // Any other tag, 55799 included when not around the top-level item
            _ => Err(decoding_error()),
        }
    }

    fn decode_item(&mut self, depth: usize) -> Result<Value> {
        match self.data.first() {
            None => return Err(decoding_error()),              // Truncated
            Some(&BREAK_BYTE) => return Err(decoding_error()), // Unexpected break code
            Some(_) => {}
        }
        let head = self.read_head()?;
        if matches!(head.major_type, MAJOR_UNSIGNED | MAJOR_NEGATIVE | MAJOR_TAG)
            && head.additional_information == INDEFINITE_LENGTH
        {
            return Err(decoding_error());
        }
        match head.major_type {
            MAJOR_UNSIGNED => i64::try_from(head.argument)
                .map(Value::Integer)
                .map_err(|_| unsupported_type()),
            MAJOR_NEGATIVE => {
                // -1 - argument, which fits when the argument is within int64
                let argument = i64::try_from(head.argument).map_err(|_| unsupported_type())?;
                (-1i64)
                    .checked_sub(argument)
                    .map(Value::Integer)
                    .ok_or_else(unsupported_type)
            }
            MAJOR_BYTES => {
                let content = self.read_string_content(&head)?;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(content.len())
                    .map_err(|_| Error::new(ErrorKind::OutOfMemory))?;
                bytes.extend_from_slice(content);
                Ok(Value::Bytes(bytes))
            }
            MAJOR_TEXT => self.read_text(&head).map(Value::Text),
            MAJOR_ARRAY => self.decode_array(&head, depth.saturating_add(1)),
            MAJOR_MAP => self.decode_map(&head, depth.saturating_add(1)),
            MAJOR_TAG => self.decode_tagged_item(&head),
            _ => match head.additional_information {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                25..=27 => Err(unsupported_type()), // Floats
                _ => Err(decoding_error()),         // Other simple values
            },
        }
    }
}

/// Decode a whole document, whose top-level item must be a map or an array, nested at most `maximum_depth` levels.
pub(crate) fn decode_wacbor_subprofile_document(cbor: &[u8], maximum_depth: usize) -> Result<Value> {
    let mut decoder = Decoder {
        data: cbor,
        maximum_depth,
    };
    let head = decoder.peek_head()?;
    if head.major_type == MAJOR_TAG
        && head.additional_information != INDEFINITE_LENGTH
        && head.argument == SELF_DESCRIBED_TAG
    {
        return Err(unsupported_type()); // Valid around the top-level item, outside the sub-profile
    }
    if head.major_type != MAJOR_ARRAY && head.major_type != MAJOR_MAP {
        return Err(decoding_error()); // Top-level item is not a map nor an array
    }
    let document = decoder.decode_item(0)?;
    if !decoder.data.is_empty() {
        return Err(decoding_error()); // Bytes after the top-level item
    }
    Ok(document)
}

/// Decode a WA-CBOR document of the device profile sub-profile (null, booleans, integers, text, bytes, UUIDs,
/// arrays and maps with text keys) into a value tree, e.g. cryptainer metadata received as CBOR. The top-level
/// item must be a map or an array, nested at most as deep as `limits` allow.
///
/// Errors: `ErrorKind::DecodingError` for bytes that are not such a document, `ErrorKind::UnsupportedType` for
/// valid WA-CBOR outside the sub-profile (floats, dates, big numbers...), `ErrorKind::NestingTooDeep`,
/// `ErrorKind::InvalidProfile` for Extended JSON keyword maps, `ErrorKind::OutOfMemory`.
pub fn decode_document_from_cbor(cbor: &[u8], limits: &crate::limits::EncryptorLimits) -> Result<Value> {
    decode_wacbor_subprofile_document(cbor, limits.max_cbor_nesting_depth())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn decode(cbor: &[u8]) -> core::result::Result<Value, ErrorKind> {
        decode_wacbor_subprofile_document(cbor, 64).map_err(|error| error.kind())
    }

    fn item(encoded_item: &[u8]) -> core::result::Result<Value, ErrorKind> {
        // The item as the single element of an array
        let mut cbor = vec![0x81];
        cbor.extend_from_slice(encoded_item);
        decode(&cbor).map(|document| document.as_array().unwrap()[0].clone())
    }

    #[test]
    fn accepted_types() {
        assert_eq!(item(&[0xF6]), Ok(Value::Null));
        assert_eq!(item(&[0xF4]), Ok(Value::Bool(false)));
        assert_eq!(item(&[0xF5]), Ok(Value::Bool(true)));
        assert_eq!(item(&[0x17]), Ok(Value::Integer(23)));
        assert_eq!(item(&[0x20]), Ok(Value::Integer(-1)));
        assert_eq!(
            item(&[0x1B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            Ok(Value::Integer(i64::MAX))
        );
        assert_eq!(
            item(&[0x3B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            Ok(Value::Integer(i64::MIN))
        );
        assert_eq!(item(&[0x42, 1, 2]), Ok(Value::Bytes(vec![1, 2])));
        assert_eq!(item(&[0x62, 0xC3, 0xA9]), Ok(Value::Text("\u{e9}".into())));
        let mut uuid = vec![0xD8, 0x25, 0x50];
        uuid.extend_from_slice(&[9; 16]);
        assert_eq!(item(&uuid), Ok(Value::Uuid([9; 16])));
        assert_eq!(decode(&[0x80]), Ok(Value::Array(vec![])));
        assert_eq!(decode(&[0xA0]), Ok(Value::Map(Map::new())));
    }

    #[test]
    fn non_shortest_heads_and_unsorted_keys_are_accepted() {
        assert_eq!(item(&[0x18, 0x01]), Ok(Value::Integer(1)));
        assert_eq!(item(&[0x19, 0x00, 0x01]), Ok(Value::Integer(1)));
        assert_eq!(item(&[0x1B, 0, 0, 0, 0, 0, 0, 0, 1]), Ok(Value::Integer(1)));
        assert_eq!(item(&[0x58, 0x01, 0xAA]), Ok(Value::Bytes(vec![0xAA])));
        assert_eq!(decode(&[0x98, 0x01, 0x00]), Ok(Value::Array(vec![Value::Integer(0)])));
        let document = decode(&[0xA2, 0x61, b'b', 0x01, 0x61, b'a', 0x02]).unwrap();
        let keys: Vec<_> = document.as_map().unwrap().iter().map(|(key, _)| key).collect();
        assert_eq!(keys, ["a", "b"]);
    }

    #[test]
    fn unsupported_types() {
        let unsupported = Err(ErrorKind::UnsupportedType);
        assert_eq!(item(&[0xF9, 0x3C, 0x00]), unsupported); // Half float
        assert_eq!(item(&[0xFA, 0, 0, 0, 0]), unsupported);
        assert_eq!(item(&[0xFB, 0, 0, 0, 0, 0, 0, 0, 0]), unsupported);
        assert_eq!(item(&[0xC0, 0x60]), unsupported); // Datetime
        assert_eq!(item(&[0xC2, 0x41, 0x01]), unsupported); // Bignums
        assert_eq!(item(&[0xC3, 0x41, 0x01]), unsupported);
        assert_eq!(item(&[0xC4, 0x82, 0x00, 0x01]), unsupported); // Decimal
        assert_eq!(item(&[0x5F, 0x41, 0x01, 0xFF]), unsupported); // Indefinite lengths
        assert_eq!(item(&[0x7F, 0x61, b'a', 0xFF]), unsupported);
        assert_eq!(item(&[0x9F, 0xFF]), unsupported);
        assert_eq!(item(&[0xBF, 0xFF]), unsupported);
        assert_eq!(decode(&[0x9F, 0xFF]), unsupported);
        assert_eq!(item(&[0x1B, 0x80, 0, 0, 0, 0, 0, 0, 0]), unsupported); // Beyond int64
        assert_eq!(item(&[0x3B, 0x80, 0, 0, 0, 0, 0, 0, 0]), unsupported);
        assert_eq!(decode(&[0xD9, 0xD9, 0xF7, 0x80]), unsupported); // Tag 55799 around the document
    }

    #[test]
    fn invalid_data() {
        let invalid = Err(ErrorKind::DecodingError);
        assert_eq!(decode(&[]), invalid);
        assert_eq!(decode(&[0x01]), invalid); // Top-level item is not a container
        assert_eq!(decode(&[0x60]), invalid);
        assert_eq!(decode(&[0x80, 0x00]), invalid); // Trailing bytes
        assert_eq!(decode(&[0x81]), invalid); // Truncated
        assert_eq!(decode(&[0x82, 0x00]), invalid);
        assert_eq!(decode(&[0x98]), invalid);
        assert_eq!(item(&[0x19, 0x00]), invalid);
        assert_eq!(item(&[0x42, 0x01]), invalid);
        assert_eq!(item(&[0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), invalid);
        assert_eq!(decode(&[0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), invalid);
        assert_eq!(decode(&[0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), invalid);
        assert_eq!(item(&[0x1C]), invalid); // Reserved additional information
        assert_eq!(item(&[0x1D]), invalid);
        assert_eq!(item(&[0x1E]), invalid);
        assert_eq!(item(&[0x1F]), invalid); // Indefinite on integers and tags
        assert_eq!(item(&[0x3F]), invalid);
        assert_eq!(item(&[0xDF, 0x00]), invalid);
        assert_eq!(item(&[0xFF]), invalid); // Break code
        assert_eq!(item(&[0x62, 0xC3, 0x28]), invalid); // Invalid UTF-8
        assert_eq!(item(&[0x63, 0xED, 0xA0, 0x80]), invalid); // Encoded surrogate
        assert_eq!(decode(&[0xA1, 0x01, 0x02]), invalid); // Non-text key
        assert_eq!(decode(&[0xA2, 0x61, b'a', 0x01, 0x61, b'a', 0x02]), invalid); // Duplicate key
        assert_eq!(item(&[0xC1, 0x00]), invalid); // Other tags
        assert_eq!(item(&[0xD9, 0xD9, 0xF7, 0x80]), invalid); // Tag 55799 inside
        assert_eq!(
            item(&[0xD8, 0x25, 0x4F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            invalid
        ); // 15-byte UUID
        assert_eq!(item(&[0xD8, 0x25, 0x60]), invalid); // UUID tag around text
        assert_eq!(item(&[0xF7]), invalid); // undefined
        assert_eq!(item(&[0xE0]), invalid); // Simple value 0
        assert_eq!(item(&[0xF8, 0x20]), invalid);
        // Extended JSON keyword map
        assert_eq!(decode(&[0xA1, 0x65, b'$', b'u', b'u', b'i', b'd', 0x60]), invalid);
        assert!(decode(&[0xA2, 0x65, b'$', b'u', b'u', b'i', b'd', 0x60, 0x61, b'a', 0x60]).is_ok());
    }

    #[test]
    fn nesting_depth() {
        let nested = |depth: usize| {
            let mut cbor = vec![0x81; depth - 1];
            cbor.push(0x80);
            cbor
        };
        assert!(decode(&nested(64)).is_ok());
        assert_eq!(decode(&nested(65)), Err(ErrorKind::NestingTooDeep));
        assert!(decode_wacbor_subprofile_document(&nested(8), 8).is_ok());
        assert_eq!(
            decode_wacbor_subprofile_document(&nested(9), 8).map_err(|error| error.kind()),
            Err(ErrorKind::NestingTooDeep)
        );
        // Checked before the item count, as in the C decoder
        let mut too_deep_and_truncated = vec![0x81; 64];
        too_deep_and_truncated.push(0x98);
        too_deep_and_truncated.push(0xFF);
        assert_eq!(decode(&too_deep_and_truncated), Err(ErrorKind::NestingTooDeep));
        // A very deep input does not overflow the stack
        assert_eq!(decode(&vec![0x81; 1_000_000]), Err(ErrorKind::NestingTooDeep));
    }
}
