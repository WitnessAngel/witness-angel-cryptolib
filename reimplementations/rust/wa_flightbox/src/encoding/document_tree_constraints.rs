// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Constraints that a value tree must satisfy to be a WA-CBOR document readable in both formats: a bounded
//! nesting depth, and no map that Extended JSON would read back as another type.

use crate::encoding::value_tree::Value;
use crate::error::{Error, ErrorKind, Result};

/// The keys of the single-key maps that Extended JSON reserves.
const EXTENDED_JSON_KEYWORDS: [&str; 8] = [
    "$binary",
    "$uuid",
    "$date",
    "$numberInt",
    "$numberLong",
    "$numberDouble",
    "$numberDecimal",
    "$undefined",
];

/// Whether `key` is an Extended JSON keyword.
pub(crate) fn is_extended_json_keyword(key: &str) -> bool {
    EXTENDED_JSON_KEYWORDS.contains(&key)
}

fn check_node(node: &Value, depth: usize, maximum_depth: usize) -> Result<()> {
    match node {
        Value::Array(items) => {
            if depth >= maximum_depth {
                return Err(Error::new(ErrorKind::NestingTooDeep));
            }
            for item in items {
                check_node(item, depth.saturating_add(1), maximum_depth)?;
            }
        }
        Value::Map(map) => {
            if depth >= maximum_depth {
                return Err(Error::new(ErrorKind::NestingTooDeep));
            }
            if map.len() == 1 && map.iter().any(|(key, _)| is_extended_json_keyword(key)) {
                return Err(Error::new(ErrorKind::InvalidProfile));
            }
            for (_, value) in map.iter() {
                check_node(value, depth.saturating_add(1), maximum_depth)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Check `tree`: `ErrorKind::NestingTooDeep` when arrays and maps are nested more than `maximum_depth` levels (a
/// tree that is one flat map has depth 1), `ErrorKind::InvalidProfile` for a single-key map whose key is an
/// Extended JSON keyword.
pub(crate) fn check_document_tree_constraints(tree: &Value, maximum_depth: usize) -> Result<()> {
    check_node(tree, 0, maximum_depth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::value_tree::Map;
    use alloc::vec;

    fn nested_arrays(depth: usize) -> Value {
        let mut value = Value::Integer(1);
        for _ in 0..depth {
            value = Value::Array(vec![value]);
        }
        value
    }

    #[test]
    fn depth_is_bounded() {
        assert!(check_document_tree_constraints(&nested_arrays(3), 3).is_ok());
        assert_eq!(
            check_document_tree_constraints(&nested_arrays(4), 3).map_err(|error| error.kind()),
            Err(ErrorKind::NestingTooDeep)
        );
        assert!(check_document_tree_constraints(&Value::Integer(1), 0).is_ok());
        let map = Value::Map(Map::from_entries([("k", nested_arrays(2))]).unwrap());
        assert!(check_document_tree_constraints(&map, 3).is_ok());
        assert!(check_document_tree_constraints(&map, 2).is_err());
    }

    #[test]
    fn keyword_maps_are_rejected() {
        for keyword in EXTENDED_JSON_KEYWORDS {
            let keyword_map = Value::Map(Map::from_entries([(keyword, "0123")]).unwrap());
            let tree = Value::Map(Map::from_entries([("field", Value::Array(vec![keyword_map]))]).unwrap());
            assert_eq!(
                check_document_tree_constraints(&tree, 64).map_err(|error| error.kind()),
                Err(ErrorKind::InvalidProfile)
            );
        }
        // Two keys, or another "$" key: an ordinary map
        let two_keys = Value::Map(Map::from_entries([("$uuid", "0123"), ("other", "x")]).unwrap());
        assert!(check_document_tree_constraints(&two_keys, 64).is_ok());
        let other_key = Value::Map(Map::from_entries([("$oid", "0123")]).unwrap());
        assert!(check_document_tree_constraints(&other_key, 64).is_ok());
    }
}
