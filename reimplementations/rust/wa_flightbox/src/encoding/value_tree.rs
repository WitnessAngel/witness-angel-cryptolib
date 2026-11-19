// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Value trees: the data model of cryptoconfs, cryptainers and cryptainer metadata (design D6).
//!
//! Node types are those of the device profile sub-profile of WA-CBOR: null, booleans, signed 64-bit integers,
//! UTF-8 text, bytes, UUIDs, arrays and maps with text keys. Maps are kept sorted by key (bytewise UTF-8, which is
//! the code point order), as in the C library: validation then reports the same faulty key in both
//! implementations, and writers order keys as their format requires without sorting anything.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, ErrorKind, Result};

/// Size of a UUID, in bytes.
pub const UUID_SIZE: usize = 16;

/// A node of a value tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// The null value.
    Null,
    /// A boolean.
    Bool(bool),
    /// A signed 64-bit integer.
    Integer(i64),
    /// A text string (valid UTF-8 by construction, NUL characters allowed).
    Text(String),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A UUID, in network byte order.
    Uuid([u8; UUID_SIZE]),
    /// An array of nodes.
    Array(Vec<Value>),
    /// A map with text keys.
    Map(Map),
}

impl Value {
    /// The text of a text node.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    /// The bytes of a bytes node.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// The integer of an integer node.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Value::Integer(integer) => Some(*integer),
            _ => None,
        }
    }

    /// The boolean of a boolean node.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(boolean) => Some(*boolean),
            _ => None,
        }
    }

    /// The UUID of a UUID node.
    pub fn as_uuid(&self) -> Option<&[u8; UUID_SIZE]> {
        match self {
            Value::Uuid(uuid) => Some(uuid),
            _ => None,
        }
    }

    /// The items of an array node.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The items of an array node, for update.
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The map of a map node.
    pub fn as_map(&self) -> Option<&Map> {
        match self {
            Value::Map(map) => Some(map),
            _ => None,
        }
    }

    /// The map of a map node, for update.
    pub fn as_map_mut(&mut self) -> Option<&mut Map> {
        match self {
            Value::Map(map) => Some(map),
            _ => None,
        }
    }

    /// Whether this is the null value.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// The value of `key` when this node is a map having it.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map().and_then(|map| map.get(key))
    }
}

impl From<bool> for Value {
    fn from(boolean: bool) -> Self {
        Value::Bool(boolean)
    }
}

impl From<i64> for Value {
    fn from(integer: i64) -> Self {
        Value::Integer(integer)
    }
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Value::Text(text.into())
    }
}

impl From<String> for Value {
    fn from(text: String) -> Self {
        Value::Text(text)
    }
}

impl From<Vec<u8>> for Value {
    fn from(bytes: Vec<u8>) -> Self {
        Value::Bytes(bytes)
    }
}

impl From<&[u8]> for Value {
    fn from(bytes: &[u8]) -> Self {
        Value::Bytes(bytes.to_vec())
    }
}

impl From<[u8; UUID_SIZE]> for Value {
    fn from(uuid: [u8; UUID_SIZE]) -> Self {
        Value::Uuid(uuid)
    }
}

impl From<Vec<Value>> for Value {
    fn from(items: Vec<Value>) -> Self {
        Value::Array(items)
    }
}

impl From<Map> for Value {
    fn from(map: Map) -> Self {
        Value::Map(map)
    }
}

/// A map with text keys, without duplicates, kept sorted by key (bytewise UTF-8).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Map {
    entries: Vec<(String, Value)>,
}

impl Map {
    /// An empty map.
    pub const fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map has no entry.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn search(&self, key: &str) -> core::result::Result<usize, usize> {
        self.entries
            .binary_search_by(|(entry_key, _)| entry_key.as_bytes().cmp(key.as_bytes()))
    }

    /// Whether `key` is present.
    pub fn contains_key(&self, key: &str) -> bool {
        self.search(key).is_ok()
    }

    /// The value of `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        let index = self.search(key).ok()?;
        self.entries.get(index).map(|(_, value)| value)
    }

    /// The value of `key`, for update.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        let index = self.search(key).ok()?;
        self.entries.get_mut(index).map(|(_, value)| value)
    }

    /// Add the entry `key` -> `value`. A key already present gives `ErrorKind::InvalidArgument`.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) -> Result<()> {
        let key = key.into();
        match self.search(&key) {
            Ok(_) => Err(Error::new(ErrorKind::InvalidArgument)),
            Err(index) => {
                self.entries.insert(index, (key, value.into()));
                Ok(())
            }
        }
    }

    /// Set the value of `key`, adding the entry or replacing its value, which is then returned.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<Value>) -> Option<Value> {
        let key = key.into();
        match self.search(&key) {
            Ok(index) => self
                .entries
                .get_mut(index)
                .map(|(_, previous)| core::mem::replace(previous, value.into())),
            Err(index) => {
                self.entries.insert(index, (key, value.into()));
                None
            }
        }
    }

    /// Remove the entry of `key`, returning its value.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let index = self.search(key).ok()?;
        Some(self.entries.remove(index).1)
    }

    /// The entries, in key order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &Value)> {
        self.entries.iter().map(|(key, value)| (key.as_str(), value))
    }

    /// The entry at `index` of the key order.
    pub fn entry_at(&self, index: usize) -> Option<(&str, &Value)> {
        self.entries.get(index).map(|(key, value)| (key.as_str(), value))
    }

    /// A map from entries. A duplicate key gives `ErrorKind::InvalidArgument`.
    pub fn from_entries<K: Into<String>, V: Into<Value>>(entries: impl IntoIterator<Item = (K, V)>) -> Result<Self> {
        let mut map = Self::new();
        for (key, value) in entries {
            map.insert(key, value)?;
        }
        Ok(map)
    }
}

/// A borrowed view of a tree, for the writers: an owned subtree, or nodes built on the stack around borrowed data,
/// so that secrets (symkeys, shards, key structs) are serialized without being copied into owned trees.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Node<'a> {
    /// An owned subtree.
    Value(&'a Value),
    /// The null value.
    Null,
    /// An integer.
    Integer(i64),
    /// Borrowed bytes.
    Bytes(&'a [u8]),
    /// An array of views.
    Array(&'a [Node<'a>]),
    /// A map of views, its entries **sorted by key** like those of [`Map`].
    Map(&'a [(&'a str, Node<'a>)]),
}

/// The entries of an owned or borrowed map, in bytewise key order.
#[derive(Clone, Copy)]
pub(crate) enum MapEntries<'a> {
    Owned(&'a Map),
    Borrowed(&'a [(&'a str, Node<'a>)]),
}

impl<'a> MapEntries<'a> {
    pub(crate) fn len(&self) -> usize {
        match self {
            MapEntries::Owned(map) => map.len(),
            MapEntries::Borrowed(entries) => entries.len(),
        }
    }

    pub(crate) fn entry_at(&self, index: usize) -> Option<(&'a str, Node<'a>)> {
        match self {
            MapEntries::Owned(map) => map.entry_at(index).map(|(key, value)| (key, Node::Value(value))),
            MapEntries::Borrowed(entries) => entries.get(index).copied(),
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'a str, Node<'a>)> + '_ {
        (0..self.len()).filter_map(|index| self.entry_at(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn maps_are_sorted_bytewise_and_refuse_duplicates() {
        let mut map = Map::new();
        map.insert("b", 1i64).unwrap();
        map.insert("a", 2i64).unwrap();
        map.insert("aa", 3i64).unwrap();
        map.insert("\u{e9}", 4i64).unwrap();
        map.insert("Z", 5i64).unwrap();
        let keys: Vec<_> = map.iter().map(|(key, _)| key).collect();
        assert_eq!(keys, ["Z", "a", "aa", "b", "\u{e9}"]);
        assert_eq!(
            map.insert("a", Value::Null).map_err(|error| error.kind()),
            Err(ErrorKind::InvalidArgument)
        );
        assert_eq!(map.len(), 5);
        assert_eq!(map.get("aa"), Some(&Value::Integer(3)));
        assert_eq!(map.get("c"), None);
        assert!(map.contains_key("Z"));
    }

    #[test]
    fn set_and_remove() {
        let mut map = Map::new();
        assert_eq!(map.set("k", "v"), None);
        assert_eq!(map.set("k", 7i64), Some(Value::Text("v".into())));
        assert_eq!(map.get("k").and_then(Value::as_integer), Some(7));
        assert_eq!(map.remove("k"), Some(Value::Integer(7)));
        assert_eq!(map.remove("k"), None);
        assert!(map.is_empty());
    }

    #[test]
    fn a_clone_does_not_alias_its_source() {
        let inner = Map::from_entries([("bytes", Value::Bytes(vec![1, 2, 3]))]).unwrap();
        let source = Value::Array(vec![Value::Map(inner), Value::Text("text".into())]);
        let mut copy = source.clone();
        assert_eq!(copy, source);
        if let Some(Value::Map(map)) = copy.as_array_mut().and_then(|items| items.first_mut()) {
            map.set("bytes", Value::Bytes(vec![9]));
            map.set("more", true);
        }
        assert_ne!(copy, source);
        let source_map = source
            .as_array()
            .and_then(|items| items.first())
            .and_then(Value::as_map)
            .unwrap();
        assert_eq!(
            source_map.get("bytes").and_then(Value::as_bytes),
            Some(&[1u8, 2, 3][..])
        );
        assert_eq!(source_map.len(), 1);
    }

    #[test]
    fn accessors_check_the_type() {
        assert_eq!(Value::from("x").as_text(), Some("x"));
        assert_eq!(Value::from(1i64).as_text(), None);
        assert_eq!(Value::from(true).as_bool(), Some(true));
        assert_eq!(Value::from([7u8; 16]).as_uuid(), Some(&[7u8; 16]));
        assert!(Value::Null.is_null());
        assert_eq!(Value::Null.get("k"), None);
        assert_eq!(Value::from(&b"ab"[..]).as_bytes(), Some(&b"ab"[..]));
    }
}
