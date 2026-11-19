// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! Standard base64 with padding (RFC 4648, section 4), written to a buffered sink writer without building the
//! encoded string in memory.

use crate::encoding::buffered_sink_writer::BufferedSinkWriter;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn symbol(six_bits: u32) -> u8 {
    // The mask keeps the index below 64
    ALPHABET.get((six_bits & 0x3F) as usize).copied().unwrap_or(b'=')
}

pub(crate) fn write_base64(writer: &mut BufferedSinkWriter<'_>, bytes: &[u8]) {
    let mut groups = bytes.chunks_exact(3);
    for group in &mut groups {
        if let &[first, second, third] = group {
            let bits = (u32::from(first) << 16) | (u32::from(second) << 8) | u32::from(third);
            writer.write(&[symbol(bits >> 18), symbol(bits >> 12), symbol(bits >> 6), symbol(bits)]);
        }
    }
    match *groups.remainder() {
        [first] => {
            let bits = u32::from(first) << 16;
            writer.write(&[symbol(bits >> 18), symbol(bits >> 12), b'=', b'=']);
        }
        [first, second] => {
            let bits = (u32::from(first) << 16) | (u32::from(second) << 8);
            writer.write(&[symbol(bits >> 18), symbol(bits >> 12), symbol(bits >> 6), b'=']);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn encode(bytes: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        let mut writer = BufferedSinkWriter::new(&mut output);
        write_base64(&mut writer, bytes);
        writer.finish().unwrap();
        output
    }

    #[test]
    fn rfc_4648_section_10_vectors() {
        let vectors: [(&[u8], &[u8]); 7] = [
            (b"", b""),
            (b"f", b"Zg=="),
            (b"fo", b"Zm8="),
            (b"foo", b"Zm9v"),
            (b"foob", b"Zm9vYg=="),
            (b"fooba", b"Zm9vYmE="),
            (b"foobar", b"Zm9vYmFy"),
        ];
        for (input, expected) in vectors {
            assert_eq!(encode(input), expected);
        }
    }

    #[test]
    fn every_symbol_is_reachable() {
        assert_eq!(encode(&[0xFB, 0xFF, 0xBF]), b"+/+/");
        assert_eq!(encode(&[0x00, 0x10, 0x83]), b"ABCD");
    }
}
