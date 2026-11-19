// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! PKCS#7 padding to 16-byte blocks (AES_CBC, and the chunks of the shared secret scheme).

pub(crate) const PKCS7_BLOCK_SIZE: usize = 16;

/// The number of padding bytes after `data_length` bytes of data: 1 to 16.
pub(crate) fn pkcs7_padding_length(data_length: usize) -> usize {
    PKCS7_BLOCK_SIZE - (data_length % PKCS7_BLOCK_SIZE)
}

/// Pad the final block in place, which holds `data_length_in_block` bytes of data (0 to 15).
pub(crate) fn pkcs7_pad_final_block(block: &mut [u8; PKCS7_BLOCK_SIZE], data_length_in_block: usize) {
    let data_length = data_length_in_block % PKCS7_BLOCK_SIZE;
    let padding_length = PKCS7_BLOCK_SIZE - data_length;
    block[data_length..].fill(padding_length as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_lengths() {
        assert_eq!(pkcs7_padding_length(0), 16);
        assert_eq!(pkcs7_padding_length(1), 15);
        assert_eq!(pkcs7_padding_length(15), 1);
        assert_eq!(pkcs7_padding_length(16), 16);
        assert_eq!(pkcs7_padding_length(17), 15);
    }

    #[test]
    fn final_blocks() {
        let mut block = [0xAA; 16];
        pkcs7_pad_final_block(&mut block, 0);
        assert_eq!(block, [16; 16]);
        let mut block = [0xAA; 16];
        pkcs7_pad_final_block(&mut block, 15);
        assert_eq!(&block[..15], [0xAA; 15]);
        assert_eq!(block[15], 1);
        let mut block = [0xAA; 16];
        pkcs7_pad_final_block(&mut block, 3);
        assert_eq!(&block[..3], [0xAA; 3]);
        assert_eq!(&block[3..], [13; 13]);
    }
}
