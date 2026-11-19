// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! The raw RSA public operation over `crypto-bigint`: a Montgomery exponentiation on heap-allocated integers of
//! the size of the modulus. The modulus and the exponent are public; the input (an OAEP-encoded key) is not, and
//! the copies made here are wiped. Those that `crypto-bigint` makes inside the exponentiation are not: its
//! `BoxedUint` has no wiping `Drop`, even with its `zeroize` feature (0.7), so the table of powers of the input
//! built by `pow_montgomery_form_amm` goes back to the allocator unwiped.

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Odd};
use wa_flightbox::{Error, ErrorKind, Result};
use zeroize::Zeroize;

/// `output = input^e mod n`, on big-endian byte strings of the length of the modulus.
pub(crate) fn rsa_compute_public_operation(
    modulus: &[u8],
    public_exponent: &[u8],
    input: &[u8],
    output: &mut [u8],
) -> Result<()> {
    let invalid_argument = || Error::new(ErrorKind::InvalidArgument);
    if modulus.is_empty()
        || modulus[0] == 0
        || public_exponent.is_empty()
        || input.len() != modulus.len()
        || output.len() != modulus.len()
    {
        return Err(invalid_argument());
    }
    let bits_precision = u32::try_from(modulus.len())
        .ok()
        .and_then(|length| length.checked_mul(8));
    let bits_precision = bits_precision.ok_or_else(invalid_argument)?;
    let modulus_integer = BoxedUint::from_be_slice(modulus, bits_precision).map_err(|_| invalid_argument())?;
    let mut input_integer = BoxedUint::from_be_slice(input, bits_precision).map_err(|_| invalid_argument())?;
    if input_integer >= modulus_integer {
        input_integer.zeroize();
        return Err(invalid_argument());
    }
    let Some(odd_modulus) = Odd::new(modulus_integer).into_option() else {
        input_integer.zeroize();
        return Err(invalid_argument()); // Even modulus
    };
    // Variable-time in the modulus and in the exponent, which are public
    let params = BoxedMontyParams::new_vartime(odd_modulus);
    let exponent_integer = BoxedUint::from_be_slice_vartime(public_exponent);
    let mut input_form = BoxedMontyForm::new(input_integer, &params);
    let mut output_bytes = input_form.pow(&exponent_integer).retrieve().to_be_bytes();
    input_form.zeroize();
    // The integer has whole limbs: its big-endian form may start with zero bytes beyond the modulus length
    let result = match output_bytes.len().checked_sub(output.len()) {
        Some(extra_length) => {
            output.copy_from_slice(&output_bytes[extra_length..]);
            Ok(())
        }
        None => Err(Error::new(ErrorKind::CryptoBackendFailure)),
    };
    output_bytes.zeroize();
    result
}
