// This file is part of Witness Angel Cryptolib
// SPDX-FileCopyrightText: Copyright Prolifik SARL
// SPDX-License-Identifier: GPL-2.0-or-later

//! UUID0 (encryptor specification, section 3.2): a 48-bit time prefix, the Unix time in 1/10000 s, followed by 80
//! random bits. Without a clock, the prefix is zero.

use crate::encoding::value_tree::UUID_SIZE;
use crate::error::Result;
use crate::platform_hooks::PlatformHooks;
use crate::primitives::fill_random_bytes;

pub(crate) const UUID0_TIME_PREFIX_SIZE: usize = 6;

/// A new UUID0: the clock hook is read first, then 10 bytes are drawn from the random hook.
pub(crate) fn generate_uuid0(hooks: &mut dyn PlatformHooks) -> Result<[u8; UUID_SIZE]> {
    let unix_time = hooks.unix_time_in_ten_thousandths_of_second().unwrap_or(0);
    let mut uuid = [0u8; UUID_SIZE];
    // The big-endian uint64 without its 2 most significant bytes
    uuid[..UUID0_TIME_PREFIX_SIZE].copy_from_slice(&unix_time.to_be_bytes()[2..]);
    fill_random_bytes(hooks, &mut uuid[UUID0_TIME_PREFIX_SIZE..])?;
    Ok(uuid)
}
