# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
from typing import Sequence

from wacryptolib import _crypto_backend
from wacryptolib.utilities import do_recombine_secret_from_shards, do_split_secret_into_shards

logger = logging.getLogger(__name__)


def split_secret_into_shards(secret: bytes, *, shard_count: int, threshold_count: int) -> list:
    logger.debug("Generating shared-secret shards (%d needed amongst %d)", threshold_count, shard_count)
    return do_split_secret_into_shards(secret, shard_count=shard_count, threshold_count=threshold_count,
                                       shamir_128b_split_func=_crypto_backend.shamir_128b_split_func)


def recombine_secret_from_shards(shards: Sequence) -> bytes:
    logger.debug("Recombining %d shared-secret shards", len(shards))
    return do_recombine_secret_from_shards(shards=shards, shamir_128b_recombine_func=_crypto_backend.shamir_128b_combine_func)