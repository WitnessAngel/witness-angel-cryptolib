/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Single compilation unit of the vendored mlkem-native, with wa_mlkem_native_config.h (set through MLK_CONFIG_FILE
 * by the build). Device builds compile this file alone, with this directory and mlkem/ in the include path. */

#include "mlkem/mlkem_native.c"
