/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* A deliberately failing check: registered in CTest with WILL_FAIL, it proves that a failed check fails the test. */

#include "wa_minimal_test_harness.h"

static void test_deliberately_failing_check(void)
{
    WA_CHECK(1 + 1 == 3);
}

int main(void)
{
    WA_RUN_TEST(test_deliberately_failing_check);
    return wa_test_finish();
}
