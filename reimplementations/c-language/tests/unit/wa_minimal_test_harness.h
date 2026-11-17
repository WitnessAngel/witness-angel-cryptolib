/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Minimal unit test harness: checks count failures (and print their location) without stopping the test, requires
 * return from the current test function. A test executable runs its tests with WA_RUN_TEST() and returns
 * wa_test_finish(), which is non-zero if any check failed, so that CTest reports the failure. */

#ifndef WA_MINIMAL_TEST_HARNESS_H
#define WA_MINIMAL_TEST_HARNESS_H

#include <stddef.h>
#include <stdint.h>

#include "wa_flightbox/wa_status_codes.h"

typedef void (*wa_test_function_t)(void);

void wa_test_run(const char *test_name, wa_test_function_t test_function);
int wa_test_finish(void);

/* Implementation of the macros below: each returns 1 if the check passed, else reports the failure and returns 0 */
int wa_test_check_condition(int condition, const char *file, int line, const char *expression);
int wa_test_check_status(wa_status_t actual, wa_status_t expected, const char *file, int line,
                         const char *expression);
int wa_test_check_size(size_t actual, size_t expected, const char *file, int line, const char *expression);
int wa_test_check_bytes(const uint8_t *actual, size_t actual_length, const uint8_t *expected, size_t expected_length,
                        const char *file, int line, const char *expression);
int wa_test_check_hex(const uint8_t *actual, size_t actual_length, const char *expected_hex, const char *file,
                      int line, const char *expression);
int wa_test_check_text(const char *actual, size_t actual_length, const char *expected, const char *file, int line,
                       const char *expression);

#define WA_CHECK(condition) ((void)wa_test_check_condition((condition) ? 1 : 0, __FILE__, __LINE__, #condition))
#define WA_CHECK_STATUS(expression, expected) \
    ((void)wa_test_check_status((expression), (expected), __FILE__, __LINE__, #expression))
#define WA_CHECK_SIZE(actual, expected) \
    ((void)wa_test_check_size((size_t)(actual), (size_t)(expected), __FILE__, __LINE__, #actual))
#define WA_CHECK_BYTES(actual, actual_length, expected, expected_length)                                         \
    ((void)wa_test_check_bytes((actual), (actual_length), (expected), (expected_length), __FILE__, __LINE__, \
                               #actual))
#define WA_CHECK_HEX(actual, actual_length, expected_hex) \
    ((void)wa_test_check_hex((actual), (actual_length), (expected_hex), __FILE__, __LINE__, #actual))
/* Compares a byte string (not NUL-terminated) with a NUL-terminated expected text */
#define WA_CHECK_TEXT(actual, actual_length, expected) \
    ((void)wa_test_check_text((const char *)(actual), (actual_length), (expected), __FILE__, __LINE__, #actual))

/* Like WA_CHECK / WA_CHECK_STATUS, but returning from the current (void) test function on failure */
#define WA_REQUIRE(condition)                                                              \
    do {                                                                                   \
        if (!wa_test_check_condition((condition) ? 1 : 0, __FILE__, __LINE__, #condition)) \
            return;                                                                        \
    } while (0)
#define WA_REQUIRE_STATUS(expression, expected)                                               \
    do {                                                                                      \
        if (!wa_test_check_status((expression), (expected), __FILE__, __LINE__, #expression)) \
            return;                                                                           \
    } while (0)

#define WA_RUN_TEST(test_function) wa_test_run(#test_function, test_function)

#endif /* WA_MINIMAL_TEST_HARNESS_H */
