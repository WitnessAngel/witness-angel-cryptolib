/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Test harness and test support implementation (host only: uses the C standard library). */

#include "wa_test_support.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_minimal_test_harness.h"

/* HARNESS */

static int wa_test_failure_count = 0;
static int wa_test_check_count = 0;
static int wa_test_count = 0;
static const char *wa_current_test_name = "(no test)";

void wa_test_run(const char *test_name, wa_test_function_t test_function)
{
    int failures_before = wa_test_failure_count;
    wa_current_test_name = test_name;
    wa_test_count++;
    test_function();
    printf("%s %s\n", wa_test_failure_count == failures_before ? "PASS" : "FAIL", test_name);
    fflush(stdout);
    wa_current_test_name = "(no test)";
}

int wa_test_finish(void)
{
    printf("%d test(s), %d check(s), %d failure(s)\n", wa_test_count, wa_test_check_count, wa_test_failure_count);
    return wa_test_failure_count == 0 ? 0 : 1;
}

static void wa_test_report_failure_location(const char *file, int line, const char *expression)
{
    wa_test_failure_count++;
    printf("%s:%d: check failed in %s: %s\n", file, line, wa_current_test_name, expression);
}

static void wa_test_print_hex_line(const char *label, const uint8_t *bytes, size_t length)
{
    size_t index;
    printf("    %s (%lu bytes): ", label, (unsigned long)length);
    for (index = 0; index < length && index < 256; index++) {
        printf("%02x", bytes[index]);
    }
    printf("%s\n", length > 256 ? "..." : "");
}

int wa_test_check_condition(int condition, const char *file, int line, const char *expression)
{
    wa_test_check_count++;
    if (!condition) {
        wa_test_report_failure_location(file, line, expression);
        return 0;
    }
    return 1;
}

int wa_test_check_status(wa_status_t actual, wa_status_t expected, const char *file, int line,
                         const char *expression)
{
    wa_test_check_count++;
    if (actual != expected) {
        wa_test_report_failure_location(file, line, expression);
        printf("    status %d (%s), expected %d (%s)\n", (int)actual, wa_status_get_description(actual), (int)expected,
               wa_status_get_description(expected));
        return 0;
    }
    return 1;
}

int wa_test_check_size(size_t actual, size_t expected, const char *file, int line, const char *expression)
{
    wa_test_check_count++;
    if (actual != expected) {
        wa_test_report_failure_location(file, line, expression);
        printf("    value %lu, expected %lu\n", (unsigned long)actual, (unsigned long)expected);
        return 0;
    }
    return 1;
}

int wa_test_check_bytes(const uint8_t *actual, size_t actual_length, const uint8_t *expected, size_t expected_length,
                        const char *file, int line, const char *expression)
{
    wa_test_check_count++;
    if (actual_length != expected_length ||
        (actual_length != 0 && (actual == NULL || expected == NULL || memcmp(actual, expected, actual_length) != 0))) {
        wa_test_report_failure_location(file, line, expression);
        wa_test_print_hex_line("actual  ", actual != NULL ? actual : (const uint8_t *)"", actual != NULL ? actual_length : 0);
        wa_test_print_hex_line("expected", expected != NULL ? expected : (const uint8_t *)"",
                               expected != NULL ? expected_length : 0);
        return 0;
    }
    return 1;
}

int wa_test_check_hex(const uint8_t *actual, size_t actual_length, const char *expected_hex, const char *file,
                      int line, const char *expression)
{
    size_t expected_length = 0;
    uint8_t *expected = wa_test_decode_hex(expected_hex, &expected_length);
    int result;
    if (expected == NULL) {
        wa_test_check_count++;
        wa_test_report_failure_location(file, line, "invalid expected hex in test");
        return 0;
    }
    result = wa_test_check_bytes(actual, actual_length, expected, expected_length, file, line, expression);
    free(expected);
    return result;
}

int wa_test_check_text(const char *actual, size_t actual_length, const char *expected, const char *file, int line,
                       const char *expression)
{
    size_t expected_length = strlen(expected);
    wa_test_check_count++;
    if (actual_length != expected_length ||
        (actual_length != 0 && (actual == NULL || memcmp(actual, expected, actual_length) != 0))) {
        wa_test_report_failure_location(file, line, expression);
        printf("    actual  : %.*s\n", actual != NULL ? (int)actual_length : 0, actual != NULL ? actual : "");
        printf("    expected: %s\n", expected);
        return 0;
    }
    return 1;
}

/* TEST ALLOCATOR: each block is preceded by a header recording its size and an owner tag */

#define WA_TEST_BLOCK_HEADER_SIZE 32u
#define WA_TEST_BLOCK_MAGIC 0x57414c4cu

typedef struct wa_test_block_header {
    size_t size;
    uint32_t magic;
    const wa_test_allocator_t *owner;
} wa_test_block_header_t;

void wa_test_allocator_initialize(wa_test_allocator_t *allocator)
{
    size_t index;
    memset(allocator, 0, sizeof(*allocator));
    allocator->fail_at_attempt_index = WA_TEST_NO_FAILURE;
    allocator->check_secret_patterns = 1;
    for (index = 0; index < 65536u; index++) {
        allocator->pattern_bucket_heads[index] = -1;
    }
}

void wa_test_allocator_register_secret_pattern(wa_test_allocator_t *allocator, const uint8_t *bytes, size_t length)
{
    size_t pattern_index;
    unsigned bucket;
    if (length < WA_TEST_SECRET_PATTERN_LENGTH || allocator->secret_pattern_count >= WA_TEST_MAXIMUM_SECRET_PATTERNS) {
        return;
    }
    pattern_index = allocator->secret_pattern_count++;
    memcpy(allocator->secret_patterns[pattern_index], bytes, WA_TEST_SECRET_PATTERN_LENGTH);
    bucket = ((unsigned)bytes[0] << 8) | bytes[1];
    allocator->pattern_next_index[pattern_index] = allocator->pattern_bucket_heads[bucket];
    allocator->pattern_bucket_heads[bucket] = (int32_t)pattern_index;
}

int wa_test_allocator_is_clean(const wa_test_allocator_t *allocator)
{
    return allocator->live_block_count == 0 && allocator->live_bytes == 0 && allocator->size_mismatch_count == 0 &&
           allocator->foreign_release_count == 0;
}

static int wa_test_block_contains_secret_pattern(const wa_test_allocator_t *allocator, const uint8_t *block,
                                                 size_t size)
{
    size_t position;
    if (size < WA_TEST_SECRET_PATTERN_LENGTH || allocator->secret_pattern_count == 0) {
        return 0;
    }
    for (position = 0; position + WA_TEST_SECRET_PATTERN_LENGTH <= size; position++) {
        int32_t pattern_index = allocator->pattern_bucket_heads[((unsigned)block[position] << 8) | block[position + 1]];
        while (pattern_index >= 0) {
            if (memcmp(block + position, allocator->secret_patterns[pattern_index], WA_TEST_SECRET_PATTERN_LENGTH) ==
                0) {
                return 1;
            }
            pattern_index = allocator->pattern_next_index[pattern_index];
        }
    }
    return 0;
}

void *wa_test_allocate(void *allocator_context, size_t size)
{
    wa_test_allocator_t *allocator = (wa_test_allocator_t *)allocator_context;
    uint8_t *raw_block;
    wa_test_block_header_t header;
    size_t attempt_index = allocator->attempted_allocation_count++;
    if (attempt_index == allocator->fail_at_attempt_index) {
        allocator->failure_was_injected = 1;
        return NULL;
    }
    if (size == 0 || size > ((size_t)-1) - WA_TEST_BLOCK_HEADER_SIZE) {
        return NULL;
    }
    raw_block = (uint8_t *)malloc(WA_TEST_BLOCK_HEADER_SIZE + size);
    if (raw_block == NULL) {
        return NULL;
    }
    header.size = size;
    header.magic = WA_TEST_BLOCK_MAGIC;
    header.owner = allocator;
    memcpy(raw_block, &header, sizeof(header));
    memset(raw_block + WA_TEST_BLOCK_HEADER_SIZE, 0xa5, size); /* Uninitialized memory is not zero */
    allocator->allocation_count++;
    allocator->live_block_count++;
    allocator->live_bytes += size;
    if (allocator->live_bytes > allocator->peak_live_bytes) {
        allocator->peak_live_bytes = allocator->live_bytes;
    }
    return raw_block + WA_TEST_BLOCK_HEADER_SIZE;
}

void wa_test_release(void *allocator_context, void *pointer, size_t size)
{
    wa_test_allocator_t *allocator = (wa_test_allocator_t *)allocator_context;
    uint8_t *raw_block;
    wa_test_block_header_t header;
    if (pointer == NULL) {
        return;
    }
    raw_block = (uint8_t *)pointer - WA_TEST_BLOCK_HEADER_SIZE;
    memcpy(&header, raw_block, sizeof(header));
    if (header.magic != WA_TEST_BLOCK_MAGIC || header.owner != allocator) {
        allocator->foreign_release_count++;
        return;
    }
    if (header.size != size) {
        allocator->size_mismatch_count++;
    }
    if (allocator->check_secret_patterns &&
        wa_test_block_contains_secret_pattern(allocator, (const uint8_t *)pointer, header.size)) {
        allocator->unwiped_secret_release_count++;
    }
    allocator->release_count++;
    allocator->live_block_count--;
    allocator->live_bytes -= header.size;
    header.magic = 0;
    memcpy(raw_block, &header, sizeof(header));
    free(raw_block);
}

/* DETERMINISTIC RANDOM HOOK (splitmix64) */

void wa_test_random_generator_initialize(wa_test_random_generator_t *generator, uint64_t seed)
{
    memset(generator, 0, sizeof(*generator));
    generator->state = seed;
    generator->fail_at_call_index = WA_TEST_NO_FAILURE;
}

static uint64_t wa_splitmix64_next(uint64_t *state)
{
    uint64_t value;
    *state += UINT64_C(0x9e3779b97f4a7c15);
    value = *state;
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

int wa_test_fill_random(void *random_context, uint8_t *buffer, size_t length)
{
    wa_test_random_generator_t *generator = (wa_test_random_generator_t *)random_context;
    size_t index;
    size_t call_index;
    if (generator == NULL) {
        return -1;
    }
    call_index = generator->call_count++;
    if (call_index == generator->fail_at_call_index) {
        generator->failure_was_injected = 1;
        return -1;
    }
    for (index = 0; index < length; index += 8) {
        uint64_t value = wa_splitmix64_next(&generator->state);
        size_t byte_index;
        for (byte_index = 0; byte_index < 8 && index + byte_index < length; byte_index++) {
            buffer[index + byte_index] = (uint8_t)(value >> (8 * byte_index));
        }
    }
    generator->produced_byte_count += length;
    if (generator->allocator_registering_secrets_or_null != NULL &&
        length >= WA_TEST_MINIMUM_SECRET_RANDOM_OUTPUT_LENGTH) {
        wa_test_allocator_register_secret_pattern(generator->allocator_registering_secrets_or_null, buffer, length);
    }
    return 0;
}

/* REPLAYED RANDOM */

void wa_test_replayed_random_initialize(wa_test_replayed_random_t *replayed_random, const uint8_t *bytes,
                                        size_t length)
{
    replayed_random->bytes = bytes;
    replayed_random->length = length;
    replayed_random->offset = 0;
    replayed_random->call_count = 0;
}

int wa_test_fill_replayed_random(void *random_context, uint8_t *buffer, size_t length)
{
    wa_test_replayed_random_t *replayed_random = (wa_test_replayed_random_t *)random_context;
    replayed_random->call_count++;
    if (length > replayed_random->length - replayed_random->offset) {
        return -1;
    }
    if (length > 0) {
        memcpy(buffer, replayed_random->bytes + replayed_random->offset, length);
    }
    replayed_random->offset += length;
    return 0;
}

/* FIXED CLOCK */

int wa_test_get_unix_time(void *clock_context, uint64_t *unix_time_out)
{
    wa_test_clock_t *clock = (wa_test_clock_t *)clock_context;
    if (clock == NULL || !clock->is_available) {
        return -1;
    }
    *unix_time_out = clock->unix_time_in_ten_thousandths_of_second;
    clock->unix_time_in_ten_thousandths_of_second += clock->increment_per_call;
    return 0;
}

/* PLATFORM */

wa_test_platform_t *wa_test_platform_create(uint64_t seed)
{
    wa_test_platform_t *platform = (wa_test_platform_t *)malloc(sizeof(*platform));
    if (platform == NULL) {
        fprintf(stderr, "wa_test_platform_create: out of memory\n");
        abort();
    }
    memset(platform, 0, sizeof(*platform));
    wa_test_allocator_initialize(&platform->allocator);
    wa_test_random_generator_initialize(&platform->random_generator, seed);
    platform->random_generator.allocator_registering_secrets_or_null = &platform->allocator;
    platform->clock.is_available = 1;
    platform->clock.unix_time_in_ten_thousandths_of_second = UINT64_C(17672256000000); /* 2026-01-01T00:00:00Z */
    platform->clock.increment_per_call = 1;
    platform->hooks.allocate = wa_test_allocate;
    platform->hooks.release = wa_test_release;
    platform->hooks.allocator_context = &platform->allocator;
    platform->hooks.fill_random = wa_test_fill_random;
    platform->hooks.random_context = &platform->random_generator;
    platform->hooks.get_unix_time_in_ten_thousandths_of_second = wa_test_get_unix_time;
    platform->hooks.clock_context = &platform->clock;
    return platform;
}

void wa_test_platform_destroy(wa_test_platform_t *platform_or_null)
{
    free(platform_or_null);
}

/* MEMORY SINK */

static wa_status_t wa_test_memory_sink_write(void *sink_context, const uint8_t *bytes, size_t length)
{
    wa_test_memory_sink_t *memory_sink = (wa_test_memory_sink_t *)sink_context;
    memory_sink->write_call_count++;
    if (memory_sink->fail_after_byte_count != WA_TEST_NO_FAILURE &&
        memory_sink->length + length > memory_sink->fail_after_byte_count) {
        return memory_sink->failure_status;
    }
    if (length == 0) {
        return WA_STATUS_OK;
    }
    if (memory_sink->length + length > memory_sink->capacity) {
        size_t new_capacity = memory_sink->capacity == 0 ? 256 : memory_sink->capacity;
        uint8_t *new_bytes;
        while (new_capacity < memory_sink->length + length) {
            new_capacity *= 2;
        }
        new_bytes = (uint8_t *)realloc(memory_sink->bytes, new_capacity);
        if (new_bytes == NULL) {
            return WA_STATUS_SINK_WRITE_FAILURE;
        }
        memory_sink->bytes = new_bytes;
        memory_sink->capacity = new_capacity;
    }
    memcpy(memory_sink->bytes + memory_sink->length, bytes, length);
    memory_sink->length += length;
    return WA_STATUS_OK;
}

void wa_test_memory_sink_initialize(wa_test_memory_sink_t *memory_sink)
{
    memset(memory_sink, 0, sizeof(*memory_sink));
    memory_sink->fail_after_byte_count = WA_TEST_NO_FAILURE;
    memory_sink->failure_status = WA_STATUS_SINK_WRITE_FAILURE;
    memory_sink->sink.write = wa_test_memory_sink_write;
    memory_sink->sink.sink_context = memory_sink;
}

void wa_test_memory_sink_release(wa_test_memory_sink_t *memory_sink)
{
    free(memory_sink->bytes);
    memory_sink->bytes = NULL;
    memory_sink->length = 0;
    memory_sink->capacity = 0;
}

/* HEX */

static int wa_test_hex_digit_value(char character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

uint8_t *wa_test_decode_hex(const char *hex, size_t *length_out)
{
    size_t text_length = strlen(hex);
    uint8_t *bytes = (uint8_t *)malloc(text_length / 2 + 1);
    size_t length = 0;
    int high_nibble = -1;
    size_t index;
    if (bytes == NULL) {
        return NULL;
    }
    for (index = 0; index < text_length; index++) {
        int value;
        char character = hex[index];
        if (character == ' ' || character == '\n' || character == '\t' || character == '\r') {
            continue;
        }
        value = wa_test_hex_digit_value(character);
        if (value < 0) {
            free(bytes);
            return NULL;
        }
        if (high_nibble < 0) {
            high_nibble = value;
        } else {
            bytes[length++] = (uint8_t)((high_nibble << 4) | value);
            high_nibble = -1;
        }
    }
    if (high_nibble >= 0) {
        free(bytes);
        return NULL;
    }
    *length_out = length;
    return bytes;
}

char *wa_test_encode_hex(const uint8_t *bytes, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    char *text = (char *)malloc(2 * length + 1);
    size_t index;
    if (text == NULL) {
        return NULL;
    }
    for (index = 0; index < length; index++) {
        text[2 * index] = digits[bytes[index] >> 4];
        text[2 * index + 1] = digits[bytes[index] & 15u];
    }
    text[2 * length] = '\0';
    return text;
}
