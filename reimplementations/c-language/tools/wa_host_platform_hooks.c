/* This file is part of Witness Angel Cryptolib
 * SPDX-FileCopyrightText: Copyright Prolifik SARL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wa_host_platform_hooks.h"

#include <stdlib.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

#if !defined(_WIN32)
/* Read exactly `length` bytes from a device file; -1 if it can't be opened or runs short */
static int wa_host_read_random_device(const char *path, uint8_t *buffer, size_t length)
{
    int file_descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (file_descriptor < 0) {
        return -1;
    }
    while (length > 0) {
        ssize_t read_count = read(file_descriptor, buffer, length);
        if (read_count < 0 && errno == EINTR) {
            continue;
        }
        if (read_count <= 0) {
            (void)close(file_descriptor);
            return -1;
        }
        buffer += read_count;
        length -= (size_t)read_count;
    }
    (void)close(file_descriptor);
    return 0;
}
#endif

int wa_host_fill_random(void *random_context, uint8_t *buffer, size_t length)
{
#if defined(_WIN32)
    (void)random_context;
    while (length > 0) {
        ULONG block_length = length > 0x10000000u ? 0x10000000u : (ULONG)length;
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, buffer, block_length, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            return -1;
        }
        buffer += block_length;
        length -= block_length;
    }
    return 0;
#else
    const wa_host_random_source_t *random_source = (const wa_host_random_source_t *)random_context;
    if (random_source != NULL && random_source->device_path_or_null != NULL) {
        return wa_host_read_random_device(random_source->device_path_or_null, buffer, length);
    }
#if defined(__linux__)
    while (length > 0) {
        /* Blocks only until the kernel pool is initialized, then never; at most 32 MiB per call */
        ssize_t read_count = getrandom(buffer, length, 0);
        if (read_count < 0 && errno == EINTR) {
            continue;
        }
        if (read_count < 0 && errno == ENOSYS) {
            return wa_host_read_random_device("/dev/urandom", buffer, length); /* Kernels before 3.17 */
        }
        if (read_count <= 0) {
            return -1;
        }
        buffer += read_count;
        length -= (size_t)read_count;
    }
    return 0;
#else
    return wa_host_read_random_device("/dev/urandom", buffer, length);
#endif
#endif
}

int wa_host_get_unix_time_in_ten_thousandths_of_second(void *clock_context, uint64_t *unix_time_out)
{
#if defined(_WIN32)
    /* FILETIME counts 100 ns intervals since 1601-01-01 */
    static const uint64_t unix_epoch_as_file_time = 116444736000000000u;
    FILETIME file_time;
    uint64_t intervals;
    (void)clock_context;
    GetSystemTimeAsFileTime(&file_time);
    intervals = ((uint64_t)file_time.dwHighDateTime << 32) | (uint64_t)file_time.dwLowDateTime;
    if (intervals < unix_epoch_as_file_time) {
        return -1;
    }
    *unix_time_out = (intervals - unix_epoch_as_file_time) / 1000u;
    return 0;
#else
    struct timespec now;
    (void)clock_context;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 0) {
        return -1;
    }
    *unix_time_out = (uint64_t)now.tv_sec * 10000u + (uint64_t)now.tv_nsec / 100000u;
    return 0;
#endif
}

void *wa_host_allocate(void *allocator_context, size_t size)
{
    (void)allocator_context;
    return malloc(size);
}

void wa_host_release(void *allocator_context, void *pointer, size_t size)
{
    (void)allocator_context;
    (void)size;
    free(pointer);
}

void wa_host_platform_hooks_initialize(wa_platform_hooks_t *hooks, wa_host_random_source_t *random_source_or_null)
{
    hooks->allocate = wa_host_allocate;
    hooks->release = wa_host_release;
    hooks->allocator_context = NULL;
    hooks->fill_random = wa_host_fill_random;
    hooks->random_context = random_source_or_null;
    hooks->get_unix_time_in_ten_thousandths_of_second = wa_host_get_unix_time_in_ten_thousandths_of_second;
    hooks->clock_context = NULL;
}
