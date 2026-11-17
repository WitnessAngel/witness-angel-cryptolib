# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Compile-only Cortex-M4 toolchain (arm-none-eabi-gcc, newlib headers), for the cross-compilation checks: the library,
# its Mbed TLS backend and mlkem-native are compiled, not linked (no device startup code nor hooks here).
#
#   cmake -S . -B build_cortex_m4 -DCMAKE_TOOLCHAIN_FILE=cmake/wa_arm_cortex_m4_toolchain.cmake \
#         -DWA_CRYPTO_BACKEND=MBEDTLS -DWA_LIBRARY_ONLY=ON -DWA_DOCUMENT_FORMATS=CBOR
#   cmake --build build_cortex_m4 --target wa_flightbox mbedcrypto wa_mlkem_native
#
# Per-function stack usage is written by -fstack-usage in .su files next to the objects.

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_AR arm-none-eabi-ar)
set(CMAKE_RANLIB arm-none-eabi-ranlib)
set(WA_ARM_SIZE_TOOL arm-none-eabi-size)

# No linking: compiler checks build static libraries
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_FLAGS_INIT "-mcpu=cortex-m4 -mthumb -mfloat-abi=soft -ffunction-sections -fdata-sections -fstack-usage")
set(CMAKE_C_FLAGS_MINSIZEREL_INIT "-Os -DNDEBUG")
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE MinSizeRel CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
