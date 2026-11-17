# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Host build of the flightbox C encryptor.
#
#   cmake -S . -B build -DWA_CRYPTO_BACKEND=MBEDTLS        # or WOLFCRYPT
#         [-DWA_DOCUMENT_FORMATS="JSON;CBOR"] [-DWA_ENABLE_SANITIZERS=ON] [-DWA_BUILD_FUZZERS=ON]
#   cmake --build build && ctest --test-dir build
#
# Device builds (ESP-IDF, bare metal) compile the sources listed in README.md with their own build system.

cmake_minimum_required(VERSION 3.16)
project(wa_flightbox VERSION 0.1.0 LANGUAGES C)

include(CTest)
include(FetchContent)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)  # Fetched archives get extraction-time timestamps
endif()

# OPTIONS #

set(WA_CRYPTO_BACKEND "" CACHE STRING "Crypto backend: MBEDTLS (Mbed TLS 3.6 + mlkem-native) or WOLFCRYPT")
set_property(CACHE WA_CRYPTO_BACKEND PROPERTY STRINGS MBEDTLS WOLFCRYPT)
set(WA_DOCUMENT_FORMATS "JSON;CBOR" CACHE STRING "Document formats compiled in: JSON, CBOR, or both")
option(WA_USE_SYSTEM_CRYPTO_LIBRARIES "Use installed Mbed TLS / wolfSSL instead of fetching pinned versions" OFF)
option(WA_ENABLE_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(WA_BUILD_TOOLS "Build the host command-line tool and test driver" ON)
option(WA_BUILD_FUZZERS "Build libFuzzer targets (Clang only)" OFF)
option(WA_LIBRARY_ONLY "Only compile the library (cross-compilation checks: no tests, no tools)" OFF)

if(NOT WA_CRYPTO_BACKEND STREQUAL "MBEDTLS" AND NOT WA_CRYPTO_BACKEND STREQUAL "WOLFCRYPT")
    message(FATAL_ERROR
        "WA_CRYPTO_BACKEND must be set to MBEDTLS or WOLFCRYPT (got \"${WA_CRYPTO_BACKEND}\"), "
        "e.g. cmake -DWA_CRYPTO_BACKEND=MBEDTLS")
endif()

set(WA_DOCUMENT_FORMAT_JSON_ENABLED 0)
set(WA_DOCUMENT_FORMAT_CBOR_ENABLED 0)
foreach(document_format IN LISTS WA_DOCUMENT_FORMATS)
    if(document_format STREQUAL "JSON")
        set(WA_DOCUMENT_FORMAT_JSON_ENABLED 1)
    elseif(document_format STREQUAL "CBOR")
        set(WA_DOCUMENT_FORMAT_CBOR_ENABLED 1)
    else()
        message(FATAL_ERROR "Unknown document format \"${document_format}\" in WA_DOCUMENT_FORMATS (expected JSON and/or CBOR)")
    endif()
endforeach()
if(NOT WA_DOCUMENT_FORMAT_JSON_ENABLED AND NOT WA_DOCUMENT_FORMAT_CBOR_ENABLED)
    message(FATAL_ERROR "WA_DOCUMENT_FORMATS must contain JSON, CBOR, or both (e.g. -DWA_DOCUMENT_FORMATS=\"JSON;CBOR\")")
endif()
message(STATUS "wa_flightbox: backend ${WA_CRYPTO_BACKEND}, document formats ${WA_DOCUMENT_FORMATS}")

if(WA_LIBRARY_ONLY)
    set(BUILD_TESTING OFF)
    set(WA_BUILD_TOOLS OFF)
    set(WA_BUILD_FUZZERS OFF)
endif()

set(WA_STRICT_WARNING_FLAGS -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
    -Wmissing-prototypes -Wvla -Wcast-align -Werror)
set(WA_SANITIZER_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
if(WA_BUILD_FUZZERS)
    # Fuzzing always runs under ASan/UBSan, with the whole build instrumented for coverage
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "WA_BUILD_FUZZERS requires Clang (libFuzzer)")
    endif()
    set(WA_ENABLE_SANITIZERS ON)
    add_compile_options(-fsanitize=fuzzer-no-link)
endif()
if(WA_ENABLE_SANITIZERS)
    add_compile_options(${WA_SANITIZER_FLAGS})
    add_link_options(${WA_SANITIZER_FLAGS})
endif()

# Fetch content without adding its CMake project, when we compile it ourselves
macro(wa_fetch_sources_only name)
    if(CMAKE_VERSION VERSION_LESS 3.18)
        FetchContent_GetProperties(${name})
        if(NOT ${name}_POPULATED)
            FetchContent_Populate(${name})
        endif()
    else()
        FetchContent_MakeAvailable(${name})
    endif()
endmacro()

# CRYPTO BACKEND #

set(WA_CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/config")

if(WA_CRYPTO_BACKEND STREQUAL "MBEDTLS")
    if(WA_USE_SYSTEM_CRYPTO_LIBRARIES)
        find_package(MbedTLS 3.6 REQUIRED)
        set(WA_CRYPTO_LIBRARIES MbedTLS::mbedcrypto)
    else()
        set(MBEDTLS_CONFIG_FILE "${WA_CONFIG_DIR}/wa_mbedtls_config_for_flightbox.h" CACHE FILEPATH "" FORCE)
        set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
        set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
        set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
        set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
        set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
        set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
        FetchContent_Declare(mbedtls
            URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.8/mbedtls-3.6.8.tar.bz2
            URL_HASH SHA256=bc54b818e87f49c0b3281dd85d24adaede0e63b4e822e3fbd49c005a38b9595b
            SOURCE_SUBDIR wa_no_cmake_project_here)
        wa_fetch_sources_only(mbedtls)
        # Only mbedcrypto is built (the TLS and X.509 libraries are excluded from "all", and never linked). Its
        # objects go to this build tree, even when FETCHCONTENT_BASE_DIR is shared by several builds.
        add_subdirectory("${mbedtls_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/mbedtls_build" EXCLUDE_FROM_ALL)
        set(WA_CRYPTO_LIBRARIES mbedcrypto)
    endif()

    # mlkem-native, vendored: ML-KEM-768 only, single compilation unit, derandomized API only
    add_library(wa_mlkem_native STATIC
        third_party/mlkem-native/wa_mlkem_native_single_unit.c)
    target_include_directories(wa_mlkem_native
        PUBLIC third_party/mlkem-native third_party/mlkem-native/mlkem)
    target_compile_definitions(wa_mlkem_native
        PUBLIC MLK_CONFIG_FILE="wa_mlkem_native_config.h")
    set_target_properties(wa_mlkem_native PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    target_compile_options(wa_mlkem_native PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror)
    list(APPEND WA_CRYPTO_LIBRARIES wa_mlkem_native)
    set(WA_BACKEND_SOURCE src/backends/wa_crypto_backend_mbedtls.c)
    set(WA_BACKEND_DEFINITION WA_CRYPTO_BACKEND_MBEDTLS)
else()
    if(WA_USE_SYSTEM_CRYPTO_LIBRARIES)
        find_package(wolfssl REQUIRED)
        set(WA_CRYPTO_LIBRARIES wolfssl::wolfssl)
    else()
        FetchContent_Declare(wolfssl
            URL https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.8.4-stable.tar.gz
            URL_HASH SHA256=2b702b7a66b0067bfd284408827b1e59288b357b0dd758d0089c062395f2a522
            SOURCE_SUBDIR wa_no_cmake_project_here)
        wa_fetch_sources_only(wolfssl)
        # wolfCrypt only, compiled from the sources the flightbox needs, with our user_settings.h
        set(WA_WOLFCRYPT_SOURCE_NAMES
            aes.c asn.c chacha.c chacha20_poly1305.c coding.c curve25519.c error.c fe_operations.c hash.c hmac.c
            logging.c memory.c poly1305.c rsa.c sha.c sha256.c sha3.c sha512.c sp_int.c wc_mlkem.c wc_mlkem_poly.c
            wc_port.c wolfmath.c)
        list(TRANSFORM WA_WOLFCRYPT_SOURCE_NAMES PREPEND "${wolfssl_SOURCE_DIR}/wolfcrypt/src/")
        # wolfSSL includes "user_settings.h" with WOLFSSL_USER_SETTINGS: this shim forwards to our settings file
        set(WA_WOLFSSL_SETTINGS_DIR "${CMAKE_CURRENT_BINARY_DIR}/wa_wolfssl_settings")
        file(WRITE "${WA_WOLFSSL_SETTINGS_DIR}/user_settings.h"
            "/* Generated by CMake: wolfSSL settings of the flightbox encryptor */\n"
            "#include \"${WA_CONFIG_DIR}/wa_wolfssl_user_settings_for_flightbox.h\"\n")
        add_library(wa_wolfcrypt STATIC ${WA_WOLFCRYPT_SOURCE_NAMES})
        target_include_directories(wa_wolfcrypt SYSTEM PUBLIC "${wolfssl_SOURCE_DIR}" "${WA_WOLFSSL_SETTINGS_DIR}")
        set_target_properties(wa_wolfcrypt PROPERTIES C_STANDARD 99 C_EXTENSIONS OFF)
        target_compile_definitions(wa_wolfcrypt PUBLIC WOLFSSL_USER_SETTINGS)
        set(WA_CRYPTO_LIBRARIES wa_wolfcrypt)
    endif()
    set(WA_BACKEND_SOURCE src/backends/wa_crypto_backend_wolfcrypt.c)
    set(WA_BACKEND_DEFINITION WA_CRYPTO_BACKEND_WOLFCRYPT)
endif()

# LIBRARY #

set(WA_LIBRARY_SOURCES
    src/core/wa_cryptainer_encryptor.c
    src/core/wa_cryptainer_base_generation.c
    src/core/wa_key_cipher_layers_encryption.c
    src/core/wa_payload_encryption_pipeline.c
    src/core/wa_cryptainer_finalization.c
    src/core/wa_cryptoconf_validation.c
    src/core/wa_error_location_path.c
    src/core/wa_platform_hooks_calls.c
    src/core/wa_status_codes.c
    src/encoding/wa_buffered_sink_writer.c
    src/encoding/wa_value_tree.c
    src/encoding/wa_document_tree_constraints.c
    src/encoding/wa_wacbor_subprofile_decoder.c
    src/encoding/wa_device_profile_decoding.c
    src/encoding/wa_document_serialization.c
    src/encoding/wa_growable_byte_buffer.c
    src/encoding/wa_utf8_validation.c
    src/primitives/wa_symmetric_key_generation.c
    src/primitives/wa_symmetric_cipher_streams.c
    src/primitives/wa_aes_cbc_pkcs7_padding.c
    src/primitives/wa_aes_cmac_omac1.c
    src/primitives/wa_aes_eax_mode.c
    src/primitives/wa_rsa_oaep_sha512_padding.c
    src/primitives/wa_rsa_oaep_chunked_encryption.c
    src/primitives/wa_hkdf_sha256.c
    src/primitives/wa_hpke_base_mode_seal.c
    src/primitives/wa_hpke_kem_dhkem_x25519.c
    src/primitives/wa_hpke_kem_ml_kem_768.c
    src/primitives/wa_public_key_constraints.c
    src/primitives/wa_asymmetric_key_wrapping.c
    src/primitives/wa_shamir_secret_sharing_gf128.c
    src/primitives/wa_uuid0_generation.c
    src/primitives/wa_secure_memory_wipe.c
    ${WA_BACKEND_SOURCE})
if(WA_DOCUMENT_FORMAT_JSON_ENABLED)
    list(APPEND WA_LIBRARY_SOURCES src/encoding/wa_extended_json_writer.c src/encoding/wa_base64_encoder.c)
endif()
if(WA_DOCUMENT_FORMAT_CBOR_ENABLED)
    list(APPEND WA_LIBRARY_SOURCES src/encoding/wa_wacbor_deterministic_writer.c)
endif()

add_library(wa_flightbox STATIC ${WA_LIBRARY_SOURCES})
target_include_directories(wa_flightbox PUBLIC include PRIVATE src)
target_compile_definitions(wa_flightbox
    PUBLIC
        WA_DOCUMENT_FORMAT_JSON_ENABLED=${WA_DOCUMENT_FORMAT_JSON_ENABLED}
        WA_DOCUMENT_FORMAT_CBOR_ENABLED=${WA_DOCUMENT_FORMAT_CBOR_ENABLED}
    PRIVATE ${WA_BACKEND_DEFINITION})
target_compile_options(wa_flightbox PRIVATE ${WA_STRICT_WARNING_FLAGS})
target_link_libraries(wa_flightbox PRIVATE ${WA_CRYPTO_LIBRARIES})
set_target_properties(wa_flightbox PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)

# Internal access for unit tests, tools and fuzzers (internal headers and the backend definition)
add_library(wa_flightbox_internal INTERFACE)
target_include_directories(wa_flightbox_internal INTERFACE src)
target_compile_definitions(wa_flightbox_internal INTERFACE ${WA_BACKEND_DEFINITION})
target_link_libraries(wa_flightbox_internal INTERFACE wa_flightbox ${WA_CRYPTO_LIBRARIES})

# TOOLS #

if(WA_BUILD_TOOLS)
    # Host hooks (operating system randomness and clock), and helpers shared by the tools
    add_library(wa_host_platform_hooks STATIC tools/wa_host_platform_hooks.c)
    target_link_libraries(wa_host_platform_hooks PUBLIC wa_flightbox)
    target_include_directories(wa_host_platform_hooks PUBLIC tools)
    if(WIN32)
        target_link_libraries(wa_host_platform_hooks PUBLIC bcrypt)
    endif()
    add_library(wa_tool_common STATIC tools/wa_tool_common.c)
    target_link_libraries(wa_tool_common PUBLIC wa_flightbox)
    target_include_directories(wa_tool_common PUBLIC tools)

    add_executable(wa_flightbox_encrypt_file_cli tools/wa_flightbox_encrypt_file_cli.c)
    target_link_libraries(wa_flightbox_encrypt_file_cli PRIVATE wa_host_platform_hooks wa_tool_common wa_flightbox)

    # The driver uses internal functions, and the deterministic hooks of the unit tests
    add_executable(wa_flightbox_test_driver tools/wa_flightbox_test_driver.c tests/unit/wa_test_support.c)
    target_include_directories(wa_flightbox_test_driver PRIVATE tests/unit)
    target_link_libraries(wa_flightbox_test_driver PRIVATE wa_host_platform_hooks wa_tool_common wa_flightbox_internal)

    foreach(tool_target wa_host_platform_hooks wa_tool_common wa_flightbox_encrypt_file_cli wa_flightbox_test_driver)
        target_compile_options(${tool_target} PRIVATE ${WA_STRICT_WARNING_FLAGS})
        set_target_properties(${tool_target} PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
        # Host tools use POSIX file, clock and randomness APIs beyond C99
        if(NOT WIN32)
            target_compile_definitions(${tool_target} PRIVATE _POSIX_C_SOURCE=200809L)
        endif()
    endforeach()
endif()

# UNIT TESTS #

if(BUILD_TESTING)
    add_subdirectory(tests/unit)
endif()

if(WA_BUILD_FUZZERS)
    add_subdirectory(tests/fuzz)
endif()
