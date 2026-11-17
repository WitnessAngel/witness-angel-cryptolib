# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Unit tests: one executable per test file, registered in CTest.

add_library(wa_test_support STATIC wa_test_support.c wa_test_value_notation.c wa_test_document_reader.c
    wa_test_device_profile_samples.c)
target_include_directories(wa_test_support PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(wa_test_support PUBLIC wa_flightbox_internal)
target_compile_options(wa_test_support PRIVATE ${WA_STRICT_WARNING_FLAGS})
set_target_properties(wa_test_support PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)

function(wa_add_unit_test test_name)
    add_executable(${test_name} ${test_name}.c ${ARGN})
    target_link_libraries(${test_name} PRIVATE wa_test_support wa_flightbox_internal)
    target_compile_options(${test_name} PRIVATE ${WA_STRICT_WARNING_FLAGS})
    set_target_properties(${test_name} PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

# The public API compiles alone (only the umbrella header, no internal include path)
add_executable(test_wa_public_headers_compile test_wa_public_headers_compile.c)
target_include_directories(test_wa_public_headers_compile PRIVATE "${PROJECT_SOURCE_DIR}/include")
target_compile_definitions(test_wa_public_headers_compile PRIVATE
    WA_DOCUMENT_FORMAT_JSON_ENABLED=${WA_DOCUMENT_FORMAT_JSON_ENABLED}
    WA_DOCUMENT_FORMAT_CBOR_ENABLED=${WA_DOCUMENT_FORMAT_CBOR_ENABLED})
target_compile_options(test_wa_public_headers_compile PRIVATE ${WA_STRICT_WARNING_FLAGS})
set_target_properties(test_wa_public_headers_compile PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_test(NAME test_wa_public_headers_compile COMMAND test_wa_public_headers_compile)

# The harness itself: a passing sample, and a deliberately failing check that must make the test fail
wa_add_unit_test(test_wa_test_harness_sample)
add_executable(test_wa_test_harness_deliberate_failure test_wa_test_harness_deliberate_failure.c)
target_link_libraries(test_wa_test_harness_deliberate_failure PRIVATE wa_test_support)
target_compile_options(test_wa_test_harness_deliberate_failure PRIVATE ${WA_STRICT_WARNING_FLAGS})
add_test(NAME test_wa_test_harness_deliberate_failure COMMAND test_wa_test_harness_deliberate_failure)
set_tests_properties(test_wa_test_harness_deliberate_failure PROPERTIES WILL_FAIL TRUE)

# Encoding layer
if(CMAKE_NM)
    # Single-format builds carry no code of the other format's writer
    set(wa_forbidden_symbol_prefixes "")
    if(NOT WA_DOCUMENT_FORMAT_JSON_ENABLED)
        list(APPEND wa_forbidden_symbol_prefixes wa_extended_json_ wa_base64_)
    endif()
    if(NOT WA_DOCUMENT_FORMAT_CBOR_ENABLED)
        list(APPEND wa_forbidden_symbol_prefixes wa_wacbor_deterministic_writer_)
    endif()
    if(wa_forbidden_symbol_prefixes)
        string(REPLACE ";" "\;" wa_forbidden_symbol_prefixes_argument "${wa_forbidden_symbol_prefixes}")
        add_test(NAME test_wa_library_symbols_of_disabled_formats
            COMMAND "${CMAKE_COMMAND}" "-DNM=${CMAKE_NM}" "-DLIBRARY=$<TARGET_FILE:wa_flightbox>"
                "-DFORBIDDEN_PREFIXES=${wa_forbidden_symbol_prefixes_argument}"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/check_library_symbols.cmake")
    endif()
endif()
wa_add_unit_test(test_wa_growable_byte_buffer)
wa_add_unit_test(test_wa_value_tree)
wa_add_unit_test(test_wa_document_writers)
wa_add_unit_test(test_wa_document_serialization)
wa_add_unit_test(test_wa_wacbor_subprofile_decoder)

# Crypto backend and portable primitives
wa_add_unit_test(test_wa_crypto_backend_conformance)

# A crypto library configuration missing a required option fails the build with an error naming it (task 4.4): the
# adapter is compiled, in a target excluded from "all", with MBEDTLS_CHACHAPOLY_C or WOLFSSL_AES_COUNTER undefined
if(NOT WA_USE_SYSTEM_CRYPTO_LIBRARIES)
    set(wa_option_check_dir "${CMAKE_CURRENT_BINARY_DIR}/wa_missing_option_check")
    if(WA_CRYPTO_BACKEND STREQUAL "MBEDTLS")
        set(wa_removed_option MBEDTLS_CHACHAPOLY_C)
        # Included by Mbed TLS after our configuration file
        file(WRITE "${wa_option_check_dir}/wa_option_removing_config.h"
            "#undef ${wa_removed_option}\n")
    else()
        set(wa_removed_option WOLFSSL_AES_COUNTER)
        # Found before the user_settings.h shim of the real build
        file(WRITE "${wa_option_check_dir}/user_settings.h"
            "#include \"${WA_CONFIG_DIR}/wa_wolfssl_user_settings_for_flightbox.h\"\n"
            "#undef ${wa_removed_option}\n")
    endif()
    add_library(wa_backend_adapter_without_required_option OBJECT EXCLUDE_FROM_ALL
        "${PROJECT_SOURCE_DIR}/${WA_BACKEND_SOURCE}")
    target_link_libraries(wa_backend_adapter_without_required_option PRIVATE wa_flightbox_internal)
    if(WA_CRYPTO_BACKEND STREQUAL "MBEDTLS")
        target_compile_definitions(wa_backend_adapter_without_required_option PRIVATE
            "MBEDTLS_USER_CONFIG_FILE=\"${wa_option_check_dir}/wa_option_removing_config.h\"")
    else()
        target_include_directories(wa_backend_adapter_without_required_option BEFORE PRIVATE "${wa_option_check_dir}")
    endif()
    add_test(NAME test_wa_crypto_backend_missing_option_names_it
        COMMAND "${CMAKE_COMMAND}" --build "${PROJECT_BINARY_DIR}" --target wa_backend_adapter_without_required_option)
    # Passes only on the adapter's #error message (whatever the exit code, which a successful build would not print)
    set_tests_properties(test_wa_crypto_backend_missing_option_names_it PROPERTIES
        PASS_REGULAR_EXPRESSION "error: [^\n]*backend requires [^\n]*${wa_removed_option}")
endif()
wa_add_unit_test(test_wa_symmetric_primitives)
wa_add_unit_test(test_wa_asymmetric_primitives)
wa_add_unit_test(test_wa_shamir_and_uuid)
wa_add_unit_test(test_wa_public_key_constraints)

# Profile loading, validation and core
wa_add_unit_test(test_wa_cryptoconf_validation)
wa_add_unit_test(test_wa_device_profile_loading)
wa_add_unit_test(test_wa_cryptainer_creation)
wa_add_unit_test(test_wa_robustness)

# Host tools
if(TARGET wa_host_platform_hooks)
    wa_add_unit_test(test_wa_host_platform_hooks)
    target_link_libraries(test_wa_host_platform_hooks PRIVATE wa_host_platform_hooks)
    if(NOT WIN32)
        target_compile_definitions(test_wa_host_platform_hooks PRIVATE _POSIX_C_SOURCE=200809L)
    endif()
endif()

# The minimal example of README.md, extracted from between its markers at configure time, compiles and runs
set(wa_readme_path "${PROJECT_SOURCE_DIR}/README.md")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${wa_readme_path}")
file(READ "${wa_readme_path}" wa_readme_text)
string(REGEX MATCH "<!-- minimal-example-begin -->\r?\n```c\r?\n(.*)```\r?\n<!-- minimal-example-end -->"
    wa_readme_example_match "${wa_readme_text}")
if(NOT wa_readme_example_match)
    message(FATAL_ERROR "No minimal example found between the markers of ${wa_readme_path}")
endif()
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wa_readme_minimal_example/wa_readme_minimal_example.c" "${CMAKE_MATCH_1}")
wa_add_unit_test(test_wa_readme_minimal_example)
target_include_directories(test_wa_readme_minimal_example PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/wa_readme_minimal_example")
