# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Fails if the library defines a symbol starting with one of the FORBIDDEN_PREFIXES (";"-separated), e.g. the
# Extended JSON writer in a CBOR-only build (task 3.6).
#   cmake -DNM=<nm> -DLIBRARY=<libwa_flightbox.a> -DFORBIDDEN_PREFIXES=<prefixes> -P check_library_symbols.cmake

execute_process(COMMAND "${NM}" "${LIBRARY}" OUTPUT_VARIABLE symbol_listing RESULT_VARIABLE nm_result)
if(NOT nm_result EQUAL 0)
    message(FATAL_ERROR "${NM} failed on ${LIBRARY}")
endif()
string(REPLACE "\n" ";" symbol_lines "${symbol_listing}")
set(defined_symbol_count 0)
foreach(symbol_line IN LISTS symbol_lines)
    # Defined symbols: "<address> <type> <name>", undefined ones have no address
    if(symbol_line MATCHES "^[0-9a-fA-F]+ [A-Za-z] ([A-Za-z0-9_.]+)$")
        set(symbol_name "${CMAKE_MATCH_1}")
        math(EXPR defined_symbol_count "${defined_symbol_count} + 1")
        foreach(prefix IN LISTS FORBIDDEN_PREFIXES)
            string(FIND "${symbol_name}" "${prefix}" prefix_position)
            if(prefix_position EQUAL 0)
                message(FATAL_ERROR "Forbidden symbol ${symbol_name} (prefix ${prefix}) in ${LIBRARY}")
            endif()
        endforeach()
    endif()
endforeach()
if(defined_symbol_count LESS 10)
    message(FATAL_ERROR "Too few symbols read from ${LIBRARY}: is ${NM} working?")
endif()
message(STATUS "${defined_symbol_count} defined symbols, none starting with: ${FORBIDDEN_PREFIXES}")
