# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate wa_wacbor_specification_vectors.h: the test vectors of §10 of docs/specifications/wa_cbor_document_format.md,
with the status the C sub-profile decoder must return for each (design D8), for tasks 3.5 and 3.7.

Every vector of the specification must be classified below: the script fails on an unknown one, so that new
vectors are never silently skipped.

Run from anywhere (no dependency beyond the standard library):
    python reimplementations/c-language/tests/unit/generate_wacbor_specification_vectors.py
"""

import json
import re
from pathlib import Path

SPECIFICATION_PATH = Path(__file__).resolve().parents[4].joinpath(
    "docs", "specifications", "wa_cbor_document_format.md"
)
OUTPUT_PATH = Path(__file__).with_name("wa_wacbor_specification_vectors.h")

# Valid WA-CBOR vectors inside the device profile sub-profile; every other valid vector is unsupported
ACCEPTED_VALID_VECTORS = {
    "empty_map",
    "empty_array",
    "simple_values",
    "text_strings",
    "byte_strings",
    "uuid",
    "map_keys_in_bytewise_order",
    "maximal_nesting_depth",
    "non_shortest_integer",
}
UNSUPPORTED_VALID_VECTORS = {
    "unsigned_integers",  # 18446744073709551615 is outside int64
    "negative_integers",  # -18446744073709551616 is outside int64
    "bignums",
    "floats_half_precision",
    "floats_single_and_double_precision",
    "floats_special",
    "datetime_utc_without_fraction",
    "datetime_with_offset",
    "datetime_with_negative_offset",
    "decimals",
    "decimal_with_bignum_mantissa",
    "cryptainer_like_map",  # Holds a float and a datetime
    "indefinite_map_with_unsorted_keys",
    "indefinite_array_and_chunked_strings",
    "non_shortest_float",
    "small_bignum",
    "self_described_cbor_tag_around_top_level_item",
    "datetime_with_one_fraction_digit",
    "datetime_with_lowercase_letters",
    "datetime_with_negative_zero_offset",
    "indefinite_decimal_fraction_array",
}

# Invalid vectors whose first offending item is a tag, float or indefinite length outside the sub-profile: rejected
# either as unsupported or as invalid (design D8: "a WA-CBOR tag whose content is malformed may be reported with
# either status")
EITHER_STATUS_INVALID_VECTORS = {
    "datetime_over_integer",
    "datetime_without_offset",
    "datetime_with_four_fraction_digits",
    "datetime_with_invalid_month",
    "decimal_with_bignum_exponent",
    "decimal_with_float_mantissa",
    "decimal_over_three_items",
    "bignum_over_text",
    "chunk_of_another_type_in_indefinite_text",
    "truncated_float",
}
NESTING_TOO_DEEP_INVALID_VECTORS = {"excessive_nesting_depth"}
DECODING_ERROR_INVALID_VECTORS = {
    "integer_map_key",
    "duplicate_map_key",
    "extended_json_keyword_map",
    "undefined",
    "simple_value_16",
    "simple_value_32",
    "epoch_datetime_tag_1",
    "unknown_tag_258",
    "nested_self_described_cbor_tag",
    "uuid_of_15_bytes",
    "uuid_over_text",
    "invalid_utf8",
    "utf8_encoded_surrogate",
    "indefinite_length_integer",
    "reserved_additional_information",
    "break_outside_indefinite_item",
    "array_count_beyond_data",
    "bytes_after_top_level_item",
    "scalar_top_level_item",
    "text_top_level_item",
    "empty_data",
}


def _to_c_string_literal(text: str) -> str:
    return '"%s"' % text.replace("\\", "\\\\").replace('"', '\\"').replace("?", "\\?")


def main():
    specification_text = SPECIFICATION_PATH.read_text(encoding="utf-8")
    match = re.search(r"^```json wa-cbor-test-vectors\n(.*?)^```", specification_text, re.MULTILINE | re.DOTALL)
    assert match, "No test vector block found in the WA-CBOR specification"
    test_vectors = json.loads(match.group(1))

    entries = []
    for vector in test_vectors["valid"]:
        name = vector["name"]
        if name in ACCEPTED_VALID_VECTORS:
            expectation = "WA_EXPECT_ACCEPTED"
        elif name in UNSUPPORTED_VALID_VECTORS:
            expectation = "WA_EXPECT_UNSUPPORTED"
        else:
            raise ValueError("Unclassified valid vector %r: add it to this script" % name)
        entries.append((name, vector["cbor_hex"], expectation, vector["deterministic"], vector["extjson"]))
    for vector in test_vectors["invalid"]:
        name = vector["name"]
        if name in DECODING_ERROR_INVALID_VECTORS:
            expectation = "WA_EXPECT_DECODING_ERROR"
        elif name in EITHER_STATUS_INVALID_VECTORS:
            expectation = "WA_EXPECT_UNSUPPORTED_OR_DECODING_ERROR"
        elif name in NESTING_TOO_DEEP_INVALID_VECTORS:
            expectation = "WA_EXPECT_NESTING_TOO_DEEP"
        else:
            raise ValueError("Unclassified invalid vector %r: add it to this script" % name)
        entries.append((name, vector["cbor_hex"], expectation, False, None))

    all_names = [entry[0] for entry in entries]
    classified_names = (
        ACCEPTED_VALID_VECTORS
        | UNSUPPORTED_VALID_VECTORS
        | EITHER_STATUS_INVALID_VECTORS
        | NESTING_TOO_DEEP_INVALID_VECTORS
        | DECODING_ERROR_INVALID_VECTORS
    )
    assert len(set(all_names)) == len(all_names)
    assert classified_names == set(all_names), classified_names ^ set(all_names)

    lines = [
        "/* This file is part of Witness Angel Cryptolib",
        " * SPDX-FileCopyrightText: Copyright Prolifik SARL",
        " * SPDX-License-Identifier: GPL-2.0-or-later",
        " */",
        "",
        "/* GENERATED by generate_wacbor_specification_vectors.py from section 10 of the WA-CBOR specification: do not edit. */",
        "",
        "#ifndef WA_WACBOR_SPECIFICATION_VECTORS_H",
        "#define WA_WACBOR_SPECIFICATION_VECTORS_H",
        "",
        "typedef enum wa_wacbor_vector_expectation {",
        "    WA_EXPECT_ACCEPTED,",
        "    WA_EXPECT_UNSUPPORTED,",
        "    WA_EXPECT_DECODING_ERROR,",
        "    WA_EXPECT_UNSUPPORTED_OR_DECODING_ERROR,",
        "    WA_EXPECT_NESTING_TOO_DEEP",
        "} wa_wacbor_vector_expectation_t;",
        "",
        "typedef struct wa_wacbor_specification_vector {",
        "    const char *name;",
        "    const char *cbor_hex;",
        "    wa_wacbor_vector_expectation_t expectation;",
        "    int is_deterministic;  /* Writers must re-encode the decoded tree to exactly cbor_hex */",
        "    const char *extjson;  /* For valid vectors, else NULL */",
        "} wa_wacbor_specification_vector_t;",
        "",
        "static const wa_wacbor_specification_vector_t wa_wacbor_specification_vectors[] = {",
    ]
    for name, cbor_hex, expectation, is_deterministic, extjson in entries:
        lines.append(
            '    {"%s", "%s", %s, %d, %s},'
            % (name, cbor_hex, expectation, int(is_deterministic), "NULL" if extjson is None else _to_c_string_literal(extjson))
        )
    lines += ["};", "", "#endif /* WA_WACBOR_SPECIFICATION_VECTORS_H */", ""]
    OUTPUT_PATH.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print("Written", OUTPUT_PATH, "with", len(entries), "vectors")


if __name__ == "__main__":
    main()
