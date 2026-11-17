# WA-CBOR document format: specification

Status: normative specification of WA-CBOR, the CBOR dialect of wacryptolib documents, written 2026-11-16.

WA-CBOR is a profile of CBOR (RFC 8949) in which wacryptolib documents (cryptoconfs, cryptainers, cipherdicts,
signatures, keystore metadata...) can be stored, as an alternative to their Extended JSON form. Both formats carry
the same data model, so a document can be converted from one to the other, back and forth, without losing
information. This document is meant to let other implementations (the C and MicroPython ports, third-party tools)
read and write WA-CBOR exactly like wacryptolib.

Sources of truth (in this repository):

| Topic | File |
|---|---|
| WA-CBOR codec | `src/wacryptolib/utilities/wacbor.py` |
| Document file API and format recognition | `src/wacryptolib/utilities/document_utils.py` |
| Extended JSON | `extjson` package |
| Tests of the test vectors of section 10 | `tests/test_wacryptolib_utilities.py` |

The key words MUST, SHOULD and MAY are used in the RFC 2119 sense.

## 1. Data model

A document is a tree of the following values:

- maps, whose keys are text strings;
- arrays;
- text strings (sequences of Unicode scalar values, so without lone surrogates);
- integers, of any size;
- floating-point numbers (IEEE 754 binary64 values), including NaN, positive and negative infinity, and negative
  zero;
- booleans, and null;
- byte strings;
- UUIDs (16 bytes);
- datetimes with a UTC offset (timezone-aware), whose offset is a whole number of minutes, at millisecond precision;
- decimal numbers, made of a sign, a sequence of digits (the mantissa) and an exponent, all of them significant:
  `1.0` (mantissa 10, exponent -1) and `1.00` (mantissa 100, exponent -2) are distinct values.

The top-level item of a document MUST be a map or an array. Arrays have no tuple counterpart: in Python, tuples are
written as arrays, and load back as lists.

## 2. Type mapping

| Data model value | WA-CBOR encoding | Extended JSON equivalent (RELAXED form) |
|---|---|---|
| map | major type 5, text string keys | object |
| array | major type 4 | array |
| text string | major type 3 | string |
| integer in [-2^64, 2^64-1] | major type 0 (positive or zero) or 1 (negative) | number |
| integer outside that range | tag 2 (positive bignum) or tag 3 (negative bignum) over a byte string | number |
| float | major type 7, half, single or double precision | number, or `{"$numberDouble": "NaN" / "Infinity" / "-Infinity"}` |
| false, true, null | simple values 20, 21, 22 (`F4`, `F5`, `F6`) | `false`, `true`, `null` |
| byte string | major type 2, untagged | `{"$binary": {"base64": ..., "subType": "00"}}` |
| UUID | tag 37 over a byte string of exactly 16 bytes | `{"$uuid": <32 hex digits>}` (or `$binary` of subType 04) |
| datetime | tag 0 over a text string, see below | `{"$date": <the same text>}` (or `{"$date": {"$numberLong": <milliseconds>}}`) |
| decimal | tag 4 (decimal fraction) over `[exponent, mantissa]` | `{"$numberDecimal": <decimal text>}` |

Datetimes are written, in both formats, as the text `YYYY-MM-DDTHH:MM:SS[.fff]` followed by `Z` for a zero UTC offset,
or by `+HH:MM` / `-HH:MM` otherwise. The fraction has exactly three digits, and is present only when the datetime
has a non-zero sub-second part. Sub-millisecond precision is truncated, never rounded: a datetime with 123999
microseconds is written with the fraction `.123`, and one with 500 microseconds with the fraction `.000`.

Decimals are written with the exponent and the mantissa of the decimal itself, never normalized: `1.0` is
`[-1, 10]`, `1.00` is `[-2, 100]`, and `1E+3` is `[3, 1]`. The exponent is an integer of major type 0 or 1, and the
mantissa an integer of major type 0 or 1, or a bignum.

Bignums carry the magnitude as a big-endian byte string without leading zero bytes: tag 2 over `n` for a positive
integer `n`, and tag 3 over `-1 - n` for a negative integer `n`.

## 3. Generic item grammar (CDDL, RFC 8610)

```cddl
wa-cbor-document = document-root / #6.55799(document-root)
document-root = map-item / array-item

item = map-item / array-item / tstr / integer / float / bool / null
     / bstr / uuid / datetime / decimal

map-item = { * tstr => item }
array-item = [ * item ]

integer = int / bignum
bignum = #6.2(bstr) / #6.3(bstr)
uuid = #6.37(bstr .size 16)
datetime = #6.0(tstr)    ; text constrained as in section 2 and section 5
decimal = #6.4([exponent: int, mantissa: int / bignum])
```

The grammar does not express the following constraints, which are normative too:

- map keys are unique;
- a map with exactly one key, when that key is an Extended JSON keyword (`$binary`, `$uuid`, `$date`, `$numberInt`,
  `$numberLong`, `$numberDouble`, `$numberDecimal`, `$undefined`), is forbidden, since Extended JSON readers would
  load it as a typed value;
- arrays and maps are nested at most 64 levels deep, the top-level item having depth 1 (the array of a decimal
  fraction is not counted).

## 4. Encoding rules

Writers MUST produce the "core deterministic encoding" of RFC 8949 section 4.2.1:

- integers, lengths and tag numbers in their shortest form;
- definite lengths only;
- map keys sorted by the bytewise lexicographic order of their deterministic encodings (so shorter keys first, as
  all keys are text strings);
- floats in the shortest of the half (`F9`), single (`FA`) and double (`FB`) precision forms that preserves the
  value exactly, the sign of zero included; NaN is always written `F9 7E 00`, positive infinity `F9 7C 00`, and
  negative infinity `F9 FC 00`;
- integers outside [-2^64, 2^64-1] as bignums, the others never as bignums.

Writers MUST NOT emit the self-described CBOR tag 55799. Two equal trees therefore always give the same bytes,
whatever the insertion order of their map keys.

## 5. Decoding rules

Readers MUST accept any well-formed CBOR within the dialect, even if not deterministically encoded: indefinite-length
strings, arrays and maps, non-shortest integers, lengths and floats, unsorted map keys, and bignums of integers that
fit in major types 0 and 1. They MUST accept a single tag 55799 wrapping the top-level item.

Readers MUST reject the whole document, without returning a partial result, when it holds:

- a map key that is not a text string, or the same key twice in a map;
- `undefined` (simple value 23), or any simple value other than false, true and null;
- any tag other than 0, 2, 3, 4 and 37, in particular tag 1 (epoch-based datetime); and tag 55799 anywhere but
  around the top-level item;
- tag 37 over anything but a byte string of exactly 16 bytes;
- tag 0 over anything but a text string matching the RFC 3339 `date-time` production, with an offset, with at most
  three fraction digits, and with an offset whose hours are at most 23 (the letters `T` and `Z` may be lowercase,
  as RFC 3339 allows; the offset `-00:00` means UTC);
- tag 2 or 3 over anything but a byte string;
- tag 4 over anything but an array of exactly two items, whose exponent is an integer of major type 0 or 1, and
  whose mantissa is an integer of major type 0 or 1, or a bignum;
- invalid UTF-8 in a text string, including encoded surrogates (each chunk of an indefinite-length text string
  must be valid UTF-8 on its own);
- a chunk of an indefinite-length string which is not a definite-length string of the same major type;
- an indefinite length on an integer or a tag, a reserved additional information value (28 to 30), or a break code
  outside an indefinite-length item;
- a top-level item which is not a map nor an array, or bytes left over after the top-level item;
- a single-key map whose key is an Extended JSON keyword (section 3);
- arrays and maps nested more than 64 levels deep;
- a declared length or count exceeding the remaining data, or truncated data.

Datetimes read with one or two fraction digits are completed with zeros (`.1` is 100 milliseconds). As the
writers always use three digits, `Z` and uppercase letters, such documents are not written back identically.

## 6. Unsupported values

When writing WA-CBOR, and when converting a document between Extended JSON and WA-CBOR in either direction, the
following values MUST be rejected with an error, and nothing MUST be written. None of them is silently altered:

| Value | Reason |
|---|---|
| naive datetime (without UTC offset) | Extended JSON readers refuse them; an instant can't be inferred |
| datetime whose UTC offset has a seconds or sub-seconds part | the text form only has `±HH:MM` offsets |
| decimal NaN, signaling NaN, and infinities | tag 4 can't carry them |
| decimal negative zero (`-0`, `-0.00`...) | a mantissa of 0 has no sign |
| decimal whose exponent doesn't fit in [-2^64, 2^64-1] | the exponent must be of major type 0 or 1 |
| text string with lone surrogate code points | not encodable as UTF-8 |
| map key that is not a text string | Extended JSON object keys are strings |
| single-key map whose key is an Extended JSON keyword | it would load as a typed value from Extended JSON |
| arrays and maps nested more than 64 levels deep | readers refuse them |
| any value of a type outside the data model (sets, dates without time, byte arrays...) | no faithful encoding |

Sub-millisecond precision of datetimes is not an error: both formats truncate it to milliseconds, so they always
hold the same instant.

## 7. Bijection with Extended JSON

For every document of the data model holding no unsupported value:

- loading its Extended JSON dump and loading its WA-CBOR dump yield equal trees, with the same types at every
  position, the same datetime UTC offsets, and the same decimal digits and exponents;
- converting a WA-CBOR document written by a WA-CBOR writer to Extended JSON, then back to WA-CBOR, yields the
  identical bytes;
- converting an Extended JSON document written by wacryptolib's default JSON writer (RELAXED Extended JSON with
  sorted keys) to WA-CBOR, then back to Extended JSON, yields the identical bytes.

Extended JSON files are many-to-one with trees (CANONICAL and RELAXED forms, whitespace, key order, `$numberInt`
wrappers...), so a CANONICAL Extended JSON document converted to WA-CBOR and back comes out in the RELAXED form of
the same tree. The guarantee is about trees, and about the bytes of the default writers.

## 8. File format recognition

The format of a document file is given by its name, the following extensions being matched in any letter case:

| Name ending with | Format |
|---|---|
| `.json`, `.crypt.json` | Extended JSON |
| `.crypt` (legacy cryptainers) | Extended JSON |
| `.cbor`, `.crypt.cbor` | WA-CBOR |

For any other name (e.g. `01_simple.cryptoconf`, or a temporary cryptainer `x.crypt.cbor~`), or for a stream
without a name (STDIN), the format is detected from the first significant byte:

- after an optional UTF-8 byte order mark (`EF BB BF`) and JSON whitespace (space, tab, line feed, carriage return),
  `{` or `[` means Extended JSON;
- a first byte in the range `80`-`BF` (CBOR array or map), or the tag 55799 prefix `D9 D9 F7`, means WA-CBOR;
- anything else is an error.

These byte ranges don't overlap, so the detection is unambiguous for documents whose top-level item is a map or an
array. A file whose content is detected as the other format than the one given by its name MUST be refused, with an
error naming the file and both formats.

When writing a document file, the format is the one explicitly requested, or else the one given by a `.json` or
`.cbor` extension (in any letter case). An explicit format contradicting that extension, or the absence of both, is
an error, and nothing is written.

Cryptainer files are named `<basename>.crypt.json` (Extended JSON) or `<basename>.crypt.cbor` (WA-CBOR), with
lowercase suffixes; legacy `<basename>.crypt` cryptainers are always Extended JSON. Readers recognize these suffixes
in any letter case. Tools creating a file from a name typed by a user SHOULD lowercase such a trailing extension
(`Clip.CRYPT.JSON` becomes `Clip.crypt.json`), keeping the rest of the name as typed.

## 9. Relation to the C device profile

The device profile of the C flightbox encryptor (`docs/flightbox_specifications/flightbox_device_profile_specification.md`)
is a strict sub-profile of WA-CBOR: definite lengths only, no floats, no tag other than 37 (not even tag 55799 around
the top-level item), and integers within the signed 64-bit range. Every valid device profile is therefore a valid
WA-CBOR document, and its specification only needs to list these restrictions on top of this document. As writers
never emit tag 55799, the C decoder never meets it in files written by wacryptolib.

## 10. Test vectors

The machine-readable block below holds test vectors, checked by wacryptolib's test suite.

- Each `valid` vector gives CBOR bytes in hexadecimal (`cbor_hex`), and the document they decode to, as written by
  wacryptolib's default Extended JSON writer (`extjson`). Readers MUST decode `cbor_hex` to the tree of `extjson`.
  When `deterministic` is true, writers MUST also encode that tree to exactly `cbor_hex`, and the Extended JSON
  writer gives exactly `extjson` for the decoded tree. When it is false, the bytes are valid but not in
  deterministic encoding.
- Each `invalid` vector gives CBOR bytes that readers MUST reject. Its `reason` describes the rejection, and is a
  fragment of the error message of wacryptolib's reader.

Trees are compared with strict types: a float is never equal to an integer, datetimes must have the same UTC
offset, decimals the same digits and exponent, and NaN equals NaN.

```json wa-cbor-test-vectors
{
  "valid": [
    {"name": "empty_map", "deterministic": true, "cbor_hex": "a0", "extjson": "{}"},
    {"name": "empty_array", "deterministic": true, "cbor_hex": "80", "extjson": "[]"},
    {"name": "unsigned_integers", "deterministic": true, "cbor_hex": "8a0017181818ff19010019ffff1a000100001affffffff1b00000001000000001bffffffffffffffff", "extjson": "[0, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296, 18446744073709551615]"},
    {"name": "negative_integers", "deterministic": true, "cbor_hex": "862037381838ff3901003bffffffffffffffff", "extjson": "[-1, -24, -25, -256, -257, -18446744073709551616]"},
    {"name": "bignums", "deterministic": true, "cbor_hex": "83c249010000000000000000c349010000000000000000c24d10000000000000000000000000", "extjson": "[18446744073709551616, -18446744073709551617, 1267650600228229401496703205376]"},
    {"name": "floats_half_precision", "deterministic": true, "cbor_hex": "85f93e00f90000f98000f97bfff90001", "extjson": "[1.5, 0.0, -0.0, 65504.0, 5.960464477539063e-08]"},
    {"name": "floats_single_and_double_precision", "deterministic": true, "cbor_hex": "84fa47c35000fa7f7ffffffb3ff199999999999afb7e37e43c8800759c", "extjson": "[100000.0, 3.4028234663852886e+38, 1.1, 1e+300]"},
    {"name": "floats_special", "deterministic": true, "cbor_hex": "83f97e00f97c00f9fc00", "extjson": "[{\"$numberDouble\": \"NaN\"}, {\"$numberDouble\": \"Infinity\"}, {\"$numberDouble\": \"-Infinity\"}]"},
    {"name": "simple_values", "deterministic": true, "cbor_hex": "83f4f5f6", "extjson": "[false, true, null]"},
    {"name": "text_strings", "deterministic": true, "cbor_hex": "8560616162c3a963e6b0b464f09f9880", "extjson": "[\"\", \"a\", \"\\u00e9\", \"\\u6c34\", \"\\ud83d\\ude00\"]"},
    {"name": "byte_strings", "deterministic": true, "cbor_hex": "824044000102ff", "extjson": "[{\"$binary\": {\"base64\": \"\", \"subType\": \"00\"}}, {\"$binary\": {\"base64\": \"AAEC/w==\", \"subType\": \"00\"}}]"},
    {"name": "uuid", "deterministic": true, "cbor_hex": "81d825500123456789abcdef0123456789abcdef", "extjson": "[{\"$uuid\": \"0123456789abcdef0123456789abcdef\"}]"},
    {"name": "datetime_utc_without_fraction", "deterministic": true, "cbor_hex": "81c074323032362d30312d30325430333a30343a30355a", "extjson": "[{\"$date\": \"2026-01-02T03:04:05Z\"}]"},
    {"name": "datetime_with_offset", "deterministic": true, "cbor_hex": "81c0781d323032362d30312d30325430333a30343a30352e3132332b30323a3030", "extjson": "[{\"$date\": \"2026-01-02T03:04:05.123+02:00\"}]"},
    {"name": "datetime_with_negative_offset", "deterministic": true, "cbor_hex": "81c0781d313939392d31322d33315432333a35393a35392e3939392d30353a3330", "extjson": "[{\"$date\": \"1999-12-31T23:59:59.999-05:30\"}]"},
    {"name": "decimals", "deterministic": true, "cbor_hex": "86c482200ac482211864c48220387cc4820301c4820000c4822100", "extjson": "[{\"$numberDecimal\": \"1.0\"}, {\"$numberDecimal\": \"1.00\"}, {\"$numberDecimal\": \"-12.5\"}, {\"$numberDecimal\": \"1E+3\"}, {\"$numberDecimal\": \"0\"}, {\"$numberDecimal\": \"0.00\"}]"},
    {"name": "decimal_with_bignum_mantissa", "deterministic": true, "cbor_hex": "81c48220c34d0f951a9fa3a286c94f0e766c38", "extjson": "[{\"$numberDecimal\": \"-123456789012345678901234567890.5\"}]"},
    {"name": "map_keys_in_bytewise_order", "deterministic": true, "cbor_hex": "a4600461610261620162616103", "extjson": "{\"\": 4, \"a\": 2, \"aa\": 3, \"b\": 1}"},
    {"name": "maximal_nesting_depth", "deterministic": true, "cbor_hex": "81818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818180", "extjson": "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"},
    {"name": "cryptainer_like_map", "deterministic": true, "cbor_hex": "a66c6b6579636861696e5f756964d8255006a0b5c41e2f7a8b9c0d0000000000016e637279707461696e65725f756964d8255006a0b5c41e2f7a8b9c0d1e2f3a4b5c6d71637279707461696e65725f666f726d61746e637279707461696e65725f312e3073637279707461696e65725f6d65746164617461a265726174696ff938006763726561746564c074323032362d31312d31315431383a34303a30305a757061796c6f61645f6369706865725f6c617965727381a36e6b65795f6369706865727465787443102030737061796c6f61645f6369706865725f616c676f674145535f434243781d7061796c6f61645f636970686572746578745f7369676e6174757265738078197061796c6f61645f636970686572746578745f737472756374a173636970686572746578745f6c6f636174696f6e696f66666c6f61646564", "extjson": "{\"cryptainer_format\": \"cryptainer_1.0\", \"cryptainer_metadata\": {\"created\": {\"$date\": \"2026-11-11T18:40:00Z\"}, \"ratio\": 0.5}, \"cryptainer_uid\": {\"$uuid\": \"06a0b5c41e2f7a8b9c0d1e2f3a4b5c6d\"}, \"keychain_uid\": {\"$uuid\": \"06a0b5c41e2f7a8b9c0d000000000001\"}, \"payload_cipher_layers\": [{\"key_ciphertext\": {\"$binary\": {\"base64\": \"ECAw\", \"subType\": \"00\"}}, \"payload_cipher_algo\": \"AES_CBC\", \"payload_ciphertext_signatures\": []}], \"payload_ciphertext_struct\": {\"ciphertext_location\": \"offloaded\"}}"},
    {"name": "indefinite_map_with_unsorted_keys", "deterministic": false, "cbor_hex": "bf616201616102ff", "extjson": "{\"a\": 2, \"b\": 1}"},
    {"name": "indefinite_array_and_chunked_strings", "deterministic": false, "cbor_hex": "9f5f41014102ff7f61616162ffff", "extjson": "[{\"$binary\": {\"base64\": \"AQI=\", \"subType\": \"00\"}}, \"ab\"]"},
    {"name": "non_shortest_integer", "deterministic": false, "cbor_hex": "81190001", "extjson": "[1]"},
    {"name": "non_shortest_float", "deterministic": false, "cbor_hex": "81fb3ff8000000000000", "extjson": "[1.5]"},
    {"name": "small_bignum", "deterministic": false, "cbor_hex": "81c24101", "extjson": "[1]"},
    {"name": "self_described_cbor_tag_around_top_level_item", "deterministic": false, "cbor_hex": "d9d9f7a0", "extjson": "{}"},
    {"name": "datetime_with_one_fraction_digit", "deterministic": false, "cbor_hex": "81c076323032362d30312d30325430333a30343a30352e315a", "extjson": "[{\"$date\": \"2026-01-02T03:04:05.100Z\"}]"},
    {"name": "datetime_with_lowercase_letters", "deterministic": false, "cbor_hex": "81c074323032362d30312d30327430333a30343a30357a", "extjson": "[{\"$date\": \"2026-01-02T03:04:05Z\"}]"},
    {"name": "datetime_with_negative_zero_offset", "deterministic": false, "cbor_hex": "81c07819323032362d30312d30325430333a30343a30352d30303a3030", "extjson": "[{\"$date\": \"2026-01-02T03:04:05Z\"}]"},
    {"name": "indefinite_decimal_fraction_array", "deterministic": false, "cbor_hex": "81c49f2114ff", "extjson": "[{\"$numberDecimal\": \"0.20\"}]"}
  ],
  "invalid": [
    {"name": "integer_map_key", "cbor_hex": "a10102", "reason": "Map key is not a text string"},
    {"name": "duplicate_map_key", "cbor_hex": "a2616101616102", "reason": "Duplicate map key"},
    {"name": "extended_json_keyword_map", "cbor_hex": "81a16524757569646430313233", "reason": "Extended JSON keyword map"},
    {"name": "undefined", "cbor_hex": "81f7", "reason": "Unsupported simple value"},
    {"name": "simple_value_16", "cbor_hex": "81f0", "reason": "Unsupported simple value"},
    {"name": "simple_value_32", "cbor_hex": "81f820", "reason": "Unsupported simple value"},
    {"name": "epoch_datetime_tag_1", "cbor_hex": "81c11a5f5e1000", "reason": "Unsupported tag 1"},
    {"name": "unknown_tag_258", "cbor_hex": "81d9010280", "reason": "Unsupported tag 258"},
    {"name": "nested_self_described_cbor_tag", "cbor_hex": "81d9d9f701", "reason": "Unsupported tag 55799"},
    {"name": "uuid_of_15_bytes", "cbor_hex": "81d8254f000000000000000000000000000000", "reason": "Invalid UUID"},
    {"name": "uuid_over_text", "cbor_hex": "81d8256430313233", "reason": "Invalid content of tag 37"},
    {"name": "datetime_over_integer", "cbor_hex": "81c001", "reason": "Invalid content of tag 0"},
    {"name": "datetime_without_offset", "cbor_hex": "81c073323032362d30312d30325430333a30343a3035", "reason": "Invalid datetime text"},
    {"name": "datetime_with_four_fraction_digits", "cbor_hex": "81c07819323032362d30312d30325430333a30343a30352e313233345a", "reason": "Invalid datetime text"},
    {"name": "datetime_with_invalid_month", "cbor_hex": "81c074323032362d31332d30325430333a30343a30355a", "reason": "Invalid datetime text"},
    {"name": "decimal_with_bignum_exponent", "cbor_hex": "81c482c2410101", "reason": "Invalid decimal fraction exponent"},
    {"name": "decimal_with_float_mantissa", "cbor_hex": "81c48221f93c00", "reason": "Invalid decimal fraction mantissa"},
    {"name": "decimal_over_three_items", "cbor_hex": "81c483210101", "reason": "Invalid content of tag 4"},
    {"name": "bignum_over_text", "cbor_hex": "81c26131", "reason": "Invalid content of tag 2"},
    {"name": "invalid_utf8", "cbor_hex": "8162c328", "reason": "Invalid UTF-8"},
    {"name": "utf8_encoded_surrogate", "cbor_hex": "8163eda080", "reason": "Invalid UTF-8"},
    {"name": "chunk_of_another_type_in_indefinite_text", "cbor_hex": "817f4161ff", "reason": "Invalid chunk"},
    {"name": "indefinite_length_integer", "cbor_hex": "811f", "reason": "Invalid indefinite length"},
    {"name": "reserved_additional_information", "cbor_hex": "811c", "reason": "Reserved additional information"},
    {"name": "break_outside_indefinite_item", "cbor_hex": "81ff", "reason": "Unexpected break code"},
    {"name": "array_count_beyond_data", "cbor_hex": "8201", "reason": "exceeds the remaining data"},
    {"name": "truncated_float", "cbor_hex": "81fb3ff8", "reason": "Truncated"},
    {"name": "bytes_after_top_level_item", "cbor_hex": "a000", "reason": "Unexpected bytes after the top-level item"},
    {"name": "scalar_top_level_item", "cbor_hex": "01", "reason": "Top-level item is not a map nor an array"},
    {"name": "text_top_level_item", "cbor_hex": "6161", "reason": "Top-level item is not a map nor an array"},
    {"name": "empty_data", "cbor_hex": "", "reason": "Truncated"},
    {"name": "excessive_nesting_depth", "cbor_hex": "8181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818180", "reason": "Nesting depth"}
  ]
}
```
