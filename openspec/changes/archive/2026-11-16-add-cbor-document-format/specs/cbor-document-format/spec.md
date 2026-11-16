## Purpose

Defines WA-CBOR, the CBOR (RFC 8949) dialect in which wacryptolib documents can be stored as an alternative to Extended JSON. It covers the data model shared by both formats, the bijection between them, the encoding and decoding rules, the values that neither format can carry, and how a document file's format is recognized.

## ADDED Requirements

### Requirement: Shared document data model
The system SHALL define one document data model, shared by Extended JSON and WA-CBOR, made of: maps with text keys, arrays, text strings, integers of any size, floating-point numbers (including NaN, positive and negative infinity, and negative zero), booleans, null, byte strings, UUIDs, timezone-aware datetimes, and decimal numbers. The top-level item of a document SHALL be a map or an array. Tuples SHALL be written as arrays, and therefore load back as arrays (lists).

#### Scenario: Cryptainer loads to the same tree from both formats
- **WHEN** the same cryptainer is dumped to Extended JSON and to WA-CBOR, and both files are loaded
- **THEN** both loaded trees are equal, with the same value types at every position (bytes, UUIDs, datetimes, decimals, integers and floats are not confused with one another)

#### Scenario: Scalar top-level document refused
- **WHEN** a document whose top-level value is not a map nor an array is dumped to WA-CBOR, or a WA-CBOR file whose top-level item is not a map nor an array is loaded
- **THEN** an error is raised and nothing is written

### Requirement: WA-CBOR type mapping uses semantic tags
WA-CBOR SHALL encode each data model value with native CBOR types and standard semantic tags, never with Extended JSON `$`-wrapper maps:
- maps: major type 5, with text string keys only; arrays: major type 4; text strings: major type 3; booleans and null: simple values 20, 21, 22;
- integers: major types 0 and 1 when they fit, and tags 2 / 3 (bignums) otherwise;
- floats: major type 7;
- byte strings: major type 2, untagged;
- UUIDs: tag 37 over a byte string of exactly 16 bytes;
- datetimes: tag 0 over an RFC 3339 text string `YYYY-MM-DDTHH:MM:SS[.fff]` followed by `Z` for a zero UTC offset or `+HH:MM` / `-HH:MM` otherwise, where the fraction has exactly three digits and is present only when the datetime has a non-zero sub-second part;
- decimals: tag 4 (decimal fraction) over `[exponent, mantissa]`, keeping the decimal's own exponent and digits, without normalization.

#### Scenario: Bytes and UUIDs are native
- **WHEN** a map holding a byte string and a UUID is dumped to WA-CBOR
- **THEN** the byte string is encoded as an untagged CBOR byte string, the UUID as tag 37 over its 16 bytes, and the output contains no `$binary` nor `$uuid` key

#### Scenario: Datetime with offset
- **WHEN** the datetime 2026-01-02 03:04:05.123 at UTC+02:00 is dumped to WA-CBOR
- **THEN** it is encoded as tag 0 over the text `2026-01-02T03:04:05.123+02:00`, and loads back as an equal datetime with the same UTC offset

#### Scenario: Decimal keeps its exponent
- **WHEN** the decimals `1.0` and `1.00` are dumped to WA-CBOR and loaded back
- **THEN** they are encoded as tag 4 over `[-1, 10]` and `[-2, 100]`, and load back with the same digits and exponents as the originals

#### Scenario: Big integer
- **WHEN** an integer greater than 2^64 - 1 is dumped to WA-CBOR and loaded back
- **THEN** it is encoded as a tag 2 bignum, and loads back as the same integer

### Requirement: Deterministic WA-CBOR encoding
WA-CBOR writers SHALL produce the "core deterministic encoding" of RFC 8949 section 4.2.1: shortest-form integers and lengths, definite lengths only, map keys sorted by the bytewise order of their encodings, and floats in the shortest of the half, single and double precision forms that preserves the value. Writers SHALL NOT emit the self-described CBOR tag 55799.

#### Scenario: Same tree, same bytes
- **WHEN** two equal trees, whose maps were built with different key insertion orders, are dumped to WA-CBOR
- **THEN** both outputs are byte-identical

#### Scenario: Shortest float form
- **WHEN** the float `1.5` is dumped to WA-CBOR
- **THEN** it is encoded as a half-precision float, and loads back as the float `1.5`

### Requirement: Strict WA-CBOR decoding
WA-CBOR readers SHALL accept any well-formed CBOR within the dialect, even if not deterministically encoded (indefinite lengths, non-shortest forms, unsorted keys), and SHALL accept a single tag 55799 wrapping the top-level item. Readers SHALL reject, with an error that leaves no partial result:
- map keys that are not text strings, and duplicate map keys;
- `undefined` and simple values other than false, true and null;
- any tag other than 0, 2, 3, 4 and 37 (including tag 1, epoch-based datetime) and tag 55799 anywhere but around the top-level item;
- tag 37 over anything but a 16-byte byte string; tag 0 over a text that is not an RFC 3339 date-time with an offset, or that has more than three fraction digits; tag 4 whose exponent is not an integer of major type 0 or 1, or whose mantissa is not an integer or bignum;
- invalid UTF-8 in text strings, and bytes left over after the top-level item;
- a single-key map whose key is an Extended JSON keyword (`$binary`, `$uuid`, `$date`, `$numberInt`, `$numberLong`, `$numberDouble`, `$numberDecimal`, `$undefined`).

#### Scenario: Non-deterministic but valid input
- **WHEN** a WA-CBOR file uses an indefinite-length map and unsorted keys, but only allowed types
- **THEN** it loads successfully

#### Scenario: Epoch datetime refused
- **WHEN** a CBOR file contains a tag 1 datetime
- **THEN** loading fails with an error naming the unsupported tag

#### Scenario: Duplicate key refused
- **WHEN** a CBOR file contains a map with the same text key twice
- **THEN** loading fails

#### Scenario: Extended JSON keyword map refused
- **WHEN** a CBOR file contains the map `{"$uuid": "0123"}` as a value
- **THEN** loading fails, since that map would load as a UUID once converted to Extended JSON

### Requirement: Unsupported values are rejected, not altered
When writing WA-CBOR, and when converting a document between Extended JSON and WA-CBOR, the system SHALL raise an error, and write nothing, for any value outside the data model or that the target format cannot carry faithfully:
- naive datetimes, and datetimes whose UTC offset has a seconds or sub-seconds part;
- decimal NaN, signaling NaN and infinities, decimal negative zeros (e.g. `-0`, `-0.00`), and decimals whose exponent does not fit in a CBOR integer;
- text strings containing lone surrogate code points;
- map keys that are not text strings;
- single-key maps whose key is an Extended JSON keyword (listed in the strict decoding requirement);
- any value of a type outside the data model.
Sub-millisecond precision of datetimes SHALL be truncated (not rounded) to milliseconds by both the Extended JSON and the WA-CBOR writers, so that both formats always hold the same instant.

#### Scenario: Decimal NaN refused
- **WHEN** a document containing `Decimal("NaN")` is dumped to WA-CBOR
- **THEN** an error naming the unsupported value is raised, and no output is produced

#### Scenario: Keyword collision refused
- **WHEN** a document containing the map `{"$date": "not a date"}` is dumped to WA-CBOR
- **THEN** an error is raised, since that map is ambiguous in Extended JSON

#### Scenario: Microseconds truncated identically
- **WHEN** a datetime with 123999 microseconds is dumped to Extended JSON and to WA-CBOR
- **THEN** both outputs hold the fraction `.123`, and both files load back to equal datetimes

### Requirement: Bijection with Extended JSON
For every document of the data model that contains no unsupported value, loading its Extended JSON dump and loading its WA-CBOR dump SHALL yield equal trees, with the same types, the same datetime UTC offsets, and the same decimal digits and exponents. Converting a WA-CBOR document to Extended JSON and back SHALL yield the identical CBOR bytes when the original was deterministically encoded. Converting an Extended JSON document written by the library's default JSON writer to WA-CBOR and back SHALL yield the identical JSON bytes.

#### Scenario: Round-trip from CBOR
- **WHEN** a deterministically encoded WA-CBOR cryptainer is converted to Extended JSON, and the result converted back to WA-CBOR
- **THEN** the final bytes equal the original bytes

#### Scenario: Round-trip from library JSON
- **WHEN** a cryptoconf file dumped by the library's default JSON writer is converted to WA-CBOR and back to Extended JSON
- **THEN** the final bytes equal the original bytes

#### Scenario: Canonical Extended JSON normalizes
- **WHEN** a cryptainer stored in CANONICAL Extended JSON is converted to WA-CBOR and back to Extended JSON
- **THEN** the result is the RELAXED Extended JSON form of the same tree, and loads to a tree equal to the original's

### Requirement: Document file format recognition
When reading a document file, the system SHALL determine its format from its name: names ending with `.json` or with the legacy cryptainer suffix `.crypt` are Extended JSON, and names ending with `.cbor` are WA-CBOR, these extensions being matched in any letter case, on every platform. For any other name, or for a stream without a name, it SHALL detect the format from the first significant byte: after an optional UTF-8 byte order mark and JSON whitespace, `{` or `[` means Extended JSON; a first byte in the range 0x80-0xBF (CBOR array or map), or the tag 55799 prefix `D9 D9 F7`, means WA-CBOR; anything else is an error. A file whose content contradicts the format given by its name SHALL be refused with an error naming the file and both formats. When writing a document file, the system SHALL use the format explicitly requested, or else the format given by a `.json` or `.cbor` extension, matched the same way, and SHALL write the file at the exact path given. An explicit format contradicting that extension, or the absence of both, SHALL raise an error, and nothing SHALL be written.

#### Scenario: Corpus asset without format extension
- **WHEN** an Extended JSON cryptoconf named `01_simple.cryptoconf` is read
- **THEN** it is detected and loaded as Extended JSON

#### Scenario: Extension in another letter case
- **WHEN** an Extended JSON cryptoconf named `CONF.JSON` is read
- **THEN** it is loaded as Extended JSON, as given by its extension, on every platform

#### Scenario: CBOR read from STDIN
- **WHEN** a WA-CBOR cryptoconf is piped to a command reading the cryptoconf from STDIN
- **THEN** it is detected and loaded as WA-CBOR

#### Scenario: Mislabeled file refused
- **WHEN** a file named `conf.json` contains WA-CBOR bytes
- **THEN** reading it fails with an error naming the file, the format expected from its name and the format detected

### Requirement: Library API for both formats
The library SHALL provide public functions to dump a document to WA-CBOR bytes and load it back, and to dump and load document files in either format, the format being chosen by file extension, detected as specified above, or explicitly requested. The existing Extended JSON functions SHALL keep their behaviour.

#### Scenario: Dump a file in the format of its extension
- **WHEN** a cryptoconf is dumped to `conf.cbor` with the generic file function, without an explicit format
- **THEN** the file holds WA-CBOR, and the generic load function returns an equal cryptoconf

#### Scenario: No format for a written file
- **WHEN** a cryptoconf is dumped with the generic file function to `conf.data`, without an explicit format
- **THEN** an error is raised, and no file is created

#### Scenario: Dump to an extension in another letter case
- **WHEN** a cryptoconf is dumped with the generic file function to `conf.CBOR`, without an explicit format
- **THEN** the file `conf.CBOR` holds WA-CBOR, on every platform

### Requirement: Normative dialect specification in the repository
The repository SHALL contain a normative specification of WA-CBOR, usable by other implementations, giving the data model, the type mapping table with its Extended JSON equivalents, a CDDL (RFC 8610) description of the generic item grammar, the deterministic encoding and strict decoding rules, the unsupported values, the file format recognition rules, and hex test vectors covering each data model type and each rejection case. The library's test suite SHALL check every test vector of that specification.

#### Scenario: Test vectors stay in sync
- **WHEN** the library's WA-CBOR encoding of a test vector differs from the hex given in the specification
- **THEN** the test suite fails, naming the vector
