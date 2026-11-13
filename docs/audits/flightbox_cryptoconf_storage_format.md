# Cryptoconf storage format for embedded and C flightbox implementations

Date: 2026-11-13. Status: audit, no code changed.
Scope: which format should replace "BSON" (in fact Extended JSON) to store
and transmit the cryptoconf, and the trustee public keys it needs, on
embedded flightboxes: the MicroPython port
(`reimplementations/micropython/`) and the C prototype of the sibling
`witness-angel-cryptolib-c` repository (ESP32, ESP-IDF). Complements
`../flightbox_specifications/flightbox_encryptor_specification.md`
(section 2 for serialization, section 5 for the cryptoconf grammar).

## Summary

- **The flightbox does not use BSON today.** It uses MongoDB Extended JSON
  (relaxed mode): plain JSON text in which bytes and UUIDs are wrapped as
  `{"$binary": ...}` and `{"$uuid": ...}`. Real BSON would be worse for C:
  field names repeated in every document, int32 length prefixes everywhere,
  and a heavy reference library (libbson).
- **Only the device-side input is free to change.** The cryptainer, and every
  intermediate structure encrypted on the way (symkeys, key structs,
  cipherdicts, shards), is Extended JSON, a format shared with every
  decryptor. A device therefore needs an Extended JSON *writer* in any case;
  a new cryptoconf format only removes the *parser* (and its base64 decoder),
  the costly half in C.
- **Trustee public keys belong in the same blob.** They are the binary-heavy
  part (256-byte RSA modulus, 32-byte X25519 keys), and the MicroPython demo
  keeps the RSA modulus as an integer, a number of about 617 digits in JSON,
  which most C JSON parsers can't read.
- **Recommendation: CBOR (RFC 8949) with a CDDL schema (RFC 8610)**, keeping
  the current string keys and data model, UUIDs as tag 37, and a COSE_Sign1
  envelope (RFC 9052) for integrity. **Alternative** for devices whose
  configuration is fixed per firmware build: a C header generated and
  validated at build time, with no format and no parser at all.

## 1. Terminology

Section 2 of the encryptor specification defines `dump_to_json_bytes()` as
the Extended JSON dialect of the `extjson` package: the JSON *representation*
of BSON types, not BSON itself. In this report "Extended JSON" means that
text format, and "BSON" the binary MongoDB format, which nothing in the
flightbox uses.

## 2. Current state

- **CPython** (`src/wacryptolib/cryptainer/`): cryptoconfs are Python dicts,
  validated upfront against `CRYPTOCONF_SCHEMA_PYTHON` (a JSON Schema export,
  `CRYPTOCONF_SCHEMA_JSON`, also exists). Cryptainers are written as
  Extended JSON.
- **MicroPython** (`reimplementations/micropython/`): the cryptoconf is
  a Python literal in `main.py`, and trustee public keys an in-memory dict
  `{keystore_uid: {keychain_uid: {"n": int, "e": int, "x25519": bytes}}}`.
  Extended JSON is written by the vendored `extjson` module.
- **C prototype** (`witness-angel-cryptolib-c`, a single commit): an early
  skeleton. `lib/cryptainer/CryptainerEncryptor.c` pulls in both cJSON and
  lwjson, and looks up `keychain_uid.$binary.base64`, a canonical UUID form
  that encoders no longer emit (UUIDs are now `{"$uuid": "<hex>"}`). Its
  "deep copy" of the cryptoconf casts the JSON `char*` to a struct pointer.
  There is little existing code to protect, so the format choice is open.

## 3. The deciding constraint

```
 provisioning (CPython / app)           device (C, MicroPython)                    desktop decryptor
 +---------------------------+          +--------------------------------+         +-----------------+
 | cryptoconf                |          | parse --> flightbox core       |         |                 |
 | + trustee public keys     |--fmt X-->|           |                    |--fmt Y->| parse cryptainer|
 +---------------------------+          |           v                    |         +-----------------+
                                        | J(symkey) J(key_struct)        |
                                        | J(cipherdict) J(shard)         |
                                        | cryptainer (embeds a copy of   |
                                        |   the whole cryptoconf tree)   |
                                        +--------------------------------+
   fmt X = device-local: free choice         fmt Y = Extended JSON, a protocol shared
                                             with every decryptor: costly to change
```

Two consequences:

1. **The Extended JSON writer stays.** Changing format X removes the parser
   and base64 decoder from the device, not the writer.
2. **The cryptoconf is copied into the cryptainer** (section 6.6 of the
   specification), then completed with key ciphertexts, MACs and signatures.
   Whatever format the device reads, it must write the tree back out as
   Extended JSON, so format X needs a clean mapping to the JSON data model.

The cryptoconf itself holds almost no binary data: only UUIDs
(`keychain_uid`, `keystore_uid`). Native binary types matter mostly for the
public keys, hence the "device profile" idea: one document holding the
cryptoconf and the public keys of its trustees.

## 4. Integrity, not secrecy

The cryptoconf and public keys stored on a device are not secret, but they
are integrity-critical: whoever can swap them substitutes their own trustee
key, and every later recording becomes readable by them. The format should
therefore allow a signed envelope, verified on the device against a
provisioning key. This favours formats with a standard signing container and
a defined deterministic encoding; JSON would need JWS plus canonicalization,
a known source of verification bugs.

## 5. Options

| | Extended JSON (today) | **CBOR (RFC 8949)** | MessagePack | Protobuf (nanopb) | FlatBuffers (flatcc) | C header generated at build time |
|---|---|---|---|---|---|---|
| C parsing without malloc | ok with jsmn/lwjson (token array) | yes (zcbor, QCBOR, NanoCBOR, TinyCBOR) | yes (mpack, cmp) | yes, but recursion is painful | zero-copy, read in place from flash | no parsing at all |
| Native bytes / UUID | no: base64 + wrappers | byte strings; UUID = tag 37 | bin; UUID needs a custom ext type | `bytes` | `[ubyte]` | anything |
| Recursive layers (shards, nested key layers) | natural | natural | natural | `oneof` + recursive messages, awkward in nanopb | supported | natural |
| Schema and validation | JSON Schema (`CRYPTOCONF_SCHEMA_JSON` exists) | CDDL (RFC 8610); zcbor generates C decoders from it | none | .proto | .fbs | Python validates before generating |
| Maps cleanly to JSON (for the copy in the cryptainer) | identity | yes, RFC 8949 section 6.1 | mostly | via field names | via reflection | the generator emits it |
| CPython / MicroPython | extjson / done | `cbor2` / micropython-lib `cbor2` | msgpack / limited | protobuf / weak | flatbuffers / heavy | no runtime needed |
| Signing envelope | JWS, with canonicalization problems | COSE_Sign1, CBOR-native, deterministic encoding defined | none standard | none standard | none | firmware signature |
| Change config without reflashing | yes | yes | yes | yes | yes | **no** |

## 6. Recommendation

**CBOR with a CDDL schema, keeping the current string keys and data model.**
In order of weight:

1. **Integrity**: COSE_Sign1 is a ready-made signed envelope for CBOR, with
   deterministic encoding defined in RFC 8949 section 4.2 (section 4).
2. **Same data model**: with string keys kept, `cbor2.loads()` returns the
   same dict, with real `uuid.UUID` objects, that `CRYPTOCONF_SCHEMA_PYTHON`
   already validates. The CPython side changes almost nothing, and the
   conversion to Extended JSON for the cryptainer copy is mechanical: byte
   string to `$binary`, tag 37 to `$uuid`.
3. **C side**: zcbor can generate a typed decoder from a CDDL description of
   the grammar of section 5.1 of the specification, which also gives upfront
   validation on the device. Byte strings remove base64 decoding and the
   parsing of big numbers.
4. **Size is not a reason**: a cryptoconf is a few hundred bytes. Integer
   keys, as in COSE, would save little and lose readability and the shared
   data model; they are not recommended.

**Alternative: a C header generated at build time.** If a device's
cryptoconf is fixed per firmware build, a Python tool can validate it and
emit a `const` C tree into flash: no parser, no allocation, no format to
maintain, and integrity covered by the firmware signature. The cost is that
changing the configuration in the field requires reflashing.

## 7. Open questions

- **How does a device receive its cryptoconf?** Flashed at build time,
  pushed by the authenticator app over BLE or serial, or over the air? Build
  time favours the generated header; anything arriving at runtime favours
  CBOR plus COSE_Sign1.
- **Is the cryptainer format in scope?** This report only covers the input.
  Moving the cryptainer to CBOR would be the bigger win (base64 adds a third
  to inline ciphertexts, and the device's JSON writer would disappear), but
  it is a breaking change of the on-disk format, shared with every
  decryptor, and deserves its own change.
- **Which C platform?** Zephyr has zcbor built in. ESP-IDF ships cJSON; an
  Espressif registry component wrapping TinyCBOR probably exists (not
  verified).
- **Single-pass C design**: a C encryptor could walk the cryptoconf once and
  write the cryptainer's Extended JSON as it goes, with no tree in RAM,
  writing each key ciphertext as an extra field right after its layer is
  processed (allowed, since byte-exact key order is not required, section 2
  of the specification). Payload MACs and signatures, added in step 3, would
  need placeholders or a second section. This works with either input
  format, but is much simpler with CBOR's length-prefixed items.

## 8. Verified and not verified

Verified:

- micropython-lib provides `cbor2` 1.0.0 on the mip index used by
  `vendor_dependencies.py` (`https://micropython.org/pi/v2`).
- CPython's `cbor2` encodes `uuid.UUID` as tag 37 (`d8 25`) followed by a
  16-byte string, and decodes it back to an equal `uuid.UUID`.
- The C prototype's state, as described in section 2.

Not verified:

- Whether micropython-lib's `cbor2` decodes tag 37 into a UUID, or returns a
  generic tag object (the device only needs the 16 bytes either way).
- The availability and size of a CBOR component for ESP-IDF.
- Code size and RAM figures of the C libraries on ESP32: none were measured.
