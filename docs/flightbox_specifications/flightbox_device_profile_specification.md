# Flightbox device profile: specification

Status: normative specification of the flightbox device profile, format `flightbox_device_profile_1.0`, written
2026-11-17.

A **device profile** provisions an embedded flightbox encryptor, such as the C library of
`reimplementations/c-language/`. It is a single binary document holding the cryptoconf to apply and the raw public
keys of the trustees it references, so that the device can create cryptainers without parsing Extended JSON, PEM
files or keystores.

A device profile is a WA-CBOR document (`docs/specifications/wa_cbor_document_format.md`, referred to below as "the
WA-CBOR specification"), restricted to a sub-profile that small decoders can handle. Every rule that this document
does not restrict is the one of the WA-CBOR specification. The cryptoconf grammar and the cryptographic rules are
those of the flightbox encryptor specification (`docs/flightbox_specifications/flightbox_encryptor_specification.md`,
referred to below as "the encryptor specification").

The key words MUST, SHOULD and MAY are used in the RFC 2119 sense.

Sources of truth (in this repository):

| Topic | File |
|---|---|
| Export from CPython | `scripts/flightbox/export_device_profile.py` |
| C decoder | `reimplementations/c-language/src/encoding/wa_wacbor_subprofile_decoder.c`, `wa_device_profile_decoding.c` |
| Tests of exported profiles | `tests/test_flightbox_device_profile_export.py` |

## 1. WA-CBOR sub-profile

A device profile MUST only contain the following items:

- definite-length maps with text-string keys, and definite-length arrays;
- byte strings, and text strings that are valid UTF-8, without encoded surrogates;
- integers of major types 0 and 1, within the signed 64-bit range [-2^63, 2^63-1];
- `false`, `true` and `null`;
- tag 37 over a byte string of exactly 16 bytes (UUIDs).

Every UUID (`keychain_uid`, `keystore_uid`) MUST be such a tag 37 item, never a text string, and every binary value
MUST be a byte string, never base64 text.

Decoders MUST reject, as **invalid**, everything that WA-CBOR readers reject (section 5 of the WA-CBOR specification),
for the same reasons: non-text or duplicate map keys, simple values other than false/true/null, tags other than those
of WA-CBOR, tag 37 over anything but 16 bytes, invalid UTF-8, reserved additional information values, stray break
codes, truncated items or lengths beyond the data, a top-level item that is neither a map nor an array, bytes after
the top-level item, a single-key map whose key is an Extended JSON keyword (`$binary`, `$uuid`, `$date`, `$numberInt`,
`$numberLong`, `$numberDouble`, `$numberDecimal`, `$undefined`), and arrays and maps nested more than 64 levels deep,
the top-level item having depth 1.

Decoders MUST reject, as **unsupported**, the valid WA-CBOR items outside the sub-profile:

- floats (major type 7, additional information 25 to 27);
- tags 0 (datetimes), 2 and 3 (bignums) and 4 (decimals);
- indefinite lengths;
- tag 55799, even around the top-level item;
- integers outside the signed 64-bit range.

A WA-CBOR tag whose content is malformed (e.g. tag 0 over an integer) MAY be reported as either: it is rejected either
way. Decoders MAY accept the non-shortest heads and unsorted map keys that WA-CBOR readers accept. Every profile that a
conforming decoder accepts therefore loads with wacryptolib's `load_from_cbor_bytes()`, to the same tree.

Decoders MAY use a lower nesting limit than 64, to save stack, as long as it accepts the profiles they are provisioned
with (the profiles exported from the compatibility corpus nest 11 to 13 levels deep).

## 2. Root map

The top-level item MUST be a map with exactly these three text-string keys:

| Key | Value |
|---|---|
| `device_profile_format` | the text string `flightbox_device_profile_1.0` |
| `cryptoconf` | a cryptoconf map (section 3) |
| `trustee_public_keys` | an array of public key entries (section 4), possibly empty |

Any other value of `device_profile_format`, or its absence, MUST be rejected as an unsupported format. Any other root
key MUST be rejected as invalid. Later versions of the format will use another `device_profile_format` value.

## 3. Cryptoconf

`cryptoconf` follows the cryptoconf grammar of section 5.1 of the encryptor specification, with the same text-string
keys and the same case-sensitive algorithm names, and is validated by the rules of its section 5.2 (the cryptoconf
schema of wacryptolib: unknown keys rejected, non-empty `payload_cipher_layers` and `key_cipher_layers` lists,
`1 <= key_shared_secret_threshold <= len(key_shared_secret_shards)`, the legacy `payload_signatures` key accepted as
an alias of `payload_ciphertext_signatures`, a payload layer with both keys rejected). On top of these rules:

- the cryptoconf MUST have a root `keychain_uid`. A device can't use keys provisioned in advance for a keychain uid
  generated at encryption time;
- every asymmetric key cipher layer MUST resolve to exactly one public key entry (section 4), through its own
  `keychain_uid`, or else the root one;
- the output fields of cryptainers (`key_ciphertext`, `key_ciphertext_format`, `payload_macs`...) are not allowed, like
  any unknown key.

Encryptors MAY support only a subset of the grammar, and MUST then reject the profiles using the rest with an
unsupported-feature error when the profile is loaded. The C encryptor of `reimplementations/c-language/` rejects
non-empty signature lists (`payload_plaintext_signatures`, `payload_ciphertext_signatures`, `payload_signatures`), and
`jsonrpc_api` trustees can't be resolved by the export script (section 7).

## 4. Trustee public key entries

Each entry of `trustee_public_keys` is a map with exactly the keys `trustee`, `keychain_uid`, `key_algo` and
`public_key`:

| Key | Value |
|---|---|
| `trustee` | a trustee map, with the grammar of the cryptoconf |
| `keychain_uid` | a UUID |
| `key_algo` | `RSA_OAEP`, `ECIES_X25519` or `ML_KEM_768` |
| `public_key` | the raw public key, encoded as below |

Raw public key encodings:

| `key_algo` | `public_key` |
|---|---|
| `RSA_OAEP` | a map with exactly the keys `modulus` and `public_exponent`, both unsigned big-endian byte strings without leading zero bytes |
| `ECIES_X25519` | a 32-byte byte string: the RFC 7748 u-coordinate, little-endian |
| `ML_KEM_768` | a 1184-byte byte string: the FIPS 203 encapsulation key |

**Trustee identity.** An entry matches an asymmetric layer when their trustee identities, keychain uids and key algos
are equal. The trustee identity is:

- for `authenticator` trustees, `trustee_type` plus `keystore_uid`;
- for `jsonrpc_api` trustees, `trustee_type` plus `jsonrpc_url`;
- for `local_keyfactory` trustees, `trustee_type` alone.

`keystore_owner` is informative and never part of the identity: a layer and an entry whose `keystore_owner` differ
still match. The tuple (trustee identity, `keychain_uid`, `key_algo`) MUST be unique among the entries.

**Local keyfactory.** For a `local_keyfactory` trustee, the entry holds a key pre-provisioned from the local
keyfactory of the machine that will decrypt the cryptainers, typically the one that exported the profile. The device
never generates keypairs, unlike CPython encryptors, which create missing local keyfactory keys on demand.

**Unused entries.** Entries that no layer of the cryptoconf uses MUST be accepted and ignored, so that a provisioning
tool can ship a key bundle shared by several cryptoconfs. They MUST still be well-formed and satisfy section 5.

## 5. Public key constraints

A device profile MUST only be accepted if every public key respects the constraints of section 11.2 of the encryptor
specification, tightened so that all implementations accept exactly the same keys, whatever their crypto backend:

- RSA: modulus of at least 2048 bits, and at most a maximum configurable by the implementation, 4096 bits by default;
  odd modulus; `3 <= e < n`, with `e` odd.
- X25519: canonical u-coordinate, so the most significant bit of the last byte is clear and u < p = 2^255 - 19. The
  low-order points are rejected: 0, 1, the two points of order 8 (`e0eb7a7c...` and `5f9c95bc...` of RFC 7748), and
  p - 1. As non-canonical encodings are rejected, u + p and u + 2p never need to be checked.
- ML-KEM-768: encapsulation key of 1184 bytes whose 768 decoded 12-bit coefficients are all below 3329 (the modulus
  check of FIPS 203, section 7.2).

Keys exported by wacryptolib always satisfy these constraints.

## 6. File naming and integrity

Device profile files MUST have a name ending with `.cbor`, written in lowercase by tools that create them (e.g.
`frontcam.device_profile.cbor`), so that wacryptolib recognizes their format (section 8 of the WA-CBOR specification).
A device profile is an ordinary WA-CBOR document: `flightbox convert-format frontcam.device_profile.cbor` turns it into
readable Extended JSON for review, and converting that file back gives the identical bytes when the profile was
written in the deterministic encoding.

**Warning: device profiles are not authenticated.** Whoever can replace a device profile can replace the trustees'
public keys, and read every cryptainer created afterwards. Devices MUST store their profile where only authorized
provisioning can write it (e.g. a read-only or secure-boot-protected partition). Signing profiles (e.g. with
COSE_Sign1, which the deterministic encoding of WA-CBOR makes straightforward) is left to a later version of the
format.

## 7. Export from CPython

`scripts/flightbox/export_device_profile.py` builds a device profile from a cryptoconf file, in Extended JSON or
WA-CBOR, and a filesystem keystore pool:

```
PYTHONPATH=src python scripts/flightbox/export_device_profile.py CRYPTOCONF_FILE KEYSTORE_POOL_DIR -o NAME.cbor [--force]
```

It validates the cryptoconf with wacryptolib, requires a root `keychain_uid`, gathers the public key of every
asymmetric layer from the pool's local keyfactory or imported authenticator keystores (refusing `jsonrpc_api`
trustees), converts each to its raw form, and writes one entry per distinct (trustee identity, keychain uid, key algo),
with `dump_to_cbor_bytes()`. The same cryptoconf and pool therefore always give the same bytes, whichever the format of
the cryptoconf file. Trustee maps of the entries are copied from the first layer using them. On any error, it exits
with a non-zero status and writes nothing; it refuses to overwrite an existing file unless `--force` is given.

## 8. CDDL

The CDDL (RFC 8610) below is normative. It describes the trees of section 2 to 4, with the default RSA maximum of
4096 bits; the rules of sections 1 and 5 that CDDL can't express (sub-profile items, uniqueness, nesting depth, key
resolution, thresholds against shard counts, key arithmetic) are normative too. It was checked with `pycddl` 0.6.4
(Python bindings of `cddl-rs`), which also validates the profiles exported from the compatibility corpus against it.
Two limitations of `cddl-rs` 0.6.4 shaped it, without changing what it means: choices of maps used as array items
are written inline (`[+ (a / b)]`), since a named choice there is only tried with its first alternative; and maps
used as array items are not checked as closed, so `pycddl` accepts unlisted keys in them (for instance both
`payload_ciphertext_signatures` and `payload_signatures` in a payload cipher layer, or an extra key in a public key
entry). Such documents are still invalid, and the encryptor rejects them.

```cddl
device-profile = {
  "device_profile_format": "flightbox_device_profile_1.0",
  "cryptoconf": cryptoconf,
  "trustee_public_keys": public-key-entries,
}

uuid = #6.37(bstr .size 16)

; Cryptoconf (section 5.1 of the encryptor specification), with a mandatory root keychain uid

cryptoconf = {
  "payload_cipher_layers": [+ payload-cipher-layer],
  "keychain_uid": uuid,
  ? "payload_plaintext_signatures": [* signature-conf],
}

payload-cipher-layer = {
  "payload_cipher_algo": symmetric-cipher-algo,
  "key_cipher_layers": key-cipher-layers,
  payload-ciphertext-signatures,
}

; The legacy key "payload_signatures" is an alias, never present along with the current one
payload-ciphertext-signatures = (
  "payload_ciphertext_signatures": [* signature-conf] //
  "payload_signatures": [* signature-conf]
)

; Choices of maps inside arrays are written inline, since cddl-rs only tries the first alternative of a named
; choice there
key-cipher-layers = [+ (asymmetric-key-cipher-layer / symmetric-key-cipher-layer / shared-secret-key-cipher-layer)]

asymmetric-key-cipher-layer = {
  "key_cipher_algo": asymmetric-cipher-algo,
  "key_cipher_trustee": trustee,
  ? "keychain_uid": uuid,
}

symmetric-key-cipher-layer = {
  "key_cipher_algo": symmetric-cipher-algo,
  "key_cipher_layers": key-cipher-layers,
}

shared-secret-key-cipher-layer = {
  "key_cipher_algo": "[SHARED_SECRET]",
  "key_shared_secret_threshold": uint .ge 1,   ; and at most the number of shards
  "key_shared_secret_shards": [+ shared-secret-shard],
}

shared-secret-shard = {
  "key_cipher_layers": key-cipher-layers,
}

signature-conf = {
  "payload_digest_algo": "SHA256" / "SHA512" / "SHA3_256" / "SHA3_512",
  "payload_signature_algo": "RSA_PSS" / "DSA_DSS" / "ECC_DSS" / "ML_DSA_65",
  "payload_signature_trustee": trustee,
  ? "keychain_uid": uuid,
}

symmetric-cipher-algo = "AES_CBC" / "AES_EAX" / "CHACHA20_POLY1305"
asymmetric-cipher-algo = "RSA_OAEP" / "ECIES_X25519" / "ML_KEM_768"

trustee = local-keyfactory-trustee / authenticator-trustee / jsonrpc-api-trustee

local-keyfactory-trustee = {
  "trustee_type": "local_keyfactory",
}

authenticator-trustee = {
  "trustee_type": "authenticator",
  "keystore_uid": uuid,
  ? "keystore_owner": tstr,
}

jsonrpc-api-trustee = {
  "trustee_type": "jsonrpc_api",
  "jsonrpc_url": tstr,
}

; Public key entries (section 4)

public-key-entries = [* (rsa-oaep-public-key-entry / ecies-x25519-public-key-entry / ml-kem-768-public-key-entry)]

rsa-oaep-public-key-entry = {
  public-key-entry-identity,
  "key_algo": "RSA_OAEP",
  "public_key": {
    "modulus": bstr .size (256..512),         ; 2048 to 4096 bits, big-endian, no leading zero byte
    "public_exponent": bstr .size (1..512),   ; big-endian, no leading zero byte
  },
}

ecies-x25519-public-key-entry = {
  public-key-entry-identity,
  "key_algo": "ECIES_X25519",
  "public_key": bstr .size 32,
}

ml-kem-768-public-key-entry = {
  public-key-entry-identity,
  "key_algo": "ML_KEM_768",
  "public_key": bstr .size 1184,
}

public-key-entry-identity = (
  "trustee": trustee,
  "keychain_uid": uuid,
)
```
