# Vendored mlkem-native

| | |
|---|---|
| Project | mlkem-native (PQ Code Package), https://github.com/pq-code-package/mlkem-native |
| Version | v2.0.0 (commit `d1b2fe782888bdb761a50336012923180be7f502`) |
| Source archive | https://github.com/pq-code-package/mlkem-native/archive/refs/tags/v2.0.0.tar.gz |
| Archive SHA-256 | `76bf71771f09a25f30463218974ae10752d72bca34bbc470c7f6f8655f51d622` |
| Licence | Apache-2.0 OR ISC OR MIT (see `LICENSE`) |

## What is vendored

Unmodified copies of, from the archive's `mlkem/` directory:

- `mlkem_native.c` (the single compilation unit including every source) and `mlkem_native.h`;
- the portable C sources and headers of `src/` and `src/fips202/`, and `zetas.inc`;
- the two backend interface headers `src/native/api.h` and `src/fips202/native/api.h`. The native (assembly or
  intrinsics) backends themselves are left out: the build is pure C99 on every target.

Plus `LICENSE`, from the archive's root.

## Local files

- `wa_mlkem_native_config.h`: the configuration (`MLK_CONFIG_FILE`): ML-KEM-768 only, the `wa_mlkem_` namespace
  prefix, and only the deterministic encapsulation `wa_mlkem_enc_derand()` (no key generation, no decapsulation, no
  randomized API), with internal functions made `static`.
- `wa_mlkem_native_single_unit.c`: includes `mlkem/mlkem_native.c`, to be compiled with
  `-DMLK_CONFIG_FILE="wa_mlkem_native_config.h"` and this directory and `mlkem/` in the include path.

This is the release line embedded in pycryptodome 4.2, whose ML-KEM-768 output the interoperability tests compare
byte for byte with this build's. Only the Mbed TLS backend uses it: the wolfCrypt backend uses wolfCrypt's own ML-KEM.

## Updating

Extract the new release archive, copy the same files over these ones, update this table (version, commit, archive
SHA-256), check that `wa_mlkem_native_config.h` still uses valid options (`mlkem/mlkem_native_config.h` of the
release documents them), and rebuild with `-Werror`.
