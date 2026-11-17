# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Helpers building flightbox device profiles for tests, valid or deliberately broken.

The export script (scripts/flightbox/export_device_profile.py) validates its inputs, so negative tests use these
helpers instead:

- build_raw_device_profile(): a raw cryptoconf -> profile converter with no validation at all, which adds a root
  keychain uid and the public keys the asymmetric layers need, so that only the rule targeted by a test fires;
- encode_cbor_item(): a small CBOR encoder, giving the same bytes as wacryptolib's dump_to_cbor_bytes() for
  ordinary trees, but also able to write what WA-CBOR forbids or what is outside the device profile sub-profile
  (duplicate keys, indefinite lengths, floats, arbitrary tags, Extended JSON keyword maps, raw bytes);
- mutators returning profile bytes with one targeted change (text UUIDs, unknown or duplicate keys, wrong key
  sizes, non-canonical or low-order X25519 keys, short or long RSA keys...);
- splice_cryptoconf_item(): places an arbitrary CBOR item as the profile's "cryptoconf" value, byte for byte;
- strip_signatures(): turns a signed cryptoconf into a signature-free one.

Paths inside trees are tuples of map keys and array indices, e.g. ("cryptoconf", "payload_cipher_layers", 0).
"""

import copy
import importlib.util
import math
import struct
import uuid
from functools import lru_cache
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
COMPATIBILITY_ROOT = REPOSITORY_ROOT / "compatibility"
EXPORT_SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "flightbox" / "export_device_profile.py"

DEVICE_PROFILE_FORMAT = "flightbox_device_profile_1.0"
SHARED_SECRET_ALGO_MARKER = "[SHARED_SECRET]"
ASYMMETRIC_KEY_ALGOS = ("RSA_OAEP", "ECIES_X25519", "ML_KEM_768")

# Root keychain uid added by the converter to cryptoconfs lacking one
DEFAULT_ROOT_KEYCHAIN_UID = uuid.UUID("0d0d0d0d-0000-4000-8000-000000000001")

X25519_FIELD_PRIME = 2**255 - 19
ML_KEM_MODULUS = 3329

# Low-order X25519 u-coordinates other than 0, 1 and p - 1: the two points of order 8
X25519_ORDER_8_POINTS = (
    325606250916557431795983626356110631294008115727848805560023387167927233504,
    39382357235489614581723060781553021112529911719440698176882885853963445705823,
)

UUID_TAG = 37
SELF_DESCRIBED_CBOR_TAG = 55799


@lru_cache(maxsize=None)
def import_export_script():
    """Import scripts/flightbox/export_device_profile.py as a module (it is not part of a package)."""
    spec = importlib.util.spec_from_file_location("export_device_profile", EXPORT_SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# CBOR ENCODING #


class RawMap:
    """A map given as a list of (key, value) pairs, written in that order, duplicates and non-text keys included."""

    def __init__(self, pairs):
        self.pairs = list(pairs)


class Indefinite:
    """An array, map, byte string or text string written with an indefinite length.

    Strings are written as a single chunk unless `chunks` is given."""

    def __init__(self, value, chunks=None):
        self.value = value
        self.chunks = chunks


class Tagged:
    """Any tag over any item."""

    def __init__(self, tag, value):
        self.tag = tag
        self.value = value


class RawCbor:
    """Bytes inserted as is, which may be any CBOR item, or not CBOR at all."""

    def __init__(self, data: bytes):
        self.data = bytes(data)


class Float:
    """A float of a given width (16, 32 or 64 bits), so that its exact head is chosen."""

    def __init__(self, value, width=64):
        assert width in (16, 32, 64)
        self.value = value
        self.width = width


def _encode_head(major_type, argument, out):
    initial = major_type << 5
    if argument < 24:
        out.append(initial | argument)
    elif argument < 0x100:
        out += bytes([initial | 24, argument])
    elif argument < 0x10000:
        out += struct.pack(">BH", initial | 25, argument)
    elif argument < 0x100000000:
        out += struct.pack(">BI", initial | 26, argument)
    else:
        out += struct.pack(">BQ", initial | 27, argument)


def _encode_text_bytes(text: str) -> bytes:
    return text.encode("utf-8")


def _encode_map_key(key) -> bytes:
    out = bytearray()
    _encode_item(key, out)
    return bytes(out)


def _encode_item(value, out):
    if value is None:
        out.append(0xF6)
    elif value is True:
        out.append(0xF5)
    elif value is False:
        out.append(0xF4)
    elif isinstance(value, RawCbor):
        out += value.data
    elif isinstance(value, Tagged):
        _encode_head(6, value.tag, out)
        _encode_item(value.value, out)
    elif isinstance(value, Float):
        if math.isnan(value.value) and value.width == 16:
            out += b"\xf9\x7e\x00"
        else:
            code, struct_format = {16: (25, ">e"), 32: (26, ">f"), 64: (27, ">d")}[value.width]
            out.append(0xE0 | code)
            out += struct.pack(struct_format, value.value)
    elif isinstance(value, float):
        _encode_item(Float(value, 64), out)
    elif isinstance(value, Indefinite):
        inner = value.value
        if isinstance(inner, (bytes, str)):
            major_type = 2 if isinstance(inner, bytes) else 3
            out.append((major_type << 5) | 31)
            chunks = value.chunks if value.chunks is not None else [inner]
            for chunk in chunks:
                data = chunk if isinstance(chunk, bytes) else _encode_text_bytes(chunk)
                _encode_head(major_type, len(data), out)
                out += data
        elif isinstance(inner, (list, tuple)):
            out.append(0x9F)
            for item in inner:
                _encode_item(item, out)
        else:
            assert isinstance(inner, (dict, RawMap)), inner
            out.append(0xBF)
            for encoded_key, item in _get_encoded_map_pairs(inner):
                out += encoded_key
                _encode_item(item, out)
        out.append(0xFF)
    elif isinstance(value, str):
        data = _encode_text_bytes(value)
        _encode_head(3, len(data), out)
        out += data
    elif isinstance(value, (bytes, bytearray)):
        _encode_head(2, len(value), out)
        out += value
    elif isinstance(value, int):
        if value >= 0:
            _encode_head(0, value, out)
        else:
            _encode_head(1, -1 - value, out)
    elif isinstance(value, uuid.UUID):
        _encode_head(6, UUID_TAG, out)
        _encode_head(2, 16, out)
        out += value.bytes
    elif isinstance(value, (list, tuple)):
        _encode_head(4, len(value), out)
        for item in value:
            _encode_item(item, out)
    elif isinstance(value, (dict, RawMap)):
        pairs = _get_encoded_map_pairs(value)
        _encode_head(5, len(pairs), out)
        for encoded_key, item in pairs:
            out += encoded_key
            _encode_item(item, out)
    else:
        raise TypeError("Can't encode %r" % (value,))


def _get_encoded_map_pairs(value):
    if isinstance(value, RawMap):  # Order and duplicates kept
        return [(_encode_map_key(key), item) for key, item in value.pairs]
    return sorted(((_encode_map_key(key), item) for key, item in value.items()), key=lambda pair: pair[0])


def encode_cbor_item(value) -> bytes:
    """Encode a tree, sorting the keys of plain dicts like WA-CBOR's deterministic encoding, and the helper
    wrappers (RawMap, Indefinite, Tagged, RawCbor, Float) as they say."""
    out = bytearray()
    _encode_item(value, out)
    return bytes(out)


# TREE ACCESS #


def get_value_at_path(tree, path):
    for step in path:
        tree = tree[step]
    return tree


def replace_value_at_path(tree, path, new_value):
    """Return a deep copy of `tree` whose value at `path` is `new_value` (which may be a helper wrapper)."""
    assert path, "Empty path"
    tree = copy.deepcopy(tree)
    parent = get_value_at_path(tree, path[:-1])
    if isinstance(parent, dict):
        assert path[-1] in parent, "No key %r at %r" % (path[-1], path[:-1])
    parent[path[-1]] = new_value
    return tree


def iter_uuid_paths(tree, path=()):
    """Yield the paths of every UUID of a tree."""
    if isinstance(tree, uuid.UUID):
        yield path
    elif isinstance(tree, dict):
        for key, value in tree.items():
            yield from iter_uuid_paths(value, path + (key,))
    elif isinstance(tree, (list, tuple)):
        for index, value in enumerate(tree):
            yield from iter_uuid_paths(value, path + (index,))


# RAW CRYPTOCONF -> PROFILE CONVERSION #


def _iter_key_cipher_layers_leniently(key_cipher_layers, path):
    """Yield (path, layer) of every asymmetric layer, skipping whatever is malformed."""
    if not isinstance(key_cipher_layers, list):
        return
    for index, layer in enumerate(key_cipher_layers):
        layer_path = path + (index,)
        if not isinstance(layer, dict):
            continue
        key_cipher_algo = layer.get("key_cipher_algo")
        if key_cipher_algo == SHARED_SECRET_ALGO_MARKER:
            shards = layer.get("key_shared_secret_shards")
            for shard_index, shard in enumerate(shards if isinstance(shards, list) else []):
                if isinstance(shard, dict):
                    yield from _iter_key_cipher_layers_leniently(
                        shard.get("key_cipher_layers"),
                        layer_path + ("key_shared_secret_shards", shard_index, "key_cipher_layers"),
                    )
        elif key_cipher_algo in ASYMMETRIC_KEY_ALGOS:
            yield layer_path, layer
        elif "key_cipher_layers" in layer:
            yield from _iter_key_cipher_layers_leniently(layer["key_cipher_layers"], layer_path + ("key_cipher_layers",))


def iter_asymmetric_key_cipher_layers_leniently(cryptoconf):
    """Yield (path inside the cryptoconf, layer) of every asymmetric key cipher layer of a possibly invalid
    cryptoconf, in depth-first order."""
    payload_cipher_layers = cryptoconf.get("payload_cipher_layers") if isinstance(cryptoconf, dict) else None
    for index, payload_cipher_layer in enumerate(payload_cipher_layers if isinstance(payload_cipher_layers, list) else []):
        if isinstance(payload_cipher_layer, dict):
            yield from _iter_key_cipher_layers_leniently(
                payload_cipher_layer.get("key_cipher_layers"), ("payload_cipher_layers", index, "key_cipher_layers")
            )


@lru_cache(maxsize=None)
def get_synthetic_raw_public_key(key_algo):
    """Return the raw public key, as stored in device profiles, of a keypair generated once per algorithm.

    ML_KEM_768 requires the pycryptodome backend."""
    from wacryptolib.keygen import generate_keypair

    keypair = generate_keypair(key_algo=key_algo)
    return import_export_script().convert_public_key_pem_to_raw(keypair["public_key"], key_algo=key_algo)


def _get_trustee_identity_leniently(trustee):
    if not isinstance(trustee, dict):
        return ("<invalid>", repr(trustee))
    trustee_type = trustee.get("trustee_type")
    if trustee_type == "authenticator":
        return (trustee_type, repr(trustee.get("keystore_uid")))
    if trustee_type == "jsonrpc_api":
        return (trustee_type, repr(trustee.get("jsonrpc_url")))
    return (repr(trustee_type),)


def build_raw_device_profile(
    cryptoconf,
    add_root_keychain_uid=True,
    add_public_keys=True,
    raw_public_keys=None,
    extra_entries=(),
):
    """Return the device profile tree of a raw cryptoconf, without any validation.

    - a root keychain uid (DEFAULT_ROOT_KEYCHAIN_UID) is added if missing, unless `add_root_keychain_uid` is False;
    - one public key entry is added per distinct (trustee identity, keychain uid, key algo) of the asymmetric layers
      found, with the raw key of `raw_public_keys[key_algo]` or else a synthetic one, unless `add_public_keys` is
      False; malformed layers get an entry if they have a trustee map and a known algorithm;
    - `extra_entries` are appended to the entries.

    The cryptoconf is deep-copied, so the result can be modified freely."""
    cryptoconf = copy.deepcopy(cryptoconf)
    if add_root_keychain_uid and isinstance(cryptoconf, dict) and "keychain_uid" not in cryptoconf:
        cryptoconf["keychain_uid"] = DEFAULT_ROOT_KEYCHAIN_UID
    root_keychain_uid = cryptoconf.get("keychain_uid") if isinstance(cryptoconf, dict) else None

    trustee_public_keys = []
    if add_public_keys:
        seen_key_identifiers = set()
        for _layer_path, layer in iter_asymmetric_key_cipher_layers_leniently(cryptoconf):
            trustee = layer.get("key_cipher_trustee")
            if not isinstance(trustee, dict):
                continue
            key_algo = layer["key_cipher_algo"]
            keychain_uid = layer.get("keychain_uid") or root_keychain_uid
            key_identifier = (_get_trustee_identity_leniently(trustee), repr(keychain_uid), key_algo)
            if key_identifier in seen_key_identifiers:
                continue
            seen_key_identifiers.add(key_identifier)
            raw_public_key = (raw_public_keys or {}).get(key_algo) or get_synthetic_raw_public_key(key_algo)
            trustee_public_keys.append(
                dict(
                    trustee=copy.deepcopy(trustee),
                    keychain_uid=keychain_uid,
                    key_algo=key_algo,
                    public_key=copy.deepcopy(raw_public_key),
                )
            )
    trustee_public_keys.extend(copy.deepcopy(list(extra_entries)))

    return dict(
        device_profile_format=DEVICE_PROFILE_FORMAT,
        cryptoconf=cryptoconf,
        trustee_public_keys=trustee_public_keys,
    )


def dump_device_profile(device_profile) -> bytes:
    """Encode a profile tree with wacryptolib's deterministic WA-CBOR writer (which rejects non-WA-CBOR trees)."""
    from wacryptolib.utilities import dump_to_cbor_bytes

    return dump_to_cbor_bytes(device_profile)


def strip_signatures(cryptoconf):
    """Return a copy of a cryptoconf without any signature: no root payload_plaintext_signatures, and empty
    payload_ciphertext_signatures lists (legacy payload_signatures lists being renamed)."""
    cryptoconf = copy.deepcopy(cryptoconf)
    cryptoconf.pop("payload_plaintext_signatures", None)
    for payload_cipher_layer in cryptoconf["payload_cipher_layers"]:
        payload_cipher_layer.pop("payload_signatures", None)
        payload_cipher_layer["payload_ciphertext_signatures"] = []
    return cryptoconf


# PROFILE MUTATORS, each returning the bytes of a profile with one targeted change #


def mutate_value(device_profile, path, new_value) -> bytes:
    """Profile bytes with the value at `path` replaced (by a plain value or a helper wrapper)."""
    return encode_cbor_item(replace_value_at_path(device_profile, path, new_value))


def mutate_uuid_to_text(device_profile, path) -> bytes:
    """Profile bytes with the UUID at `path` written as its canonical text form."""
    value = get_value_at_path(device_profile, path)
    assert isinstance(value, uuid.UUID), value
    return mutate_value(device_profile, path, str(value))


def mutate_add_key(device_profile, map_path, key="unexpected_key", value=0) -> bytes:
    """Profile bytes with an unknown key added to the map at `map_path`."""
    tree = copy.deepcopy(device_profile)
    target = get_value_at_path(tree, map_path)
    assert isinstance(target, dict) and key not in target
    target[key] = value
    return encode_cbor_item(tree)


def mutate_remove_key(device_profile, map_path, key) -> bytes:
    """Profile bytes without the `key` of the map at `map_path`."""
    tree = copy.deepcopy(device_profile)
    del get_value_at_path(tree, map_path)[key]
    return encode_cbor_item(tree)


def mutate_duplicate_key(device_profile, map_path, key, duplicate_value=None) -> bytes:
    """Profile bytes where the map at `map_path` holds `key` twice, the second time with `duplicate_value`
    (by default the same value)."""
    target = get_value_at_path(device_profile, map_path)
    assert isinstance(target, dict) and key in target
    pairs = sorted(target.items(), key=lambda pair: _encode_map_key(pair[0]))
    pairs.append((key, target[key] if duplicate_value is None else duplicate_value))
    return mutate_value(device_profile, map_path, RawMap(pairs)) if map_path else encode_cbor_item(RawMap(pairs))


def mutate_keyword_map(device_profile, path, keyword="$binary", keyword_value="AAAA") -> bytes:
    """Profile bytes with the value at `path` replaced by a single-key Extended JSON keyword map."""
    return mutate_value(device_profile, path, RawMap([(keyword, keyword_value)]))


def mutate_indefinite_length(device_profile, path, chunks=None) -> bytes:
    """Profile bytes with the array, map or string at `path` written with an indefinite length (the top-level
    map if `path` is empty)."""
    if not path:
        return encode_cbor_item(Indefinite(device_profile))
    return mutate_value(device_profile, path, Indefinite(get_value_at_path(device_profile, path), chunks=chunks))


def mutate_float(device_profile, path, value=1.0, width=64) -> bytes:
    """Profile bytes with a float at `path`."""
    return mutate_value(device_profile, path, Float(value, width))


def mutate_tag(device_profile, path, tag, tagged_value=None) -> bytes:
    """Profile bytes with the value at `path` wrapped in `tag` (or replaced by `tagged_value` under that tag)."""
    value = get_value_at_path(device_profile, path) if tagged_value is None else tagged_value
    return mutate_value(device_profile, path, Tagged(tag, value))


def mutate_self_described(device_profile) -> bytes:
    """Profile bytes prefixed by the self-described CBOR tag 55799."""
    return encode_cbor_item(Tagged(SELF_DESCRIBED_CBOR_TAG, device_profile))


def splice_cryptoconf_item(device_profile, cbor_item: bytes) -> bytes:
    """Profile bytes whose "cryptoconf" value is exactly `cbor_item`, which may be any bytes."""
    return mutate_value(device_profile, ("cryptoconf",), RawCbor(cbor_item))


def find_public_key_entry_index(device_profile, key_algo, occurrence=0):
    indices = [i for i, entry in enumerate(device_profile["trustee_public_keys"]) if entry["key_algo"] == key_algo]
    return indices[occurrence]


def mutate_public_key(device_profile, entry_index, public_key) -> bytes:
    """Profile bytes with the public key of entry `entry_index` replaced."""
    return mutate_value(device_profile, ("trustee_public_keys", entry_index, "public_key"), public_key)


def encode_x25519_public_key(u_coordinate: int, set_high_bit=False) -> bytes:
    """Little-endian 32-byte encoding of an X25519 u-coordinate, optionally with its unused top bit set."""
    data = bytearray((u_coordinate % 2**256).to_bytes(32, "little"))
    if set_high_bit:
        data[31] |= 0x80
    return bytes(data)


def get_low_order_x25519_public_keys():
    """Encodings of the low-order X25519 points: 0, 1, the two points of order 8, and p - 1."""
    return [encode_x25519_public_key(u) for u in (0, 1) + X25519_ORDER_8_POINTS + (X25519_FIELD_PRIME - 1,)]


def get_non_canonical_x25519_public_keys(valid_public_key: bytes):
    """Non-canonical encodings: a valid key with its top bit set, then p and p + 1 (u >= p)."""
    return [
        encode_x25519_public_key(int.from_bytes(valid_public_key, "little"), set_high_bit=True),
        encode_x25519_public_key(X25519_FIELD_PRIME),
        encode_x25519_public_key(X25519_FIELD_PRIME + 1),
    ]


def make_rsa_public_key(modulus_bits, public_exponent=65537, even_modulus=False):
    """Raw RSA public key with a modulus of exactly `modulus_bits` bits, odd unless `even_modulus`.

    The modulus is not a product of primes: key constraints only look at sizes and parities."""
    modulus = (1 << (modulus_bits - 1)) | 0x5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A
    modulus = modulus & ~1 if even_modulus else modulus | 1
    return dict(
        modulus=modulus.to_bytes((modulus_bits + 7) // 8, "big"),
        public_exponent=public_exponent.to_bytes(max(1, (public_exponent.bit_length() + 7) // 8), "big"),
    )


def set_ml_kem_coefficient(public_key: bytes, coefficient_index: int, coefficient: int) -> bytes:
    """Return an ML-KEM-768 encapsulation key with one 12-bit coefficient of its t vector replaced (the last
    32 bytes, the rho seed, never hold coefficients)."""
    assert len(public_key) == 1184 and 0 <= coefficient_index < 768 and 0 <= coefficient < 4096
    data = bytearray(public_key)
    offset = (coefficient_index // 2) * 3
    if coefficient_index % 2 == 0:
        data[offset] = coefficient & 0xFF
        data[offset + 1] = (data[offset + 1] & 0xF0) | (coefficient >> 8)
    else:
        data[offset + 1] = (data[offset + 1] & 0x0F) | ((coefficient & 0x0F) << 4)
        data[offset + 2] = coefficient >> 4
    return bytes(data)


def get_ml_kem_coefficient(public_key: bytes, coefficient_index: int) -> int:
    offset = (coefficient_index // 2) * 3
    if coefficient_index % 2 == 0:
        return public_key[offset] | ((public_key[offset + 1] & 0x0F) << 8)
    return (public_key[offset + 1] >> 4) | (public_key[offset + 2] << 4)
