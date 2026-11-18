# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Differential test of cryptoconf validation: seeded random mutations of every valid corpus cryptoconf having a root
keychain uid (signatures stripped), each turned into a device profile (with a public key for every asymmetric layer
found), loaded by the C driver and checked by wacryptolib's check_cryptoconf_sanity().

- Arbitrary mutations (removed, added or replaced entries, emptied lists, other algorithm names): whatever the C
  loader accepts, wacryptolib accepts too, the C encryptor implementing a subset of wacryptolib.
- Mutations staying within the C subset (other supported algorithms, valid thresholds, layer keychain uids, extra
  symmetric key layers within the nesting cap, removed redundant layers): both accept.
"""

import copy
import random
import uuid

import pytest

from c_flightbox_interop_support import get_valid_corpus_cryptoconfs, load_corpus_cryptoconf, profile_helpers

C_SYMMETRIC_CIPHER_ALGOS = ("AES_CBC", "AES_EAX", "CHACHA20_POLY1305")
C_ASYMMETRIC_CIPHER_ALGOS = ("RSA_OAEP", "ECIES_X25519", "ML_KEM_768")
SHARED_SECRET_ALGO_MARKER = "[SHARED_SECRET]"
C_MAXIMUM_KEY_CIPHER_NESTING_LEVEL = 8  # Default compile-time cap of the tested builds
ARBITRARY_MUTATION_COUNT = 60
SUBSET_MUTATION_COUNT = 15

OTHER_ALGO_NAMES = ("AES_GCM", "RSA_PSS", "DSA_DSS", "ECC_DSS", "ML_DSA_65", "SHA256", "aes_cbc", "AES_CBC ", "")
ODD_VALUES = (
    None, True, False, 0, 1, -1, 2, 7, 2**63 - 1, -(2**63), "", "x", "keychain_uid", b"", b"\x00" * 16,
    uuid.UUID(int=0), uuid.UUID("0e0e0e0e-0000-4000-8000-000000000001"), [], [{}], {}, {"trustee_type": "local_keyfactory"},
)


def _get_base_cryptoconfs():
    """{name: cryptoconf} of the valid corpus cryptoconfs having a root keychain uid, signatures stripped."""
    base_cryptoconfs = {}
    for name, relative_path in get_valid_corpus_cryptoconfs():
        cryptoconf = load_corpus_cryptoconf(relative_path)[0]
        if cryptoconf.get("keychain_uid"):
            base_cryptoconfs[name] = profile_helpers.strip_signatures(cryptoconf)
    return base_cryptoconfs


BASE_CRYPTOCONFS = _get_base_cryptoconfs()


# TREE HELPERS #


def _iter_paths(tree, path=()):
    """Yield (path, value) of every item of a tree, the root included."""
    yield path, tree
    if isinstance(tree, dict):
        for key, value in tree.items():
            yield from _iter_paths(value, path + (key,))
    elif isinstance(tree, list):
        for index, value in enumerate(tree):
            yield from _iter_paths(value, path + (index,))


def _get_parent_and_key(tree, path):
    return profile_helpers.get_value_at_path(tree, path[:-1]), path[-1]


def _iter_key_cipher_layer_lists(cryptoconf):
    """Yield (path, list, nesting level) of every key_cipher_layers list, the ones of payload layers at level 1."""

    def _walk(key_cipher_layers, path, level):
        yield path, key_cipher_layers, level
        for index, layer in enumerate(key_cipher_layers):
            if layer["key_cipher_algo"] == SHARED_SECRET_ALGO_MARKER:
                for shard_index, shard in enumerate(layer["key_shared_secret_shards"]):
                    yield from _walk(
                        shard["key_cipher_layers"],
                        path + (index, "key_shared_secret_shards", shard_index, "key_cipher_layers"),
                        level + 1,
                    )
            elif "key_cipher_layers" in layer:
                yield from _walk(layer["key_cipher_layers"], path + (index, "key_cipher_layers"), level + 1)

    for index, payload_cipher_layer in enumerate(cryptoconf["payload_cipher_layers"]):
        yield from _walk(payload_cipher_layer["key_cipher_layers"], ("payload_cipher_layers", index, "key_cipher_layers"), 1)


def _iter_key_cipher_layers(cryptoconf):
    """Yield (path, layer, nesting level of its list) of every key cipher layer."""
    for list_path, key_cipher_layers, level in _iter_key_cipher_layer_lists(cryptoconf):
        for index, layer in enumerate(key_cipher_layers):
            yield list_path + (index,), layer, level


def _get_maximum_nesting_level(cryptoconf):
    return max(level for _path, _list, level in _iter_key_cipher_layer_lists(cryptoconf))


# MUTATIONS #


def _apply_arbitrary_mutation(cryptoconf, randomizer):
    """Mutate a (deep-copied) cryptoconf in place, in any way keeping it a WA-CBOR tree; return a description."""
    paths = [path for path, _value in _iter_paths(cryptoconf) if path]
    path = randomizer.choice(paths)
    value = profile_helpers.get_value_at_path(cryptoconf, path)
    parent, key = _get_parent_and_key(cryptoconf, path)
    kind = randomizer.randrange(6)
    if kind == 0 and isinstance(parent, dict):
        del parent[key]
        return "removed %r" % (path,)
    if kind == 1:
        target = value if isinstance(value, dict) else parent if isinstance(parent, dict) else cryptoconf
        new_key = randomizer.choice(["unexpected_key", "keychain_uid", "key_cipher_layers", "key_cipher_trustee",
                                     "payload_signatures", "payload_plaintext_signatures", "symkey"])
        new_value = randomizer.choice(ODD_VALUES)
        target[new_key] = copy.deepcopy(new_value)
        return "set %r=%r in map at or above %r" % (new_key, new_value, path)
    if kind == 2 and isinstance(value, list):
        if value and randomizer.random() < 0.5:
            value.append(copy.deepcopy(randomizer.choice(value)))
            return "duplicated an item of %r" % (path,)
        value.clear()
        return "emptied %r" % (path,)
    if kind == 3 and isinstance(value, str):
        new_value = randomizer.choice(C_SYMMETRIC_CIPHER_ALGOS + C_ASYMMETRIC_CIPHER_ALGOS + OTHER_ALGO_NAMES
                                      + (SHARED_SECRET_ALGO_MARKER, "local_keyfactory", "authenticator"))
        parent[key] = new_value
        return "replaced %r by %r" % (path, new_value)
    new_value = randomizer.choice(ODD_VALUES)
    parent[key] = copy.deepcopy(new_value)
    return "replaced %r by %r" % (path, new_value)


def _apply_subset_mutation(cryptoconf, randomizer):
    """Mutate a (deep-copied) cryptoconf in place, keeping it valid and within the C subset; return a description."""
    layers = list(_iter_key_cipher_layers(cryptoconf))
    kind = randomizer.randrange(6)
    if kind == 0:
        index = randomizer.randrange(len(cryptoconf["payload_cipher_layers"]))
        algo = randomizer.choice(C_SYMMETRIC_CIPHER_ALGOS)
        cryptoconf["payload_cipher_layers"][index]["payload_cipher_algo"] = algo
        return "payload layer %d algo %s" % (index, algo)
    if kind == 1:
        path, layer, _level = randomizer.choice(layers)
        if layer["key_cipher_algo"] in C_ASYMMETRIC_CIPHER_ALGOS:
            layer["key_cipher_algo"] = randomizer.choice(C_ASYMMETRIC_CIPHER_ALGOS)
        elif layer["key_cipher_algo"] in C_SYMMETRIC_CIPHER_ALGOS:
            layer["key_cipher_algo"] = randomizer.choice(C_SYMMETRIC_CIPHER_ALGOS)
        return "layer %r algo %s" % (path, layer["key_cipher_algo"])
    if kind == 2:
        shared_secret_layers = [(path, layer) for path, layer, _level in layers
                                if layer["key_cipher_algo"] == SHARED_SECRET_ALGO_MARKER]
        if shared_secret_layers:
            path, layer = randomizer.choice(shared_secret_layers)
            layer["key_shared_secret_threshold"] = randomizer.randint(1, len(layer["key_shared_secret_shards"]))
            return "layer %r threshold %d" % (path, layer["key_shared_secret_threshold"])
    if kind == 3:
        path, layer, _level = randomizer.choice(layers)
        if layer["key_cipher_algo"] in C_ASYMMETRIC_CIPHER_ALGOS:  # Symmetric and shared secret ones have none
            layer["keychain_uid"] = uuid.UUID(int=randomizer.getrandbits(128))
            return "layer %r keychain uid" % (path,)
    if kind == 4:
        lists = [(path, key_cipher_layers) for path, key_cipher_layers, _level in _iter_key_cipher_layer_lists(cryptoconf)
                 if len(key_cipher_layers) > 1]
        if lists:
            path, key_cipher_layers = randomizer.choice(lists)
            del key_cipher_layers[randomizer.randrange(len(key_cipher_layers))]
            return "removed a layer of %r" % (path,)
    # Wrap a layer into a new symmetric key layer, within the nesting cap
    if _get_maximum_nesting_level(cryptoconf) < C_MAXIMUM_KEY_CIPHER_NESTING_LEVEL:
        path, layer, _level = randomizer.choice(layers)
        parent, key = _get_parent_and_key(cryptoconf, path)
        parent[key] = {"key_cipher_algo": randomizer.choice(C_SYMMETRIC_CIPHER_ALGOS), "key_cipher_layers": [layer]}
        return "wrapped layer %r" % (path,)
    return "no change"


# VERDICTS #


def _is_accepted_by_wacryptolib(cryptoconf):
    from wacryptolib.cryptainer import check_cryptoconf_sanity
    from wacryptolib.exceptions import SchemaValidationError

    try:
        check_cryptoconf_sanity(cryptoconf)
    except SchemaValidationError:
        return False
    return True


def _load_with_c(c_build, cryptoconf, work_dir):
    """The C loader's output for the device profile of a cryptoconf, or None if the profile can't be encoded."""
    from wacryptolib.utilities import WaCborEncodingError

    try:
        profile_bytes = profile_helpers.dump_device_profile(profile_helpers.build_raw_device_profile(cryptoconf))
    except WaCborEncodingError:
        return None
    profile_path = work_dir / "profile.cbor"
    profile_path.write_bytes(profile_bytes)
    return c_build.run_driver("load-profile", profile_path)


@pytest.mark.parametrize("name", sorted(BASE_CRYPTOCONFS))
def test_validation_differential(c_build, name, tmp_path):
    base_cryptoconf = BASE_CRYPTOCONFS[name]
    output = _load_with_c(c_build, base_cryptoconf, tmp_path)
    assert output["status"] == "WA_STATUS_OK" and _is_accepted_by_wacryptolib(base_cryptoconf), output

    randomizer = random.Random("validation_differential:" + name)
    verdicts = {}
    for index in range(ARBITRARY_MUTATION_COUNT):
        cryptoconf = copy.deepcopy(base_cryptoconf)
        description = _apply_arbitrary_mutation(cryptoconf, randomizer)
        if randomizer.random() < 0.3:  # Sometimes a second one
            description += ", then " + _apply_arbitrary_mutation(cryptoconf, randomizer)
        output = _load_with_c(c_build, cryptoconf, tmp_path)
        if output is None:
            continue
        is_accepted_by_c = output["status"] == "WA_STATUS_OK"
        is_accepted_by_wacryptolib = _is_accepted_by_wacryptolib(cryptoconf)
        verdicts[(is_accepted_by_c, is_accepted_by_wacryptolib)] = verdicts.get((is_accepted_by_c, is_accepted_by_wacryptolib), 0) + 1
        assert is_accepted_by_wacryptolib or not is_accepted_by_c, (
            "Mutation %d (%s) accepted by the C loader, rejected by wacryptolib" % (index, description)
        )
    assert verdicts.get((False, False)), verdicts  # Rejections are exercised

    for index in range(SUBSET_MUTATION_COUNT):
        cryptoconf = copy.deepcopy(base_cryptoconf)
        descriptions = [_apply_subset_mutation(cryptoconf, randomizer) for _ in range(randomizer.randint(1, 3))]
        assert _is_accepted_by_wacryptolib(cryptoconf), descriptions
        output = _load_with_c(c_build, cryptoconf, tmp_path)
        assert output["status"] == "WA_STATUS_OK", (index, descriptions, output)
