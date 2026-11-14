# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Read-side utilities of the compatibility/ corpus (see compatibility/README.md), shared by the test suite and by the
generation scripts of scripts/compatibility/.

Sidecars are plain JSON files named after their asset with ".json" appended, validated by the JSON-Schemas of
compatibility/_schemas/, which are resolved locally (never through the network).
"""

import base64
import hashlib
import json
from pathlib import Path, PurePosixPath

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

CORPUS_DIR = Path(__file__).resolve().parents[1] / "compatibility"
SCHEMAS_DIR = CORPUS_DIR / "_schemas"
SIDECAR_SUFFIX = ".json"
SCHEMA_SUFFIX = ".schema.json"

FIXTURE_KINDS = ("plaintext", "cipherdict", "signature", "keystore_pool", "cryptoconf", "cryptainer")

# Fixture kind expected for each asset suffix (keystore pools are directories, without suffix)
ASSET_SUFFIXES_TO_KINDS = {
    ".bin": "plaintext",
    ".cipherdict": "cipherdict",
    ".signature": "signature",
    ".cryptoconf": "cryptoconf",
    ".crypt": "cryptainer",
}


def load_schema_registry(schemas_dir: Path = SCHEMAS_DIR) -> Registry:
    """Return a registry of all corpus schemas, keyed by their $id (which is their filename)."""
    resources = []
    for schema_path in sorted(schemas_dir.glob("*" + SCHEMA_SUFFIX)):
        schema = json.loads(schema_path.read_text(encoding="utf8"))
        assert schema["$id"] == schema_path.name, schema_path
        resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def is_keystore_pool_dir(path: Path) -> bool:
    return path.is_dir() and (path / "local_keyfactory").is_dir()


def _is_hidden_or_schema(path: Path, corpus_dir: Path) -> bool:
    """True for schemas, hidden staging dirs of generators, and files INSIDE keystore pools (e.g. their own
    keystore_metadata.json files, which are not sidecars)."""
    relative_parts = path.relative_to(corpus_dir).parts
    if relative_parts[0] == SCHEMAS_DIR.name or any(part.startswith(".") for part in relative_parts):
        return True
    return any(is_keystore_pool_dir(parent) for parent in path.parents if corpus_dir in parent.parents)


def iter_sidecar_paths(corpus_dir: Path = CORPUS_DIR):
    """Yield all sidecar paths of the corpus, sorted (schemas, and hidden staging dirs of generators, excluded)."""
    for path in sorted(corpus_dir.rglob("*" + SIDECAR_SUFFIX)):
        if not _is_hidden_or_schema(path, corpus_dir):
            yield path


def iter_asset_paths(corpus_dir: Path = CORPUS_DIR):
    """Yield all paths which are assets according to their suffix, or keystore pool directories."""
    for path in sorted(corpus_dir.rglob("*")):
        if _is_hidden_or_schema(path, corpus_dir) or path.name.endswith(SIDECAR_SUFFIX):
            continue
        if path.is_file() and path.suffix in ASSET_SUFFIXES_TO_KINDS:
            yield path
        elif is_keystore_pool_dir(path):
            yield path


def get_asset_path(sidecar_path: Path) -> Path:
    """Return the path of the asset described by a sidecar (file or keystore pool directory)."""
    assert sidecar_path.name.endswith(SIDECAR_SUFFIX), sidecar_path
    return sidecar_path.with_name(sidecar_path.name[: -len(SIDECAR_SUFFIX)])


def get_sidecar_path(asset_path: Path) -> Path:
    return asset_path.with_name(asset_path.name + SIDECAR_SUFFIX)


def resolve_relpath(sidecar_path: Path, relpath: str) -> Path:
    """Resolve a sidecar-relative POSIX path, which must stay inside the corpus."""
    assert not PurePosixPath(relpath).is_absolute() and "\\" not in relpath, relpath
    path = (sidecar_path.parent / relpath).resolve()
    corpus_dir = _get_corpus_dir_of(sidecar_path)
    assert corpus_dir in path.parents, (relpath, corpus_dir)
    return path


def _get_corpus_dir_of(sidecar_path: Path) -> Path:
    for parent in Path(sidecar_path).resolve().parents:
        if (parent / SCHEMAS_DIR.name).is_dir():
            return parent
    raise ValueError("Sidecar %s is not inside a compatibility corpus" % sidecar_path)


def load_sidecar(sidecar_path: Path, registry: Registry = None) -> dict:
    """Load a sidecar and validate it against the schema of its declared fixture kind.

    Its "$schema" must point (relatively) to the corpus schema of that kind, so that standard JSON tools find it too.

    Raises jsonschema.ValidationError (or ValueError) on non-conforming sidecars.
    """
    sidecar = json.loads(Path(sidecar_path).read_text(encoding="utf8"))
    if not isinstance(sidecar, dict):
        raise ValueError("Sidecar %s is not a JSON object" % sidecar_path)

    fixture_kind = sidecar.get("fixture_kind")
    if fixture_kind not in FIXTURE_KINDS:
        raise ValueError("Sidecar %s has unknown fixture kind %r" % (sidecar_path, fixture_kind))

    corpus_dir = _get_corpus_dir_of(sidecar_path)
    schema_name = fixture_kind + SCHEMA_SUFFIX
    expected_schema_path = corpus_dir / SCHEMAS_DIR.name / schema_name
    declared_schema = sidecar.get("$schema")
    if not declared_schema or (Path(sidecar_path).parent / declared_schema).resolve() != expected_schema_path:
        raise ValueError(
            "Sidecar %s must declare its schema as a relative path to %s" % (sidecar_path, expected_schema_path)
        )

    if registry is None:
        registry = load_schema_registry(corpus_dir / SCHEMAS_DIR.name)
    schema = registry.contents(schema_name)
    Draft202012Validator(schema, registry=registry).validate(sidecar)
    return sidecar


def compute_file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def list_asset_files(asset_path: Path) -> list:
    """Return the files making up an asset: the file itself (plus an offloaded payload), or all files of a directory."""
    if asset_path.is_dir():
        return sorted(p for p in asset_path.rglob("*") if p.is_file())
    files = [asset_path]
    offloaded_payload_path = asset_path.with_name(asset_path.name + ".payload")
    if offloaded_payload_path.exists():
        files.append(offloaded_payload_path)
    return files


def compute_asset_sha256(sidecar_path: Path) -> dict:
    """Return the {relpath: sha256} map of the files of the asset of a sidecar (relpaths are relative to its dir)."""
    asset_path = get_asset_path(sidecar_path)
    return {
        path.relative_to(sidecar_path.parent).as_posix(): compute_file_sha256(path)
        for path in list_asset_files(asset_path)
    }


def generate_sha256_counter_bytes(seed: bytes, size: int) -> bytes:
    """Deterministic pseudo-random bytes: SHA256(seed || counter_be32) blocks, truncated to `size`."""
    blocks = []
    for counter in range((size + 31) // 32):
        blocks.append(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
    return b"".join(blocks)[:size]


def hex_to_bytes_dict(hex_dict: dict) -> dict:
    return {key: bytes.fromhex(value) for key, value in hex_dict.items()}


# PRIVATE KEY PEM PROTECTIONS (see "pem_protection" in _defs.schema.json) #

_OID_PBES2 = "1.2.840.113549.1.5.13"
_OID_PBKDF2 = "1.2.840.113549.1.5.12"
_OID_SCRYPT = "1.3.6.1.4.1.11591.4.11"
_PBKDF2_PRF_OIDS = {"1.2.840.113549.2.7": "sha1", "1.2.840.113549.2.9": "sha256"}
_AES_CBC_OIDS = {"2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.42"}
_DES3_CBC_OID = "1.2.840.113549.3.7"  # Used by wacryptolib <= 0.12 for DSA private keys


def _read_der_tlv(data: bytes, position: int = 0):
    """Return (tag, value, next_position) of the DER element at `position`."""
    tag, length = data[position], data[position + 1]
    position += 2
    if length & 0x80:
        length_size = length & 0x7F
        length = int.from_bytes(data[position : position + length_size], "big")
        position += length_size
    return tag, data[position : position + length], position + length


def _read_der_sequence_items(data: bytes) -> list:
    tag, value, _ = _read_der_tlv(data)
    assert tag == 0x30, tag
    items, position = [], 0
    while position < len(value):
        item_tag, _item_value, next_position = _read_der_tlv(value, position)
        items.append((item_tag, value[position:next_position]))
        position = next_position
    return items


def _decode_der_oid(data: bytes) -> str:
    tag, value, _ = _read_der_tlv(data)
    assert tag == 0x06, tag
    arcs, current = [], 0
    for byte in value:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(current)
            current = 0
    first = min(arcs[0] // 40, 2)
    return ".".join(str(arc) for arc in [first, arcs[0] - 40 * first] + arcs[1:])


def detect_pem_protection(private_key_pem: bytes) -> str:
    """Return how a private key PEM is protected, as one of the "pem_protection" values of the corpus schemas."""
    text = private_key_pem.decode("ascii")
    if "Proc-Type: 4,ENCRYPTED" in text:
        return "legacy_encapsulated_header"
    if "-----BEGIN ENCRYPTED PRIVATE KEY-----" not in text:
        return "none"
    body = "".join(line.strip() for line in text.strip().splitlines()[1:-1])
    algorithm_identifier, _ciphertext = (item for _tag, item in _read_der_sequence_items(base64.b64decode(body)))
    pbes2_oid, pbes2_parameters = (item for _tag, item in _read_der_sequence_items(algorithm_identifier))
    if _decode_der_oid(pbes2_oid) != _OID_PBES2:
        raise ValueError("Unknown private key protection scheme %s" % _decode_der_oid(pbes2_oid))
    kdf, cipher = (item for _tag, item in _read_der_sequence_items(pbes2_parameters))
    kdf_items = [item for _tag, item in _read_der_sequence_items(kdf)]
    cipher_oid = _decode_der_oid(_read_der_sequence_items(cipher)[0][1])
    if cipher_oid in _AES_CBC_OIDS:
        cipher_name = "aes_cbc"
    elif cipher_oid == _DES3_CBC_OID:
        cipher_name = "des3_cbc"
    else:
        raise ValueError("Unknown private key protection cipher %s" % cipher_oid)
    kdf_oid = _decode_der_oid(kdf_items[0])
    if kdf_oid == _OID_SCRYPT and cipher_name == "aes_cbc":
        return "pbes2_scrypt_aes_cbc"
    if kdf_oid != _OID_PBKDF2:
        raise ValueError("Unknown private key protection KDF %s" % kdf_oid)
    prf_name = "sha1"  # Default PRF of PBKDF2
    for tag, item in _read_der_sequence_items(kdf_items[1]):
        if tag == 0x30:  # Optional prf AlgorithmIdentifier
            prf_oid = _decode_der_oid(_read_der_sequence_items(item)[0][1])
            prf_name = _PBKDF2_PRF_OIDS[prf_oid]
    return "pbes2_pbkdf2_hmac_%s_%s" % (prf_name, cipher_name)


# REQUIREMENTS OF FIXTURES VERSUS CRYPTO BACKENDS #

# What each backend can NOT do, among the "requirements" values that sidecars may declare
BACKEND_LIMITATIONS = {
    "pycryptodome": {"algorithms": set(), "pem_protections": set()},
    "fallback": {
        "algorithms": {"ML_KEM_768", "ML_DSA_65"},
        "pem_protections": {"pbes2_scrypt_aes_cbc", "pbes2_pbkdf2_hmac_sha1_des3_cbc", "legacy_encapsulated_header"},
    },
}


class FixtureSkipped(Exception):
    """Raised when the active crypto backend lacks a requirement declared by a fixture."""


def get_missing_requirements(sidecar: dict, backend_name: str) -> list:
    limitations = BACKEND_LIMITATIONS[backend_name]
    requirements = sidecar["requirements"]
    return sorted(set(requirements["algorithms"]) & limitations["algorithms"]) + sorted(
        set(requirements["pem_protections"]) & limitations["pem_protections"]
    )


def _walk_data_tree(tree):
    """Yield all dicts of a nested data tree (cryptoconf, cryptainer...)."""
    if isinstance(tree, dict):
        yield tree
        for value in tree.values():
            yield from _walk_data_tree(value)
    elif isinstance(tree, list):
        for item in tree:
            yield from _walk_data_tree(item)


def collect_structure_algorithms(tree) -> set:
    """Return the cipher, signature and key algorithms used anywhere in a cryptoconf or cryptainer tree."""
    algos = set()
    for node in _walk_data_tree(tree):
        for key in ("payload_cipher_algo", "key_cipher_algo", "payload_signature_algo"):
            value = node.get(key)
            if isinstance(value, str) and value[:1].isalpha():  # Excludes the "[SHARED_SECRET]" marker
                algos.add(value.upper())
    return algos


def collect_trustee_types(tree) -> set:
    """Return the trustee types used anywhere in a cryptoconf or cryptainer tree."""
    return {node["trustee_type"] for node in _walk_data_tree(tree) if "trustee_type" in node}


# KEYSTORE POOL ACCESS (read-only on the corpus, or on a temporary copy) #

def get_pool_keystore_dir(pool_dir: Path, keystore: str) -> Path:
    from wacryptolib.keystore import FilesystemKeystorePool

    if keystore == "local_keyfactory":
        return pool_dir / FilesystemKeystorePool.LOCAL_KEYFACTORY_DIRNAME
    return (
        pool_dir
        / FilesystemKeystorePool.FOREIGN_KEYSTORES_DIRNAME
        / (FilesystemKeystorePool.FOREIGN_KEYSTORE_PREFIX + keystore)
    )


def load_referenced_key(sidecar_path: Path, key_ref: dict, private: bool):
    """Load the key object referenced by a "key_ref" of a sidecar, without writing anything in the corpus."""
    from uuid import UUID

    from wacryptolib.keygen import load_asymmetric_key_from_pem_bytestring
    from wacryptolib.keystore import ReadonlyFilesystemKeystore

    pool_dir = resolve_relpath(sidecar_path, key_ref["keystore_pool"])
    keystore = ReadonlyFilesystemKeystore(get_pool_keystore_dir(pool_dir, key_ref["keystore"]))
    getter = keystore.get_private_key if private else keystore.get_public_key
    key_pem = getter(keychain_uid=UUID(key_ref["keychain_uid"]), key_algo=key_ref["key_algo"])
    passphrase = key_ref.get("passphrase") if private else None
    return load_asymmetric_key_from_pem_bytestring(key_pem, key_algo=key_ref["key_algo"], passphrase=passphrase)


def list_keystore_keypairs(keystore_dir: Path) -> list:
    """Return the "keypair_identifier" dicts of a filesystem keystore, as sidecars describe them."""
    from wacryptolib.keystore import ReadonlyFilesystemKeystore

    keystore = ReadonlyFilesystemKeystore(keystore_dir)
    keypairs = []
    for identifier in keystore.list_keypair_identifiers():
        keypair = dict(
            keychain_uid=str(identifier["keychain_uid"]),
            key_algo=identifier["key_algo"],
            private_key_present=identifier["private_key_present"],
        )
        if identifier["private_key_present"]:
            private_key_pem = keystore.get_private_key(
                keychain_uid=identifier["keychain_uid"], key_algo=identifier["key_algo"]
            )
            keypair["pem_protection"] = detect_pem_protection(private_key_pem)
        keypairs.append(keypair)
    return keypairs


def copy_keystore_pool_dir(sidecar_path: Path, pool_relpath: str, work_dir: Path) -> Path:
    """Return a fresh temporary copy of a pool fixture (pools may get written when used)."""
    import shutil
    import uuid

    pool_dir = resolve_relpath(sidecar_path, pool_relpath)
    assert is_keystore_pool_dir(pool_dir), pool_dir
    copy_dir = Path(work_dir) / ("pool-%s-%s" % (pool_dir.name, uuid.uuid4().hex[:8]))
    shutil.copytree(pool_dir, copy_dir)
    return copy_dir


def copy_keystore_pool(sidecar_path: Path, pool_relpath: str, work_dir: Path):
    """Return a FilesystemKeystorePool on a fresh temporary copy of a pool fixture."""
    from wacryptolib.keystore import FilesystemKeystorePool

    return FilesystemKeystorePool(copy_keystore_pool_dir(sidecar_path, pool_relpath, work_dir))


def snapshot_directory(directory: Path) -> dict:
    """Return the {relpath: sha256} map of all files of a directory tree."""
    return {
        path.relative_to(directory).as_posix(): compute_file_sha256(path)
        for path in sorted(Path(directory).rglob("*"))
        if path.is_file()
    }


def parse_passphrase_mapper(passphrase_mapper: dict) -> dict:
    """Return a fresh passphrase mapper for decryption APIs (sidecar trustee ids are those of get_trustee_id())."""
    return {trustee_id: list(passphrases) for trustee_id, passphrases in passphrase_mapper.items()}


# BEHAVIORAL CHECKS OF FIXTURES (raising AssertionError, or another exception, on failure) #

def check_asset_integrity(sidecar_path: Path, sidecar: dict):
    actual = compute_asset_sha256(sidecar_path)
    expected = sidecar["asset_sha256"]
    assert actual == expected, "Asset files of %s differ from their recorded SHA-256 digests: %s" % (
        sidecar_path,
        sorted(set(actual.items()) ^ set(expected.items())),
    )


def check_plaintext_fixture(sidecar_path: Path, sidecar: dict, work_dir: Path):
    plaintext = get_asset_path(sidecar_path).read_bytes()
    assert len(plaintext) == sidecar["size"], (len(plaintext), sidecar["size"])
    generator = sidecar["generator"]
    assert plaintext == generate_sha256_counter_bytes(bytes.fromhex(generator["seed"]), sidecar["size"])


def check_cipherdict_fixture(sidecar_path: Path, sidecar: dict, work_dir: Path):
    from wacryptolib.cipher import CIPHER_ALGOS_REGISTRY, decrypt_bytestring, encrypt_bytestring
    from wacryptolib.exceptions import DecryptionError, DecryptionIntegrityError
    from wacryptolib.utilities import load_from_json_file

    cipherdict = load_from_json_file(get_asset_path(sidecar_path))
    plaintext = resolve_relpath(sidecar_path, sidecar["plaintext"]).read_bytes()
    cipher_algo = sidecar["cipher_algo"]
    if "symkey" in sidecar:
        key_dict = hex_to_bytes_dict(sidecar["symkey"])
    else:
        key_dict = {"key": load_referenced_key(sidecar_path, sidecar["private_key"], private=True)}

    if not sidecar.get("expected_valid", True):
        # Authenticated symmetric algorithms must detect the tampering as such; with asymmetric ones (e.g. KEM + AEAD),
        # a tampered ciphertext can't be told apart from a wrong private key
        is_authenticated = CIPHER_ALGOS_REGISTRY[cipher_algo]["is_authenticated"]
        expected_exception_class = DecryptionIntegrityError if is_authenticated and "symkey" in sidecar else DecryptionError
        try:
            decrypt_bytestring(cipherdict, cipher_algo=cipher_algo, key_dict=key_dict)
        except expected_exception_class:
            pass
        else:
            raise AssertionError("Tampered cipherdict %s was not rejected" % sidecar_path)
        return

    assert decrypt_bytestring(cipherdict, cipher_algo=cipher_algo, key_dict=key_dict) == plaintext
    if sidecar["direction"] == "bidirectional":
        assert encrypt_bytestring(plaintext, cipher_algo=cipher_algo, key_dict=key_dict) == cipherdict


def check_signature_fixture(sidecar_path: Path, sidecar: dict, work_dir: Path):
    from wacryptolib.exceptions import SignatureVerificationError
    from wacryptolib.signature import verify_message_signature
    from wacryptolib.utilities import load_from_json_file

    signature = load_from_json_file(get_asset_path(sidecar_path))
    if "message" in sidecar:
        message = resolve_relpath(sidecar_path, sidecar["message"]).read_bytes()
    else:
        message = bytes.fromhex(sidecar["message_hex"])
    public_key = load_referenced_key(sidecar_path, sidecar["public_key"], private=False)

    def _verify():
        verify_message_signature(
            message=message, signature_algo=sidecar["signature_algo"], signature=signature, public_key=public_key
        )

    if sidecar["expected_valid"]:
        _verify()
        return
    try:
        _verify()
    except SignatureVerificationError:
        pass
    else:
        raise AssertionError("Signature %s unexpectedly verified" % sidecar_path)


def check_keystore_pool_fixture(sidecar_path: Path, sidecar: dict, work_dir: Path):
    from uuid import UUID

    from wacryptolib.exceptions import KeyLoadingError
    from wacryptolib.keygen import load_asymmetric_key_from_pem_bytestring
    from wacryptolib.keystore import ReadonlyFilesystemKeystore

    pool_dir = get_asset_path(sidecar_path)

    def _check_keypairs(keystore_dir, expected_keypairs, passphrase):
        assert list_keystore_keypairs(keystore_dir) == expected_keypairs, keystore_dir
        keystore = ReadonlyFilesystemKeystore(keystore_dir)
        for keypair in expected_keypairs:
            keychain_uid, key_algo = UUID(keypair["keychain_uid"]), keypair["key_algo"]
            public_key_pem = keystore.get_public_key(keychain_uid=keychain_uid, key_algo=key_algo)
            load_asymmetric_key_from_pem_bytestring(public_key_pem, key_algo=key_algo)
            if not keypair["private_key_present"]:
                continue
            private_key_pem = keystore.get_private_key(keychain_uid=keychain_uid, key_algo=key_algo)
            load_asymmetric_key_from_pem_bytestring(private_key_pem, key_algo=key_algo, passphrase=passphrase)
            if passphrase is not None:
                try:
                    load_asymmetric_key_from_pem_bytestring(
                        private_key_pem, key_algo=key_algo, passphrase=passphrase + "-wrong"
                    )
                except KeyLoadingError:
                    pass
                else:
                    raise AssertionError("Private key %s/%s loaded with a wrong passphrase" % (key_algo, keychain_uid))

    _check_keypairs(get_pool_keystore_dir(pool_dir, "local_keyfactory"), sidecar["local_keyfactory"]["keypairs"], None)

    # Pool APIs are only used on a copy, since they may write into the pool
    keystore_pool = copy_keystore_pool(sidecar_path, pool_dir.name, work_dir)
    expected_uids = sorted(UUID(authenticator["keystore_uid"]) for authenticator in sidecar["authenticators"])
    assert keystore_pool.list_foreign_keystore_uids() == expected_uids
    for authenticator in sidecar["authenticators"]:
        keystore_uid = UUID(authenticator["keystore_uid"])
        metadata = keystore_pool.get_foreign_keystore_metadata(keystore_uid)  # Validates the metadata file too
        assert metadata["keystore_uid"] == keystore_uid
        assert metadata["keystore_owner"] == authenticator["keystore_owner"]
        _check_keypairs(
            get_pool_keystore_dir(pool_dir, authenticator["keystore_uid"]),
            authenticator["keypairs"],
            authenticator["passphrase"],
        )


def load_referenced_pool_sidecar(sidecar_path: Path, pool_relpath: str) -> dict:
    """Return the (raw) sidecar of a keystore pool referenced by another sidecar."""
    pool_dir = resolve_relpath(sidecar_path, pool_relpath)
    return json.loads(get_sidecar_path(pool_dir).read_text(encoding="utf8"))


def get_pool_keypair_identifiers(pool_sidecar: dict) -> set:
    """Return the (trustee_id, keychain_uid, key_algo) triplets of all keypairs that a pool sidecar declares."""
    identifiers = {
        ("local_keyfactory", keypair["keychain_uid"], keypair["key_algo"])
        for keypair in pool_sidecar["local_keyfactory"]["keypairs"]
    }
    for authenticator in pool_sidecar["authenticators"]:
        identifiers.update(
            ("authenticator@" + authenticator["keystore_uid"], keypair["keychain_uid"], keypair["key_algo"])
            for keypair in authenticator["keypairs"]
        )
    return identifiers


def check_cryptoconf_fixture(sidecar_path: Path, sidecar: dict, work_dir: Path):
    import copy
    from uuid import UUID

    from wacryptolib.cryptainer import check_cryptoconf_sanity, decrypt_payload_from_cryptainer
    from wacryptolib.cryptainer import encrypt_payload_into_cryptainer
    from wacryptolib.exceptions import SchemaValidationError
    from wacryptolib.keystore import FilesystemKeystorePool
    from wacryptolib.utilities import load_from_json_file

    asset_path = get_asset_path(sidecar_path)
    cryptoconf = load_from_json_file(asset_path)

    if not sidecar["expected_valid"]:
        # Only the python mode is required to reject them, since e.g. a threshold above the shard count can't be
        # expressed in JSON-Schema
        try:
            check_cryptoconf_sanity(cryptoconf)
        except SchemaValidationError:
            return
        raise AssertionError("Invalid cryptoconf %s was accepted" % sidecar_path)

    check_cryptoconf_sanity(cryptoconf)
    check_cryptoconf_sanity(json.loads(asset_path.read_text(encoding="utf8")), jsonschema_mode=True)

    # Encryption must use the keys of the pool, and never autogenerate missing ones (which would hide unloadable old
    # keys). Cryptoconfs of old releases may lack a keychain_uid, which was then given at encryption time, so the local
    # keychains of the pool are tried in turn
    if "keychain_uid" in cryptoconf:
        candidate_keychain_uids = [None]
    else:
        pool_sidecar = load_referenced_pool_sidecar(sidecar_path, sidecar["keystore_pool"])
        candidate_keychain_uids = sorted(
            {keypair["keychain_uid"] for keypair in pool_sidecar["local_keyfactory"]["keypairs"]}
        )
    payload = b"Compatibility round-trip payload of " + sidecar_path.name.encode("utf8")
    for keychain_uid in candidate_keychain_uids:
        pool_dir = copy_keystore_pool_dir(sidecar_path, sidecar["keystore_pool"], work_dir)
        pool_snapshot = snapshot_directory(pool_dir)
        keystore_pool = FilesystemKeystorePool(pool_dir)
        effective_cryptoconf = copy.deepcopy(cryptoconf)
        if keychain_uid is not None:
            effective_cryptoconf["keychain_uid"] = UUID(keychain_uid)
        cryptainer = encrypt_payload_into_cryptainer(
            payload=payload,
            cryptoconf=effective_cryptoconf,
            cryptainer_metadata={"round_trip": True},
            keystore_pool=keystore_pool,
        )
        if snapshot_directory(pool_dir) == pool_snapshot:
            break
    else:
        raise AssertionError("Encryption with cryptoconf %s autogenerated keys missing from its pool" % sidecar_path)

    result, operation_report = decrypt_payload_from_cryptainer(
        cryptainer,
        keystore_pool=keystore_pool,
        passphrase_mapper=parse_passphrase_mapper(sidecar["passphrase_mapper"]),
    )
    assert not operation_report.has_errors(), operation_report.format_entries()
    assert result == payload
    assert snapshot_directory(pool_dir) == pool_snapshot, "Decryption modified the keystore pool"


def get_cryptainer_plaintext(sidecar_path: Path, sidecar: dict) -> bytes:
    if "plaintext" in sidecar:
        return resolve_relpath(sidecar_path, sidecar["plaintext"]).read_bytes()
    return bytes.fromhex(sidecar["plaintext_hex"])


def count_cryptainer_signatures(cryptainer: dict) -> int:
    """Count the plaintext and ciphertext signatures of a cryptainer, whatever the field naming of its generation."""
    signature_count = len(cryptainer.get("payload_plaintext_signatures") or ())
    for payload_cipher_layer in cryptainer["payload_cipher_layers"]:
        signature_count += len(
            payload_cipher_layer.get("payload_ciphertext_signatures")
            or payload_cipher_layer.get("payload_signatures")  # Before its renaming in 2024
            or ()
        )
    return signature_count


# Key decryption errors of shards whose trustee is not unlocked by a scenario: which shards the decryptor tries before
# reaching a Shamir threshold is an implementation detail, so they are tolerated, but not required, in successes
TRUSTEE_DEPENDENT_ERROR_TYPES = {"ASYMMETRIC_DECRYPTION_ERROR"}


def run_cryptainer_decryption_scenario(cryptainer_path: Path, keystore_pool, scenario: dict) -> tuple:
    """Decrypt a freshly loaded cryptainer, and return (payload or None, sorted list of the distinct error types of
    the decryption report, count of the signature verifications performed)."""
    from unittest import mock

    import wacryptolib.cryptainer._decryptor as decryptor_module
    from wacryptolib.cryptainer import decrypt_payload_from_cryptainer, load_cryptainer_from_filesystem

    cryptainer = load_cryptainer_from_filesystem(cryptainer_path)
    with mock.patch.object(
        decryptor_module, "verify_message_signature", wraps=decryptor_module.verify_message_signature
    ) as verify_message_signature_spy:
        payload, operation_report = decrypt_payload_from_cryptainer(
            cryptainer,
            keystore_pool=keystore_pool,
            passphrase_mapper=parse_passphrase_mapper(scenario["passphrase_mapper"]),
        )
    error_types = sorted({entry["entry_type"] for entry in operation_report.get_error_entries()})
    return payload, error_types, verify_message_signature_spy.call_count


def _check_cryptainer_analysis(asset_path: Path, pool_sidecar: dict):
    """Check the APIs which only need the light cryptainer (without payload), e.g. to prepare revelation requests."""
    from wacryptolib.cryptainer import check_cryptainer_sanity, gather_decryptable_symkeys
    from wacryptolib.cryptainer import gather_trustee_dependencies, get_cryptoconf_summary
    from wacryptolib.cryptainer import load_cryptainer_from_filesystem

    light_cryptainer = load_cryptainer_from_filesystem(asset_path, include_payload_ciphertext=False)
    check_cryptainer_sanity(light_cryptainer, require_inline_payload=False)
    assert get_cryptoconf_summary(light_cryptainer)

    pool_keypair_identifiers = get_pool_keypair_identifiers(pool_sidecar)

    def _check_keypair_is_in_pool(trustee_id, keychain_uid, key_algo):
        keypair_identifier = (trustee_id, str(keychain_uid), key_algo)
        assert keypair_identifier in pool_keypair_identifiers, "Keypair %s is not in the pool" % (keypair_identifier,)

    trustee_dependencies = gather_trustee_dependencies([light_cryptainer])
    for dependencies in trustee_dependencies.values():  # "encryption" and "signature" dependencies
        for trustee_id, (_trustee_conf, keypair_identifiers) in dependencies.items():
            for keypair_identifier in keypair_identifiers:
                _check_keypair_is_in_pool(trustee_id, keypair_identifier["keychain_uid"], keypair_identifier["key_algo"])

    decryptable_symkeys = gather_decryptable_symkeys([(asset_path.name, light_cryptainer)])
    assert decryptable_symkeys and set(decryptable_symkeys) <= set(trustee_dependencies["encryption"])
    for trustee_id, (_trustee_conf, symkey_decryption_requests) in decryptable_symkeys.items():
        for request in symkey_decryption_requests:
            assert request["symkey_decryption_request_data"]
            _check_keypair_is_in_pool(trustee_id, request["keychain_uid"], request["key_algo"])


def check_cryptainer_fixture(sidecar_path: Path, sidecar: dict, work_dir: Path):
    import shutil

    from wacryptolib.cryptainer import ReadonlyCryptainerStorage, check_cryptainer_sanity
    from wacryptolib.cryptainer import extract_metadata_from_cryptainer, load_cryptainer_from_filesystem
    from wacryptolib.keystore import FilesystemKeystorePool

    asset_path = get_asset_path(sidecar_path)
    raw_cryptainer = asset_path.read_bytes()
    is_canonical = b'"$uuid"' not in raw_cryptainer  # CANONICAL UUIDs are "$binary" of subtype 04 instead
    assert is_canonical == (sidecar["extjson_flavor"] == "canonical"), "Unexpected extended JSON flavor"
    assert asset_path.with_name(asset_path.name + ".payload").exists() == sidecar["payload_offloaded"]

    check_cryptainer_sanity(json.loads(raw_cryptainer), jsonschema_mode=True)
    cryptainer = load_cryptainer_from_filesystem(asset_path)
    check_cryptainer_sanity(cryptainer)
    if "cryptainer_metadata" in sidecar:
        assert extract_metadata_from_cryptainer(cryptainer) == sidecar["cryptainer_metadata"]
    expected_signature_count = count_cryptainer_signatures(cryptainer)

    pool_sidecar = load_referenced_pool_sidecar(sidecar_path, sidecar["keystore_pool"])
    _check_cryptainer_analysis(asset_path, pool_sidecar)

    plaintext = get_cryptainer_plaintext(sidecar_path, sidecar)

    for scenario in sidecar["decryption_scenarios"]:
        # Each scenario gets fresh copies, so that no state (e.g. cached keys) leaks between scenarios
        keystore_pool = copy_keystore_pool(sidecar_path, sidecar["keystore_pool"], work_dir)
        payload, error_types, signature_verification_count = run_cryptainer_decryption_scenario(
            asset_path, keystore_pool, scenario
        )
        if scenario["expected"] == "success":
            assert payload == plaintext, "Scenario %r did not return the original plaintext" % scenario["name"]
            expected_error_types = set(scenario.get("expected_warnings", [])) - TRUSTEE_DEPENDENT_ERROR_TYPES
            assert set(error_types) - TRUSTEE_DEPENDENT_ERROR_TYPES == expected_error_types, (scenario["name"], error_types)
            # Proves that signatures, whatever their generation's field naming, are still verified
            assert signature_verification_count == expected_signature_count, (
                scenario["name"],
                signature_verification_count,
                expected_signature_count,
            )
        else:
            assert payload is None, "Scenario %r unexpectedly decrypted the cryptainer" % scenario["name"]
            assert error_types, scenario["name"]
            assert set(scenario.get("expected_errors", [])) <= set(error_types), (scenario["name"], error_types)

    # Decryption through a storage of cryptainers, as done by applications
    first_scenario = sidecar["decryption_scenarios"][0]
    storage_dir = Path(work_dir) / ("storage-" + asset_path.name)
    storage_dir.mkdir()
    for asset_file in list_asset_files(asset_path):
        shutil.copyfile(asset_file, storage_dir / asset_file.name)
    storage = ReadonlyCryptainerStorage(
        storage_dir, keystore_pool=copy_keystore_pool(sidecar_path, sidecar["keystore_pool"], work_dir)
    )
    assert storage.list_cryptainer_names() == [Path(asset_path.name)]
    storage.check_cryptainer_sanity(asset_path.name)
    payload, _operation_report = storage.decrypt_cryptainer_from_storage(
        asset_path.name, passphrase_mapper=parse_passphrase_mapper(first_scenario["passphrase_mapper"])
    )
    expected_payload = plaintext if first_scenario["expected"] == "success" else None
    assert payload == expected_payload, "Unexpected outcome of decryption from storage"


FIXTURE_CHECKERS = {
    "plaintext": check_plaintext_fixture,
    "cipherdict": check_cipherdict_fixture,
    "signature": check_signature_fixture,
    "keystore_pool": check_keystore_pool_fixture,
    "cryptoconf": check_cryptoconf_fixture,
    "cryptainer": check_cryptainer_fixture,
}


def check_fixture(sidecar_path: Path, work_dir: Path, backend_name: str = None, registry: Registry = None) -> dict:
    """Fully check a fixture against the current library: sidecar schema, asset integrity, then behavior.

    Raises FixtureSkipped (after the structural checks) if the crypto backend lacks a declared requirement;
    when this backend is the active one, the fixture must then really fail its behavioral checks, so that
    BACKEND_LIMITATIONS can't silently hide fixtures from a backend which gained the missing capabilities.
    """
    from wacryptolib._crypto_backend import BACKEND_NAME as active_backend_name

    if backend_name is None:
        backend_name = active_backend_name
    sidecar = load_sidecar(sidecar_path, registry=registry)
    check_asset_integrity(sidecar_path, sidecar)
    expected_fixture_kind = get_expected_fixture_kind(get_asset_path(sidecar_path))
    assert sidecar["fixture_kind"] == expected_fixture_kind, (sidecar["fixture_kind"], expected_fixture_kind)
    fixture_checker = FIXTURE_CHECKERS[sidecar["fixture_kind"]]
    missing_requirements = get_missing_requirements(sidecar, backend_name)
    if missing_requirements:
        missing_requirements_str = ", ".join(missing_requirements)
        if backend_name == active_backend_name:
            try:
                fixture_checker(sidecar_path, sidecar, Path(work_dir))
            except Exception:
                pass  # Expected, since the backend lacks these requirements
            else:
                raise AssertionError(
                    "%s crypto backend handles this fixture despite lacking %s, BACKEND_LIMITATIONS must be updated"
                    % (backend_name, missing_requirements_str)
                )
        raise FixtureSkipped(
            "%s crypto backend lacks %s, required by this fixture" % (backend_name, missing_requirements_str)
        )
    fixture_checker(sidecar_path, sidecar, Path(work_dir))
    return sidecar


# CORPUS-WIDE CHECKS (returning lists of problems, empty when the corpus is sound) #

ALLOWED_TRUSTEE_TYPES = {"local_keyfactory", "authenticator"}

# Files of the corpus root which belong to no fixture
CORPUS_DOCUMENTATION_FILENAMES = ("README.md",)


def get_expected_fixture_kind(asset_path: Path) -> str:
    if is_keystore_pool_dir(asset_path):
        return "keystore_pool"
    return ASSET_SUFFIXES_TO_KINDS.get(asset_path.suffix)


def _load_raw_sidecars(corpus_dir: Path):
    """Yield (sidecar_path, sidecar) pairs, WITHOUT schema validation, skipping unparseable sidecars."""
    for sidecar_path in iter_sidecar_paths(corpus_dir):
        try:
            sidecar = json.loads(sidecar_path.read_text(encoding="utf8"))
        except ValueError:
            continue  # Reported by the schema validation of this fixture
        if isinstance(sidecar, dict):
            yield sidecar_path, sidecar


def find_orphan_paths(corpus_dir: Path = CORPUS_DIR) -> list:
    """Return problems about sidecars without their asset, assets without their sidecar, and corpus files which
    belong to no fixture (e.g. an offloaded payload without its cryptainer, or a leftover staging directory)."""
    problems = []
    accounted_paths = {corpus_dir / filename for filename in CORPUS_DOCUMENTATION_FILENAMES}

    for sidecar_path in iter_sidecar_paths(corpus_dir):
        accounted_paths.add(sidecar_path)
        asset_path = get_asset_path(sidecar_path)
        if not asset_path.exists():
            problems.append("Sidecar without its asset: %s" % sidecar_path)
            continue
        accounted_paths.update(list_asset_files(asset_path))

    for asset_path in iter_asset_paths(corpus_dir):
        if not get_sidecar_path(asset_path).exists():
            problems.append("Asset without its sidecar: %s" % asset_path)
            accounted_paths.update(list_asset_files(asset_path))  # Already reported

    schemas_dir = corpus_dir / SCHEMAS_DIR.name
    for path in sorted(corpus_dir.rglob("*")):
        if path.is_file() and path not in accounted_paths and path.parent != schemas_dir:
            problems.append("File belonging to no fixture: %s" % path)
    return problems


def find_forbidden_trustees(corpus_dir: Path = CORPUS_DIR) -> list:
    """Return problems about valid cryptoconfs, or cryptainers, using other trustees than local/authenticator ones."""
    from wacryptolib.utilities import load_from_json_file

    problems = []
    for sidecar_path, sidecar in _load_raw_sidecars(corpus_dir):
        if sidecar.get("fixture_kind") == "cryptainer" or (
            sidecar.get("fixture_kind") == "cryptoconf" and sidecar.get("expected_valid")
        ):
            asset_path = get_asset_path(sidecar_path)
            if not asset_path.is_file():
                continue  # Reported as orphan
            forbidden_trustee_types = collect_trustee_types(load_from_json_file(asset_path)) - ALLOWED_TRUSTEE_TYPES
            if forbidden_trustee_types:
                problems.append("Forbidden trustee types %s in %s" % (sorted(forbidden_trustee_types), asset_path))
    return problems


def find_uncovered_algorithms(corpus_dir: Path = CORPUS_DIR) -> dict:
    """Return, per algorithm registry of the library, the algorithms which appear in no fixture of the corpus: cipher
    algorithms need a cipherdict vector, signature algorithms a signature vector, and asymmetric key algorithms a
    keypair in a keystore pool."""
    from wacryptolib.cipher import CIPHER_ALGOS_REGISTRY
    from wacryptolib.keygen import ASYMMETRIC_KEY_ALGOS_REGISTRY
    from wacryptolib.signature import SIGNATURE_ALGOS_REGISTRY

    covered_cipher_algos, covered_signature_algos, covered_key_algos = set(), set(), set()
    for sidecar_path, sidecar in _load_raw_sidecars(corpus_dir):
        fixture_kind = sidecar.get("fixture_kind")
        if fixture_kind == "cipherdict":
            covered_cipher_algos.add(sidecar.get("cipher_algo"))
        elif fixture_kind == "signature":
            covered_signature_algos.add(sidecar.get("signature_algo"))
        elif fixture_kind == "keystore_pool":
            keystores = [sidecar.get("local_keyfactory", {})] + sidecar.get("authenticators", [])
            covered_key_algos.update(keypair["key_algo"] for keystore in keystores for keypair in keystore["keypairs"])

    uncovered_algorithms = {
        "cipher_algos": sorted(set(CIPHER_ALGOS_REGISTRY) - covered_cipher_algos),
        "signature_algos": sorted(set(SIGNATURE_ALGOS_REGISTRY) - covered_signature_algos),
        "asymmetric_key_algos": sorted(set(ASYMMETRIC_KEY_ALGOS_REGISTRY) - covered_key_algos),
    }
    return {registry: algos for registry, algos in uncovered_algorithms.items() if algos}


def snapshot_corpus(corpus_dir: Path = CORPUS_DIR) -> dict:
    """Return the {relpath: sha256} map of all files of the corpus."""
    return snapshot_directory(corpus_dir)
