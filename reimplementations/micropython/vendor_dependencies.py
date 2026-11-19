"""
Regenerate reimplementations/micropython/lib/ : PyPI packages at the exact versions and hashes of ../../poetry.lock (so
that micropython and cpython code get cross-validated), plus micropython-lib stdlib modules (python sources from the
index used by "mip", at the versions and file hashes pinned below), micropython patches, stubs and shared wacryptolib
modules; lib/ is only replaced once all of it was vendored and checked. Also refresh the verbatim copies of wacryptolib
modules in reimplementations/micropython/src/cryptainer/ (the portable flightbox core and the Shamir module).
tests/test_micropython_port_packaging.py checks that all these copies are up to date.

Usage (from any directory, with CPython >= 3.11):  python reimplementations/micropython/vendor_dependencies.py

On a microcontroller, freeze lib/ and src/ into the firmware (or at least precompile them with mpy-cross): as python
sources, the demo needs about 384 KB of heap on the 64-bit unix port of MicroPython 1.22, mostly to compile them, and
their imported bytecode and tables (pyaes's, datetime for extjson, pkcs1) still take about 200 KB of it when not frozen.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.request import urlopen

MICROPYTHON_DIR = Path(__file__).resolve().parent
REPO_DIR = MICROPYTHON_DIR.parent.parent
LIB_DIR = MICROPYTHON_DIR / "lib"
SRC_DIR = MICROPYTHON_DIR / "src"

PACKAGES = ["extjson", "pkcs1", "pyaes"]

MIP_INDEX = "https://micropython.org/pi/v2"
# Pinned micropython-lib versions, and SHA-256 of their files: bumping a version means reviewing and pinning its files
MICROPYTHON_LIB_PACKAGES = {"__future__": "0.1.0", "copy": "3.3.5", "datetime": "4.1.0", "hashlib": "2.5.0",
                            "hmac": "3.4.4", "logging": "0.6.2", "operator": "0.2.0", "functools": "0.1.0"}
MICROPYTHON_LIB_FILE_HASHES = {
    "__future__.py": "68f6ed1758189a38e3d4a1d7aee47479498822234100f72b12da750f1e5c015c",
    "copy.py": "a8d4c8e6eba284e8a6433fc9053080ab7927363ce71c4a5ea343fdbb3165c2e6",
    "types.py": "c7c859a4701053d04b214779b1485a2c57cd40c9f15be0b2e283763b96558498",
    "datetime.py": "1d933d7f9089d711305677f06a5a703f6d1cad6074adb116c7f47972f03d5223",
    "hashlib/__init__.py": "8990693cb23e04bfb014531d6b2930fedc07cb839c0aabe32378141573eb6ccf",
    "hashlib/_sha.py": "dcc544f0760b59cfaedc21c62d70272f2deed8bf1dea8ee64917ae79c44197ee",
    "hashlib/_sha224.py": "af96b58ebd0456445b18ed947c42f89490313673d4e073ae6060f695ef72af8f",
    "hashlib/_sha256.py": "4763002f2adb16611e146652d74b27401348318a13c5cfcdf887857659616aa2",
    "hashlib/_sha384.py": "1429ad2abf11e14445b792c9d60890be9a550c9d981412e84364423e9c9a8479",
    "hashlib/_sha512.py": "b23d7a80ef71c16f770801e1a62da8009936e8b4b943bf4516f649c421ea233d",
    "hmac.py": "5f02f5d02590d44fe8c300f851c549e7918ccbd766dd877ab92268c7c3ebc3a2",
    "logging.py": "ba7c1bf28a494d22680556cf7565fc15cef30c74fdf5077140e39732dc3b42a8",
    "operator.py": "915133e876252ce2ea61331b3d2ea81fbab53b88a5158770d50212422fb1a0a6",
    "functools.py": "53273014a3ce38e033c5c14bdac12cc3b9c40aedc0b6e62a931a93e4b66179f8",
}

SHARED_MODULES = [REPO_DIR / "src/wacryptolib/utilities/data_utils.py",
                  REPO_DIR / "src/wacryptolib/_crypto_backend/fallback/chacha20_poly1305.py",
                  REPO_DIR / "src/wacryptolib/_crypto_backend/fallback/hpke_x25519_seal.py"]

# Verbatim copies of wacryptolib modules into micropython sources
SHARED_SOURCES = {
    REPO_DIR / "src/wacryptolib/cryptainer/_flightbox.py": SRC_DIR / "cryptainer/_flightbox.py",
    REPO_DIR / "src/wacryptolib/_crypto_backend/pycryptodome_secret_sharing.py":
        SRC_DIR / "cryptainer/pycryptodome_secret_sharing.py",
}


def install_from_mip_index(name, version, target_dir):
    """Download the files of a pinned micropython-lib package, refusing any file whose path or hash is not pinned."""
    with urlopen("%s/package/py/%s/%s.json" % (MIP_INDEX, name, version)) as response:
        package = json.load(response)
    for dependency_name, _version in package.get("deps", []):
        if dependency_name not in MICROPYTHON_LIB_PACKAGES:
            raise RuntimeError("Unpinned dependency %s of micropython-lib package %s" % (dependency_name, name))
    written_paths = []
    for path, short_hash in package["hashes"]:
        expected_hash = MICROPYTHON_LIB_FILE_HASHES.get(path)  # Also rules out paths escaping the target dir
        if expected_hash is None or not expected_hash.startswith(short_hash):
            raise RuntimeError("Unpinned file %r (hash %s) in micropython-lib package %s" % (path, short_hash, name))
        with urlopen("%s/file/%s/%s" % (MIP_INDEX, short_hash[:2], short_hash)) as response:
            content = response.read()
        if hashlib.sha256(content).hexdigest() != expected_hash:
            raise RuntimeError("Wrong SHA-256 for file %r of micropython-lib package %s" % (path, name))
        target = target_dir / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        written_paths.append(path)
    return written_paths


def vendor_into(target_dir):
    with open(REPO_DIR / "poetry.lock", "rb") as lock_file:  # Binary, since tomllib decodes it as UTF-8
        locked = {package["name"]: package for package in tomllib.load(lock_file)["package"]}
    requirements = ["%s==%s" % (name, locked[name]["version"]) for name in PACKAGES]
    requirements_path = target_dir.with_name(target_dir.name + ".requirements.txt")
    requirements_path.write_text("".join(
        "%s %s\n" % (requirement, " ".join("--hash=%s" % file["hash"] for file in locked[name]["files"]))
        for name, requirement in zip(PACKAGES, requirements)), encoding="utf8")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-deps", "--no-compile", "--require-hashes",
                               "--target", str(target_dir), "-r", str(requirements_path)])
    finally:
        requirements_path.unlink()
    shutil.rmtree(target_dir / "bin", ignore_errors=True)
    for record in target_dir.glob("*.dist-info/RECORD"):
        record.unlink()  # Depends on the local interpreter path, and useless here

    written_paths = []
    for name, version in MICROPYTHON_LIB_PACKAGES.items():
        written_paths += install_from_mip_index(name, version, target_dir)
        requirements.append("%s==%s" % (name, version))
    if sorted(written_paths) != sorted(MICROPYTHON_LIB_FILE_HASHES):
        raise RuntimeError("Pinned micropython-lib files missing or written twice: %s" % sorted(written_paths))

    for patch in sorted((MICROPYTHON_DIR / "patches").glob("*.patch")):
        # Fails loudly if a version bump in poetry.lock broke a patch; cwd matters, since inside a repo
        # subdirectory "git apply" silently skips paths outside of it
        subprocess.check_call(["git", "apply", "--verbose", "--directory", target_dir.relative_to(REPO_DIR).as_posix(),
                               str(patch)], cwd=REPO_DIR)

    for module in [*sorted((MICROPYTHON_DIR / "stubs").glob("*.py")), *SHARED_MODULES]:
        shutil.copy(module, target_dir)
    return requirements


def main():
    # Vendored next to lib/ (inside the repository, for "git apply"), then swapped with lib/ only if all succeeded
    new_lib_dir, old_lib_dir = LIB_DIR.with_name("lib.new"), LIB_DIR.with_name("lib.old")
    for leftover_dir in (new_lib_dir, old_lib_dir):
        if leftover_dir.exists():
            shutil.rmtree(leftover_dir)  # Raises if a file is locked, instead of vendoring over stale files
    try:
        requirements = vendor_into(new_lib_dir)
        if LIB_DIR.exists():
            LIB_DIR.rename(old_lib_dir)
        new_lib_dir.rename(LIB_DIR)
    finally:
        if new_lib_dir.exists():
            shutil.rmtree(new_lib_dir, ignore_errors=True)
    if old_lib_dir.exists():
        shutil.rmtree(old_lib_dir)

    for source, target in SHARED_SOURCES.items():
        shutil.copy(source, target)

    print("Vendored into %s: %s" % (LIB_DIR, ", ".join(requirements)))


if __name__ == "__main__":
    main()
