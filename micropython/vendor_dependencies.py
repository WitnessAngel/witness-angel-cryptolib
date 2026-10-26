"""
Regenerate micropython/lib/ : PyPI packages at the exact versions of ../poetry.lock (so that
micropython and cpython code get cross-validated), plus micropython-lib stdlib modules (latest versions, as python
sources, from the index used by "mip"), micropython patches, stubs and shared wacryptolib modules.

Usage (from any directory, with CPython >= 3.11):  python micropython/vendor_dependencies.py
"""

import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.request import urlopen

MICROPYTHON_DIR = Path(__file__).resolve().parent
REPO_DIR = MICROPYTHON_DIR.parent
LIB_DIR = MICROPYTHON_DIR / "lib"

PACKAGES = ["extjson", "pkcs1", "pyaes", "rsa", "pyasn1"]  # pyasn1 is required by rsa

MIP_INDEX = "https://micropython.org/pi/v2"
MICROPYTHON_LIB_PACKAGES = ["__future__", "copy", "datetime", "hashlib", "hmac", "logging", "threading", "operator", "functools"]

SHARED_MODULES = [REPO_DIR / "src/wacryptolib/utilities/data_utils.py"]


def install_from_mip_index(name):
    with urlopen("%s/package/py/%s/latest.json" % (MIP_INDEX, name)) as response:
        package = json.load(response)
    for path, short_hash in package["hashes"]:
        target = LIB_DIR / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with urlopen("%s/file/%s/%s" % (MIP_INDEX, short_hash[:2], short_hash)) as response:
            target.write_bytes(response.read())
    for dependency_name, _version in package.get("deps", []):
        install_from_mip_index(dependency_name)
    return "%s==%s" % (name, package["version"])


def main():
    locked = {p["name"]: p["version"] for p in tomllib.loads((REPO_DIR / "poetry.lock").read_text())["package"]}
    requirements = ["%s==%s" % (name, locked[name]) for name in PACKAGES]

    shutil.rmtree(LIB_DIR, ignore_errors=True)
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-deps", "--no-compile",
                           "--target", str(LIB_DIR), *requirements])
    shutil.rmtree(LIB_DIR / "bin", ignore_errors=True)
    for record in LIB_DIR.glob("*.dist-info/RECORD"):
        record.unlink()  # Depends on the local interpreter path, and useless here

    requirements += [install_from_mip_index(name) for name in MICROPYTHON_LIB_PACKAGES]

    for patch in sorted((MICROPYTHON_DIR / "patches").glob("*.patch")):
        # Fails loudly if a version bump in poetry.lock broke a patch; cwd matters, since inside a repo
        # subdirectory "git apply" silently skips paths outside of it
        subprocess.check_call(["git", "apply", "--verbose", "--directory", LIB_DIR.relative_to(REPO_DIR).as_posix(),
                               str(patch)], cwd=REPO_DIR)

    for module in [*sorted((MICROPYTHON_DIR / "stubs").glob("*.py")), *SHARED_MODULES]:
        shutil.copy(module, LIB_DIR)

    print("Vendored into %s: %s" % (LIB_DIR, ", ".join(requirements)))


if __name__ == "__main__":
    main()
