"""
Regenerate micropython/lib/ : PyPI packages at the exact versions of ../poetry.lock (so that
micropython and cpython code get cross-validated), plus micropython patches, stubs and shared wacryptolib modules.

Usage (from any directory, with CPython >= 3.11):  python micropython/vendor_dependencies.py
"""

import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

MICROPYTHON_DIR = Path(__file__).resolve().parent
REPO_DIR = MICROPYTHON_DIR.parent
LIB_DIR = MICROPYTHON_DIR / "lib"

PACKAGES = ["extjson", "pkcs1", "pyaes", "rsa", "pyasn1"]  # pyasn1 is required by rsa

SHARED_MODULES = [REPO_DIR / "src/wacryptolib/utilities/data_utils.py"]


def main():
    locked = {p["name"]: p["version"] for p in tomllib.loads((REPO_DIR / "poetry.lock").read_text())["package"]}
    requirements = ["%s==%s" % (name, locked[name]) for name in PACKAGES]

    shutil.rmtree(LIB_DIR, ignore_errors=True)
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-deps", "--no-compile",
                           "--target", str(LIB_DIR), *requirements])
    shutil.rmtree(LIB_DIR / "bin", ignore_errors=True)
    for record in LIB_DIR.glob("*.dist-info/RECORD"):
        record.unlink()  # Depends on the local interpreter path, and useless here

    for patch in sorted((MICROPYTHON_DIR / "patches").glob("*.patch")):
        # Fails loudly if a version bump in poetry.lock broke a patch
        subprocess.check_call(["git", "apply", "--unsafe-paths", "--directory", str(LIB_DIR), str(patch)])

    for module in [*sorted((MICROPYTHON_DIR / "stubs").glob("*.py")), *SHARED_MODULES]:
        shutil.copy(module, LIB_DIR)

    print("Vendored into %s: %s" % (LIB_DIR, ", ".join(requirements)))


if __name__ == "__main__":
    main()
