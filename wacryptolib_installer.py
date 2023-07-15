"""
Quick installer for the wacryptolib.
Requires Python3.7+

Launch it from repository root folder, using a system-wide python executable (requires sudo in Linux) or the python executable from a virtual environment.

Note that this installs the "poetry" package manager in the current python environment, not system-wide with a dedicated python environment. So this could create conflicts on the long term.
"""

import subprocess
import sys

commands = """
PYTHON_EXE -m pip install -U pip==23.2
PYTHON_EXE -m pip install poetry==1.5.1
PYTHON_EXE -m pip install -r pip_requirements_export.txt
PYTHON_EXE -m pytest
"""
commands = [x.strip() for x in commands.splitlines() if x.strip()]


def main():
    for cmd in commands:
        cmd = cmd.replace("PYTHON_EXE", sys.executable)
        print(">>>>>>>>> Running %r" % cmd)
        subprocess.check_call(cmd, shell=True)


if __name__ == "__main__":
    main()
