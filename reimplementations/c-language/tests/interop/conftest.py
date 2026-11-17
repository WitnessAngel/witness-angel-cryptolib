# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Interoperability tests of the C flightbox encryptor against wacryptolib (design D13).

They drive the test driver (wa_flightbox_test_driver) and the CLI (wa_flightbox_encrypt_file_cli) of the C builds
listed in WA_FLIGHTBOX_C_BUILD_DIR: one or more CMake build directories configured with -DWA_BUILD_TOOLS=ON,
separated by os.pathsep (":" on POSIX). Each build reports its crypto backend and document formats ("build-info"
driver subcommand). Every test is skipped when no build is given.

Run from the repository root, e.g.:
    WA_FLIGHTBOX_C_BUILD_DIR=build_mbedtls:build_wolfcrypt pytest reimplementations/c-language/tests/interop
"""

import pytest

from c_flightbox_interop_support import BUILD_DIR_ENVIRONMENT_VARIABLE, get_c_builds


def pytest_generate_tests(metafunc):
    """Parametrize "c_build" over the available builds, and "document_format" over their enabled formats; with no
    build, a single None parameter, skipped by the fixtures."""
    c_builds = get_c_builds()
    if "c_build" in metafunc.fixturenames and "document_format" in metafunc.fixturenames:
        pairs = [(c_build, document_format) for c_build in c_builds for document_format in c_build.document_formats]
        metafunc.parametrize(
            ("c_build", "document_format"),
            pairs or [(None, None)],
            ids=["%s/%s" % (c_build.name, document_format) for c_build, document_format in pairs] or ["no-build"],
        )
    elif "c_build" in metafunc.fixturenames:
        metafunc.parametrize("c_build", c_builds or [None], ids=[c_build.name for c_build in c_builds] or ["no-build"])


@pytest.fixture(autouse=True)
def _skip_when_no_c_build():
    """Skip every test of this directory when no C build is given (c_build is then None)."""
    if not get_c_builds():
        pytest.skip("No C build given in %s" % BUILD_DIR_ENVIRONMENT_VARIABLE)
