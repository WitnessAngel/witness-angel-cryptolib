# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from wacryptolib.cli import main


if __name__ == "__main__":
    fake_prog_name = None  # "python -m wacryptolib"  # Else __init__.py is used in help text...
    main(fake_prog_name)  # FIXME
