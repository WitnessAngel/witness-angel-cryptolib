Witness Angel Cryptolib
#############################

.. image:: https://travis-ci.com/WitnessAngel/witness-angel-cryptolib.svg?branch=master
    :target: https://travis-ci.com/WitnessAngel/witness-angel-cryptolib

This lib gathers useful utilities to generate keys, and encrypt/descrypt/sign data, for the
Witness Angel system.



First steps
===================

The interpreter for `python3.7` (see `pyproject.toml` for full version) must be installed.

Instead of pip, we use `poetry <https://github.com/sdispater/poetry>`_ to manage dependencies.

Use `pip install poetry` to install poetry (or follow its official docs to install it system-wide).

Use `poetry install` to install python dependencies.

Use `pytest` to launch unit-tests (its default arguments are in `setup.cfg`)

Use `bash ci.sh` to do a full checkup before committing or pushing your changes.

Use the `Black <https://black.readthedocs.io/en/stable/>`_ formatter to format your python code.
