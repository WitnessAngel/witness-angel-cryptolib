
Getting started
===================

The interpreter for `python3.7` or later must be installed (see `pyproject.toml` for version details).

Instead of pip, we use `poetry <https://github.com/sdispater/poetry>`_ to manage dependencies.


Quick setup
-----------

Launch `python wacryptolib_installer.py` in repository root, from inside a python virtual environment.

This will update pip, install a local version of poetry, install the python modules required by wacryptolib, and then launch unit-tests.


Manual setup
------------

Use `pip install poetry` to install poetry (or better, follow its official docs to install it system-wide).

Use `poetry install` from repository root, to install python dependencies (poetry will create its own virtualenv if you don't have one activated).


Handy commands
--------------

Use `pytest` to launch unit-tests (default pytest arguments are in `setup.cfg`). Use `poetry run pytest` instead, if poetry created its own virtualenv.

Use `bash ci.sh` to do a full checkup before committing or pushing your changes.

Use the `Black <https://black.readthedocs.io/en/stable/>`_ formatter to format the python code::

    black -l 120 src/ tests/

A simple command-line interface is available to play with simple (unsafe) cryptainers (ensure that "src/" is in your PYTHONPATH first)::

    python -m wacryptolib -h
