
Getting started
===================

The interpreter for `python3.7` (see `pyproject.toml` for full version) must be installed.

Instead of pip, we use `poetry <https://github.com/sdispater/poetry>`_ to manage dependencies.

Use `pip install poetry` to install poetry (or follow its official docs to install it system-wide).

Use `poetry install` to install python dependencies (poetry will create its own virtualenv if you don't have one activated).

Use `pytest` to launch unit-tests (default pytest arguments are in `setup.cfg`). Use `poetry run pytest` instead, if poetry created its own virtualenv.

Use `bash ci.sh` to do a full checkup before committing or pushing your changes.

Use the `Black <https://black.readthedocs.io/en/stable/>`_ formatter to format your python code.

A simple command-line interface is available to play with simple (unsafe) containers (ensure that "src/" is in your PYTHONPATH first)::

    python -m wacryptolib -h
