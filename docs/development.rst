Development instructions
===========================

Getting started
++++++++++++++++++++++++

To develop on the WACryptolib, the interpreter for `python3.7` or later must be installed (see `pyproject.toml` for version details).

Instead of pip, we use `poetry <https://github.com/sdispater/poetry>`_ to manage dependencies.


Basic `pip` setup
------------------

Set up a virtual environment, then:
```bash
pip install -r pip_requirements_export.txt
python -m main --help
```


`pip` editable installation
------------------------

(_Need a `pip3>=21.3`, see: [PEP 660 – Editable installs for pyproject.toml based builds ](https://www.python.org/dev/peps/pep-0660/)_)

Set up a virtual environment, then:
```bash
pip install -U pip
pip install -e .
python wacryptolib --help
```


Automatic setup
------------------------

Launch `python wacryptolib_installer.py` in repository root, from inside a python virtual environment.

This will update pip, install a local version of poetry, install the python modules required by wacryptolib, and then launch unit-tests.


Manual setup
------------------------

Use `pip install poetry` to install poetry (or better, follow its official docs to install it system-wide).

Use `poetry install` from repository root, to install python dependencies (poetry will create its own virtualenv if you don't have one activated).


Handy commands
------------------------

Use `pytest` to launch unit-tests (default pytest arguments are in `setup.cfg`). Use `poetry run pytest` instead, if poetry created its own virtualenv.

Add `--cov=wacryptolib` argument to the pytest command to generate coverage reports.

Use `bash ci.sh` to do a full checkup before committing or pushing your changes (under Windows, launch CI commands one by one).

Use the `Black <https://black.readthedocs.io/en/stable/>`_ formatter to format the python code like so::

    $ black -l 120 src/ tests/


Release process
++++++++++++++++++++++

To release a new version of the WACryptolib, we don't need Twine, since Poetry already has publishing commands.


Initial setup
------------------------

You must first register testpypi as a valid package store in Poetry::

    $ poetry config repositories.testpypi https://test.pypi.org/legacy/

Check it then with::

    $ poetry config --list


Publish a new version
------------------------

Issue::

    $ poetry build
    $ poetry publish -r testpypi

Then test this preview package in some project using the wacryptolib::

    $ python -m pip install -U --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ wacryptolib

When all is verified on testpypi (Readme, files uploaded, etc.), release the package to the real pypi::

    $ poetry publish
