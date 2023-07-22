Development instructions
===========================

Getting started
++++++++++++++++++++++++

To develop on the WACryptolib, the interpreter for `python3.7` or later must be installed (see `pyproject.toml` for version details).

Instead of pip, we use `poetry <https://github.com/sdispater/poetry>`_ to manage dependencies.


Automatic setup
------------------------

Launch `python wacryptolib_installer.py` in repository root, from inside a python virtual environment.

This will update pip, install a *local* version of poetry, install the python modules required by wacryptolib, and then launch unit-tests.

On Windows, poetry might try to move some DLLs it is currently using, so install might crash with file permission errors, but relaunching the installer should eventually succeed...


Manual setup
------------------------

Use `pip install poetry` to install poetry (or better, follow its official docs to install it system-wide and avoid the permission errors mentioned just above).

Use `poetry install` from repository root, to install python dependencies (poetry will create its own virtualenv if you don't have one activated).

As an alternative, you can launch `pip install -r pip_requirements_export.txt`, but this requirements file might be a bit outdated for latest Python versions.


Launching the CLI
---------------------

To try the command line interface, the easiest is to launch the `main.py` script.

If you added "src/" to your pythonpath, e.g. with `pip install -e <repo-root>` (requires pip>=21.3), you can instead use::

    $ python -m wacryptolib

When wacryptolib has been installed with pip, it exposes a **"flightbox"** executable which does the same as the main.py script.


Handy dev commands
------------------------

Use `pytest` to launch unit-tests (default pytest arguments are in `setup.cfg`).
Use `poetry run pytest` instead, if poetry manages its own virtualenv.

Add `--cov=wacryptolib` argument to the pytest command to generate coverage reports.

Use `bash ci.sh` to do a full checkup before committing or pushing your changes (under Windows, launch CI commands one by one).

Use the `Black <https://black.readthedocs.io/en/stable/>`_ formatter to format the python code like so::

    $ black -l 120 src/ tests/

To generate documentation, launch Sphinx commands ("make html"...) from the doc/subfolder. The "flightbox" entrypoint mentioned above should have been installed into your virtualenv first, else, some documentation generation will fail.


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


