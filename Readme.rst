Witness Angel Cryptolib
#############################

This lib gathers useful utilities to generate keys, and encrypt/descrypt/sign data, for the
Witness Angel system.


Prerequisites
==================

You will need:

- `python3.7` (see `pyproject.toml` for full version)


Development
===================

When developing locally, we use:

- [`poetry`](https://github.com/sdispater/poetry) (**required**)

Use "pip install poetry" to install poetry (or follow its official docs to inside it system-wide).

Use "poetry install" to install python dependencies.

Use "pytest" to launch unit-tests; its default arguments are in setup.cfg

Use "bash ci.sh" to launch sources checkup, before committing or pushing your changes.

Use Black formatter (or integrate it as an onsave-hook in your IDE) to format python sources.
