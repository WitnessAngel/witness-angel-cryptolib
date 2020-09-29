Utilities
==========

This module exposes different functions which can be useful when dealing with cryptography and workers.


Task handling
----------------

.. autofunction:: wacryptolib.utilities.TaskRunnerStateMachineBase

.. autofunction:: wacryptolib.utilities.PeriodicTaskHandler


Hashing
-----------

.. autodata:: wacryptolib.utilities.SUPPORTED_HASH_ALGOS

.. autofunction:: wacryptolib.utilities.hash_message


Serialization
------------------

.. autofunction:: wacryptolib.utilities.dump_to_json_str

.. autofunction:: wacryptolib.utilities.load_from_json_str

.. autofunction:: wacryptolib.utilities.dump_to_json_bytes

.. autofunction:: wacryptolib.utilities.load_from_json_bytes

.. autofunction:: wacryptolib.utilities.dump_to_json_file

.. autofunction:: wacryptolib.utilities.load_from_json_file


Storage metadata handling
------------------------------

.. autofunction:: wacryptolib.utilities.get_metadata_file_path


Miscellaneous
----------------------

.. autofunction:: wacryptolib.utilities.generate_uuid0

.. autofunction:: wacryptolib.utilities.split_as_chunks

.. autofunction:: wacryptolib.utilities.recombine_chunks

.. autofunction:: wacryptolib.utilities.safe_copy_directory



