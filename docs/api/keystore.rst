Key storage
=============

This module provides classes for the storage of asymmetric key pairs.


Keystore
-----------------------

Each of these key storages theoretically belongs to a single user.

.. autofunction:: wacryptolib.keystore.load_keystore_metadata

.. autoclass:: wacryptolib.keystore.InMemoryKeystore
    :inherited-members:

.. autoclass:: wacryptolib.keystore.FilesystemKeystore
    :inherited-members:


Keystore pools
-----------------------

These combine local and imported key storages under a single interface.

.. autoclass:: wacryptolib.keystore.InMemoryKeystorePool
    :inherited-members:

.. autoclass:: wacryptolib.keystore.FilesystemKeystorePool
    :inherited-members:
