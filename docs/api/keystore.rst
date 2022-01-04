Key storage
=============

This module provides classes for the storage of asymmetric key pairs.


Keystore
-----------------------

Each of these key storages theoretically belongs to a single user.

.. autofunction:: wacryptolib.keystore.load_keystore_metadata

.. autoclass:: wacryptolib.keystore.KeystoreBase

.. autoclass:: wacryptolib.keystore.DummyKeystore

.. autoclass:: wacryptolib.keystore.FilesystemKeystore


Key storage pools
-----------------------

These combine local and imported key storages under a single interface.

.. autoclass:: wacryptolib.keystore.KeystorePoolBase

.. autoclass:: wacryptolib.keystore.InMemoryKeystorePool

.. autoclass:: wacryptolib.keystore.FilesystemKeystorePool
