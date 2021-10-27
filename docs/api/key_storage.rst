Key storage
=============

This module provides classes for the storage of asymmetric key pairs.


Key storages
-----------------------

Each of these key storages theoretically belongs to a single user.

.. autoclass:: wacryptolib.key_storage.KeyStorageBase

.. autoclass:: wacryptolib.key_storage.DummyKeyStorage

.. autoclass:: wacryptolib.key_storage.FilesystemKeyStorage


Key storage pools
-----------------------

These combine local and imported key storages under a single interface.

.. autoclass:: wacryptolib.key_storage.KeyStoragePoolBase

.. autoclass:: wacryptolib.key_storage.DummyKeyStoragePool

.. autoclass:: wacryptolib.key_storage.FilesystemKeyStoragePool
