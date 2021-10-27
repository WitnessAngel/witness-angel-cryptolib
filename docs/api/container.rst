Container
==========

This module provides utilities to write and read encrypted containers, which themselves use
encryption/signing keys of the escrow system.


Container object processing
----------------------------------

.. autofunction:: wacryptolib.container.encrypt_data_into_container

.. autofunction:: wacryptolib.container.decrypt_data_from_container

.. autofunction:: wacryptolib.container.extract_metadata_from_container

.. autofunction:: wacryptolib.container.get_encryption_configuration_summary

.. autoclass:: wacryptolib.container.ContainerEncryptionStream

.. autofunction:: wacryptolib.container.encrypt_data_and_dump_container_to_filesystem


Filesystem operations
-----------------------------

.. autofunction:: wacryptolib.container.dump_container_to_filesystem

.. autofunction:: wacryptolib.container.load_container_from_filesystem

.. autofunction:: wacryptolib.container.delete_container_from_filesystem

.. autofunction:: wacryptolib.container.get_container_size_on_filesystem


Container storage system
---------------------------------

.. autoclass:: wacryptolib.container.ContainerStorage


Escrow operations
--------------------------

.. autofunction:: wacryptolib.container.get_escrow_proxy

.. autofunction:: wacryptolib.container.gather_escrow_dependencies

.. autofunction:: wacryptolib.container.request_decryption_authorizations

.. autofunction:: wacryptolib.container.check_container_sanity

.. autofunction:: wacryptolib.container.check_conf_sanity
