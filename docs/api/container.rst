Container
==========

This module provides utilities to write and read encrypted containers, which themselves use
encryption/signing keys of the escrow system.


.. autofunction:: wacryptolib.container.encrypt_data_into_container

.. autofunction:: wacryptolib.container.decrypt_data_from_container

.. autofunction:: wacryptolib.container.extract_metadata_from_container

.. autofunction:: wacryptolib.container.dump_container_to_filesystem

.. autofunction:: wacryptolib.container.load_container_from_filesystem

.. autofunction:: wacryptolib.container.delete_container_from_filesystem

.. autoclass:: wacryptolib.container.ContainerStorage

.. autofunction:: wacryptolib.container.get_escrow_proxy

.. autofunction:: wacryptolib.container.gather_escrow_dependencies

.. autofunction:: wacryptolib.container.request_decryption_authorizations
