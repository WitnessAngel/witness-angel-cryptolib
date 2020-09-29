Escrow
=============

This module provides base classes and utilities for escrow local/web services.


API for escrow services
---------------------------

.. autoclass:: wacryptolib.escrow.EscrowApi

.. autoclass:: wacryptolib.escrow.ReadonlyEscrowApi


Auto-replenishing of local free keys
-------------------------------------

.. autofunction:: wacryptolib.escrow.generate_free_keypair_for_least_provisioned_key_type

.. autofunction:: wacryptolib.escrow.get_free_keys_generator_worker
