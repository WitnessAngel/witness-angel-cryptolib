Trustee
=============

This module provides base classes and utilities for trustee local/web services.


API for trustee services
---------------------------

.. autoclass:: wacryptolib.trustee.TrusteeApi

.. autoclass:: wacryptolib.trustee.ReadonlyTrusteeApi


Auto-replenishing of local free keys
-------------------------------------

.. autofunction:: wacryptolib.trustee.generate_free_keypair_for_least_provisioned_key_algo

.. autofunction:: wacryptolib.trustee.get_free_keys_generator_worker
