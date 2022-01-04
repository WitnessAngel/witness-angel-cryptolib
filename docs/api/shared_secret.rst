Shared secret
======================

This module provides utilities to dissociate and recombine Shamir "shared secrets", for which some parts (shards)
can be lost without preventing the reconstruction of the whole secret.


.. autofunction:: wacryptolib.shared_secret.split_secret_into_shards

.. autofunction:: wacryptolib.shared_secret.recombine_secret_from_shards






