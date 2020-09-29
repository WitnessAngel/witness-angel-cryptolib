Error handling
=================

This module provides utilities to convert python exceptions from/to a generic serialized format, so that webservice
client can handle them in a hierarchical and forward-compatible manner.


.. autoclass:: wacryptolib.error_handling.StatusSlugsMapper

.. autofunction:: wacryptolib.error_handling.gather_exception_subclasses

.. autofunction:: wacryptolib.error_handling.slugify_exception_class

.. autofunction:: wacryptolib.error_handling.construct_status_slugs_mapper

.. autofunction:: wacryptolib.error_handling.get_closest_exception_class_for_status_slugs
