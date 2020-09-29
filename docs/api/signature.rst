Signature
=========

This module allows one to sign messages, and then verify the signature.


Public API
--------------

.. autodata:: wacryptolib.signature.SUPPORTED_SIGNATURE_ALGOS

.. autofunction:: wacryptolib.signature.sign_message

.. autofunction:: wacryptolib.signature.verify_message_signature


Private API
---------------

The functions below are only documented for the details they give on specific arguments.


PSS
~~~~~~~~

.. autofunction:: wacryptolib.signature._sign_with_pss


DSS
~~~~~~~~

.. autofunction:: wacryptolib.signature._sign_with_dss
