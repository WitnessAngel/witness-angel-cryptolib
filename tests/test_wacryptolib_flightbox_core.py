# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""Tests of the checks that the portable flightbox core performs by itself, whatever the validation done (or not)
by the platform calling it."""

import copy

import pytest

from wacryptolib.cryptainer import FlightBox

from test_wacryptolib_key_ciphertext_format import DeterministicFlightboxUtilities, _local_layer, _payload_layer


class _FlightboxValidationError(Exception):
    pass


class _FlightboxUtilities(DeterministicFlightboxUtilities):
    def raise_validation_error(self, msg):
        raise _FlightboxValidationError(msg)


def _simple_cryptoconf():
    return dict(payload_cipher_layers=[_payload_layer("AES_CBC", [_local_layer("RSA_OAEP")])])


def test_flightbox_core_checks_its_arguments_before_any_random_draw():
    utilities = _FlightboxUtilities()
    flightbox = FlightBox(utilities)

    # These are real exceptions, not assertions that "python -O" would strip
    for cryptainer_metadata in ([1], "text", 0, ()):
        with pytest.raises(_FlightboxValidationError, match="Cryptainer metadata must be a dict or None"):
            flightbox.generate_cryptainer_base_and_secrets(_simple_cryptoconf(), cryptainer_metadata)
    for cryptoconf in (None, [_simple_cryptoconf()], "text"):
        with pytest.raises(_FlightboxValidationError, match="Cryptoconf must be a dict"):
            flightbox.generate_cryptainer_base_and_secrets(cryptoconf)

    # The key ciphertext format is checked first, like in the encryptor specification
    with pytest.raises(ValueError, match="Unknown key ciphertext format 'yaml'"):
        flightbox.generate_cryptainer_base_and_secrets(None, [1], key_ciphertext_format="yaml")

    assert utilities._counter == 0  # Neither UUIDs nor keys were generated


def test_flightbox_core_rejects_unknown_key_cipher_algo_with_a_validation_error():
    flightbox = FlightBox(_FlightboxUtilities())
    for key_cipher_algo in ("ML_DSA_65", "rsa_oaep", None):
        cryptoconf = dict(payload_cipher_layers=[_payload_layer("AES_CBC", [_local_layer(key_cipher_algo)])])
        with pytest.raises(_FlightboxValidationError, match="Unsupported key cipher algo"):
            flightbox.generate_cryptainer_base_and_secrets(cryptoconf)


def test_flightbox_core_copies_tuples_of_the_cryptoconf():
    # Tuples are rejected by wacryptolib's schemas, but not by every platform using this core
    cryptoconf = dict(
        payload_cipher_layers=(
            dict(
                payload_cipher_algo="AES_CBC",
                key_cipher_layers=(dict(key_cipher_algo="AES_CBC", key_cipher_layers=(_local_layer("RSA_OAEP"),)),),
                payload_ciphertext_signatures=(),
            ),
        )
    )
    cryptoconf_original = copy.deepcopy(cryptoconf)
    flightbox = FlightBox(_FlightboxUtilities())

    cryptainer1, _secrets1 = flightbox.generate_cryptainer_base_and_secrets(cryptoconf)
    cryptainer1_original = copy.deepcopy(cryptainer1)
    cryptainer2, _secrets2 = flightbox.generate_cryptainer_base_and_secrets(cryptoconf)

    assert cryptoconf == cryptoconf_original  # Not mutated
    assert cryptainer1 == cryptainer1_original  # Not sharing its layers with the next cryptainer

    payload_cipher_layer1 = cryptainer1["payload_cipher_layers"][0]
    payload_cipher_layer2 = cryptainer2["payload_cipher_layers"][0]
    assert payload_cipher_layer1 is not payload_cipher_layer2
    assert payload_cipher_layer1["key_ciphertext"] != payload_cipher_layer2["key_ciphertext"]
    assert isinstance(cryptainer1["payload_cipher_layers"], list)
    assert isinstance(payload_cipher_layer1["key_cipher_layers"], list)
    assert isinstance(payload_cipher_layer1["key_cipher_layers"][0]["key_cipher_layers"], list)
    assert payload_cipher_layer1["payload_ciphertext_signatures"] == []
