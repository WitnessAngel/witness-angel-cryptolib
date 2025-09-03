# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Optional

from wacryptolib.cryptainer import get_trustee_proxy


def request_decryption_authorizations(
    trustee_dependencies: dict, keystore_pool, request_message: str, passphrases: Optional[list] = None
) -> dict:
    """Loop on encryption trustees and request decryption authorization for all the keypairs that they own.

    :return: dict mapping trustee ids to authorization result dicts.
    """
    request_authorization_result = {}
    cipher_trustee_dependencies = trustee_dependencies.get("encryption")

    for trustee_id, trustee_data in cipher_trustee_dependencies.items():
        key_cipher_trustee, keypair_identifiers = trustee_data
        proxy = get_trustee_proxy(trustee=key_cipher_trustee, keystore_pool=keystore_pool)
        result = proxy.request_decryption_authorization(
            keypair_identifiers=keypair_identifiers, request_message=request_message, passphrases=passphrases
        )
        request_authorization_result[trustee_id] = result

    return request_authorization_result