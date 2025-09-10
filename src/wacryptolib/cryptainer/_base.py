# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Optional

from wacryptolib.cryptainer import logger
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.keystore import KeystorePoolBase, InMemoryKeystorePool, FilesystemKeystore
from wacryptolib.trustee import TrusteeApi, ReadonlyTrusteeApi


CRYPTAINER_SUFFIX = ".crypt"
CRYPTAINER_DATETIME_FORMAT = "%Y%m%d_%H%M%S"  # For use in cryptainer names and their records
CRYPTAINER_DATETIME_LENGTH = (
    15  # Important to lookup prefix of filename before matching it with CRYPTAINER_DATETIME_FORMAT
)
CRYPTAINER_TEMP_SUFFIX = "~"  # To name temporary, unfinalized, cryptainers
assert len(CRYPTAINER_TEMP_SUFFIX) == 1  # Because we use strip() with it here and there


class PAYLOAD_CIPHERTEXT_LOCATIONS:
    INLINE = "inline"  # Ciphertext is included in the json cryptainer
    OFFLOADED = "offloaded"  # Ciphertext is in a nearby binary file


# Shortcut helper, should NOT be modified
OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER = dict(ciphertext_location=PAYLOAD_CIPHERTEXT_LOCATIONS.OFFLOADED)

OFFLOADED_PAYLOAD_FILENAME_SUFFIX = ".payload"  # Added to CRYPTAINER_SUFFIX

DEFAULT_DATA_CHUNK_SIZE = 1024**2  # E.g. when streaming a big payload through encryptors

DECRYPTED_FILE_SUFFIX = ".decrypted"  # To construct decrypted filename when no output filename is provided

SHARED_SECRET_ALGO_MARKER = "[SHARED_SECRET]"  # Special "key_cipher_algo" value

# FIXME get rid of this heavy global dependency? Make it lazy-loaded at least?
DUMMY_KEYSTORE_POOL = InMemoryKeystorePool()  # Common fallback storage with in-memory keys


class CRYPTAINER_TRUSTEE_TYPES:  # FIXME rename to CRYPTAINER_TRUSTEE_TYPE (singular)
    LOCAL_KEYFACTORY_TRUSTEE = "local_keyfactory"
    AUTHENTICATOR_TRUSTEE = "authenticator"
    JSONRPC_API_TRUSTEE = "jsonrpc_api"


# Shortcut helper, should NOT be modified
LOCAL_KEYFACTORY_TRUSTEE_MARKER = dict(trustee_type=CRYPTAINER_TRUSTEE_TYPES.LOCAL_KEYFACTORY_TRUSTEE)

class SIGNATURE_POLICIES:
    SKIP_SIGNING = "SKIP_SIGNING"
    ATTEMPT_SIGNING = "ATTEMPT_SIGNING"  # Fail silently if errors
    REQUIRE_SIGNING = "REQUIRE_SIGNING"


def get_trustee_id(trustee_conf: dict) -> str:
    """Build opaque identifier unique for a given trustee."""
    trustee_type = trustee_conf.get("trustee_type", None)

    if trustee_type == CRYPTAINER_TRUSTEE_TYPES.LOCAL_KEYFACTORY_TRUSTEE:
        trustee_specifier = None  # Nothing to add for local keyfactory
    elif trustee_type == CRYPTAINER_TRUSTEE_TYPES.AUTHENTICATOR_TRUSTEE:
        trustee_specifier = str(trustee_conf["keystore_uid"])  # Ignore optional keystore_owner
    elif trustee_type == CRYPTAINER_TRUSTEE_TYPES.JSONRPC_API_TRUSTEE:
        trustee_specifier = trustee_conf["jsonrpc_url"]
    else:
        raise ValueError("Unrecognized key trustee %s" % str(trustee_conf))

    trustee_id = (trustee_type + "@" + trustee_specifier) if trustee_specifier else trustee_type
    return trustee_id


class CryptainerBase:
    """
    THIS CLASS IS PRIVATE API

    `keystore_pool` will be used to fetch local/imported trustees necessary to encryption/decryption operations.

    `passphrase_mapper` maps trustees IDs to potential passphrases; a None key can be used to provide additional
    passphrases for all trustees.
    """

    def __init__(self, keystore_pool: KeystorePoolBase = None, passphrase_mapper: Optional[dict] = None):
        if not keystore_pool:
            logger.warning(
                "No key storage pool provided for %s instance, falling back to common InMemoryKeystorePool()",
                self.__class__.__name__,
            )
            keystore_pool = DUMMY_KEYSTORE_POOL
        assert isinstance(keystore_pool, KeystorePoolBase), keystore_pool
        self._keystore_pool = keystore_pool
        self._passphrase_mapper = passphrase_mapper or {}


# FIXME make it a STATIC METHOD of CryptainerBase ?
def _get_cryptainer_inline_ciphertext_value(cryptainer):
    assert "payload_ciphertext_struct" in cryptainer, list(cryptainer.keys())
    payload_ciphertext_struct = cryptainer["payload_ciphertext_struct"]
    assert (
        payload_ciphertext_struct["ciphertext_location"] == PAYLOAD_CIPHERTEXT_LOCATIONS.INLINE
    ), payload_ciphertext_struct["ciphertext_location"]
    ciphertext_value = payload_ciphertext_struct["ciphertext_value"]
    assert isinstance(ciphertext_value, bytes), repr(ciphertext_value)  # Always (no more "special markers")
    return ciphertext_value


def get_trustee_proxy(trustee: dict, keystore_pool: KeystorePoolBase):
    """
    Return an TrusteeApi subclass instance (or proxy) depending on the content of `trustee` dict.
    """
    assert isinstance(trustee, dict), trustee

    trustee_type = trustee.get("trustee_type")  # Might be None

    if trustee_type == CRYPTAINER_TRUSTEE_TYPES.LOCAL_KEYFACTORY_TRUSTEE:
        return TrusteeApi(keystore_pool.get_local_keyfactory())
    elif trustee_type == CRYPTAINER_TRUSTEE_TYPES.AUTHENTICATOR_TRUSTEE:
        keystore_uid = trustee["keystore_uid"]  # ID of authenticator is identical to that of its keystore
        readonly_keystore = keystore_pool.get_foreign_keystore(keystore_uid)
        assert not isinstance(readonly_keystore, FilesystemKeystore), readonly_keystore  # NOT writable for safety
        return ReadonlyTrusteeApi(readonly_keystore)
    elif trustee_type == CRYPTAINER_TRUSTEE_TYPES.JSONRPC_API_TRUSTEE:
        return JsonRpcProxy(url=trustee["jsonrpc_url"], response_error_handler=status_slugs_response_error_handler)
    raise ValueError("Unrecognized trustee identifiers: %s" % str(trustee))

