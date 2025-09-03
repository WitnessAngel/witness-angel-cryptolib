# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import contextlib
import copy
import logging
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from pprint import pformat
from typing import Optional, Union, Sequence, BinaryIO
from urllib.parse import urlparse

from jsonrpc_requests import JSONRPCError
from schema import And, Or, Schema

from wacryptolib.cipher import (
    encrypt_bytestring,
    decrypt_bytestring,
    PayloadEncryptionPipeline,
    STREAMABLE_CIPHER_ALGOS,
    SUPPORTED_CIPHER_ALGOS,
    _create_hashers_dict,
    _update_hashers_dict,
    _get_hashers_dict_digests,
)
from wacryptolib.cryptainer import CryptainerBase
from wacryptolib.cryptainer import _validate_data_tree, check_cryptainer_sanity
from wacryptolib.exceptions import (
    DecryptionError,
    SchemaValidationError,
    KeyDoesNotExist,
    KeyLoadingError,
    SignatureVerificationError,
    KeystoreDoesNotExist,
    DecryptionIntegrityError,
)
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.keygen import (
    generate_symkey,
    load_asymmetric_key_from_pem_bytestring,
    SUPPORTED_SYMMETRIC_KEY_ALGOS,
    SUPPORTED_ASYMMETRIC_KEY_ALGOS,
)
from wacryptolib.keystore import InMemoryKeystorePool, KeystorePoolBase, FilesystemKeystore
from wacryptolib.shared_secret import split_secret_into_shards, recombine_secret_from_shards
from wacryptolib.signature import verify_message_signature
from wacryptolib.trustee import TrusteeApi, ReadonlyTrusteeApi
from wacryptolib.utilities import (
    dump_to_json_bytes,
    load_from_json_bytes,
    dump_to_json_file,
    load_from_json_file,
    generate_uuid0,
    hash_message,
    synchronized,
    catch_and_log_exception,
    get_utc_now_date,
    consume_bytes_as_chunks,
    is_file_basename,
)













