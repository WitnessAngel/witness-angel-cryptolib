# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import logging

logger = logging.getLogger(__name__)

# Beware, the order of these imports is crucial, all submodules are supposed
# to import their own utilities from THIS __init__.py file, not from each other

from ._base import (CRYPTAINER_SUFFIX, CRYPTAINER_DATETIME_FORMAT, CRYPTAINER_DATETIME_LENGTH,
                          CRYPTAINER_TEMP_SUFFIX, PAYLOAD_CIPHERTEXT_LOCATIONS, OFFLOADED_PAYLOAD_CIPHERTEXT_MARKER,
                          OFFLOADED_PAYLOAD_FILENAME_SUFFIX, DEFAULT_DATA_CHUNK_SIZE, DECRYPTED_FILE_SUFFIX,
                          DUMMY_KEYSTORE_POOL, CRYPTAINER_TRUSTEE_TYPES,
                          LOCAL_KEYFACTORY_TRUSTEE_MARKER, SIGNATURE_POLICIES)
from ._base import CryptainerBase, get_trustee_id, get_trustee_proxy, _get_cryptainer_inline_ciphertext_value

from ._flightbox import CRYPTAINER_FORMAT, SHARED_SECRET_ALGO_MARKER, CRYPTAINER_STATES, FlightboxUtilitiesBase, FlightBox

from ._authorization import request_decryption_authorizations

from ._analysis import gather_trustee_dependencies, gather_decryptable_symkeys, is_cryptainer_cryptoconf_streamable

from ._validation import (_validate_data_tree, check_cryptoconf_sanity, check_cryptainer_sanity,
                          check_sigconf_sanity, check_sigainer_sanity)

from ._signing import _do_get_message_signature, _inject_payload_digests_and_signatures

from ._filesystem import _get_offloaded_file_path, dump_cryptainer_to_filesystem, load_cryptainer_from_filesystem, \
    delete_cryptainer_from_filesystem, get_cryptainer_size_on_filesystem

from ._decryptor import DecryptionErrorType, DecryptionErrorCriticity, OperationReport, CryptainerDecryptor

from ._encryptor import CryptainerEncryptor
from ._encryption_pipeline import CryptainerEncryptionPipeline

from ._shortcuts import encrypt_payload_and_stream_cryptainer_to_filesystem, \
    encrypt_payload_into_cryptainer, decrypt_payload_from_cryptainer, extract_metadata_from_cryptainer,  \
    get_cryptoconf_summary

from ._storage import ReadonlyCryptainerStorage, CryptainerStorage
