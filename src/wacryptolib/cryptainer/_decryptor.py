# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import contextlib
import logging
from pprint import pformat
from typing import Optional
import uuid

from jsonrpc_requests import JSONRPCError
from schema import Schema, Or, And

from wacryptolib.cipher import decrypt_bytestring, SUPPORTED_CIPHER_ALGOS
from wacryptolib.cryptainer import CryptainerBase, logger, CRYPTAINER_FORMAT, SHARED_SECRET_ALGO_MARKER, get_trustee_id, \
    get_trustee_proxy, _validate_data_tree, _get_cryptainer_inline_ciphertext_value
from wacryptolib.exceptions import KeyDoesNotExist, KeyLoadingError, DecryptionError, DecryptionIntegrityError, \
    KeystoreDoesNotExist, SignatureVerificationError
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.keygen import load_asymmetric_key_from_pem_bytestring, SUPPORTED_SYMMETRIC_KEY_ALGOS, \
    SUPPORTED_ASYMMETRIC_KEY_ALGOS
from wacryptolib.shared_secret import recombine_secret_from_shards
from wacryptolib.signature import verify_message_signature
from wacryptolib.utilities import load_from_json_bytes, hash_message


class DecryptionErrorType:  # FIXME RENAME THIS
    INFORMATION = "INFORMATION"
    SIGNATURE_ERROR = "SIGNATURE_ERROR"
    SYMMETRIC_DECRYPTION_ERROR = "SYMMETRIC_DECRYPTION_ERROR"
    ASYMMETRIC_DECRYPTION_ERROR = "ASYMMETRIC_DECRYPTION_ERROR"


class DecryptionErrorCriticity:  # FIXME rename that
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"  # Potentially non-fatal error
    CRITICAL = "CRITICAL"  # Fatal error


OPERATION_REPORT_ENTRY_SCHEMA = Schema(
    {
        "entry_type": Or(
            DecryptionErrorType.INFORMATION,
            DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
            DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
            DecryptionErrorType.SIGNATURE_ERROR,
        ),
        "entry_criticity": Or(
            DecryptionErrorCriticity.INFO,
            DecryptionErrorCriticity.ERROR,
            DecryptionErrorCriticity.WARNING,
            DecryptionErrorCriticity.CRITICAL,
        ),
        "entry_message": And(str, len),
        "entry_exception": Or(Exception, None),
        "entry_nesting": And(int, lambda x: x >= 0),
    }
)


class OperationReport:
    """
    Wrapper around a list of operation info/error entries with different levels of imbrication.
    """

    def __init__(self):
        self._current_nesting = 0
        self._entries = []

    def __len__(self):
        return len(self._entries)

    @contextlib.contextmanager
    def operation_section(self, section_message):
        """Add an INFO message and add an extra level to entries in the with... keyword"""
        self.add_information(section_message)
        self._current_nesting += 1  # NOw only we raise the
        try:
            yield
        finally:
            self._current_nesting -= 1

    def add_entry(
        self,
        entry_type: str,
        entry_message: str,
        entry_criticity=DecryptionErrorCriticity.WARNING,
        entry_exception=None,
    ):
        # We immediately forward entry to standard logging too, but always in DEBUG level!
        if entry_exception:
            logger.debug("%s report entry: %s (%r)", entry_type, entry_message, entry_exception)
        else:
            logger.debug("%s report entry: %s", entry_type, entry_message)

        error_entry = {
            "entry_type": entry_type,
            "entry_criticity": entry_criticity,
            "entry_message": entry_message,
            "entry_exception": entry_exception,
            "entry_nesting": self._current_nesting,
        }

        if __debug__:  # Sanity check
            from wacryptolib.cryptainer import _validate_data_tree  # LAZY import!
            _validate_data_tree(data_tree=error_entry, validation_schema=OPERATION_REPORT_ENTRY_SCHEMA)

        self._entries.append(error_entry)

    def add_information(self, entry_message):
        self.add_entry(
            entry_type=DecryptionErrorType.INFORMATION,
            entry_message=entry_message,
            entry_criticity=DecryptionErrorCriticity.INFO,
        )

    def get_all_entries(self):
        return self._entries[:]  # COPY

    def get_error_entries(self):
        return [x for x in self._entries if x["entry_criticity"] != DecryptionErrorCriticity.INFO]

    def get_error_count(self):
        return len(self.get_error_entries())

    def has_errors(self):
        """Returns True iff report contains warnings/erros"""
        return bool(self.get_error_count())

    def format_entries(self):  # FIXME improve that
        return pformat(self._entries)


class CryptainerDecryptor(CryptainerBase):
    """
    THIS CLASS IS PRIVATE API

    Contains every method used to read and decrypt a cryptainer, IN MEMORY.
    """

    def extract_cryptainer_metadata(self, cryptainer: dict) -> Optional[dict]:
        assert isinstance(cryptainer, dict), cryptainer
        return cryptainer["cryptainer_metadata"]

    def _decrypt_with_local_private_key(
        self, cipherdict: dict, keychain_uid: uuid.UUID, cipher_algo: str, operation_report: OperationReport
    ):
        # TODO USE TrusteeApi() with local keystore then decrypt_with_private_key() function, instead ???
        keystore = self._keystore_pool.get_local_keyfactory()
        key_struct_bytes = None  # Returns "None" when unable to decrypt with the answer key

        try:
            private_key_pem = keystore.get_private_key(keychain_uid=keychain_uid, key_algo=cipher_algo)
        except KeyDoesNotExist as exc:
            operation_report.add_entry(
                entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                entry_message="Private key of revelation response not found (%s/%s)" % (cipher_algo, keychain_uid),
                entry_criticity=DecryptionErrorCriticity.ERROR,
                entry_exception=exc,
            )
            return key_struct_bytes

        try:
            private_key = load_asymmetric_key_from_pem_bytestring(key_pem=private_key_pem, key_algo=cipher_algo)

        except KeyLoadingError as exc:
            operation_report.add_entry(
                entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                entry_message="Failed loading revelation response key of from pem bytestring (%s)" % cipher_algo,
                entry_criticity=DecryptionErrorCriticity.ERROR,
                entry_exception=exc,
            )

            return key_struct_bytes

        try:
            key_struct_bytes = decrypt_bytestring(
                cipherdict=cipherdict, cipher_algo=cipher_algo, key_dict=dict(key=private_key)
            )
        except DecryptionError as exc:
            operation_report.add_entry(
                entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                entry_message="Failed decryption of remote symkey/shard %s (%s) " % (cipher_algo, exc),
                entry_criticity=DecryptionErrorCriticity.ERROR,
                entry_exception=exc,
            )

        return key_struct_bytes

    def _unwrap_predecrypted_symkeys(self, successful_symkey_decryptions, operation_report: OperationReport):
        predecrypted_symkey_mapper = {}

        for symkey_decryption in successful_symkey_decryptions:
            keychain_uid = symkey_decryption["revelation_request"]["revelation_response_keychain_uid"]
            cipher_algo = symkey_decryption["revelation_request"]["revelation_response_key_algo"]

            request_data = symkey_decryption["symkey_decryption_request_data"]

            cipherdict = load_from_json_bytes(symkey_decryption["symkey_decryption_response_data"])

            # FIXME handle errors?
            # FIXME immediately deserialize "key_struct_bytes" here and handle operation_report ? Or somewhere else ?
            key_struct_bytes = self._decrypt_with_local_private_key(
                cipherdict=cipherdict,
                keychain_uid=keychain_uid,
                cipher_algo=cipher_algo,
                operation_report=operation_report,
            )

            if key_struct_bytes:
                predecrypted_symkey_mapper.setdefault(request_data, key_struct_bytes)

        return predecrypted_symkey_mapper

    def _get_single_gateway_revelation_request_list(
        self, gateway_url: str, revelation_requestor_uid: uuid.UUID, operation_report: OperationReport
    ):
        assert gateway_url and revelation_requestor_uid  # By construction

        gateway_revelation_request_list = []

        gateway_proxy = JsonRpcProxy(url=gateway_url, response_error_handler=status_slugs_response_error_handler)
        try:
            gateway_revelation_request_list = gateway_proxy.list_requestor_revelation_requests(
                revelation_requestor_uid=revelation_requestor_uid
            )
        except (JSONRPCError, OSError) as exc:
            operation_report.add_entry(
                entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                entry_message="Unable to reach remote server %s" % gateway_url,
                entry_exception=exc,
            )
        return gateway_revelation_request_list

    def _get_multiple_gateway_revelation_request_list(
        self, gateway_urls: list, revelation_requestor_uid: uuid.UUID, operation_report: OperationReport
    ):
        assert gateway_urls and revelation_requestor_uid  # By construction

        multiple_gateway_revelation_request_list = []
        for gateway_url in gateway_urls:
            gateway_revelation_request_list = self._get_single_gateway_revelation_request_list(
                gateway_url, revelation_requestor_uid, operation_report=operation_report
            )
            multiple_gateway_revelation_request_list.extend(gateway_revelation_request_list)

        return multiple_gateway_revelation_request_list

    def _get_successful_symkey_decryptions(
        self,
        cryptainer: dict,
        gateway_urls: list,
        revelation_requestor_uid: uuid.UUID,
        operation_report: OperationReport,
    ) -> list:
        ACCEPTED = "ACCEPTED"
        REJECTED = "REJECTED"  # USE LATER

        multiple_gateway_revelation_request_list = self._get_multiple_gateway_revelation_request_list(
            gateway_urls, revelation_requestor_uid, operation_report=operation_report
        )

        successful_symkey_decryptions = []

        if multiple_gateway_revelation_request_list:
            for revelation_request in multiple_gateway_revelation_request_list:
                revelation_request_per_symkey = {
                    key: value for key, value in revelation_request.items() if key != "symkey_decryption_requests"
                }

                # Allow not to verify all decryption requests
                if revelation_request["revelation_request_status"] == ACCEPTED:
                    for symkey_decryption in revelation_request["symkey_decryption_requests"]:
                        if (
                            symkey_decryption["cryptainer_uid"] == cryptainer["cryptainer_uid"]
                            and symkey_decryption["symkey_decryption_status"] == "DECRYPTED"
                        ):
                            symkey_decryption_accepted_for_cryptainer = dict(
                                symkey_decryption.items()
                            )  # FIXME use .copy()
                            symkey_decryption_accepted_for_cryptainer[
                                "revelation_request"
                            ] = revelation_request_per_symkey
                            successful_symkey_decryptions.append(symkey_decryption_accepted_for_cryptainer)

        # FIXME add info/warning for rejected requests???

        return successful_symkey_decryptions

    def decrypt_payload(  # FIXME test the cases with gateway_urls or revelation_requestor_uid empty
        self,
        cryptainer: dict,
        verify_integrity_tags: bool = True,
        gateway_urls: Optional[list] = None,
        revelation_requestor_uid: Optional[uuid.UUID] = None,
    ) -> tuple:
        """
        Loop through cryptainer layers, to decipher payload with the right algorithms.

        Decryption was successful if and only if plaintext returned is not None

        :param cryptainer: dictionary previously built with CryptainerEncryptor method
        :param verify_integrity_tags: whether to check MAC tags of the ciphertext

        :return: deciphered plaintext and operation report
        """
        predecrypted_symkey_mapper = None
        operation_report = OperationReport()

        if revelation_requestor_uid and gateway_urls:
            successful_symkey_decryptions = self._get_successful_symkey_decryptions(
                cryptainer=cryptainer,
                gateway_urls=gateway_urls,
                revelation_requestor_uid=revelation_requestor_uid,
                operation_report=operation_report,
            )

            predecrypted_symkey_mapper = self._unwrap_predecrypted_symkeys(
                successful_symkey_decryptions=successful_symkey_decryptions, operation_report=operation_report
            )
            operation_report.add_information(
                "Performed retrieval of remotely predecrypted symkeys: %d found" % len(predecrypted_symkey_mapper)
            )
        else:
            operation_report.add_information(
                "Skipping retrieval of remotely predecrypted symkeys (requires requestor-uid and gateway urls)"
            )

        assert isinstance(cryptainer, dict), cryptainer

        cryptainer_format = cryptainer["cryptainer_format"]
        if cryptainer_format != CRYPTAINER_FORMAT:
            raise ValueError("Unknown cryptainer format %s" % cryptainer_format)

        cryptainer_uid = cryptainer["cryptainer_uid"]
        del cryptainer_uid  # Might be used for logging etc, later...

        default_keychain_uid = cryptainer["keychain_uid"]

        cryptainer_metadata = cryptainer["cryptainer_metadata"]

        payload_current = _get_cryptainer_inline_ciphertext_value(cryptainer)

        # Non-emptiness of this will be checked by validator
        payload_cipher_layer_count = len(cryptainer["payload_cipher_layers"])

        for payload_cipher_layer_idx, payload_cipher_layer in enumerate(
            reversed(cryptainer["payload_cipher_layers"]), start=1
        ):
            with operation_report.operation_section(
                "Starting decryption of payload cipher layer %d/%d (algo: %s)"
                % (payload_cipher_layer_idx, payload_cipher_layer_count, payload_cipher_layer["payload_cipher_algo"])
            ):
                payload_current = self._decrypt_single_payload_cipher_layer(
                    payload_ciphertext=payload_current,
                    payload_cipher_layer=payload_cipher_layer,
                    verify_integrity_tags=verify_integrity_tags,
                    default_keychain_uid=default_keychain_uid,
                    cryptainer_metadata=cryptainer_metadata,
                    operation_report=operation_report,
                    predecrypted_symkey_mapper=predecrypted_symkey_mapper,
                )
                if payload_current is None:
                    """TODO PUT BACK LATER
                    operation_report.add_entry(
                        entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
                        entry_criticity=DecryptionErrorCriticity.CRITICAL,
                        entry_message="Payload cipher layer decryption failed, aborting decryption of cryptainer",
                    )
                    """
                    break

        if payload_current is not None:
            for signature_conf in cryptainer.get("payload_plaintext_signatures", ()):
                self._verify_payload_signature(  # Should NOT raise for now, just report errors!
                    default_keychain_uid=default_keychain_uid,
                    payload=payload_current,
                    cryptoconf=signature_conf,
                    operation_report=operation_report,
                )

        return payload_current, operation_report

    def _decrypt_single_payload_cipher_layer(
        self,
        payload_ciphertext: bytes,
        payload_cipher_layer: dict,
        verify_integrity_tags: bool,
        default_keychain_uid: uuid.UUID,
        cryptainer_metadata: Optional[dict],
        operation_report: OperationReport,
        predecrypted_symkey_mapper: Optional[dict],
    ) -> Optional[bytes]:
        assert isinstance(payload_ciphertext, bytes), repr(payload_ciphertext)
        payload_cipher_algo = payload_cipher_layer["payload_cipher_algo"]

        for signature_conf in payload_cipher_layer["payload_ciphertext_signatures"]:
            self._verify_payload_signature(  # Should NOT raise for now, just report errors!
                default_keychain_uid=default_keychain_uid,
                payload=payload_ciphertext,
                cryptoconf=signature_conf,
                operation_report=operation_report,
            )

        key_cipher_layers = payload_cipher_layer["key_cipher_layers"]
        operation_report.add_information(
            "Decrypting %s symmetric key through %d cipher layer(s)" % (payload_cipher_algo, len(key_cipher_layers))
        )

        key_ciphertext = payload_cipher_layer["key_ciphertext"]  # We start fully encrypted, and unravel it
        key_bytes = self._decrypt_key_through_multiple_layers(
            default_keychain_uid=default_keychain_uid,
            key_ciphertext=key_ciphertext,
            key_cipher_layers=key_cipher_layers,
            cryptainer_metadata=cryptainer_metadata,
            predecrypted_symkey_mapper=predecrypted_symkey_mapper,
            operation_report=operation_report,
        )

        if key_bytes is not None:
            assert isinstance(key_bytes, bytes), key_bytes
            symkey = load_from_json_bytes(key_bytes)

            payload_macs = payload_cipher_layer[
                "payload_macs"
            ]  # FIXME handle and test if it's None: missing integrity tags due to unfinished container!!
            payload_cipherdict = dict(ciphertext=payload_ciphertext, **payload_macs)
            try:
                payload_cleartext = decrypt_bytestring(
                    cipherdict=payload_cipherdict,
                    key_dict=symkey,
                    cipher_algo=payload_cipher_algo,
                    verify_integrity_tags=verify_integrity_tags,
                )
                assert isinstance(payload_cleartext, bytes), payload_cleartext  # Now decrypted

            except DecryptionIntegrityError as exc:
                operation_report.add_entry(
                    entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
                    entry_criticity=DecryptionErrorCriticity.ERROR,
                    entry_message="Failed decryption authentication %s (MAC check failed)" % payload_cipher_algo,
                    entry_exception=exc,
                )
                payload_cleartext = None

            except DecryptionError as exc:
                operation_report.add_entry(
                    entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
                    entry_criticity=DecryptionErrorCriticity.ERROR,
                    entry_message="Failed symmetric decryption (%s)" % payload_cipher_algo,
                    entry_exception=exc,
                )
                payload_cleartext = None
        else:
            payload_cleartext = None
            operation_report.add_entry(
                entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
                entry_criticity=DecryptionErrorCriticity.ERROR,
                entry_message="Failed symmetric decryption (%s)"
                % payload_cipher_algo,  # FIXME change this message to "aborted"? Or just skip this step?
                entry_exception=None,
            )

        return payload_cleartext  # Might be None

    def _decrypt_key_through_multiple_layers(
        self,
        default_keychain_uid: uuid.UUID,
        key_ciphertext: bytes,
        key_cipher_layers: list,
        cryptainer_metadata: Optional[dict],
        operation_report: OperationReport,
        predecrypted_symkey_mapper: Optional[dict] = None,
    ) -> Optional[bytes]:
        assert len(key_cipher_layers), key_cipher_layers  # Extra safety

        key_bytes = None

        for key_cipher_layer in reversed(key_cipher_layers):
            key_ciphertext = self._decrypt_key_through_single_layer(
                default_keychain_uid=default_keychain_uid,
                key_ciphertext=key_ciphertext,
                key_cipher_layer=key_cipher_layer,
                cryptainer_metadata=cryptainer_metadata,
                predecrypted_symkey_mapper=predecrypted_symkey_mapper,
                operation_report=operation_report,
            )
            if not key_ciphertext:
                break  # It would too complicated to analyse other cipher_layers without valid key_ciphertext
        else:
            key_bytes = key_ciphertext  # Fully decrypted version

        return key_bytes

    def _decrypt_key_through_single_layer(
        self,
        default_keychain_uid: uuid.UUID,
        key_ciphertext: bytes,
        key_cipher_layer: dict,
        cryptainer_metadata: Optional[dict],
        operation_report: OperationReport,
        predecrypted_symkey_mapper: Optional[dict] = None,
    ) -> Optional[bytes]:
        """
        Function called when decryption of a symmetric key is needed. Encryption may be made by shared secret or
        by a asymmetric algorithm.

        :param default_keychain_uid: default uuid for the set of encryption keys used
        :param key_ciphertext: encrypted symmetric key
        :param key_cipher_layer: part of the cryptainer related to this key encryption layer

        :return: deciphered symmetric key
        """
        key_bytes = None

        assert isinstance(key_ciphertext, bytes), key_ciphertext

        key_cipherdict = load_from_json_bytes(key_ciphertext)
        assert isinstance(key_cipherdict, dict), key_cipherdict

        key_cipher_algo = key_cipher_layer["key_cipher_algo"]

        if key_cipher_algo == SHARED_SECRET_ALGO_MARKER:
            decrypted_shards = []
            key_shared_secret_shards = key_cipher_layer["key_shared_secret_shards"]
            key_shared_secret_threshold = key_cipher_layer["key_shared_secret_threshold"]

            shard_ciphertexts = key_cipherdict["shard_ciphertexts"]

            with operation_report.operation_section(
                "Deciphering %d shards of shared secret (threshold: %d)"
                % (len(shard_ciphertexts), key_shared_secret_threshold)
            ):
                # If some shards are missing, we won't detect it here because zip() stops at shortest list
                for shard_idx, (shard_ciphertext, key_shared_secret_shard_conf) in enumerate(
                    zip(shard_ciphertexts, key_shared_secret_shards), start=1
                ):
                    operation_report.add_information(
                        "Decrypting shard #%d through %d cipher layer(s)"
                        % (shard_idx, len(key_shared_secret_shard_conf["key_cipher_layers"]))
                    )

                    shard_bytes = self._decrypt_key_through_multiple_layers(
                        default_keychain_uid=default_keychain_uid,
                        key_ciphertext=shard_ciphertext,
                        key_cipher_layers=key_shared_secret_shard_conf["key_cipher_layers"],
                        cryptainer_metadata=cryptainer_metadata,
                        predecrypted_symkey_mapper=predecrypted_symkey_mapper,
                        operation_report=operation_report,
                    )  # Recursive structure
                    if shard_bytes is not None:
                        shard = load_from_json_bytes(
                            shard_bytes
                        )  # The tuple (idx, payload) of each shard thus becomes encryptable
                        decrypted_shards.append(shard)
                    else:
                        operation_report.add_entry(
                            entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                            entry_message="A previous error prevented decrypting this shard",
                            entry_exception=None,
                        )

                    if len(decrypted_shards) == key_shared_secret_threshold:
                        break

                if len(decrypted_shards) < key_shared_secret_threshold:
                    operation_report.add_entry(
                        entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                        entry_message="Shared secret failure! %s valid shard(s) missing for reconstitution "
                        "of symmetric key" % (key_shared_secret_threshold - len(decrypted_shards)),
                        entry_exception=None,
                    )

                else:
                    operation_report.add_information(
                        "A sufficient number of shared-secret shards (%d) have been decrypted" % len(decrypted_shards)
                    )
                    key_bytes = recombine_secret_from_shards(shards=decrypted_shards)

        elif key_cipher_algo in SUPPORTED_SYMMETRIC_KEY_ALGOS:
            assert key_cipher_algo in SUPPORTED_CIPHER_ALGOS, key_cipher_algo  # Not a SIGNATURE algo

            sub_symkey_ciphertext = key_cipher_layer["key_ciphertext"]

            operation_report.add_information(
                "Decrypting %s symmetric key through %d cipher layer(s)"
                % (key_cipher_algo, len(key_cipher_layer["key_cipher_layers"]))
            )

            sub_symkey_bytes = self._decrypt_key_through_multiple_layers(
                default_keychain_uid=default_keychain_uid,
                key_ciphertext=sub_symkey_ciphertext,
                key_cipher_layers=key_cipher_layer["key_cipher_layers"],
                cryptainer_metadata=cryptainer_metadata,
                predecrypted_symkey_mapper=predecrypted_symkey_mapper,
                operation_report=operation_report,
            )  # Recursive structure

            if sub_symkey_bytes:
                sub_symkey_dict = load_from_json_bytes(sub_symkey_bytes)
                try:
                    key_bytes = decrypt_bytestring(
                        key_cipherdict, cipher_algo=key_cipher_algo, key_dict=sub_symkey_dict
                    )
                except DecryptionError as exc:
                    operation_report.add_entry(
                        entry_type=DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
                        entry_message="Error decrypting key with symmetric algorithm %s" % key_cipher_algo,
                        entry_criticity=DecryptionErrorCriticity.ERROR,
                        entry_exception=exc,
                    )

        else:  # Using asymmetric algorithm
            assert key_cipher_algo in SUPPORTED_ASYMMETRIC_KEY_ALGOS
            assert key_cipher_algo in SUPPORTED_CIPHER_ALGOS, key_cipher_algo  # Not a SIGNATURE algo

            keychain_uid = key_cipher_layer.get("keychain_uid") or default_keychain_uid
            trustee = key_cipher_layer["key_cipher_trustee"]

            trustee_label = trustee["trustee_type"]
            if "keystore_owner" in trustee:
                trustee_label += " " + trustee["keystore_owner"]

            with operation_report.operation_section(
                "Attempting to decrypt key with asymmetric algorithm %s (trustee: %s)"
                % (key_cipher_algo, trustee_label)
            ):
                predecrypted_symmetric_key = self._get_predecrypted_symkey_or_none(
                    key_ciphertext, predecrypted_symkey_mapper=predecrypted_symkey_mapper
                )
                if predecrypted_symmetric_key:
                    operation_report.add_information(
                        "Predecrypted symmetric key found (e.g. coming from remote trustee)"
                    )
                    key_bytes = predecrypted_symmetric_key
                else:
                    operation_report.add_information(
                        "No predecrypted symmetric found (e.g. coming from remote trustee)"
                    )
                    key_bytes = self._decrypt_with_asymmetric_cipher(
                        cipher_algo=key_cipher_algo,
                        keychain_uid=keychain_uid,
                        cipherdict=key_cipherdict,
                        trustee=trustee,
                        cryptainer_metadata=cryptainer_metadata,
                        operation_report=operation_report,
                    )

        return key_bytes

    @staticmethod
    def _get_predecrypted_symkey_or_none(key_ciphertext, predecrypted_symkey_mapper: Optional[dict]) -> Optional[bytes]:
        predecrypted_symkey = None

        if predecrypted_symkey_mapper and (key_ciphertext in predecrypted_symkey_mapper):
            predecrypted_symkey_json = predecrypted_symkey_mapper[key_ciphertext]
            ##print(">>> predecrypted_symkey_json", repr(predecrypted_symkey_json))
            predecrypted_symkey_struct = load_from_json_bytes(predecrypted_symkey_json)
            predecrypted_symkey = predecrypted_symkey_struct["key_bytes"]

        return predecrypted_symkey

    @staticmethod
    def _build_operation_report_entry_______(  # FIXME REMOVE THIS
        entry_type: str, entry_message: str, entry_criticity=DecryptionErrorCriticity.WARNING, entry_exception=None
    ) -> dict:
        # We forward entry to standard logging too
        log_level = getattr(logging, entry_criticity)  # Same identifiers in the 2 worlds
        if entry_exception:
            logger.log(log_level, "%s report entry: %s (%r)", entry_type, entry_message, entry_exception)
        else:
            logger.log(log_level, "%s report entry: %s", entry_type, entry_message)

        error_entry = {
            "entry_type": entry_type,
            "entry_criticity": entry_criticity,
            "entry_message": entry_message,
            "entry_exception": entry_exception,
        }

        SCHEMA_ERROR = Schema(  # FIXME move that OUT of here
            {
                "entry_type": Or(
                    DecryptionErrorType.SYMMETRIC_DECRYPTION_ERROR,
                    DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                    DecryptionErrorType.SIGNATURE_ERROR,
                ),
                "entry_criticity": Or(DecryptionErrorCriticity.ERROR, DecryptionErrorCriticity.WARNING),
                "entry_message": And(str, len),
                "entry_exception": Or(Exception, None),
            }
        )

        _validate_data_tree(data_tree=error_entry, validation_schema=SCHEMA_ERROR)

        return error_entry

    def _decrypt_with_asymmetric_cipher(
        self,
        cipher_algo: str,
        keychain_uid: uuid.UUID,
        cipherdict: dict,
        trustee: dict,
        cryptainer_metadata: Optional[dict],
        operation_report: OperationReport,
    ) -> Optional[bytes]:
        """
        Decrypt given cipherdict with an asymmetric algorithm.

        :param cipher_algo: string with name of algorithm to use
        :param keychain_uid: final uuid for the set of encryption keys used
        :param cipherdict: dictionary with payload components needed to decrypt the ciphered payload
        :param trustee: trustee used for encryption (findable in configuration tree)

        :return: decypted payload as bytes
        """
        key_bytes = None

        trustee_id = get_trustee_id(trustee)
        passphrases = self._passphrase_mapper.get(trustee_id) or []
        assert isinstance(passphrases, list), repr(passphrases)  # No SINGLE passphrase here

        passphrases += self._passphrase_mapper.get(None) or []  # Add COMMON passphrases

        operation_report.add_information(
            "Attempting actual decryption of key using asymmetric algorithm %s (via trustee)" % cipher_algo
        )

        try:
            trustee_proxy = get_trustee_proxy(trustee=trustee, keystore_pool=self._keystore_pool)
        except KeystoreDoesNotExist as exc:
            operation_report.add_entry(
                entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                entry_message="Trustee key storage not found (%s)" % trustee["keystore_uid"],
                entry_exception=exc,
            )

        else:
            try:
                # We expect decryption authorization requests to have already been done properly
                key_struct_bytes = trustee_proxy.decrypt_with_private_key(
                    keychain_uid=keychain_uid,
                    cipher_algo=cipher_algo,
                    cipherdict=cipherdict,
                    passphrases=passphrases,
                    cryptainer_metadata=cryptainer_metadata,
                )
                key_struct = load_from_json_bytes(key_struct_bytes)
                key_bytes = key_struct["key_bytes"]
                assert isinstance(key_bytes, bytes), key_bytes

                actual_cryptainer_metadata = key_struct[
                    "cryptainer_metadata"
                ]  # Metadata stored along the encrypted key!
                del actual_cryptainer_metadata  # No use for now

            except KeyDoesNotExist as exc:
                operation_report.add_entry(
                    entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                    entry_message="Private key not found (%s/%s)" % (cipher_algo, keychain_uid),
                    entry_exception=exc,
                )

            except KeyLoadingError as exc:
                operation_report.add_entry(
                    entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                    entry_message="Could not load private key %s/%s (missing passphrase?)"
                    % (cipher_algo, keychain_uid),
                    entry_exception=exc,
                )

            except DecryptionError as exc:
                operation_report.add_entry(
                    entry_type=DecryptionErrorType.ASYMMETRIC_DECRYPTION_ERROR,
                    entry_message="Failed decrypting key with asymmetric algorithm %s" % cipher_algo,
                    entry_criticity=DecryptionErrorCriticity.ERROR,
                    entry_exception=exc,
                )

        return key_bytes

    def _verify_payload_signature(
        self, default_keychain_uid: uuid.UUID, payload: bytes, cryptoconf: dict, operation_report: OperationReport
    ):
        """
        Verify a signature for a specific message.

        DOES NOT raise for now, just reports troubels in operation_report.

        :param default_keychain_uid: default uuid for the set of encryption keys used
        :param payload: payload on which to verify signature (after digest)
        :param cryptoconf: configuration tree inside payload_\*_signatures
        """

        payload_hash_algo = cryptoconf["payload_digest_algo"]
        payload_signature_algo = cryptoconf["payload_signature_algo"]
        keychain_uid = cryptoconf.get("keychain_uid") or default_keychain_uid
        trustee_proxy = get_trustee_proxy(
            trustee=cryptoconf["payload_signature_trustee"], keystore_pool=self._keystore_pool
        )
        try:
            public_key_pem = trustee_proxy.fetch_public_key(
                keychain_uid=keychain_uid, key_algo=payload_signature_algo, must_exist=True
            )
        except KeyDoesNotExist as exc:
            message = "Public signature key %s/%s not found" % (payload_signature_algo, keychain_uid)
            operation_report.add_entry(
                entry_type=DecryptionErrorType.SIGNATURE_ERROR,
                entry_message=message,
                entry_exception=exc,
            )
            return

        try:
            public_key = load_asymmetric_key_from_pem_bytestring(
                key_pem=public_key_pem, key_algo=payload_signature_algo
            )
        except KeyLoadingError as exc:
            message = "Failed loading signature key from pem bytestring (%s)" % payload_signature_algo
            operation_report.add_entry(
                entry_type=DecryptionErrorType.SIGNATURE_ERROR,
                entry_message=message,
                entry_exception=exc,
            )
            return

        payload_digest = hash_message(payload, hash_algo=payload_hash_algo)

        expected_payload_digest = cryptoconf.get("payload_digest_value")  # Might be missing
        if expected_payload_digest and expected_payload_digest != payload_digest:
            message = "Mismatch between actual and expected payload digests during signature verification"
            operation_report.add_entry(
                entry_type=DecryptionErrorType.SIGNATURE_ERROR,
                entry_message=message,
                entry_exception=None,
            )
            return

        payload_signature_struct = cryptoconf.get("payload_signature_struct")
        if not payload_signature_struct:
            message = "Missing signature structure"
            operation_report.add_entry(
                entry_type=DecryptionErrorType.SIGNATURE_ERROR,
                entry_message=message,
                entry_exception=None,
            )
            return

        else:
            try:
                verify_message_signature(
                    message=payload_digest,
                    signature_algo=payload_signature_algo,
                    signature=payload_signature_struct,
                    public_key=public_key,
                )  # Raises if troubles

            except SignatureVerificationError as exc:
                operation_report.add_entry(
                    entry_type=DecryptionErrorType.SIGNATURE_ERROR,
                    entry_message="Failed signature verification %s (%s)" % (payload_signature_algo, exc),
                    entry_exception=exc,
                )
                return