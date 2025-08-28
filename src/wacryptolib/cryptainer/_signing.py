# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later


from typing import Optional
import uuid

from wacryptolib.cryptainer import get_trustee_proxy, logger, SIGNATURE_POLICIES
from wacryptolib.exceptions import SignatureVerificationError
from wacryptolib.keystore import KeystorePoolBase


def _do_get_message_signature(signature_conf, default_keychain_uid, keystore_pool):
    payload_digest_algo = signature_conf["payload_digest_algo"]
    payload_signature_algo = signature_conf["payload_signature_algo"]

    payload_digest = signature_conf.get("payload_digest_value")

    if payload_digest is None:
        raise SignatureVerificationError(
            "No %s digest available in %s signature configuration" % (payload_digest_algo, payload_signature_algo)
        )

    trustee_proxy = get_trustee_proxy(trustee=signature_conf["payload_signature_trustee"], keystore_pool=keystore_pool)

    keychain_uid_for_signature = signature_conf.get("keychain_uid") or default_keychain_uid

    logger.debug("Signing %s digest with algo %r", payload_digest_algo, payload_signature_algo)
    payload_signature_struct = trustee_proxy.get_message_signature(
        keychain_uid=keychain_uid_for_signature, message=payload_digest, signature_algo=payload_signature_algo
    )

    assert payload_signature_struct is not None, "Wrong payload_signature_struct None"
    return payload_signature_struct


def _retrieve_and_inject_message_signature(
    signature_conf: dict, default_keychain_uid: uuid.UUID, signature_policy: str, keystore_pool: KeystorePoolBase
) -> dict:
    """
    Generate a signature for a provided digest, and store it in signature_conf dict

    :param signature_conf: configuration tree of the signature, which SHOULD already contain the message digest
    :param signature_policy: how to handle signing operation and potential errors
    :param default_keychain_uid: default uuid for the set of encryption keys used
    :param keystore_pool: optional key storage pool, might be required by cryptoconf

    :return: dictionary with information needed to verify_integrity_tags signature
    """

    payload_digest_algo = signature_conf["payload_digest_algo"]
    payload_signature_algo = signature_conf["payload_signature_algo"]

    if signature_policy == SIGNATURE_POLICIES.SKIP_SIGNING:
        logger.debug(
            "Skipping signing of %s digest with algo %r, per signature policy",
            payload_digest_algo,
            payload_signature_algo,
        )
        return

    try:
        payload_signature_struct = _do_get_message_signature(signature_conf, default_keychain_uid, keystore_pool)
        assert payload_signature_struct, payload_signature_struct
        signature_conf["payload_signature_struct"] = payload_signature_struct

    except Exception as exc:
        if signature_policy == SIGNATURE_POLICIES.ATTEMPT_SIGNING:
            logger.warning(
                "Abort signing of %s digest with algo %r, due to exception: %r",
                payload_digest_algo,
                payload_signature_algo,
                exc,
            )
        else:
            raise  # Let frames below handle/log this error


def _inject_payload_digests_and_signatures(
    signature_confs: list,
    payload_digests: dict,
    default_keychain_uid: uuid.UUID,
    signature_policy: Optional[str],
    keystore_pool: KeystorePoolBase,
):
    _encountered_payload_hash_algos = set()

    for signature_conf in signature_confs:
        payload_hash_algo = signature_conf["payload_digest_algo"]

        signature_conf["payload_digest_value"] = payload_digests[payload_hash_algo]  # MUST exist, else incoherence

        # payload_signature_struct = self._generate_message_signature(
        _retrieve_and_inject_message_signature(
            signature_conf=signature_conf,
            default_keychain_uid=default_keychain_uid,
            signature_policy=signature_policy,
            keystore_pool=keystore_pool,
        )

        _encountered_payload_hash_algos.add(payload_hash_algo)
    assert _encountered_payload_hash_algos == set(payload_digests)  # No abnormal extra digest

