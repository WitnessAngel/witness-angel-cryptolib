import time

import pytest
from Crypto.Random import get_random_bytes

from wacryptolib.encryption import _encrypt_via_rsa_oaep
from wacryptolib.escrow import (
    EscrowApi,
    generate_free_keypair_for_least_provisioned_key_type,
    get_free_keys_generator_worker,
)
from wacryptolib.key_generation import load_asymmetric_key_from_pem_bytestring
from wacryptolib.key_storage import DummyKeyStorage
from wacryptolib.signature import verify_message_signature
from wacryptolib.utilities import generate_uuid0


def test_escrow_api_workflow():

    key_storage = DummyKeyStorage()
    escrow_api = EscrowApi(key_storage=key_storage)

    keychain_uid = generate_uuid0()
    keychain_uid_other = generate_uuid0()
    keychain_uid_unexisting = generate_uuid0()
    secret = get_random_bytes(127)
    secret_too_big = get_random_bytes(140)

    for _ in range(2):
        generate_free_keypair_for_least_provisioned_key_type(
            key_storage=key_storage,
            max_free_keys_per_type=10,
            key_types=["RSA_OAEP", "DSA_DSS"],
        )
    assert key_storage.get_free_keypairs_count("DSA_DSS") == 1
    assert key_storage.get_free_keypairs_count("ECC_DSS") == 0
    assert key_storage.get_free_keypairs_count("RSA_OAEP") == 1
    assert (
        key_storage.get_free_keypairs_count("RSA_PSS") == 0
    )  # Different from other RSA keys

    # Keypair is well auto-created by get_public_key()
    public_key_rsa_oaep_pem = escrow_api.get_public_key(
        keychain_uid=keychain_uid, key_type="RSA_OAEP"
    )

    _public_key_rsa_oaep_pem2 = escrow_api.get_public_key(
        keychain_uid=keychain_uid, key_type="RSA_OAEP"
    )
    assert _public_key_rsa_oaep_pem2 == public_key_rsa_oaep_pem  # Same KEYS!

    _public_key_rsa_pss_pem = escrow_api.get_public_key(
        keychain_uid=keychain_uid, key_type="RSA_PSS"
    )
    assert _public_key_rsa_pss_pem != public_key_rsa_oaep_pem  # Different KEYS!

    public_key_rsa_oaep = load_asymmetric_key_from_pem_bytestring(
        key_pem=public_key_rsa_oaep_pem, key_type="RSA_OAEP"
    )

    assert key_storage.get_free_keypairs_count("DSA_DSS") == 1
    assert key_storage.get_free_keypairs_count("ECC_DSS") == 0
    assert key_storage.get_free_keypairs_count("RSA_OAEP") == 0  # Taken
    assert key_storage.get_free_keypairs_count("RSA_PSS") == 0

    signature = escrow_api.get_message_signature(
        keychain_uid=keychain_uid, message=secret, signature_algo="DSA_DSS"
    )

    with pytest.raises(ValueError, match="too big"):
        escrow_api.get_message_signature(
            keychain_uid=keychain_uid, message=secret_too_big, signature_algo="DSA_DSS"
        )

    assert key_storage.get_free_keypairs_count("DSA_DSS") == 0  # Taken
    assert key_storage.get_free_keypairs_count("ECC_DSS") == 0
    assert key_storage.get_free_keypairs_count("RSA_OAEP") == 0
    assert key_storage.get_free_keypairs_count("RSA_PSS") == 0

    public_key_dsa_pem = escrow_api.get_public_key(
        keychain_uid=keychain_uid, key_type="DSA_DSS"
    )
    public_key_dsa = load_asymmetric_key_from_pem_bytestring(
        key_pem=public_key_dsa_pem, key_type="DSA_DSS"
    )

    verify_message_signature(
        message=secret,
        signature=signature,
        key=public_key_dsa,
        signature_algo="DSA_DSS",
    )
    signature["digest"] += b"xyz"
    with pytest.raises(ValueError, match="not authentic"):
        verify_message_signature(
            message=secret,
            signature=signature,
            key=public_key_dsa,
            signature_algo="DSA_DSS",
        )

    # Keypair is well auto-created by get_message_signature(), even when no more free keys
    signature = escrow_api.get_message_signature(
        keychain_uid=keychain_uid_other, message=secret, signature_algo="RSA_PSS"
    )
    assert signature

    # Keypair well autocreated by get_public_key(), even when no more free keys
    public_key_pem = escrow_api.get_public_key(
        keychain_uid=keychain_uid_other, key_type="DSA_DSS"
    )
    assert public_key_pem

    cipherdict = _encrypt_via_rsa_oaep(plaintext=secret, key=public_key_rsa_oaep)

    # Works even without decryption authorization request, by default:
    decrypted = escrow_api.decrypt_with_private_key(
        keychain_uid=keychain_uid, encryption_algo="RSA_OAEP", cipherdict=cipherdict
    )

    # NO auto-creation of keypair in decrypt_with_private_key()
    with pytest.raises(ValueError, match="Unexisting"):
        escrow_api.decrypt_with_private_key(
            keychain_uid=keychain_uid_unexisting,
            encryption_algo="RSA_OAEP",
            cipherdict=cipherdict,
        )

    cipherdict["digest_list"].append(b"aaabbbccc")
    with pytest.raises(ValueError, match="Ciphertext with incorrect length"):
        escrow_api.decrypt_with_private_key(
            keychain_uid=keychain_uid, encryption_algo="RSA_OAEP", cipherdict=cipherdict
        )

    assert decrypted == secret

    result = escrow_api.request_decryption_authorization(
        keypair_identifiers=[(keychain_uid, "RSA_OAEP")],
        request_message="I need this decryption!",
    )
    assert result["response_message"]

    with pytest.raises(ValueError, match="empty"):
        escrow_api.request_decryption_authorization(
            keypair_identifiers=[], request_message="I need this decryption!"
        )

    assert key_storage.get_free_keypairs_count("DSA_DSS") == 0
    assert key_storage.get_free_keypairs_count("ECC_DSS") == 0
    assert key_storage.get_free_keypairs_count("RSA_OAEP") == 0
    assert key_storage.get_free_keypairs_count("RSA_PSS") == 0


def test_generate_free_keypair_for_least_provisioned_key_type():

    generated_keys_count = 0

    def key_generation_func(key_type, serialize):
        nonlocal generated_keys_count
        generated_keys_count += 1
        return dict(private_key="someprivatekey", public_key="somepublickey")

    # Check the fallback on "all types of keys" for key_types parameter

    key_storage = DummyKeyStorage()

    for _ in range(4):
        res = generate_free_keypair_for_least_provisioned_key_type(
            key_storage=key_storage,
            max_free_keys_per_type=10,
            key_generation_func=key_generation_func,
            # no key_types parameter provided
        )
        assert res

    assert key_storage.get_free_keypairs_count("DSA_DSS") == 1
    assert key_storage.get_free_keypairs_count("ECC_DSS") == 1
    assert key_storage.get_free_keypairs_count("RSA_OAEP") == 1
    assert key_storage.get_free_keypairs_count("RSA_PSS") == 1
    assert generated_keys_count == 4

    # Now test with a restricted set of key types

    key_storage = DummyKeyStorage()
    restricted_key_types = ["DSA_DSS", "ECC_DSS", "RSA_OAEP"]
    generated_keys_count = 0

    for _ in range(7):
        res = generate_free_keypair_for_least_provisioned_key_type(
            key_storage=key_storage,
            max_free_keys_per_type=10,
            key_generation_func=key_generation_func,
            key_types=restricted_key_types,
        )
        assert res

    assert key_storage.get_free_keypairs_count("DSA_DSS") == 3
    assert key_storage.get_free_keypairs_count("ECC_DSS") == 2
    assert key_storage.get_free_keypairs_count("RSA_OAEP") == 2
    assert generated_keys_count == 7

    for _ in range(23):
        res = generate_free_keypair_for_least_provisioned_key_type(
            key_storage=key_storage,
            max_free_keys_per_type=10,
            key_generation_func=key_generation_func,
            key_types=restricted_key_types,
        )
        assert res

    assert key_storage.get_free_keypairs_count("DSA_DSS") == 10
    assert key_storage.get_free_keypairs_count("ECC_DSS") == 10
    assert key_storage.get_free_keypairs_count("RSA_OAEP") == 10
    assert generated_keys_count == 30

    res = generate_free_keypair_for_least_provisioned_key_type(
        key_storage=key_storage,
        max_free_keys_per_type=10,
        key_generation_func=key_generation_func,
        key_types=restricted_key_types,
    )
    assert not res
    assert generated_keys_count == 30  # Unchanged

    for _ in range(7):
        generate_free_keypair_for_least_provisioned_key_type(
            key_storage=key_storage,
            max_free_keys_per_type=15,
            key_generation_func=key_generation_func,
            key_types=["RSA_OAEP", "DSA_DSS"],
        )

    assert (
        key_storage.get_free_keypairs_count("DSA_DSS") == 14
    )  # First in sorting order
    assert key_storage.get_free_keypairs_count("ECC_DSS") == 10
    assert key_storage.get_free_keypairs_count("RSA_OAEP") == 13
    assert generated_keys_count == 37

    res = generate_free_keypair_for_least_provisioned_key_type(
        key_storage=key_storage,
        max_free_keys_per_type=20,
        key_generation_func=key_generation_func,
        key_types=restricted_key_types,
    )
    assert res
    assert key_storage.get_free_keypairs_count("DSA_DSS") == 14
    assert key_storage.get_free_keypairs_count("ECC_DSS") == 11
    assert key_storage.get_free_keypairs_count("RSA_OAEP") == 13
    assert generated_keys_count == 38

    res = generate_free_keypair_for_least_provisioned_key_type(
        key_storage=key_storage,
        max_free_keys_per_type=5,
        key_generation_func=key_generation_func,
        key_types=restricted_key_types,
    )
    assert not res
    assert generated_keys_count == 38


def test_get_free_keys_generator_worker():

    generate_keys_count = 0

    key_storage = DummyKeyStorage()

    def key_generation_func(key_type, serialize):
        nonlocal generate_keys_count
        generate_keys_count += 1
        time.sleep(0.01)
        return dict(private_key="someprivatekey", public_key="somepublickey")

    worker = get_free_keys_generator_worker(
        key_storage=key_storage,
        max_free_keys_per_type=30,
        sleep_on_overflow_s=0.5,
        key_generation_func=key_generation_func,
    )

    try:
        worker.start()
        time.sleep(0.5)
        worker.stop()
        worker.join()

        assert (
            10 < generate_keys_count < 50
        ), generate_keys_count  # Not enough time to generate all

        worker.start()
        time.sleep(3)
        worker.stop()
        worker.join()

        assert (
            generate_keys_count == 120  # 4 key types for now
        ), generate_keys_count  # All keys had the time to be generated

        start = time.time()
        worker.start()
        worker.stop()
        worker.join()
        end = time.time()
        assert (end - start) > 0.4  # sleep-on-overflow occurred

    finally:
        if worker.is_running:
            worker.stop()
