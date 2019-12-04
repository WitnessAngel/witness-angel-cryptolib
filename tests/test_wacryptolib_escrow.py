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
    secret = get_random_bytes(101)

    public_key_pem = escrow_api.get_public_key(
        keychain_uid=keychain_uid, key_type="RSA"
    )
    public_key = load_asymmetric_key_from_pem_bytestring(
        key_pem=public_key_pem, key_type="RSA"
    )

    signature = escrow_api.get_message_signature(
        keychain_uid=keychain_uid, message=secret, key_type="RSA", signature_algo="PSS"
    )
    verify_message_signature(
        message=secret, signature=signature, key=public_key, signature_algo="PSS"
    )

    signature["digest"] += b"xyz"
    with pytest.raises(ValueError, match="Incorrect signature"):
        verify_message_signature(
            message=secret, signature=signature, key=public_key, signature_algo="PSS"
        )

    cipherdict = _encrypt_via_rsa_oaep(plaintext=secret, key=public_key)

    decrypted = escrow_api.decrypt_with_private_key(
        keychain_uid=keychain_uid,
        key_type="RSA",
        encryption_algo="RSA_OAEP",
        cipherdict=cipherdict,
    )

    cipherdict["digest_list"].append(b"aaabbbccc")
    with pytest.raises(ValueError, match="Ciphertext with incorrect length"):
        escrow_api.decrypt_with_private_key(
            keychain_uid=keychain_uid,
            key_type="RSA",
            encryption_algo="RSA_OAEP",
            cipherdict=cipherdict,
        )

    assert decrypted == secret


def test_generate_free_keypair_for_least_provisioned_key_type():

    generate_keys_count = 0

    key_storage = DummyKeyStorage()

    def key_generation_func(key_type, serialize):
        nonlocal generate_keys_count
        generate_keys_count += 1
        return dict(private_key="someprivatekey", public_key="somepublickey")

    for _ in range(7):
        res = generate_free_keypair_for_least_provisioned_key_type(
            key_storage=key_storage,
            max_keys_count_per_type=10,
            key_generation_func=key_generation_func,
        )
        assert res

    assert key_storage.get_free_keypairs_count("DSA") == 3
    assert key_storage.get_free_keypairs_count("ECC") == 2
    assert key_storage.get_free_keypairs_count("RSA") == 2
    assert generate_keys_count == 7

    for _ in range(23):
        res = generate_free_keypair_for_least_provisioned_key_type(
            key_storage=key_storage,
            max_keys_count_per_type=10,
            key_generation_func=key_generation_func,
        )
        assert res

    assert key_storage.get_free_keypairs_count("DSA") == 10
    assert key_storage.get_free_keypairs_count("ECC") == 10
    assert key_storage.get_free_keypairs_count("RSA") == 10
    assert generate_keys_count == 30

    res = generate_free_keypair_for_least_provisioned_key_type(
        key_storage=key_storage,
        max_keys_count_per_type=10,
        key_generation_func=key_generation_func,
    )
    assert not res
    assert generate_keys_count == 30  # Unchanged

    for _ in range(7):
        generate_free_keypair_for_least_provisioned_key_type(
            key_storage=key_storage,
            max_keys_count_per_type=15,
            key_generation_func=key_generation_func,
            key_types=["RSA", "DSA"],
        )

    assert key_storage.get_free_keypairs_count("DSA") == 14  # First in sorting order
    assert key_storage.get_free_keypairs_count("ECC") == 10
    assert key_storage.get_free_keypairs_count("RSA") == 13
    assert generate_keys_count == 37

    res = generate_free_keypair_for_least_provisioned_key_type(
        key_storage=key_storage,
        max_keys_count_per_type=20,
        key_generation_func=key_generation_func,
    )
    assert res
    assert key_storage.get_free_keypairs_count("DSA") == 14
    assert key_storage.get_free_keypairs_count("ECC") == 11
    assert key_storage.get_free_keypairs_count("RSA") == 13
    assert generate_keys_count == 38

    res = generate_free_keypair_for_least_provisioned_key_type(
        key_storage=key_storage,
        max_keys_count_per_type=5,
        key_generation_func=key_generation_func,
    )
    assert not res
    assert generate_keys_count == 38


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
        max_keys_count_per_type=30,
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
        time.sleep(1.5)
        worker.stop()
        worker.join()

        assert (
            generate_keys_count == 90
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
