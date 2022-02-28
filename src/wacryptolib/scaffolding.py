import functools
import time
import uuid
from concurrent.futures.thread import ThreadPoolExecutor

from wacryptolib.exceptions import KeyAlreadyExists, KeyDoesNotExist, OperationNotSupported
from wacryptolib.utilities import generate_uuid0


# SEE https://docs.pytest.org/en/stable/writing_plugins.html#assertion-rewriting and register_assert_rewrite()


def check_keystore_basic_get_set_api(keystore, readonly_keystore=None):
    """Test the workflow of getters/setters of the storage API, for uid-attached keys."""

    import pytest

    keychain_uid = generate_uuid0()
    time.sleep(0.1)  # Let UUID0 increase its base value
    keychain_uid_separated_keys = generate_uuid0()
    assert keychain_uid_separated_keys > keychain_uid
    keychain_uid_unused = generate_uuid0()
    key_algo = "abxz"

    all_keystores = [keystore, readonly_keystore] if readonly_keystore else [keystore]

    for _keystore in all_keystores:
        with pytest.raises(KeyDoesNotExist, match="not found"):
            _keystore.get_public_key(keychain_uid=keychain_uid, key_algo="abxz")
        with pytest.raises(KeyDoesNotExist, match="not found"):
            _keystore.get_private_key(keychain_uid=keychain_uid, key_algo="abxz")
        try:
            assert not _keystore.list_keypair_identifiers()
        except OperationNotSupported:
            pass

    # Test the ONESHOT "keypair" API

    keystore.set_keypair(
        keychain_uid=keychain_uid, key_algo=key_algo, public_key=b"public_data", private_key=b"private_data"
    )

    for _keystore in all_keystores:
        assert _keystore.get_public_key(keychain_uid=keychain_uid, key_algo=key_algo) == b"public_data"
        assert _keystore.get_private_key(keychain_uid=keychain_uid, key_algo=key_algo) == b"private_data"
        try:
            assert _keystore.list_keypair_identifiers() == [
                dict(keychain_uid=keychain_uid, key_algo=key_algo, private_key_present=True)
            ]
        except OperationNotSupported:
            pass

    with pytest.raises(KeyAlreadyExists, match="Already existing"):  # Even with same content, it gets rejected
        keystore.set_keypair(
            keychain_uid=keychain_uid, key_algo=key_algo, public_key=b"public_data", private_key=b"private_data"
        )
    with pytest.raises(KeyAlreadyExists, match="Already existing"):
        keystore.set_keypair(
            keychain_uid=keychain_uid, key_algo=key_algo, public_key=b"public_data2", private_key=b"private_data2"
        )

    # Test the "separated keys" API

    with pytest.raises(KeyDoesNotExist, match="does not exist"):  # IMPORTANT: public key MUST already exist
        keystore.set_private_key(
            keychain_uid=keychain_uid_separated_keys, key_algo=key_algo, private_key=b"separated_private_data"
        )
    keystore.set_public_key(
        keychain_uid=keychain_uid_separated_keys, key_algo=key_algo, public_key=b"separated_public_data"
    )
    with pytest.raises(KeyAlreadyExists, match="Already existing"):
        keystore.set_public_key(keychain_uid=keychain_uid, key_algo=key_algo, public_key=b"separated_public_data2")

    for _keystore in all_keystores:
        assert (
            _keystore.get_public_key(keychain_uid=keychain_uid_separated_keys, key_algo=key_algo)
            == b"separated_public_data"
        )
        with pytest.raises(KeyDoesNotExist, match="not found"):
            _keystore.get_private_key(keychain_uid=keychain_uid_separated_keys, key_algo=key_algo)
        try:
            assert _keystore.list_keypair_identifiers() == [
                dict(keychain_uid=keychain_uid, key_algo=key_algo, private_key_present=True),
                dict(keychain_uid=keychain_uid_separated_keys, key_algo=key_algo, private_key_present=False),
            ]
        except OperationNotSupported:
            pass

    keystore.set_private_key(
        keychain_uid=keychain_uid_separated_keys, key_algo=key_algo, private_key=b"separated_private_data"
    )
    with pytest.raises(KeyAlreadyExists, match="Already existing"):
        keystore.set_private_key(keychain_uid=keychain_uid, key_algo=key_algo, private_key=b"separated_private_data2")

    for _keystore in all_keystores:
        assert (
            _keystore.get_public_key(keychain_uid=keychain_uid_separated_keys, key_algo=key_algo)
            == b"separated_public_data"
        )
        assert (
            _keystore.get_private_key(keychain_uid=keychain_uid_separated_keys, key_algo=key_algo)
            == b"separated_private_data"
        )
        try:
            assert _keystore.list_keypair_identifiers() == [
                dict(keychain_uid=keychain_uid, key_algo=key_algo, private_key_present=True),
                dict(keychain_uid=keychain_uid_separated_keys, key_algo=key_algo, private_key_present=True),
            ]
        except OperationNotSupported:
            pass

    # Test miscellaneous "not found" cases when any part of identifiers change

    for _keystore in all_keystores:

        # Sanity check
        assert _keystore.get_public_key(keychain_uid=keychain_uid, key_algo=key_algo) == b"public_data"
        assert _keystore.get_private_key(keychain_uid=keychain_uid, key_algo=key_algo) == b"private_data"

        with pytest.raises(KeyDoesNotExist, match="not found"):
            _keystore.get_public_key(keychain_uid=keychain_uid, key_algo=key_algo + "_")

        with pytest.raises(KeyDoesNotExist, match="not found"):
            _keystore.get_private_key(keychain_uid=keychain_uid, key_algo=key_algo + "_")

        with pytest.raises(KeyDoesNotExist, match="not found"):
            _keystore.get_public_key(keychain_uid=keychain_uid_unused, key_algo=key_algo)

        with pytest.raises(KeyDoesNotExist, match="not found"):
            _keystore.get_private_key(keychain_uid=keychain_uid_unused, key_algo=key_algo)

    return locals()


def check_keystore_free_keys_api(keystore):
    """Test the storage regarding the precreation of "free keys", and their subsequent attachment to uids."""
    import pytest

    keychain_uid = generate_uuid0()
    keychain_uid_other = generate_uuid0()

    # This blocks free key attachment to this uid+type
    keystore.set_keypair(keychain_uid=keychain_uid, key_algo="type1", public_key=b"whatever1", private_key=b"whatever2")

    keystore.add_free_keypair(key_algo="type1", public_key=b"public_data", private_key=b"private_data")
    keystore.add_free_keypair(key_algo="type1", public_key=b"public_data2", private_key=b"private_data2")
    keystore.add_free_keypair(
        key_algo="type2", public_key=b"public_data_other_type", private_key=b"private_data_other_type"
    )

    assert keystore.get_free_keypairs_count("type1") == 2
    assert keystore.get_free_keypairs_count("type2") == 1
    assert keystore.get_free_keypairs_count("type3") == 0

    with pytest.raises(KeyAlreadyExists, match="Already existing"):
        keystore.attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_algo="type1")

    with pytest.raises(KeyDoesNotExist, match="not found"):
        keystore.get_public_key(keychain_uid=keychain_uid, key_algo="type2")

    keystore.attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_algo="type2")
    assert b"public_data" in keystore.get_public_key(keychain_uid=keychain_uid, key_algo="type2")

    assert keystore.get_free_keypairs_count("type1") == 2
    assert keystore.get_free_keypairs_count("type2") == 0
    assert keystore.get_free_keypairs_count("type3") == 0

    keystore.attach_free_keypair_to_uuid(keychain_uid=keychain_uid_other, key_algo="type1")

    assert keystore.get_free_keypairs_count("type1") == 1
    assert keystore.get_free_keypairs_count("type2") == 0
    assert keystore.get_free_keypairs_count("type3") == 0

    with pytest.raises(KeyDoesNotExist, match="No free keypair of type"):
        keystore.attach_free_keypair_to_uuid(keychain_uid=keychain_uid_other, key_algo="type2")

    with pytest.raises(KeyDoesNotExist, match="No free keypair of type"):
        keystore.attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_algo="type3")

    assert keystore.get_free_keypairs_count("type1") == 1
    assert keystore.get_free_keypairs_count("type2") == 0
    assert keystore.get_free_keypairs_count("type3") == 0

    return locals()


def check_keystore_free_keys_concurrency(keystore):
    """Parallel tests to check the thread-safety of the storage regarding "free keys" booking."""
    key_algo1 = "mytype1"
    key_algo2 = "mytype2"

    for i in range(77):
        for key_algo in (key_algo1, key_algo2):
            keystore.add_free_keypair(key_algo=key_algo, public_key=b"whatever1", private_key=b"whatever2")

    def retrieve_free_keypair_for_index(idx, key_algo):
        keychain_uid = uuid.UUID(int=idx)
        try:
            keystore.attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_algo=key_algo)
            time.sleep(0.001)
            public_key_content = keystore.get_public_key(keychain_uid=keychain_uid, key_algo=key_algo)
            assert public_key_content == b"whatever1"
            res = True
        except KeyDoesNotExist:
            res = False
        return res

    executor = ThreadPoolExecutor(max_workers=20)

    for key_algo in (key_algo1, key_algo2):
        results_gen = executor.map(functools.partial(retrieve_free_keypair_for_index, key_algo=key_algo), range(200))
        results = list(results_gen)
        assert results.count(True) == 77
        assert results.count(False) == 123

    assert keystore.get_free_keypairs_count(key_algo=key_algo1) == 0
    assert keystore.get_free_keypairs_count(key_algo=key_algo2) == 0
    return locals()


def check_sensor_state_machine(sensor, run_duration=0):
    """Check the proper start/stop/join behaviour of a sensor instance."""
    import pytest

    assert not sensor.is_running

    sensor.join()  # Does nothing

    with pytest.raises(RuntimeError, match="already stopped"):
        sensor.stop()

    assert not sensor.is_running

    sensor.start()

    assert sensor.is_running

    with pytest.raises(RuntimeError, match="already started"):
        sensor.start()

    with pytest.raises(RuntimeError, match="in-progress runner"):
        sensor.join()

    assert sensor.is_running

    time.sleep(run_duration)

    assert sensor.is_running

    sensor.stop()

    assert not sensor.is_running

    with pytest.raises(RuntimeError, match="already stopped"):
        sensor.stop()

    assert not sensor.is_running

    sensor.join()
    sensor.join()  # Does nothing

    assert not sensor.is_running
