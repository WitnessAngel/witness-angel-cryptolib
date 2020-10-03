import functools
import time
import uuid
from concurrent.futures.thread import ThreadPoolExecutor

from wacryptolib.exceptions import KeyAlreadyExists, KeyDoesNotExist
from wacryptolib.utilities import generate_uuid0


def check_key_storage_basic_get_set_api(key_storage):
    """Test the workflow of getters/setters of the storage API, for uid-attached keys."""

    import pytest

    keychain_uid = generate_uuid0()
    keychain_uid_other = generate_uuid0()
    key_type = "abxz"

    with pytest.raises(KeyDoesNotExist, match="not found"):
        key_storage.get_public_key(keychain_uid=keychain_uid, key_type="abxz")

    key_storage.set_keys(
        keychain_uid=keychain_uid, key_type=key_type, public_key=b"public_data", private_key=b"private_data"
    )

    assert (
        key_storage.get_public_key(keychain_uid=keychain_uid, key_type="abxz") == b"public_data"
    )  # Well readable even without any kind of "commit"

    with pytest.raises(KeyAlreadyExists, match="Already existing"):
        key_storage.set_keys(
            keychain_uid=keychain_uid, key_type=key_type, public_key=b"public_data", private_key=b"private_data"
        )
    with pytest.raises(KeyAlreadyExists, match="Already existing"):
        key_storage.set_keys(
            keychain_uid=keychain_uid, key_type=key_type, public_key=b"public_data2", private_key=b"private_data2"
        )

    assert key_storage.get_public_key(keychain_uid=keychain_uid, key_type=key_type) == b"public_data"
    assert key_storage.get_private_key(keychain_uid=keychain_uid, key_type=key_type) == b"private_data"

    with pytest.raises(KeyDoesNotExist, match="not found"):
        key_storage.get_public_key(keychain_uid=keychain_uid, key_type=key_type + "_")

    with pytest.raises(KeyDoesNotExist, match="not found"):
        key_storage.get_private_key(keychain_uid=keychain_uid, key_type=key_type + "_")

    with pytest.raises(KeyDoesNotExist, match="not found"):
        key_storage.get_public_key(keychain_uid=keychain_uid_other, key_type=key_type)

    with pytest.raises(KeyDoesNotExist, match="not found"):
        key_storage.get_private_key(keychain_uid=keychain_uid_other, key_type=key_type)

    return locals()


def check_key_storage_free_keys_api(key_storage):
    """Test the storage regarding the precreation of "free keys", and their subsequent attachment to uids."""
    import pytest

    keychain_uid = generate_uuid0()
    keychain_uid_other = generate_uuid0()

    # This blocks free key attachment to this uid+type
    key_storage.set_keys(keychain_uid=keychain_uid, key_type="type1", public_key=b"whatever1", private_key=b"whatever2")

    key_storage.add_free_keypair(key_type="type1", public_key=b"public_data", private_key=b"private_data")
    key_storage.add_free_keypair(key_type="type1", public_key=b"public_data2", private_key=b"private_data2")
    key_storage.add_free_keypair(
        key_type="type2", public_key=b"public_data_other_type", private_key=b"private_data_other_type"
    )

    assert key_storage.get_free_keypairs_count("type1") == 2
    assert key_storage.get_free_keypairs_count("type2") == 1
    assert key_storage.get_free_keypairs_count("type3") == 0

    with pytest.raises(KeyAlreadyExists, match="Already existing"):
        key_storage.attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_type="type1")

    with pytest.raises(KeyDoesNotExist, match="not found"):
        key_storage.get_public_key(keychain_uid=keychain_uid, key_type="type2")

    key_storage.attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_type="type2")
    assert b"public_data" in key_storage.get_public_key(keychain_uid=keychain_uid, key_type="type2")

    assert key_storage.get_free_keypairs_count("type1") == 2
    assert key_storage.get_free_keypairs_count("type2") == 0
    assert key_storage.get_free_keypairs_count("type3") == 0

    key_storage.attach_free_keypair_to_uuid(keychain_uid=keychain_uid_other, key_type="type1")

    assert key_storage.get_free_keypairs_count("type1") == 1
    assert key_storage.get_free_keypairs_count("type2") == 0
    assert key_storage.get_free_keypairs_count("type3") == 0

    with pytest.raises(KeyDoesNotExist, match="No free keypair of type"):
        key_storage.attach_free_keypair_to_uuid(keychain_uid=keychain_uid_other, key_type="type2")

    with pytest.raises(KeyDoesNotExist, match="No free keypair of type"):
        key_storage.attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_type="type3")

    assert key_storage.get_free_keypairs_count("type1") == 1
    assert key_storage.get_free_keypairs_count("type2") == 0
    assert key_storage.get_free_keypairs_count("type3") == 0

    return locals()


def check_key_storage_free_keys_concurrency(key_storage):
    """Parallel tests to check the thread-safety of the storage regarding "free keys" booking."""
    key_type1 = "mytype1"
    key_type2 = "mytype2"

    for i in range(77):
        for key_type in (key_type1, key_type2):
            key_storage.add_free_keypair(key_type=key_type, public_key=b"whatever1", private_key=b"whatever2")

    def retrieve_free_keypair_for_index(idx, key_type):
        keychain_uid = uuid.UUID(int=idx)
        try:
            key_storage.attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_type=key_type)
            time.sleep(0.001)
            public_key_content = key_storage.get_public_key(keychain_uid=keychain_uid, key_type=key_type)
            assert public_key_content == b"whatever1"
            res = True
        except KeyDoesNotExist:
            res = False
        return res

    executor = ThreadPoolExecutor(max_workers=20)

    for key_type in (key_type1, key_type2):
        results_gen = executor.map(functools.partial(retrieve_free_keypair_for_index, key_type=key_type), range(200))
        results = list(results_gen)
        assert results.count(True) == 77
        assert results.count(False) == 123

    assert key_storage.get_free_keypairs_count(key_type=key_type1) == 0
    assert key_storage.get_free_keypairs_count(key_type=key_type2) == 0
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
