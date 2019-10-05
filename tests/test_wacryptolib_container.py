import io
import random
import tarfile
import uuid
from datetime import datetime, timezone, timedelta

import pytest
from freezegun import freeze_time

from wacryptolib.container import (
    LOCAL_ESCROW_PLACEHOLDER,
    encrypt_data_into_container,
    decrypt_data_from_container,
    TarfileAggregator,
    TimedJsonAggregator)

SIMPLE_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[
                dict(
                    escrow_key_type="RSA",
                    key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
            data_signatures=[
                dict(
                    signature_key_type="DSA",
                    signature_algo="DSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
        )
    ]
)


COMPLEX_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_EAX",
            key_encryption_strata=[
                dict(
                    escrow_key_type="RSA",
                    key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
            data_signatures=[],
        ),
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[
                dict(
                    escrow_key_type="RSA",
                    key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
            data_signatures=[
                dict(
                    signature_key_type="DSA",
                    signature_algo="DSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
        ),
        dict(
            data_encryption_algo="CHACHA20_POLY1305",
            key_encryption_strata=[
                dict(
                    escrow_key_type="RSA",
                    key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                ),
                dict(
                    escrow_key_type="RSA",
                    key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                ),
            ],
            data_signatures=[
                dict(
                    signature_key_type="RSA",
                    signature_algo="PSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                ),
                dict(
                    signature_key_type="ECC",
                    signature_algo="DSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                ),
            ],
        ),
    ]
)


@pytest.mark.parametrize(
    "container_conf", [SIMPLE_CONTAINER_CONF, COMPLEX_CONTAINER_CONF]
)
def test_container_encryption_and_decryption(container_conf):

    data = b"abc"  # get_random_bytes(random.randint(1, 1000))

    keychain_uid = random.choice(
        [None, uuid.UUID("450fc293-b702-42d3-ae65-e9cc58e5a62a")]
    )

    container = encrypt_data_into_container(
        data=data, conf=container_conf, keychain_uid=keychain_uid
    )
    # pprint.pprint(container, width=120)

    assert container["keychain_uid"]
    if keychain_uid:
        assert container["keychain_uid"] == keychain_uid

    result = decrypt_data_from_container(container=container)
    # pprint.pprint(result, width=120)

    assert result == data

    container["container_format"] = "OAJKB"
    with pytest.raises(ValueError, match="Unknown container format"):
        decrypt_data_from_container(container=container)


def test_tarfile_aggregator():

    tarfile_aggregator = TarfileAggregator()
    assert len(tarfile_aggregator) == 0

    result_bytestring = tarfile_aggregator.finalize_tarfile()
    assert result_bytestring == ""

    data1 = "hêllö".encode("utf8")
    tarfile_aggregator.add_record(
        sensor_name="smartphone_front_camera",
        from_datetime=datetime(
            year=2014,
            month=1,
            day=2,
            hour=22,
            minute=11,
            second=55,
            tzinfo=timezone.utc,
        ),
        to_datetime=datetime(year=2015, month=2, day=3, tzinfo=timezone.utc),
        extension=".txt",
        data=data1,
    )
    assert len(tarfile_aggregator) == 1

    data2 = b"123xyz"
    tarfile_aggregator.add_record(
        sensor_name="smartphone_recorder",
        from_datetime=datetime(year=2017, month=10, day=11, tzinfo=timezone.utc),
        to_datetime=datetime(year=2017, month=12, day=1, tzinfo=timezone.utc),
        extension=".mp3",
        data=data2,
    )
    assert len(tarfile_aggregator) == 2

    result_bytestring = tarfile_aggregator.finalize_tarfile()
    tar_file = TarfileAggregator.read_tarfile_from_bytestring(result_bytestring)

    assert len(tarfile_aggregator) == 0

    filenames = sorted(tar_file.getnames())
    assert filenames == [
        "20140102221155_20150203000000_smartphone_front_camera.txt",
        "20171011000000_20171201000000_smartphone_recorder.mp3",
    ]
    assert tar_file.extractfile(filenames[0]).read() == data1
    assert tar_file.extractfile(filenames[1]).read() == data2

    for i in range(2):
        result_bytestring = tarfile_aggregator.finalize_tarfile()
        assert result_bytestring == ""
        assert len(tarfile_aggregator) == 0

    data3 = b""
    tarfile_aggregator.add_record(
        sensor_name="abc",
        from_datetime=datetime(year=2017, month=10, day=11, tzinfo=timezone.utc),
        to_datetime=datetime(year=2017, month=12, day=1, tzinfo=timezone.utc),
        extension=".avi",
        data=data3,
    )
    assert len(tarfile_aggregator) == 1

    result_bytestring = tarfile_aggregator.finalize_tarfile()
    tar_file = TarfileAggregator.read_tarfile_from_bytestring(result_bytestring)
    assert len(tarfile_aggregator) == 0

    filenames = sorted(tar_file.getnames())
    assert filenames == ["20171011000000_20171201000000_abc.avi"]
    assert tar_file.extractfile(filenames[0]).read() == b""

    for i in range(2):
        result_bytestring = tarfile_aggregator.finalize_tarfile()
        assert result_bytestring == ""
        assert len(tarfile_aggregator) == 0


def test_timed_json_aggregator():

    tarfile_aggregator = TarfileAggregator()
    assert len(tarfile_aggregator) == 0

    json_aggregator = TimedJsonAggregator(max_duration_s=2, tarfile_aggregator=tarfile_aggregator, sensor_name="some_sensors")
    assert len(json_aggregator) == 0

    with freeze_time() as frozen_datetime:

        json_aggregator.add_data(dict(pulse=42))
        json_aggregator.add_data(dict(timing=True))

        assert len(tarfile_aggregator) == 0
        assert len(json_aggregator) == 2

        frozen_datetime.tick(delta=timedelta(seconds=1))

        json_aggregator.add_data(dict(abc=2.2))

        assert len(tarfile_aggregator) == 0
        assert len(json_aggregator) == 3

        frozen_datetime.tick(delta=timedelta(seconds=1))

        json_aggregator.add_data(dict(x="abc"))

        assert len(tarfile_aggregator) == 1  # single json file
        assert len(json_aggregator) == 1

        json_aggregator.finalize_dataset()

        assert len(tarfile_aggregator) == 2  # 2 json files
        assert len(json_aggregator) == 0

        frozen_datetime.tick(delta=timedelta(seconds=10))

        json_aggregator.finalize_dataset()

        # Unchanged
        assert len(tarfile_aggregator) == 2
        assert len(json_aggregator) == 0

        result_bytestring = tarfile_aggregator.finalize_tarfile()
        tar_file = TarfileAggregator.read_tarfile_from_bytestring(result_bytestring)
        assert len(tarfile_aggregator) == 0

        filenames = sorted(tar_file.getnames())
        assert len(filenames) == 2

        for filename in filenames:
            assert "some_sensors" in filename
            assert filename.endswith(".json")

        data = tar_file.extractfile(filenames[0]).read()
        assert data == b'[{"pulse": {"$numberInt": "42"}}, {"timing": true}, {"abc": {"$numberDouble": "2.2"}}]'

        data = tar_file.extractfile(filenames[1]).read()
        assert data == b'[{"x": "abc"}]'
