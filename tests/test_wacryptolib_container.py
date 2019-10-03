import io
import random
import tarfile
import uuid
from datetime import datetime, timezone

import pytest

from wacryptolib.container import (
    LOCAL_ESCROW_PLACEHOLDER,
    encrypt_data_into_container,
    decrypt_data_from_container,
    DataAggregator,
)

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


def test_data_aggregator():

    aggregator = DataAggregator()

    result_bytestring = aggregator.finalize_tarfile()
    assert result_bytestring == ""

    data1 = "hêllö".encode("utf8")
    aggregator.add_record(
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

    data2 = b"123xyz"
    aggregator.add_record(
        sensor_name="smartphone_recorder",
        from_datetime=datetime(year=2017, month=10, day=11, tzinfo=timezone.utc),
        to_datetime=datetime(year=2017, month=12, day=1, tzinfo=timezone.utc),
        extension=".mp3",
        data=data2,
    )

    result_bytestring = aggregator.finalize_tarfile()
    tar_file = DataAggregator.read_tarfile_from_bytestring(result_bytestring)

    filenames = sorted(tar_file.getnames())
    assert filenames == [
        "20140102221155_20150203000000_smartphone_front_camera.txt",
        "20171011000000_20171201000000_smartphone_recorder.mp3",
    ]
    assert tar_file.extractfile(filenames[0]).read() == data1
    assert tar_file.extractfile(filenames[1]).read() == data2

    for i in range(2):
        result_bytestring = aggregator.finalize_tarfile()
        assert result_bytestring == ""

    data3 = b""
    aggregator.add_record(
        sensor_name="abc",
        from_datetime=datetime(year=2017, month=10, day=11, tzinfo=timezone.utc),
        to_datetime=datetime(year=2017, month=12, day=1, tzinfo=timezone.utc),
        extension=".avi",
        data=data3,
    )

    result_bytestring = aggregator.finalize_tarfile()
    tar_file = DataAggregator.read_tarfile_from_bytestring(result_bytestring)

    filenames = sorted(tar_file.getnames())
    assert filenames == ["20171011000000_20171201000000_abc.avi"]
    assert tar_file.extractfile(filenames[0]).read() == b""

    for i in range(2):
        result_bytestring = aggregator.finalize_tarfile()
        assert result_bytestring == ""
