import random
import uuid

import pytest

from wacryptolib.container import (
    LOCAL_ESCROW_PLACEHOLDER,
    encrypt_data_into_container,
    decrypt_data_from_container,
)

SIMPLE_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_type="AES_CBC",
            key_encryption_strata=[
                dict(
                        escrow_key_type="RSA",
                       key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
            signatures=[
                dict(
                    signature_type=("DSA", "DSS"),  # FIXME use subkey_type here
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
        )
    ]
)


COMPLEX_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_type="AES_EAX",
            key_encryption_strata=[
                dict(
                        escrow_key_type="RSA",
                       key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
            signatures=[],
        ),
        dict(
            data_encryption_type="AES_CBC",
            key_encryption_strata=[
                dict(
                        escrow_key_type="RSA",
                       key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
            signatures=[
                dict(
                    signature_type=("DSA", "DSS"),  # FIXME use subkey_type here
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
        ),
        dict(
            data_encryption_type="CHACHA20_POLY1305",
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
            signatures=[
                dict(
                    signature_type=("RSA", "PSS"),  # FIXME use subkey_type here
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
                ),
                dict(
                    signature_type=("ECC", "DSS"),  # FIXME use subkey_type here
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

    uid = random.choice([None, uuid.UUID("450fc293-b702-42d3-ae65-e9cc58e5a62a")])

    container = encrypt_data_into_container(data=data, conf=container_conf, uid=uid)
    # pprint.pprint(container, width=120)

    assert container["uid"]
    if uid:
        assert container["uid"] == uid

    result = decrypt_data_from_container(container=container)
    # pprint.pprint(result, width=120)

    assert result == data
