import pprint
import random
import uuid

import pytest
from Crypto.Random import get_random_bytes

from wacryptolib.container import ContainerWriter, LOCAL_ESCROW_PLACEHOLDER, ContainerReader



SIMPLE_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(data_encryption_type="AES_CBC",
             key_encryption_strata=[
                 dict(key_encryption_type=("RSA", "RSA_OAEP"),  # FIXME use subkey_type here
                      key_escrow=LOCAL_ESCROW_PLACEHOLDER,)
             ],
             signatures=[  # TODO PUT DSA HERE!!
                 dict(signature_type=("DSA", "DSS"),  # FIXME use subkey_type here
                      signature_escrow=LOCAL_ESCROW_PLACEHOLDER,)
             ],),
])


COMPLEX_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(data_encryption_type="AES_EAX",
             key_encryption_strata=[
                 dict(key_encryption_type=("RSA", "RSA_OAEP"),  # FIXME use subkey_type here
                      key_escrow=LOCAL_ESCROW_PLACEHOLDER,)
             ],
             signatures=[]),
        dict(data_encryption_type="AES_CBC",
             key_encryption_strata=[
                 dict(key_encryption_type=("RSA", "RSA_OAEP"),  # FIXME use subkey_type here
                      key_escrow=LOCAL_ESCROW_PLACEHOLDER,)
             ],
             signatures=[
                dict(signature_type=("DSA", "DSS"),  # FIXME use subkey_type here
                     signature_escrow=LOCAL_ESCROW_PLACEHOLDER,)
             ],),
        dict(data_encryption_type="CHACHA20_POLY1305",
             key_encryption_strata=[
                 dict(key_encryption_type=("RSA", "RSA_OAEP"),  # FIXME use subkey_type here
                      key_escrow=LOCAL_ESCROW_PLACEHOLDER,),
                 dict(key_encryption_type=("RSA", "RSA_OAEP"),  # FIXME use subkey_type here
                      key_escrow=LOCAL_ESCROW_PLACEHOLDER,)
             ],
             signatures=[
                 dict(signature_type=("RSA", "PSS"),  # FIXME use subkey_type here
                      signature_escrow=LOCAL_ESCROW_PLACEHOLDER),
                 dict(signature_type=("ECC", "DSS"),  # FIXME use subkey_type here
                      signature_escrow=LOCAL_ESCROW_PLACEHOLDER)
             ],)
])



@pytest.mark.parametrize(
    "container_conf", [SIMPLE_CONTAINER_CONF, COMPLEX_CONTAINER_CONF]
)
def test_container_encryption_and_decryption(container_conf):

    container_uid = uuid.UUID('450fc293-b702-42d3-ae65-e9cc58e5a62a')

    data = b"abc"  # get_random_bytes(random.randint(1, 1000))

    writer = ContainerWriter(container_uid)
    container = writer.encrypt_data(data, conf=container_conf)
    pprint.pprint(container, width=120)

    reader = ContainerReader(container_uid)
    result = reader.decrypt_data(container)
    pprint.pprint(result, width=120)

    assert result == data
