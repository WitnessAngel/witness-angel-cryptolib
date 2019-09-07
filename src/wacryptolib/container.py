import json
import pprint
import uuid
from base64 import b64decode

import wacryptolib
from wacryptolib.encryption import encrypt_bytestring
from wacryptolib.key_generation import generate_symmetric_key, KEY_TYPES_REGISTRY
from wacryptolib.utilities import dump_to_json_bytes

LOCAL_ESCROW_PLACEHOLDER = "_local_"

def _get_proxy_for_escrow(escrow):
    import waserver.escrow_api
    if escrow == LOCAL_ESCROW_PLACEHOLDER:
        return waserver.escrow_api
    else:
        raise NotImplementedError("escrow system to be completed")




EXAMPLE_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(data_encryption_type="AES_EAX",
             key_encryption_strata=[
                 dict(key_encryption_type=("RSA", "RSA_OAEP"),  # FIXME use subkey_type here
                      key_escrow=LOCAL_ESCROW_PLACEHOLDER,)
             ],
             signatures=[
                 dict(signature_type=("DSA", "DSS"),  # FIXME use subkey_type here
                      signature_escrow=LOCAL_ESCROW_PLACEHOLDER,)
             ],)
])




class CONTENT_TYPES:
    DATA = "data"  # Real media data
    KEY = "key"  # Cryptographic key
    CIPHERDICT = "cipherdict"  # Encrypted json dictionary (wrapping any of content types)



class ContainerWriter:

    def encrypt_data(self, data, conf):
        assert isinstance(data, bytes), data
        assert isinstance(conf, dict), conf

        container_uid = uuid.uuid4()

        data_ciphertext = data  # Initially unencrypted, might remain so if no strata
        result_data_encryption_strata = []

        for data_encryption_stratum in conf["data_encryption_strata"]:
            data_encryption_type = data_encryption_stratum["data_encryption_type"]
            symmetric_key = generate_symmetric_key(encryption_type=data_encryption_type)
            data_cipherdict = encrypt_bytestring(plaintext=data_ciphertext, encryption_type=data_encryption_type, key=symmetric_key)
            assert isinstance(data_cipherdict, dict), data_cipherdict
            data_ciphertext = dump_to_json_bytes(data_cipherdict)

            symmetric_key_ciphertext = symmetric_key  # Initially unencrypted, might remain so if no strata

            result_key_encryption_strata = []
            for key_encryption_stratum in data_encryption_stratum["key_encryption_strata"]:
                symmetric_key_ciphertext = self._encrypt_key(container_uid=container_uid,
                                                             key=symmetric_key_ciphertext,
                                                             conf=key_encryption_stratum)
                result_key_encryption_strata.append(key_encryption_stratum)  # Unmodified for now

            result_signatures = []
            for signature_conf in data_encryption_stratum["signatures"]:
                result_signature = self._generate_signature(container_uid=container_uid, data_ciphertext=data_ciphertext, conf=signature_conf)
                result_signatures.append(result_signature)

            result_data_encryption_strata.append(
                    dict(data_encryption_type=data_encryption_type,
                         key_ciphertext = symmetric_key_ciphertext,
                            key_encryption_strata=result_key_encryption_strata,
                        signatures=result_signatures)
            )

        return dict(
                data_ciphertext=data_ciphertext,
                data_encryption_strata=result_data_encryption_strata)


    def _encrypt_key(self, container_uid: uuid.UUID, key: bytes, conf: dict) -> bytes:
        assert isinstance(key, bytes), key
        subkey_type, key_encryption_type = conf["key_encryption_type"]
        encryption_proxy = _get_proxy_for_escrow(conf["key_escrow"])

        subkey_bytes = encryption_proxy.get_public_key(uid=container_uid, key_type=subkey_type)
        subkey_pem = b64decode(subkey_bytes)
        subkey = KEY_TYPES_REGISTRY[subkey_type]["pem_import_function"](subkey_pem)

        key_ciphertext = encrypt_bytestring(plaintext=key, encryption_type=key_encryption_type, key=subkey)
        return key_ciphertext

    def _generate_signature(self, container_uid: uuid.UUID, data_ciphertext: bytes, conf: dict) -> dict:
        encryption_proxy = _get_proxy_for_escrow(conf["signature_escrow"])
        subkey_type, signature_type = conf["signature_type"]
        signature = encryption_proxy.get_message_signature(uid=container_uid, plaintext=data_ciphertext,
                                                            key_type=subkey_type, signature_type=signature_type)
        return signature



if __name__ == "__main__":
    writer = ContainerWriter()
    result = writer.encrypt_data(b"qdjdnidazdazopdihazdoi", conf=EXAMPLE_CONTAINER_CONF)

    pprint.pprint(result, width=150)
