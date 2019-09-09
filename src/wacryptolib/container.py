import copy
import uuid

from wacryptolib.encryption import encrypt_bytestring, decrypt_bytestring
from wacryptolib.key_generation import generate_symmetric_key, KEY_TYPES_REGISTRY
from wacryptolib.signature import verify_signature
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes

LOCAL_ESCROW_PLACEHOLDER = "_local_"


def _get_proxy_for_escrow(escrow):
    import waserver.escrow_api

    if escrow == LOCAL_ESCROW_PLACEHOLDER:
        return waserver.escrow_api
    else:
        raise NotImplementedError("escrow system to be completed")


class ContainerBase:
    pass


class ContainerWriter(ContainerBase):
    def encrypt_data(self, data: bytes, conf: dict, uid=None) -> dict:

        container_uid = uid or uuid.uuid4()

        conf = copy.deepcopy(conf)  # So that we can manipulate it

        assert isinstance(data, bytes), data
        assert isinstance(conf, dict), conf

        # FIXME rename this
        data_ciphertext = data  # Initially unencrypted, might remain so if no strata
        result_data_encryption_strata = []

        for data_encryption_stratum in conf["data_encryption_strata"]:
            data_encryption_type = data_encryption_stratum["data_encryption_type"]
            symmetric_key = generate_symmetric_key(encryption_type=data_encryption_type)

            data_cipherdict = encrypt_bytestring(
                plaintext=data_ciphertext,
                encryption_type=data_encryption_type,
                key=symmetric_key,
            )
            assert isinstance(data_cipherdict, dict), data_cipherdict
            data_ciphertext = dump_to_json_bytes(data_cipherdict)

            symmetric_key_data = (
                symmetric_key
            )  # Initially unencrypted, might remain so if no strata

            result_key_encryption_strata = []
            for key_encryption_stratum in data_encryption_stratum[
                "key_encryption_strata"
            ]:
                symmetric_key_cipherdict = self._encrypt_symmetric_key(
                    container_uid=container_uid,
                    symmetric_key_data=symmetric_key_data,
                    conf=key_encryption_stratum,
                )
                symmetric_key_data = dump_to_json_bytes(
                    symmetric_key_cipherdict
                )  # Remain as bytes all along
                result_key_encryption_strata.append(
                    key_encryption_stratum
                )  # Unmodified for now

            result_signatures = []
            for signature_conf in data_encryption_stratum["signatures"]:
                signature_value = self._generate_signature(
                    container_uid=container_uid,
                    data_ciphertext=data_ciphertext,
                    conf=signature_conf,
                )
                signature_conf["signature_value"] = signature_value
                result_signatures.append(signature_conf)

            result_data_encryption_strata.append(
                dict(
                    data_encryption_type=data_encryption_type,
                    key_ciphertext=symmetric_key_data,
                    key_encryption_strata=result_key_encryption_strata,
                    signatures=result_signatures,
                )
            )

        return dict(
            uid=container_uid,
            data_ciphertext=data_ciphertext,
            data_encryption_strata=result_data_encryption_strata,
        )

    def _encrypt_symmetric_key(
        self, container_uid: uuid.UUID, symmetric_key_data: bytes, conf: dict
    ) -> bytes:
        assert isinstance(symmetric_key_data, bytes), symmetric_key_data
        subkey_type, key_encryption_type = conf["key_encryption_type"]
        encryption_proxy = _get_proxy_for_escrow(conf["key_escrow"])

        subkey_pem = encryption_proxy.get_public_key(
            uid=container_uid, key_type=subkey_type
        )
        subkey = KEY_TYPES_REGISTRY[subkey_type]["pem_import_function"](
            subkey_pem
        )  # FIXME

        key_cipherdict = encrypt_bytestring(
            plaintext=symmetric_key_data,
            encryption_type=key_encryption_type,
            key=subkey,
        )
        return key_cipherdict

    def _generate_signature(
        self, container_uid: uuid.UUID, data_ciphertext: bytes, conf: dict
    ) -> dict:
        encryption_proxy = _get_proxy_for_escrow(conf["signature_escrow"])
        subkey_type, signature_type = conf["signature_type"]
        signature_value = encryption_proxy.get_message_signature(
            uid=container_uid,
            plaintext=data_ciphertext,
            key_type=subkey_type,
            signature_type=signature_type,
        )
        # FIXME remove "type" from inside signature!!!
        return signature_value


class ContainerReader(ContainerBase):
    def decrypt_data(self, container: dict) -> bytes:
        assert isinstance(container, dict), container

        container_uid = container["uid"]

        data_ciphertext = container["data_ciphertext"]

        for data_encryption_stratum in reversed(container["data_encryption_strata"]):

            data_encryption_type = data_encryption_stratum[
                "data_encryption_type"
            ]  # FIXME USE THIS

            for signature_conf in data_encryption_stratum["signatures"]:
                self._verify_signatures(
                    container_uid=container_uid,
                    message=data_ciphertext,
                    conf=signature_conf,
                )

            symmetric_key_data = data_encryption_stratum[
                "key_ciphertext"
            ]  # We start fully encrypted and unravel it
            for key_encryption_stratum in data_encryption_stratum[
                "key_encryption_strata"
            ]:
                symmetric_key_cipherdict = load_from_json_bytes(
                    symmetric_key_data
                )  # Remain as bytes all along
                symmetric_key_data = self._decrypt_symmetric_key(
                    container_uid=container_uid,
                    symmetric_key_cipherdict=symmetric_key_cipherdict,
                    conf=key_encryption_stratum,
                )

            assert isinstance(symmetric_key_data, bytes), symmetric_key_data
            data_cipherdict = load_from_json_bytes(data_ciphertext)
            data_ciphertext = decrypt_bytestring(
                cipherdict=data_cipherdict, key=symmetric_key_data
            )

        data = data_ciphertext  # Now decrypted  FIXME FIND BETTER NAME
        return data

    def _decrypt_symmetric_key(
        self, container_uid: uuid.UUID, symmetric_key_cipherdict: dict, conf: list
    ):
        assert isinstance(symmetric_key_cipherdict, dict), symmetric_key_cipherdict
        subkey_type, key_encryption_type = conf["key_encryption_type"]
        encryption_proxy = _get_proxy_for_escrow(conf["key_escrow"])

        symmetric_key_plaintext = encryption_proxy.decrypt_with_private_key(
            uid=container_uid, key_type=subkey_type, cipherdict=symmetric_key_cipherdict
        )
        return symmetric_key_plaintext

    def _verify_signatures(self, container_uid: uuid.UUID, message: bytes, conf: dict):
        subkey_type, signature_type = conf["signature_type"]
        encryption_proxy = _get_proxy_for_escrow(conf["signature_escrow"])
        public_key_pem = encryption_proxy.get_public_key(
            uid=container_uid, key_type=subkey_type
        )
        public_key = KEY_TYPES_REGISTRY[subkey_type]["pem_import_function"](
            public_key_pem
        )

        print(
            "\n> VERYFYING SIGNATURE FOR \n%s with %s key of public form %s"
            % (message, public_key.__class__, public_key.export_key(format="PEM"))
        )

        verify_signature(
            plaintext=message, signature=conf["signature_value"], key=public_key
        )  # Raises if troubles


def encrypt_data_into_container(data: bytes, conf: dict, uid=None) -> dict:
    """

    :param data:
    :param conf:
    :param uid:
    :return:
    """
    writer = ContainerWriter()
    container = writer.encrypt_data(data, conf=conf, uid=uid)
    return container


def decrypt_data_from_container(container: dict) -> bytes:
    """

    :param container:
    :return:
    """
    reader = ContainerReader()
    data = reader.decrypt_data(container)
    return data
