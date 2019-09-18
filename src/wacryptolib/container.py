import copy
import uuid

from wacryptolib.encryption import encrypt_bytestring, decrypt_bytestring
from wacryptolib.escrow import DummyKeyStorage, EscrowApi, LOCAL_ESCROW_PLACEHOLDER
from wacryptolib.key_generation import (
    generate_symmetric_key,
    load_asymmetric_key_from_pem_bytestring,
)
from wacryptolib.signature import verify_message_signature
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes

CONTAINER_FORMAT = "WA_0.1a"

LOCAL_ESCROW_API = EscrowApi(key_storage=DummyKeyStorage())


def _get_proxy_for_escrow(escrow):
    if escrow == LOCAL_ESCROW_PLACEHOLDER:
        return LOCAL_ESCROW_API
    else:
        raise NotImplementedError("Escrow system for testing needs to be completed")


class ContainerBase:
    """
    BEWARE - this class-based design is provisional and might change a lot.
    """

    pass


class ContainerWriter(ContainerBase):
    def encrypt_data(self, data: bytes, *, conf: dict, keychain_uid=None) -> dict:

        container_format = CONTAINER_FORMAT
        container_uid = uuid.uuid4()  # ALWAYS UNIQUE!
        keychain_uid = (
            keychain_uid or uuid.uuid4()
        )  # Might be shared by lots of containers

        conf = copy.deepcopy(conf)  # So that we can manipulate it

        assert isinstance(data, bytes), data
        assert isinstance(conf, dict), conf

        data_current = data  # Initially unencrypted, might remain so if no strata
        result_data_encryption_strata = []

        for data_encryption_stratum in conf["data_encryption_strata"]:
            data_encryption_algo = data_encryption_stratum["data_encryption_algo"]
            symmetric_key = generate_symmetric_key(encryption_algo=data_encryption_algo)

            data_cipherdict = encrypt_bytestring(
                plaintext=data_current,
                encryption_algo=data_encryption_algo,
                key=symmetric_key,
            )
            assert isinstance(data_cipherdict, dict), data_cipherdict
            data_current = dump_to_json_bytes(data_cipherdict)

            symmetric_key_data = (
                symmetric_key
            )  # Initially unencrypted, might remain so if no strata

            result_key_encryption_strata = []
            for key_encryption_stratum in data_encryption_stratum[
                "key_encryption_strata"
            ]:
                symmetric_key_cipherdict = self._encrypt_symmetric_key(
                    keychain_uid=keychain_uid,
                    symmetric_key_data=symmetric_key_data,
                    conf=key_encryption_stratum,
                )
                symmetric_key_data = dump_to_json_bytes(
                    symmetric_key_cipherdict
                )  # Remain as bytes all along
                result_key_encryption_strata.append(
                    key_encryption_stratum
                )  # Unmodified for now

            data_signatures = []
            for signature_conf in data_encryption_stratum["data_signatures"]:
                signature_value = self._generate_signature(
                    keychain_uid=keychain_uid,
                    data_ciphertext=data_current,
                    conf=signature_conf,
                )
                signature_conf["signature_value"] = signature_value
                data_signatures.append(signature_conf)

            result_data_encryption_strata.append(
                dict(
                    data_encryption_algo=data_encryption_algo,
                    key_ciphertext=symmetric_key_data,
                    key_encryption_strata=result_key_encryption_strata,
                    data_signatures=data_signatures,
                )
            )

        data_ciphertext = (
            data_current
        )  # New fully encrypted (unless data_encryption_strata is empty)

        return dict(
            container_format=container_format,
            container_uid=container_uid,
            keychain_uid=keychain_uid,
            data_ciphertext=data_ciphertext,
            data_encryption_strata=result_data_encryption_strata,
        )

    def _encrypt_symmetric_key(
        self, keychain_uid: uuid.UUID, symmetric_key_data: bytes, conf: dict
    ) -> dict:
        assert isinstance(symmetric_key_data, bytes), symmetric_key_data
        escrow_key_type = conf["escrow_key_type"]
        key_encryption_algo = conf["key_encryption_algo"]
        encryption_proxy = _get_proxy_for_escrow(conf["key_escrow"])

        subkey_pem = encryption_proxy.get_public_key(
            keychain_uid=keychain_uid, key_type=escrow_key_type
        )
        subkey = load_asymmetric_key_from_pem_bytestring(
            key_pem=subkey_pem, key_type=escrow_key_type
        )

        key_cipherdict = encrypt_bytestring(
            plaintext=symmetric_key_data,
            encryption_algo=key_encryption_algo,
            key=subkey,
        )
        return key_cipherdict

    def _generate_signature(
        self, keychain_uid: uuid.UUID, data_ciphertext: bytes, conf: dict
    ) -> dict:
        encryption_proxy = _get_proxy_for_escrow(conf["signature_escrow"])
        signature_key_type = conf["signature_key_type"]
        signature_algo = conf["signature_algo"]
        signature_value = encryption_proxy.get_message_signature(
            keychain_uid=keychain_uid,
            message=data_ciphertext,
            key_type=signature_key_type,
            signature_algo=signature_algo,
        )
        return signature_value


class ContainerReader(ContainerBase):
    def decrypt_data(self, container: dict) -> bytes:
        assert isinstance(container, dict), container

        container_format = container["container_format"]
        if container_format != CONTAINER_FORMAT:
            raise ValueError("Unknown container format %s" % container_format)

        container_uid = container["container_format"]
        del container_uid  # Might be used for logging etc, later...

        keychain_uid = container["keychain_uid"]

        data_current = container["data_ciphertext"]

        for data_encryption_stratum in reversed(container["data_encryption_strata"]):

            data_encryption_algo = data_encryption_stratum["data_encryption_algo"]

            for signature_conf in data_encryption_stratum["data_signatures"]:
                self._verify_message_signatures(
                    keychain_uid=keychain_uid, message=data_current, conf=signature_conf
                )

            symmetric_key_data = data_encryption_stratum[
                "key_ciphertext"
            ]  # We start fully encrypted, and unravel it
            for key_encryption_stratum in data_encryption_stratum[
                "key_encryption_strata"
            ]:
                symmetric_key_cipherdict = load_from_json_bytes(
                    symmetric_key_data
                )  # We remain as bytes all along
                symmetric_key_data = self._decrypt_symmetric_key(
                    keychain_uid=keychain_uid,
                    symmetric_key_cipherdict=symmetric_key_cipherdict,
                    conf=key_encryption_stratum,
                )

            assert isinstance(symmetric_key_data, bytes), symmetric_key_data
            data_cipherdict = load_from_json_bytes(data_current)
            data_current = decrypt_bytestring(
                cipherdict=data_cipherdict,
                key=symmetric_key_data,
                encryption_algo=data_encryption_algo,
            )

        data = data_current  # Now decrypted
        return data

    def _decrypt_symmetric_key(
        self, keychain_uid: uuid.UUID, symmetric_key_cipherdict: dict, conf: list
    ):
        assert isinstance(symmetric_key_cipherdict, dict), symmetric_key_cipherdict
        escrow_key_type = conf["escrow_key_type"]
        key_encryption_algo = conf["key_encryption_algo"]
        encryption_proxy = _get_proxy_for_escrow(conf["key_escrow"])

        symmetric_key_plaintext = encryption_proxy.decrypt_with_private_key(
            keychain_uid=keychain_uid,
            key_type=escrow_key_type,
            encryption_algo=key_encryption_algo,
            cipherdict=symmetric_key_cipherdict,
        )
        return symmetric_key_plaintext

    def _verify_message_signatures(
        self, keychain_uid: uuid.UUID, message: bytes, conf: dict
    ):
        signature_key_type = conf["signature_key_type"]
        signature_algo = conf["signature_algo"]
        encryption_proxy = _get_proxy_for_escrow(conf["signature_escrow"])
        public_key_pem = encryption_proxy.get_public_key(
            keychain_uid=keychain_uid, key_type=signature_key_type
        )
        public_key = load_asymmetric_key_from_pem_bytestring(
            key_pem=public_key_pem, key_type=signature_key_type
        )

        verify_message_signature(
            message=message,
            signature_algo=signature_algo,
            signature=conf["signature_value"],
            key=public_key,
        )  # Raises if troubles


def encrypt_data_into_container(data: bytes, *, conf: dict, keychain_uid=None) -> dict:
    """Turn raw data into a high-security container, which can only be decrypted with
    the agreement of the owner and multiple third-party escrows.

    :param data: bytestring of media (image, video, sound...) to protect
    :param conf: tree of format-specific settings
    :param keychain_uid: optional ID of a keychain to reuse

    :return:
    """
    writer = ContainerWriter()
    container = writer.encrypt_data(data, conf=conf, keychain_uid=keychain_uid)
    return container


def decrypt_data_from_container(container: dict) -> bytes:
    """Decrypt a container with the help of third-parties.

    :param container: the container tree, which holds all information about involved keys

    :return: raw bytestring
    """
    reader = ContainerReader()
    data = reader.decrypt_data(container)
    return data
