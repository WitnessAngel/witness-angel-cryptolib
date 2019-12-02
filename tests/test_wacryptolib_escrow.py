import os
import random
import uuid

import pytest
from Crypto.Random import get_random_bytes

from wacryptolib.encryption import _encrypt_via_rsa_oaep
from wacryptolib.escrow import EscrowApi, DummyKeyStorage, KeyStorageBase, FilesystemKeyStorage
from wacryptolib.key_generation import load_asymmetric_key_from_pem_bytestring
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


def test_key_storage_basic_get_set_api(tmp_path):

    with pytest.raises(TypeError, match="Can't instantiate abstract class"):
        KeyStorageBase()

    dummy_key_storage = DummyKeyStorage()
    filesystem_key_storage = FilesystemKeyStorage(keys_dir=str(tmp_path))

    keychain_uid = generate_uuid0()
    keychain_uid_other = generate_uuid0()

    for key_storage in (dummy_key_storage, filesystem_key_storage):

        key_storage.set_keys(
            keychain_uid=keychain_uid, key_type="abxz", public_key=b"public_data", private_key=b"private_data"
        )
        with pytest.raises(RuntimeError, match="Already existing"):
            key_storage.set_keys(
                keychain_uid=keychain_uid,
                key_type="abxz",
                public_key=b"public_data",
                private_key=b"private_data",
            )
        with pytest.raises(RuntimeError, match="Already existing"):
            key_storage.set_keys(
                keychain_uid=keychain_uid,
                key_type="abxz",
                public_key=b"public_data2",
                private_key=b"private_data2",
            )

        assert key_storage.get_public_key(keychain_uid=keychain_uid, key_type="abxz") == b"public_data"
        assert key_storage.get_private_key(keychain_uid=keychain_uid, key_type="abxz") == b"private_data"

        assert key_storage.get_public_key(keychain_uid=keychain_uid, key_type="abxz_") == None
        assert key_storage.get_private_key(keychain_uid=keychain_uid, key_type="abxz_") == None

        assert key_storage.get_public_key(keychain_uid=keychain_uid_other, key_type="abxz") == None
        assert key_storage.get_private_key(keychain_uid=keychain_uid_other, key_type="abxz") == None


    is_public = random.choice([True, False])
    basename = filesystem_key_storage._get_filename(keychain_uid, key_type="abxz", is_public=is_public)
    with open(os.path.join(str(tmp_path), basename), "rb") as f:
        key_data = f.read()
        assert key_data == (b"public_data" if is_public else b"private_data")  # IMPORTANT no exchange of keys in files!


def test_key_storage_free_keys_api(tmp_path):

    dummy_key_storage = DummyKeyStorage()
    filesystem_key_storage = FilesystemKeyStorage(keys_dir=str(tmp_path))

    keychain_uid = generate_uuid0()
    keychain_uid_other = generate_uuid0()

    for key_storage in (dummy_key_storage, filesystem_key_storage):

        # This blocks free key attachment to this uid+type
        key_storage.set_keys(keychain_uid=keychain_uid, key_type="type1", public_key=b"whatever1", private_key=b"whatever2")

        key_storage.add_free_keypair(key_type="type1", public_key=b"public_data", private_key=b"private_data")
        key_storage.add_free_keypair(key_type="type1", public_key=b"public_data2", private_key=b"private_data2")
        key_storage.add_free_keypair(key_type="type2", public_key=b"public_data_other_type", private_key=b"private_data_other_type")

        assert key_storage.get_free_keypairs_count("type1") == 2
        assert key_storage.get_free_keypairs_count("type2") == 1
        assert key_storage.get_free_keypairs_count("type3") == 0

        with pytest.raises(RuntimeError, match="Already existing"):
            key_storage.attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_type="type1")

        key_storage.attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_type="type2")

        assert key_storage.get_free_keypairs_count("type1") == 2
        assert key_storage.get_free_keypairs_count("type2") == 0
        assert key_storage.get_free_keypairs_count("type3") == 0

        key_storage.attach_free_keypair_to_uuid(keychain_uid=keychain_uid_other, key_type="type1")

        assert key_storage.get_free_keypairs_count("type1") == 1
        assert key_storage.get_free_keypairs_count("type2") == 0
        assert key_storage.get_free_keypairs_count("type3") == 0

        with pytest.raises(RuntimeError, match="No free keypair of type"):
            key_storage.attach_free_keypair_to_uuid(keychain_uid=keychain_uid_other, key_type="type2")

        with pytest.raises(RuntimeError, match="No free keypair of type"):
            key_storage.attach_free_keypair_to_uuid(keychain_uid=keychain_uid, key_type="type3")

        assert key_storage.get_free_keypairs_count("type1") == 1
        assert key_storage.get_free_keypairs_count("type2") == 0
        assert key_storage.get_free_keypairs_count("type3") == 0
