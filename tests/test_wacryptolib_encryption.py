import copy
import functools
import io
import random

import pytest
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

import wacryptolib
from wacryptolib.container import ContainerWriter
from wacryptolib.encryption import STREAMABLE_ENCRYPTION_ALGOS
from wacryptolib.exceptions import DecryptionError, EncryptionError, DecryptionIntegrityError
from wacryptolib.key_generation import SUPPORTED_SYMMETRIC_KEY_ALGOS, generate_symmetric_key_dict, \
    SYMMETRIC_KEY_TYPES_REGISTRY
from wacryptolib.utilities import SUPPORTED_HASH_ALGOS, hash_message
from wacryptolib.encryption import AUTHENTICATED_ENCRYPTION_ALGOS


def _get_binary_content():
    bytes_length = random.randint(1, 1000)
    return get_random_bytes(bytes_length)


def test_generic_encryption_and_decryption_errors():
    key_dict = {"key": get_random_bytes(32)}
    binary_content = _get_binary_content()

    with pytest.raises(ValueError, match="Unknown cipher type"):
        wacryptolib.encryption.encrypt_bytestring(key_dict=key_dict, plaintext=binary_content, encryption_algo="EXHD")

    with pytest.raises(ValueError, match="Unknown cipher type"):
        wacryptolib.encryption.decrypt_bytestring(key_dict=key_dict, cipherdict={}, encryption_algo="EXHD")


def _test_random_ciphertext_corruption(decryption_func, cipherdict, initial_content):
    initial_cipherdict = copy.deepcopy(cipherdict)

    def _check_decryption_fails(new_cipherdict):
        try:
            decrypted_content_bad = decryption_func(cipherdict=new_cipherdict)
            assert decrypted_content_bad != initial_content  # Decryption weirdly succeeded but gave bad content
        except DecryptionError as exc:
            pass  # Proper failure

    for _ in range(5):

        # Test in-place modification of encrypted data

        encryption = copy.deepcopy(initial_cipherdict)

        if encryption.get("digest_list"):  # RSA OAEP CASE
            digest_list = encryption["digest_list"][:]
            idx = random.randint(0, len(digest_list) - 1)
            encryption["digest_list"][idx] = get_random_bytes(random.randint(1, 10))
        else:
            original_ciphertext = encryption["ciphertext"]
            editable_ciphertext = bytearray(original_ciphertext)
            idx = random.randint(0, len(editable_ciphertext) - 1)
            editable_ciphertext[idx] = (editable_ciphertext[idx] + random.randint(1, 100)) % 256
            corrupted_ciphertext = bytes(editable_ciphertext)
            encryption["ciphertext"] = corrupted_ciphertext

        _check_decryption_fails(encryption)

    for _ in range(3):

        # Test extension of encrypetd data with random bytes

        suffix = get_random_bytes(random.randint(4, 10))
        if encryption.get("digest_list"):
            encryption["digest_list"].append(suffix)
        else:
            encryption["ciphertext"] += suffix

        _check_decryption_fails(encryption)


@pytest.mark.parametrize("encryption_algo", SUPPORTED_SYMMETRIC_KEY_ALGOS)
@pytest.mark.parametrize("use_empty_data", [True, False])
def test_symmetric_encryption_and_decryption_for_algo(encryption_algo, use_empty_data):
    key_dict = generate_symmetric_key_dict(encryption_algo)

    binary_content = b"" if use_empty_data else _get_binary_content()

    cipherdict = wacryptolib.encryption.encrypt_bytestring(
        key_dict=key_dict, plaintext=binary_content, encryption_algo=encryption_algo
    )

    assert "ciphertext" in cipherdict  # Mandatory field
    assert isinstance(cipherdict["ciphertext"], bytes)

    decrypted_content = wacryptolib.encryption.decrypt_bytestring(
        key_dict=key_dict, cipherdict=cipherdict, encryption_algo=encryption_algo
    )

    assert decrypted_content == binary_content

    if not use_empty_data:
        decryption_func = functools.partial(
            wacryptolib.encryption.decrypt_bytestring, key_dict=key_dict, encryption_algo=encryption_algo
        )
        _test_random_ciphertext_corruption(decryption_func, cipherdict=cipherdict, initial_content=binary_content)

    main_key_too_short = get_random_bytes(16)

    main_key_too_short_dict = key_dict.copy()
    main_key_too_short_dict["key"] = main_key_too_short

    with pytest.raises(EncryptionError, match="symmetric key length"):
        wacryptolib.encryption.encrypt_bytestring(
            key_dict=main_key_too_short_dict, plaintext=binary_content, encryption_algo=encryption_algo
        )

    with pytest.raises(DecryptionError, match="symmetric key length"):
        wacryptolib.encryption.decrypt_bytestring(
            key_dict=main_key_too_short_dict, cipherdict=cipherdict, encryption_algo=encryption_algo
        )


def test_rsa_oaep_asymmetric_encryption_and_decryption():
    key_length_bits = random.choice([2048, 3072, 4096])
    encryption_algo = "RSA_OAEP"
    keypair = wacryptolib.key_generation.generate_asymmetric_keypair(
        key_type="RSA_OAEP", serialize=False, key_length_bits=key_length_bits
    )

    binary_content = _get_binary_content()

    cipherdict = wacryptolib.encryption.encrypt_bytestring(
        key_dict=dict(key=keypair["public_key"]), plaintext=binary_content, encryption_algo=encryption_algo
    )

    decrypted_content = wacryptolib.encryption.decrypt_bytestring(
        key_dict=dict(key=keypair["private_key"]), cipherdict=cipherdict, encryption_algo=encryption_algo
    )

    assert decrypted_content == binary_content

    decryption_func = functools.partial(
        wacryptolib.encryption.decrypt_bytestring, key_dict=dict(key=keypair["private_key"]), encryption_algo="RSA_OAEP"
    )
    _test_random_ciphertext_corruption(decryption_func, cipherdict=cipherdict, initial_content=binary_content)

    private_key_too_short = RSA.generate(1024)
    public_key_too_short = private_key_too_short.publickey()

    with pytest.raises(EncryptionError, match="asymmetric key length"):
        wacryptolib.encryption.encrypt_bytestring(
            key_dict=dict(key=public_key_too_short), plaintext=binary_content, encryption_algo=encryption_algo
        )

    with pytest.raises(DecryptionError, match="asymmetric key length"):
        wacryptolib.encryption.decrypt_bytestring(
            key_dict=dict(key=private_key_too_short), cipherdict=cipherdict, encryption_algo=encryption_algo
        )


# test each node separately, then a pipeline with all nodes
_stream_algo_nodes = [[algo] for algo in STREAMABLE_ENCRYPTION_ALGOS] + [STREAMABLE_ENCRYPTION_ALGOS]


@pytest.mark.parametrize("encryption_algo_list", _stream_algo_nodes)
def test_stream_manager(encryption_algo_list):

    output_stream = io.BytesIO()

    data_encryption_strata_extracts = []
    for encryption_algo in encryption_algo_list:
        data_encryption_strata_extract = {'encryption_algo': encryption_algo,
                                          'symmetric_key_dict': generate_symmetric_key_dict(encryption_algo),
                                          'message_digest_algos': random.choices(SUPPORTED_HASH_ALGOS, k=randint(1,
                                                                                                                 len(SUPPORTED_HASH_ALGOS)))}
        data_encryption_strata_extracts.append(data_encryption_strata_extract)
    print(data_encryption_strata_extracts)

    streammanager = wacryptolib.encryption.StreamManager(
        data_encryption_strata_extracts=data_encryption_strata_extracts,
        output_stream=output_stream)

    plaintext_full = get_random_bytes(randint(10, 10000))
    plaintext_current = plaintext_full
    while plaintext_current:     # TODO factorize this utility
        chunk_length = randint(1, 300)
        chunk = plaintext_current[0:chunk_length]
        plaintext_current = plaintext_current[chunk_length:]
        streammanager.encrypt_chunk(chunk)

    streammanager.finalize()

    current_ciphertext = output_stream.getvalue()

    for data_encryption_node, authentication_data in zip(reversed(data_encryption_strata_extracts),
                                                         reversed(streammanager.get_authentication_data())):

        for hash_algo in data_encryption_node['message_digest_algos']:
            assert (hash_message(message=current_ciphertext, hash_algo=hash_algo) ==  # TODO NOW create local vars
                    authentication_data['message_digests'][hash_algo])

        cipherdict = {"ciphertext": current_ciphertext}
        cipherdict.update(authentication_data["integrity_tags"])

        decrypted_ciphertext = wacryptolib.encryption.decrypt_bytestring(cipherdict=cipherdict,
                                                                         encryption_algo=data_encryption_node[
                                                                             'encryption_algo'],
                                                                         key_dict=data_encryption_node[
                                                                             "symmetric_key_dict"])

        current_ciphertext = decrypted_ciphertext

    assert decrypted_ciphertext == plaintext_full


@pytest.mark.parametrize("encryption_algo", SUPPORTED_SYMMETRIC_KEY_ALGOS)
def test_symmetric_decryption_verify(encryption_algo):

    attribute_to_corrupt = "tag"  # For now it's the only kind of authentication marker
    is_corruptable = encryption_algo in AUTHENTICATED_ENCRYPTION_ALGOS

    key_dict = generate_symmetric_key_dict(encryption_algo)
    binary_content = _get_binary_content()

    cipherdict = wacryptolib.encryption.encrypt_bytestring(
        key_dict=key_dict, plaintext=binary_content, encryption_algo=encryption_algo
    )

    if is_corruptable:
        assert attribute_to_corrupt in cipherdict, cipherdict
        # Replace the attribute with random bytes
        cipherdict[attribute_to_corrupt] = get_random_bytes(len(cipherdict[attribute_to_corrupt]))

    # Decryption should not fail if verify==False
    decrypted_content = wacryptolib.encryption.decrypt_bytestring(
        key_dict=key_dict, cipherdict=cipherdict, encryption_algo=encryption_algo, verify=False
    )
    assert decrypted_content == binary_content

    decryption_callable = lambda: wacryptolib.encryption.decrypt_bytestring(key_dict=key_dict, cipherdict=cipherdict, encryption_algo=encryption_algo, verify=True)

    # Decryption should fail if verify==True, but only for algorithms that enforce an authentication check
    if is_corruptable:
        with pytest.raises(DecryptionIntegrityError):
            decryption_callable()
    else:
        decryption_callable()
