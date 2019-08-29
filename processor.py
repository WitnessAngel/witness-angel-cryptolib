import json
import sys
import pathlib
import uuid
import time

from Crypto.Random import get_random_bytes
from src.wacryptolib import key_generation, cipher, signature
from src.wacryptolib.signature import sign_with_rsa, sign_with_dsa_or_ecc

import click  # See https://click.palletsprojects.com/en/7.x/
from click.utils import LazyFile
from django.core.serializers.json import DjangoJSONEncoder

ROOT = pathlib.Path(__file__).resolve().parents[0]
assert (ROOT / "manage.py").exists()
sys.path.append(str(ROOT / "src"))

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

CONTAINER_SUFFIX = ".crypt"
MEDIUM_SUFFIX = ".medium"
DEFAULT_ENCODING = "utf8"

# TODO - much later, use "schema" for validation of config data and container format!  See https://github.com/keleshev/schema
# Then export corresponding jsons-chema for the world to see!


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option(
    "-c",
    "--config",
    default=None,
    help="Json configuration file",
    type=click.File("rb"),
)
@click.pass_context
def cli(ctx, config):
    ctx.ensure_object(dict)
    ctx.obj["config"] = config  # TODO read and validate this file later


def _sign_content(content, algo):
    """Permits to sign a hash of `content`

    :param content: plaintext to sign
    :param algo: algorithm to use to sign. Can be "DSA" or "RSA"
    :return: dictionary with informations necessary to verify the signature
    """
    uid = uuid.uuid4()

    signer_generator = dict(
        RSA={
            "sign_function": sign_with_rsa,
            "keypair": key_generation.generate_assymetric_keypair(
                uid=uid, key_type="RSA"
            ),
        },
        DSA={
            "sign_function": sign_with_dsa_or_ecc,
            "keypair": key_generation.generate_assymetric_keypair(
                uid=uid, key_type="DSA"
            ),
        },
    )

    generation_func = signer_generator[algo]["sign_function"]
    keypair = signer_generator[algo]["keypair"]

    signer = generation_func(keypair["private_key"], content)
    signature = {
        "signature_algorithm": algo,
        "signature_payload": signer,
        "signature_public_key": keypair["public_key"],
        "signature_escrow": {"escrow_type": "standalone", "escrow_identity": uid},
    }
    return signature


def get_cryptolib_proxy():
    """
    TODO - if ths jsonrpc webservice is ready, instantiate and return a jsonrpc client here instead of the local lib.
    Note that of course the waserver would have to be launched in a separate console!

    We shall ensure that the wacryptolib root package and the proxy both expose the same high level functions like "generate_assymetric_keypair(uid, ...)"
    """
    import src.wacryptolib

    return src.wacryptolib


def _do_encrypt(plaintext, algorithms):
    """Encrypt the plaintext and sign the resulting ciphertext, then cipher the
    ciphering key with given algorithms. Can be repeated as much as you want.

    :param plaintext: Initial plaintext which have to be ciphered
    :param algorithms: dictionary composed of the different algorithms to use. Should be
    in this form :
    {
    "cipher_algo": [`tuple of algorithms to cipher the plaintext`],
    "signature_algo": [`tuple of algorithms to sign`],
    "key_cipher_algo": [`tuple of algorithms to cipher the ciphering key`]
    :return: dictionary composed of information necessary to decipher the ciphertext.
    It has to be parameter of function _do_decrypt."""

    uid_container = uuid.uuid4()
    data_encryption_strata = []
    algos = zip(
        algorithms["cipher_algo"][0],
        algorithms["signature_algo"][0],
        algorithms["key_cipher_algo"][0],
    )
    for cipher_algo, signature_algo, key_cipher_algo in algos:

        cipher_algo_generator = dict(
            aes={"function": cipher.encrypt_via_aes_eax, "key_length": 16},
            chacha={"function": cipher.encrypt_via_chacha20_poly1305, "key_length": 32},
            RSA=cipher.encrypt_via_rsa_oaep,
        )
        cipher_key = get_random_bytes(cipher_algo_generator[cipher_algo]["key_length"])
        encryption = cipher_algo_generator[cipher_algo]["function"](
            key=cipher_key, plaintext=plaintext
        )

        uid_cipher = uuid.uuid4()
        keypair_cipher_key = key_generation.generate_assymetric_keypair(
            uid=uid_cipher, key_type=key_cipher_algo
        )
        encryption_key = cipher_algo_generator[key_cipher_algo](
            key=keypair_cipher_key["public_key"], plaintext=cipher_key
        )

        signature = _sign_content(content=encryption["ciphertext"], algo=signature_algo)
        plaintext = encryption["ciphertext"]

        data_encryption = {
            "signatures": signature,
            "encryption_algorithm": cipher_algo,
            "encryption": encryption,
            "encryption_key": encryption_key,
            "key_encryption_strata": {
                "encryption_algorithm": key_cipher_algo,
                "key_escrow": {
                    "escrow_type": "standalone",
                    "escrow_identity": uid_cipher,
                },
            },
        }

        data_encryption_strata.append(data_encryption)
    data_ciphertext = encryption["ciphertext"]

    container = {
        "uid_container": uid_container,
        "data_ciphertext": data_ciphertext,
        "data_encryption_strata": data_encryption_strata,
    }
    return container


@cli.command()
@click.option(
    "-i",
    "--input-medium",
    type=click.File("r", encoding=DEFAULT_ENCODING),
    required=True,
)
@click.option(
    "-o", "--output-container", type=click.File("w", encoding=DEFAULT_ENCODING)
)
def encrypt(input_medium, output_container):
    """Turn a media file into a secure container."""
    if not output_container:
        output_container = LazyFile(
            input_medium.name + CONTAINER_SUFFIX, "w", encoding=DEFAULT_ENCODING
        )
    click.echo("In encrypt: %s" % str(locals()))

    # FIXME here compute real container data
    container_data = _do_encrypt(plaintext=input_medium.read())

    with output_container:
        container_data_str = json.dump(
            container_data,
            fp=output_container,
            sort_keys=True,
            indent=4,
            cls=DjangoJSONEncoder,
        )


def _do_decrypt(container_data):
    """Permits to decrypt a ciphertext thanks to `container_data` which
    is created in function _do_encrypt

    :param container_data: container returned from function _do_encrypt
    :return: plaintext deciphered"""

    for nb_encryption in range(1, -1, -1):

        data_encryption_strata = container_data["data_encryption_strata"][nb_encryption]
        decipher_algo_generator = dict(
            aes=cipher.decrypt_via_aes_eax,
            chacha=cipher.decrypt_via_chacha20_poly1305,
            RSA=cipher.decrypt_via_rsa_oaep,
        )
        algo_encryption_key = data_encryption_strata["key_encryption_strata"][
            "encryption_algorithm"
        ]

        # Get the initial key to decipher
        decrypted_key = decipher_algo_generator[algo_encryption_key](
            key=key_generation.generate_assymetric_keypair(
                uid=data_encryption_strata["key_encryption_strata"]["key_escrow"][
                    "escrow_identity"
                ],
                key_type=data_encryption_strata["key_encryption_strata"][
                    "encryption_algorithm"
                ],
            )["private_key"],
            encryption=data_encryption_strata["encryption_key"],
        )

        # Decipher the text
        decrypted_text = decipher_algo_generator[
            data_encryption_strata["encryption_algorithm"]
        ](key=decrypted_key, encryption=data_encryption_strata["encryption"])

        signature.verify_signature(
            public_key=data_encryption_strata["signatures"]["signature_public_key"],
            plaintext=data_encryption_strata["encryption"]["ciphertext"],
            signature=data_encryption_strata["signatures"]["signature_payload"],
        )
        container_data["medium_content"] = decrypted_text

    plaintext = container_data["medium_content"]
    return plaintext


@cli.command()
@click.option(
    "-i",
    "--input-container",
    type=click.File("r", encoding=DEFAULT_ENCODING),
    required=True,
)
@click.option("-o", "--output-medium", type=click.File("w", encoding=DEFAULT_ENCODING))
def decrypt(input_container, output_medium):
    """Turn a container file back into its original media file."""
    if not output_medium:
        if input_container.name.endswith(CONTAINER_SUFFIX):
            output_medium_name = input_container.name[: -len(CONTAINER_SUFFIX)]
        else:
            output_medium_name = input_container.name + MEDIUM_SUFFIX
        output_medium = LazyFile(output_medium_name, "w", encoding=DEFAULT_ENCODING)

    click.echo("In decrypt: %s" % str(locals()))

    container_data = json.load(input_container)

    medium_content = _do_decrypt(container_data)

    with output_medium:
        output_medium.write(medium_content)


if __name__ == "__main__":
    cli()
