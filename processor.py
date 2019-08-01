import json
import sys
import pathlib
import uuid
import time

from Crypto.Random import get_random_bytes
from src.wacryptolib import key_generation, cipher, signature
from src.wacryptolib.signature import sign_rsa, sign_dsa

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
    # HASH content and then send it to proper cryptolib function
    uid = uuid.uuid4()

    signer_generator = dict(
        RSA={"sign_function": sign_rsa,
             "keypair": key_generation.generate_public_key(uid=uid, key_type="RSA")},
        DSA={"sign_function": sign_dsa,
             "keypair": key_generation.generate_public_key(uid=uid, key_type="DSA")}
    )

    generation_func = signer_generator[algo]["sign_function"]
    keypair = signer_generator[algo]["keypair"]

    signer = generation_func(keypair["private_key"], content)
    signature = {
        "signature_algorithm": algo,
        "signature_payload": signer,
        "signature_keypair": keypair,  # TODO: DELETE
        "signature_escrow": {
            "escrow_type": "standalone",
            "escrow_identity": uid
        }
    }
    return signature


def get_cryptolib_proxy():
    """
    TODO - if ths jsonrpc webservice is ready, instantiate and return a jsonrpc client here instead of the local lib.
    Note that of course the waserver would have to be launched in a separate console!

    We shall ensure that the wacryptolib root package and the proxy both expose the same high level functions like "generate_public_key(uid, ...)"
    """
    import src.wacryptolib

    return src.wacryptolib


def _do_encrypt(plaintext, algorithms):
    """
    TODO:

        - generate a common UID for the whole container (stored at the root of result json)
        - encrypt the plaintext twice, first with AES/OAEP and then in chain with ChaCha20-Poly1305
        - for each of these 2 encryptions:
            - the symmetric cipher key must be generated randomly and locally,
              used on data, and then RSA-encrypted (with cryptolib-originated public key) before being stored in container
            - the resulting ciphertext must be signed with RSA (for the first encryption) or DSA (for the second and final encryption);
              of course, only sign a HASH of the content (thanks to new _sign_content() above)
        - the result json must "roughly" follow the format of containers.rst, except for signatures where the output dict of the cryptolib must be stored as-is
    """

    data_encryption_strata = []
    algos = zip(algorithms["cipher_algo"][0], algorithms["signature_algo"][0], algorithms["key_cipher_algo"][0])
    for cipher_algo, signature_algo, key_cipher_algo in algos:

        cipher_algo_generator = dict(
            aes={"function": cipher.encrypt_via_aes_eax, "key_length": 16},
            chacha={"function": cipher.encrypt_via_chacha20_poly1305, "key_length": 32},
            RSA=cipher.encrypt_via_rsa_oaep,
        )
        cipher_key = get_random_bytes(cipher_algo_generator[cipher_algo]["key_length"])
        encryption = cipher_algo_generator[cipher_algo]["function"](key=cipher_key, plaintext=plaintext)

        uid_cipher = uuid.uuid4()
        keypair_cipher_key = key_generation.generate_public_key(uid=uid_cipher, key_type=key_cipher_algo)
        encryption_key = cipher_algo_generator[key_cipher_algo](key=keypair_cipher_key["public_key"],
                                                                plaintext=cipher_key)

        signature = _sign_content(content=encryption["ciphertext"], algo=signature_algo)
        plaintext = encryption["ciphertext"]

        data_encryption = {
            "signatures": signature,
            "encryption_algorithm": cipher_algo,
            "encryption": encryption,
            "encryption_key": encryption_key,
            "key_encryption_strata": {
                "encryption_algorithm": key_cipher_algo,
                "keypair_cipher": keypair_cipher_key,  # TODO: DELETE
                "key_escrow": {
                    "escrow_type": "standalone",
                    "escrow_identity": uid_cipher,
                }
            }
        }

        data_encryption_strata.append(data_encryption)
    data_ciphertext = encryption["ciphertext"]

    container = {"data_ciphertext": data_ciphertext, "data_encryption_strata": data_encryption_strata}
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
    """
    TODO:

        This function must be able to decrypt the container created by _do_encrypt().
        It must not rely on any external config, all data (uids, algos, digests...) is supposed to be in the container_data.
    """
    for nb_encryption in range(1, -1, -1):

        data_encryption_strata = container_data["data_encryption_strata"][nb_encryption]
        decipher_algo_generator = dict(
            aes=cipher.decrypt_via_aes_eax,
            chacha=cipher.decrypt_via_chacha20_poly1305,
            RSA=cipher.decrypt_via_rsa_oaep,
        )
        algo_encryption_key = data_encryption_strata["key_encryption_strata"]["encryption_algorithm"]

        # Get the initial key to decipher
        decrypted_key = decipher_algo_generator[algo_encryption_key](
            # key=data_encryption_strata["key_encryption_strata"]["keypair_cipher"]["private_key"],
            key=key_generation.generate_public_key(
                uid=data_encryption_strata["key_encryption_strata"]["key_escrow"]["escrow_identity"],
                key_type=data_encryption_strata["key_encryption_strata"]["encryption_algorithm"]
            )["private_key"],
            encryption=data_encryption_strata["encryption_key"]
        )

        # Decipher the text
        decrypted_text = decipher_algo_generator[data_encryption_strata["encryption_algorithm"]](
            key=decrypted_key,
            encryption=data_encryption_strata["encryption"]
        )

        signature.verify_signature(
            public_key=data_encryption_strata["signatures"]["signature_keypair"]["public_key"],
            # public_key=key_generation.generate_public_key(
            #     uid=data_encryption_strata["signatures"]["signature_escrow"]["escrow_identity"],
            #     key_type=data_encryption_strata["signatures"]["signature_algorithm"]
            # )["public_key"],
            plaintext=data_encryption_strata["encryption"]["ciphertext"],
            signature=data_encryption_strata["signatures"]["signature_payload"]
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
