import json
import sys
import pathlib
import uuid

from Crypto.Random import get_random_bytes
from src.wacryptolib import key_generation, cipher
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
    signer_generator = dict(
        RSA={"sign_function": sign_rsa,
             "keypair": key_generation.generate_public_key(uid=None, key_type="RSA")},
        DSA={"sign_function": sign_dsa,
             "keypair": key_generation.generate_public_key(uid=None, key_type="DSA")}
    )

    generation_func = signer_generator[algo]["sign_function"]
    keypair = signer_generator[algo]["keypair"]
    signature = generation_func(keypair["private_key"], content)

    return signature


def get_cryptolib_proxy():
    """
    TODO - if ths jsonrpc webservice is ready, instantiate and return a jsonrpc client here instead of the local lib.
    Note that of course the waserver would have to be launched in a separate console!

    We shall ensure that the wacryptolib root package and the proxy both expose the same high level functions like "generate_public_key(uid, ...)"
    """
    import src.wacryptolib

    return src.wacryptolib


def _do_encrypt(plaintext):
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

        A loop like this would be a proper way to start the algorithm

        ::

            data_encryption_strata = []
            for cipher_algo, signature_algo in [("aes", "rsa"), ("chacha???", "dsa")]:
                signatures = []
                # apply standard recipe


    """
    uid = uuid.uuid4()

    # ---- 1ST ENCRYPTION (WITH AES) ----
    cipher_aes_key = get_random_bytes(16)
    encryption_aes = cipher.encrypt_via_aes_eax(key=cipher_aes_key, plaintext=plaintext)

    rsa_keypair_cipher = key_generation.generate_public_key(uid=uid, key_type="RSA")
    encrypted_cipher_key_aes = cipher.encrypt_via_rsa_oaep(key=rsa_keypair_cipher["private_key"],
                                                           plaintext=cipher_aes_key)
    rsa_keypair_sign = key_generation.generate_public_key(uid=uid, key_type="RSA")
    signed_ciphertext_rsa = _sign_content(content=encryption_aes["ciphertext"], algo="RSA")

    # ---- 2ND ENCRYPTION (WITH CHACHA20) ----
    cipher_chacha_key = get_random_bytes(32)
    encryption_chacha = cipher.encrypt_via_chacha20_poly1305(key=cipher_chacha_key,
                                                             plaintext=encryption_aes["ciphertext"])

    rsa_keypair_cipher2 = key_generation.generate_public_key(uid=uid, key_type="RSA")
    encrypted_cipher_key_chacha = cipher.encrypt_via_rsa_oaep(key=rsa_keypair_cipher2["private_key"],
                                                              plaintext=cipher_chacha_key)

    dsa_keypair_sign = key_generation.generate_public_key(uid=uid, key_type="DSA")
    signed_ciphertext_dsa = _sign_content(content=encryption_chacha["ciphertext"], algo="DSA")

    return {
        "1": {"encrypted_cipher_key": encrypted_cipher_key_aes,
              "rsa_keypair_sign": rsa_keypair_sign,
              "signed_ciphertext_rsa": signed_ciphertext_rsa},
        "2": {"encrypted_cipher_key": encrypted_cipher_key_chacha,
              "rsa_keypair_sign": dsa_keypair_sign,
              "signed_ciphertext_rsa": signed_ciphertext_dsa}}


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
