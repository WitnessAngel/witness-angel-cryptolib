import json
import sys
import pathlib

import click  # See https://click.palletsprojects.com/en/7.x/
from click.utils import LazyFile
from django.core.serializers.json import DjangoJSONEncoder

ROOT = pathlib.Path(__file__).resolve().parents[0]
assert (ROOT / "manage.py").exists()
sys.path.append(str(ROOT / "src"))


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

CONTAINER_SUFFIX = ".crypt"
MEDIUM_SUFFIX = ".medium"
DEFAULT_ENCODING = "utf8"


# TODO - much later, use "schema" for validation of config data and container format!  See https://github.com/keleshev/schema
# Then export corresponding jsons-chema for the world to see!


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("-c", '--config', default=None, help='Json configuration file', type=click.File('rb'))
@click.pass_context
def cli(ctx, config):
    ctx.ensure_object(dict)
    ctx.obj['config'] = config  # TODO read and validate this file later


def _sign_content(content, algo):
    pass # HASH content and then send it to proper cryptolib function

def get_cryptolib_proxy():
    """
    TODO - if ths jsonrpc webservice is ready, instantiate and return a jsonrpc client here instead of the local lib.
    Note that of course the waserver would have to be launched in a separate console!

    We shall ensure that the wacryptolib root package and the proxy both expose the same high level functions like "generate_public_key(uid, ...)"
    """
    import wacryptolib
    return wacryptolib

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
    return {"aa":33, "bb": {"toto": True}, "medium_content": plaintext}


@cli.command()
@click.option("-i", "--input-medium", type=click.File('r', encoding=DEFAULT_ENCODING), required=True)
@click.option("-o", "--output-container", type=click.File('w', encoding=DEFAULT_ENCODING))
def encrypt(input_medium, output_container):
    """Turn a media file into a secure container."""
    if not output_container:
        output_container = LazyFile(input_medium.name + CONTAINER_SUFFIX, "w", encoding=DEFAULT_ENCODING)
    click.echo("In encrypt: %s" % str(locals()))

    # FIXME here compute real container data
    container_data = _do_encrypt(plaintext=input_medium.read())

    with output_container:
        container_data_str = json.dump(container_data, fp=output_container, sort_keys=True, indent=4, cls=DjangoJSONEncoder)


def _do_decrypt(container_data):
    """
    TODO:

        This function must be able to decrypt the container created by _do_encrypt().
        It must not rely on any external config, all data (uids, algos, digests...) is suppoed to be in the container_data.

    """
    plaintext = container_data["medium_content"]
    return plaintext


@cli.command()
@click.option("-i", "--input-container", type=click.File('r', encoding=DEFAULT_ENCODING), required=True)
@click.option("-o", "--output-medium", type=click.File('w', encoding=DEFAULT_ENCODING))
def decrypt(input_container, output_medium):
    """Turn a container file back into its original media file."""
    if not output_medium:
        if input_container.name.endswith(CONTAINER_SUFFIX):
            output_medium_name = input_container.name[:-len(CONTAINER_SUFFIX)]
        else:
            output_medium_name = input_container.name + MEDIUM_SUFFIX
        output_medium = LazyFile(output_medium_name, "w", encoding=DEFAULT_ENCODING)

    click.echo("In decrypt: %s" % str(locals()))

    container_data = json.load(input_container)

    medium_content = _do_decrypt(container_data)

    with output_medium:
        output_medium.write(medium_content)




if __name__ == '__main__':
    cli()
