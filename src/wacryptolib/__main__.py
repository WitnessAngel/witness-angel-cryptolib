from pathlib import Path

import click  # See https://click.palletsprojects.com/en/7.x/
from click.utils import LazyFile
import os

from wacryptolib.cryptainer import (
    LOCAL_ESCROW_MARKER,
    encrypt_data_into_cryptainer,
    decrypt_data_from_cryptainer,
    CRYPTAINER_SUFFIX,
    MEDIUM_SUFFIX,
    SHARED_SECRET_MARKER,
)
from wacryptolib.key_storage import FilesystemKeyStoragePool
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])
DEFAULT_KEY_STORAGE_POOl_DIRNAME = ".key_storage_pool"

# TODO - much later, use "schema" for validation of config data and cryptainer format!  See https://github.com/keleshev/schema
# Then export corresponding jsons-chema for the world to see!


def _get_key_storage_pool(ctx):
    key_storage_pool_path = ctx.obj["key_storage_pool"]
    if not key_storage_pool_path:
        key_storage_pool_path = Path().joinpath(DEFAULT_KEY_STORAGE_POOl_DIRNAME)
        key_storage_pool_path.mkdir(exist_ok=True)
    return FilesystemKeyStoragePool(key_storage_pool_path)


EXAMPLE_CRYPTOCONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[
                dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER),
                dict(
                    key_encryption_algo=SHARED_SECRET_MARKER,
                    key_shared_secret_threshold=1,
                    key_shared_secret_escrows=[
                        dict(key_encryption_strata=[
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)]),
                        dict(key_encryption_strata=[
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)]),
                    ],  # Beware, same escrow for the 2 shares, for now
                ),
            ],
            data_signatures=[
                dict(message_digest_algo="SHA256", signature_algo="DSA_DSS", signature_escrow=LOCAL_ESCROW_MARKER)
            ],
        )
    ]
)


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("-c", "--config", default=None, help="Json configuration file", type=click.File("rb"))
@click.option(
    "-k",
    "--key-storage-pool",
    default=None,
    help="Folder to get/set crypto keys (else ./%s gets created)" % DEFAULT_KEY_STORAGE_POOl_DIRNAME,
    type=click.Path(
        exists=True, file_okay=False, dir_okay=True, writable=True, readable=True, resolve_path=True, allow_dash=False
    ),
)
@click.pass_context
def cli(ctx, config, key_storage_pool):
    ctx.ensure_object(dict)
    ctx.obj["config"] = config  # TODO read and validate this file later
    ctx.obj["key_storage_pool"] = key_storage_pool


def _do_encrypt(data, key_storage_pool):
    cryptainer = encrypt_data_into_cryptainer(
        data, cryptoconf=EXAMPLE_CRYPTOCONF, metadata=None, key_storage_pool=key_storage_pool
    )
    return cryptainer


@cli.command()
@click.option("-i", "--input-medium", type=click.File("rb"), required=True)
@click.option("-o", "--output-cryptainer", type=click.File("wb"))
@click.pass_context
def encrypt(ctx, input_medium, output_cryptainer):
    """Turn a media file into a secure cryptainer."""
    if not output_cryptainer:
        output_cryptainer = LazyFile(input_medium.name + CRYPTAINER_SUFFIX, "wb")
    click.echo("In encrypt: %s" % str(locals()))

    key_storage_pool = _get_key_storage_pool(ctx)
    cryptainer_data = _do_encrypt(data=input_medium.read(), key_storage_pool=key_storage_pool)

    cryptainer_data_bytes = dump_to_json_bytes(cryptainer_data, indent=4)

    with output_cryptainer as f:
        f.write(cryptainer_data_bytes)


def _do_decrypt(cryptainer, key_storage_pool):
    data = decrypt_data_from_cryptainer(cryptainer, key_storage_pool=key_storage_pool)
    return data


@cli.command()
@click.option("-i", "--input-cryptainer", type=click.File("rb"), required=True)
@click.option("-o", "--output-medium", type=click.File("wb"))
@click.pass_context
def decrypt(ctx, input_cryptainer, output_medium):
    """Turn a cryptainer file back into its original media file."""
    if not output_medium:
        if input_cryptainer.name.endswith(CRYPTAINER_SUFFIX):
            output_medium_name = input_cryptainer.name[: -len(CRYPTAINER_SUFFIX)]
        else:
            output_medium_name = input_cryptainer.name + MEDIUM_SUFFIX
        output_medium = LazyFile(output_medium_name, "wb")

    click.echo("In decrypt: %s" % str(locals()))

    cryptainer = load_from_json_bytes(input_cryptainer.read())

    key_storage_pool = _get_key_storage_pool(ctx)
    medium_content = _do_decrypt(cryptainer=cryptainer, key_storage_pool=key_storage_pool)

    with output_medium:
        output_medium.write(medium_content)


if __name__ == "__main__":
    cli()
