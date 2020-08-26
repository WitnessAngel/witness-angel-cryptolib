from pathlib import Path

import click  # See https://click.palletsprojects.com/en/7.x/
from click.utils import LazyFile
import os

from wacryptolib.container import (
    LOCAL_ESCROW_MARKER,
    encrypt_data_into_container,
    decrypt_data_from_container,
    CONTAINER_SUFFIX,
    MEDIUM_SUFFIX, SHARED_SECRET_MARKER,
)
from wacryptolib.key_storage import FilesystemKeyStorage
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])
DEFAULT_KEY_STORAGE_DIRNAME = ".key_storage"

# TODO - much later, use "schema" for validation of config data and container format!  See https://github.com/keleshev/schema
# Then export corresponding jsons-chema for the world to see!


def _get_key_storage(ctx):
    key_storage_path = ctx.obj["key_storage"]
    if not key_storage_path:
        key_storage_path = Path().joinpath(DEFAULT_KEY_STORAGE_DIRNAME)
        key_storage_path.mkdir(exist_ok=True)
    return FilesystemKeyStorage(key_storage_path)


EXAMPLE_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[
                dict(
                    key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER
                ),
                dict(
                    key_encryption_algo=SHARED_SECRET_MARKER,
                    key_shared_secret_threshold=1,
                    key_shared_secret_escrows=[
                        dict(
                            share_encryption_algo="RSA_OAEP",
                            share_escrow=LOCAL_ESCROW_MARKER,
                        ),
                        dict(
                            share_encryption_algo="RSA_OAEP",
                            share_escrow=LOCAL_ESCROW_MARKER)]  # Beware, same escrow for the 2 shares, for now
                )
            ],
            data_signatures=[
                dict(
                    message_prehash_algo="SHA256",
                    signature_algo="DSA_DSS",
                    signature_escrow=LOCAL_ESCROW_MARKER,
                )
            ],
        )
    ]
)


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option(
    "-c",
    "--config",
    default=None,
    help="Json configuration file",
    type=click.File("rb"),
)
@click.option(
    "-k",
    "--key-storage",
    default=None,
    help="Folder to get/set crypto keys (else ./%s gets created)" % DEFAULT_KEY_STORAGE_DIRNAME,
    type=click.Path(exists=True,
                    file_okay=False,
                    dir_okay=True,
                    writable=True,
                    readable=True,
                    resolve_path=True,
                    allow_dash=False))
@click.pass_context
def cli(ctx, config, key_storage):
    ctx.ensure_object(dict)
    ctx.obj["config"] = config  # TODO read and validate this file later
    ctx.obj["key_storage"] = key_storage


def _do_encrypt(data, local_key_storage):
    container = encrypt_data_into_container(
        data, conf=EXAMPLE_CONTAINER_CONF, metadata=None, local_key_storage=local_key_storage
    )
    return container


@cli.command()
@click.option("-i", "--input-medium", type=click.File("rb"), required=True)
@click.option("-o", "--output-container", type=click.File("wb"))
@click.pass_context
def encrypt(ctx, input_medium, output_container):
    """Turn a media file into a secure container."""
    if not output_container:
        output_container = LazyFile(input_medium.name + CONTAINER_SUFFIX, "wb")
    click.echo("In encrypt: %s" % str(locals()))

    local_key_storage = _get_key_storage(ctx)
    container_data = _do_encrypt(data=input_medium.read(), local_key_storage=local_key_storage)

    container_data_bytes = dump_to_json_bytes(container_data, indent=4)

    with output_container as f:
        f.write(container_data_bytes)


def _do_decrypt(container, local_key_storage):
    data = decrypt_data_from_container(container, local_key_storage=local_key_storage)
    return data


@cli.command()
@click.option("-i", "--input-container", type=click.File("rb"), required=True)
@click.option("-o", "--output-medium", type=click.File("wb"))
@click.pass_context
def decrypt(ctx, input_container, output_medium):
    """Turn a container file back into its original media file."""
    if not output_medium:
        if input_container.name.endswith(CONTAINER_SUFFIX):
            output_medium_name = input_container.name[: -len(CONTAINER_SUFFIX)]
        else:
            output_medium_name = input_container.name + MEDIUM_SUFFIX
        output_medium = LazyFile(output_medium_name, "wb")

    click.echo("In decrypt: %s" % str(locals()))

    container = load_from_json_bytes(input_container.read())

    local_key_storage = _get_key_storage(ctx)
    medium_content = _do_decrypt(container=container, local_key_storage=local_key_storage)

    with output_medium:
        output_medium.write(medium_content)


if __name__ == "__main__":
    cli()
