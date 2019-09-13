import click  # See https://click.palletsprojects.com/en/7.x/
from click.utils import LazyFile

from wacryptolib.container import (
    ContainerReader,
    ContainerWriter,
    LOCAL_ESCROW_PLACEHOLDER,
)
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


CONTAINER_SUFFIX = ".crypt"
MEDIUM_SUFFIX = ".medium"


# TODO - much later, use "schema" for validation of config data and container format!  See https://github.com/keleshev/schema
# Then export corresponding jsons-chema for the world to see!


EXAMPLE_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[
                dict(
                    escrow_key_type="RSA",
                    key_encryption_algo="RSA_OAEP",
                    key_escrow=LOCAL_ESCROW_PLACEHOLDER,
                )
            ],
            data_signatures=[
                dict(
                    signature_key_type="DSA",
                    signature_algo="DSS",
                    signature_escrow=LOCAL_ESCROW_PLACEHOLDER,
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
@click.pass_context
def cli(ctx, config):
    ctx.ensure_object(dict)
    ctx.obj["config"] = config  # TODO read and validate this file later


def _do_encrypt(data):
    writer = ContainerWriter()
    container = writer.encrypt_data(data, conf=EXAMPLE_CONTAINER_CONF)
    return container


@cli.command()
@click.option("-i", "--input-medium", type=click.File("rb"), required=True)
@click.option("-o", "--output-container", type=click.File("wb"))
def encrypt(input_medium, output_container):
    """Turn a media file into a secure container."""
    if not output_container:
        output_container = LazyFile(input_medium.name + CONTAINER_SUFFIX, "wb")
    click.echo("In encrypt: %s" % str(locals()))

    container_data = _do_encrypt(data=input_medium.read())

    container_data_bytes = dump_to_json_bytes(container_data, indent=4)

    with output_container as f:
        f.write(container_data_bytes)


def _do_decrypt(container):
    reader = ContainerReader()
    result = reader.decrypt_data(container)
    return result


@cli.command()
@click.option("-i", "--input-container", type=click.File("rb"), required=True)
@click.option("-o", "--output-medium", type=click.File("wb"))
def decrypt(input_container, output_medium):
    """Turn a container file back into its original media file."""
    if not output_medium:
        if input_container.name.endswith(CONTAINER_SUFFIX):
            output_medium_name = input_container.name[: -len(CONTAINER_SUFFIX)]
        else:
            output_medium_name = input_container.name + MEDIUM_SUFFIX
        output_medium = LazyFile(output_medium_name, "wb")

    click.echo("In decrypt: %s" % str(locals()))

    container = load_from_json_bytes(input_container.read())

    medium_content = _do_decrypt(container=container)

    with output_medium:
        output_medium.write(medium_content)


if __name__ == "__main__":
    cli()
