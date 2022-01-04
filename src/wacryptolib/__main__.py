from pathlib import Path

import click  # See https://click.palletsprojects.com/en/7.x/
from click.utils import LazyFile

from wacryptolib.cryptainer import (
    LOCAL_FACTORY_TRUSTEE_MARKER,
    encrypt_payload_into_cryptainer,
    decrypt_payload_from_cryptainer,
    CRYPTAINER_SUFFIX,
    DECRYPTED_FILE_SUFFIX,
    SHARED_SECRET_ALGO_MARKER,
)
from wacryptolib.keystore import FilesystemKeystorePool
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])
DEFAULT_KEYSTORE_POOL_DIRNAME = ".keystore_pool"

# TODO - much later, use "schema" for validation of config data and cryptainer format!  See https://github.com/keleshev/schema
# Then export corresponding jsons-chema for the world to see!


def _get_keystore_pool(ctx):
    keystore_pool_dir = ctx.obj["keystore_pool"]
    if not keystore_pool_dir:
        keystore_pool_dir = Path().joinpath(DEFAULT_KEYSTORE_POOL_DIRNAME)
        keystore_pool_dir.mkdir(exist_ok=True)
    return FilesystemKeystorePool(keystore_pool_dir)


EXAMPLE_CRYPTOCONF = dict(
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[
                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_FACTORY_TRUSTEE_MARKER),
                dict(
                    key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
                    key_shared_secret_threshold=1,
                    key_shared_secret_shards=[
                        dict(
                            key_cipher_layers=[
                                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_FACTORY_TRUSTEE_MARKER)
                            ]
                        ),
                        dict(
                            key_cipher_layers=[
                                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_FACTORY_TRUSTEE_MARKER)
                            ]
                        ),
                    ],  # Beware, same trustee for the 2 shards, for now
                ),
            ],
            payload_signatures=[
                dict(
                    payload_digest_algo="SHA256",
                    payload_signature_algo="DSA_DSS",
                    payload_signature_trustee=LOCAL_FACTORY_TRUSTEE_MARKER,
                )
            ],
        )
    ]
)


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("-c", "--config", default=None, help="Json configuration file", type=click.File("rb"))
@click.option(
    "-k",
    "--keystore-pool",
    default=None,
    help="Folder to get/set crypto keys (else ./%s gets created)" % DEFAULT_KEYSTORE_POOL_DIRNAME,
    type=click.Path(
        exists=True, file_okay=False, dir_okay=True, writable=True, readable=True, resolve_path=True, allow_dash=False
    ),
)
@click.pass_context
def cli(ctx, config, keystore_pool):
    ctx.ensure_object(dict)
    ctx.obj["config"] = config  # TODO read and validate this file later
    ctx.obj["keystore_pool"] = keystore_pool


def _do_encrypt(payload, keystore_pool):
    cryptainer = encrypt_payload_into_cryptainer(
        payload, cryptoconf=EXAMPLE_CRYPTOCONF, metadata=None, keystore_pool=keystore_pool
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

    keystore_pool = _get_keystore_pool(ctx)
    cryptainer = _do_encrypt(payload=input_medium.read(), keystore_pool=keystore_pool)

    cryptainer_bytes = dump_to_json_bytes(cryptainer, indent=4)

    with output_cryptainer as f:
        f.write(cryptainer_bytes)


def _do_decrypt(cryptainer, keystore_pool):
    payload = decrypt_payload_from_cryptainer(cryptainer, keystore_pool=keystore_pool)
    return payload


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
            output_medium_name = input_cryptainer.name + DECRYPTED_FILE_SUFFIX
        output_medium = LazyFile(output_medium_name, "wb")

    click.echo("In decrypt: %s" % str(locals()))

    cryptainer = load_from_json_bytes(input_cryptainer.read())

    keystore_pool = _get_keystore_pool(ctx)
    medium_content = _do_decrypt(cryptainer=cryptainer, keystore_pool=keystore_pool)

    with output_medium:
        output_medium.write(medium_content)


if __name__ == "__main__":
    cli()
