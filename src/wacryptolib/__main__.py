import os
from pathlib import Path
from pprint import pprint

import click  # See https://click.palletsprojects.com/en/7.x/
from click.utils import LazyFile

from wacryptolib import operations
from wacryptolib.cryptainer import (
    LOCAL_KEYFACTORY_TRUSTEE_MARKER,
    encrypt_payload_into_cryptainer,
    decrypt_payload_from_cryptainer,
    CRYPTAINER_SUFFIX,
    DECRYPTED_FILE_SUFFIX,
    SHARED_SECRET_ALGO_MARKER,
    check_cryptoconf_sanity,
    check_cryptainer_sanity,
    get_cryptoconf_summary, ReadonlyCryptainerStorage, CryptainerStorage, dump_cryptainer_to_filesystem,
)
from wacryptolib.keystore import FilesystemKeystorePool
from wacryptolib.operations import decrypt_payload_from_bytes
from wacryptolib.utilities import dump_to_json_bytes, load_from_json_bytes

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

_internal_app_dir = Path("~/.witnessangel").expanduser().resolve()
DEFAULT_KEYSTORE_POOL_PATH = _internal_app_dir / "keystore_pool"
DEFAULT_CRYPTAINER_STORAGE_PATH = _internal_app_dir / "cryptainers"


def _get_keystore_pool(ctx):
    keystore_pool_dir = ctx.obj["keystore_pool"]
    if not keystore_pool_dir:
        keystore_pool_dir = Path().joinpath(DEFAULT_KEYSTORE_POOL_PATH).resolve()
        click.echo("No keystore-pool directory provided, defaulting to '%s'" % keystore_pool_dir)
        keystore_pool_dir.mkdir(exist_ok=True)
    return FilesystemKeystorePool(keystore_pool_dir)


def _get_cryptainer_storage(ctx, keystore_pool=None, offload_payload_ciphertext=True):
    cryptainer_storage_dir = ctx.obj["cryptainer_storage"]
    if not cryptainer_storage_dir:
        cryptainer_storage_dir = Path().joinpath(DEFAULT_CRYPTAINER_STORAGE_PATH).resolve()
        click.echo("No cryptainer-storage directory provided, defaulting to '%s'" % cryptainer_storage_dir)
        cryptainer_storage_dir.mkdir(exist_ok=True)
    return CryptainerStorage(cryptainer_storage_dir,
                             keystore_pool=keystore_pool,
                             offload_payload_ciphertext=offload_payload_ciphertext)


EXAMPLE_CRYPTOCONF = dict(
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[
                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER),
                dict(
                    key_cipher_algo=SHARED_SECRET_ALGO_MARKER,
                    key_shared_secret_threshold=1,
                    key_shared_secret_shards=[
                        dict(
                            key_cipher_layers=[
                                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                            ]
                        ),
                        dict(
                            key_cipher_layers=[
                                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)
                            ]
                        ),
                    ],  # Beware, same trustee for the 2 shards, for now
                ),
            ],
            payload_signatures=[
                dict(
                    payload_digest_algo="SHA256",
                    payload_signature_algo="DSA_DSS",
                    payload_signature_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER,
                )
            ],
        )
    ]
)


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option(
    "-k",
    "--keystore-pool",
    default=None,
    help="Folder to get/set crypto keys (else %s gets created)" % DEFAULT_KEYSTORE_POOL_PATH,
    type=click.Path(
        exists=True, file_okay=False, dir_okay=True, writable=True, readable=True, resolve_path=True, allow_dash=False
    ),
)
@click.option(
    "-c",
    "--cryptainer-storage",
    default=None,
    help="Folder to store cryptainers (else %s gets created)" % DEFAULT_CRYPTAINER_STORAGE_PATH,
    type=click.Path(
        exists=True, file_okay=False, dir_okay=True, writable=True, readable=True, resolve_path=True, allow_dash=False
    ),
)
@click.pass_context
def wacryptolib_cli(ctx, keystore_pool, cryptainer_storage) -> object:
    ctx.ensure_object(dict)
    ctx.obj["keystore_pool"] = keystore_pool
    ctx.obj["cryptainer_storage"] = cryptainer_storage


@wacryptolib_cli.command()
@click.argument('input_medium', type=click.File('rb'), )
@click.option("-o", "--output-cryptainer", type=click.Path(
    exists=False, file_okay=True, dir_okay=False, writable=True, resolve_path=True, allow_dash=False
)) # TODO allow piping via allow-dash
@click.option("-c", "--cryptoconf", default=None, help="Json crypotoconf file", type=click.File("rb"))
@click.option("--bundle", help="Combine cryptainer data and metadata", is_flag=True)
@click.pass_context
def encrypt(ctx, input_medium, output_cryptainer, cryptoconf, bundle):
    """Turn a media file into a secure cryptainer."""

    input_medium_name = input_medium.name
    offload_payload_ciphertext = not bundle

    # click.echo("In encrypt: %s" % str(locals()))
    if not cryptoconf:
        click.echo("No cryptoconf provided, defaulting to simple example conf")
        cryptoconf = EXAMPLE_CRYPTOCONF
    else:
        cryptoconf = load_from_json_bytes(cryptoconf.read())

    keystore_pool = _get_keystore_pool(ctx)

    payload = input_medium.read()

    if output_cryptainer:
        cryptainer = encrypt_payload_into_cryptainer(
            payload, cryptoconf=cryptoconf, cryptainer_metadata=None, keystore_pool=keystore_pool
        )

        dump_cryptainer_to_filesystem(
            cryptainer_filepath=output_cryptainer,
            cryptainer=cryptainer,
            offload_payload_ciphertext=offload_payload_ciphertext)

    else:
        cryptainer_storage = _get_cryptainer_storage(ctx, keystore_pool=keystore_pool, offload_payload_ciphertext=offload_payload_ciphertext)
        cryptainer_storage.enqueue_file_for_encryption(
            filename_base=input_medium.name, payload=payload, cryptainer_metadata=None, cryptoconf=cryptoconf
        )
        cryptainer_storage.wait_for_idle_state()

    ##output_cryptainer = LazyFile(input_medium.name + CRYPTAINER_SUFFIX, "wb")
    click.echo("Encryption of file '%s' finished" % input_medium.name)


@wacryptolib_cli.command()
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

    # click.echo("In decrypt: %s" % str(locals()))
    cryptainer_bytes = input_cryptainer.read()

    keystore_pool = _get_keystore_pool(ctx)
    medium_content, error_report = decrypt_payload_from_bytes(cryptainer_bytes=cryptainer_bytes, keystore_pool=keystore_pool)

    if error_report:
        print("Decryption errors occured:")
        pprint(error_report)

    if not medium_content:
        raise RuntimeError("Content could not be decrypted")

    with output_medium:
        output_medium.write(medium_content)

    click.echo("Decryption finished to file '%s'" % output_medium.name)


@wacryptolib_cli.command()
@click.option("-i", "--input-file", type=click.File("rb"), required=True)
@click.pass_context
def summarize(ctx, input_file):
    """Display a summary of a cryptoconf (or cryptainer) structure."""

    # click.echo("In display_cryptoconf_summary: %s" % str(locals()))

    cryptoconf = load_from_json_bytes(input_file.read())

    text_summary = get_cryptoconf_summary(cryptoconf)
    print(text_summary)


@wacryptolib_cli.group()
def cryptainers():
    """Manage cryptainers"""
    pass


@cryptainers.command("list")
@click.pass_context
def list_cryptainers(ctx):
    cryptainer_storage = _get_cryptainer_storage(ctx)
    cryptainer_dicts = cryptainer_storage.list_cryptainer_properties(with_age=True, with_size=True)
    print(cryptainer_dicts)

'''
@cryptainers.command("purge")
@click.pass_context
def purge_cryptainers(ctx):
    cryptainer_storage = _get_cryptainer_storage(ctx)
    cryptainer_dicts = cryptainer_storage.list_cryptainer_properties(with_age=True, with_size=True)
    print(cryptainer_dicts)

cryptainers purge –max-cryptainer-quota/max-cryptainer-count/max-cryptainer-age # Purge les cryptainers en trop par rapport à ces critères
'''

if __name__ == "__main__":
    fake_prog_name = "python -m wacryptolib"  # Else __init__.py is used in help text...
    wacryptolib_cli(prog_name=fake_prog_name)


if __name__ == "__main__":
    main()
