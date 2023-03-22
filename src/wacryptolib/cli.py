import json
import os
from pathlib import Path
from pprint import pprint
from datetime import timedelta
import uuid
import logging

import click  # See https://click.palletsprojects.com/en/7.x/
from click.utils import LazyFile
import click_log
from prettytable import PrettyTable
import shutil


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

logger = logging.getLogger(__name__)
click_log.basic_config(logger)
click.echo = None  # Break this on purpose

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

_internal_app_dir = Path("~/.witnessangel").expanduser().resolve()
DEFAULT_KEYSTORE_POOL_PATH = _internal_app_dir / "keystore_pool"
DEFAULT_CRYPTAINER_STORAGE_PATH = _internal_app_dir / "cryptainers"
INDENT = "  "

def _short_format_datetime(dt):
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M")

def _get_keystore_pool(ctx):
    keystore_pool_dir = ctx.obj["keystore_pool"]
    if not keystore_pool_dir:
        keystore_pool_dir = Path().joinpath(DEFAULT_KEYSTORE_POOL_PATH).resolve()
        logger.debug("No keystore-pool directory provided, defaulting to '%s'" % keystore_pool_dir)
        keystore_pool_dir.mkdir(exist_ok=True)
    return FilesystemKeystorePool(keystore_pool_dir)


def _get_cryptainer_storage(ctx, keystore_pool=None, offload_payload_ciphertext=True, **extra_kwargs):
    cryptainer_storage_dir = ctx.obj["cryptainer_storage"]
    if not cryptainer_storage_dir:
        cryptainer_storage_dir = Path().joinpath(DEFAULT_CRYPTAINER_STORAGE_PATH).resolve()
        logger.debug("No cryptainer-storage directory provided, defaulting to '%s'" % cryptainer_storage_dir)
        cryptainer_storage_dir.mkdir(exist_ok=True)
    return CryptainerStorage(cryptainer_storage_dir,
                             keystore_pool=keystore_pool,
                             offload_payload_ciphertext=offload_payload_ciphertext,
                             **extra_kwargs)


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
@click_log.simple_verbosity_option(logger)
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
@click.option(  # Fixme use Pypi click-params.URl one day?
    "-g",
    "--gateway-url",
    default=None,
    help="URL of the web registry endpoint",
)
@click.pass_context
def wacryptolib_cli(ctx, keystore_pool, cryptainer_storage, gateway_url) -> object:
    ctx.ensure_object(dict)
    ctx.obj["keystore_pool"] = keystore_pool
    ctx.obj["cryptainer_storage"] = cryptainer_storage
    ctx.obj["gateway-url"] = gateway_url


@wacryptolib_cli.group()
def foreign_keystores():
    pass


@foreign_keystores.command("list")
@click.pass_context
def list_foreign_keystores(ctx):  # FIXME list count of public/private keys too!
    keystore_pool = _get_keystore_pool(ctx)
    foreign_keystore_metadata_list = keystore_pool.get_all_foreign_keystore_metadata()
    print(foreign_keystore_metadata_list)
    if not foreign_keystore_metadata_list:
        logger.warning("No foreign keystores found")
    else:
        table = PrettyTable(["Keystore UID", "Owner", "Created at"])
        # table.align = "l"  useless
        for foreign_keystore_uid, foreign_keystore_metadata in sorted(foreign_keystore_metadata_list.items()):
            table.add_row([foreign_keystore_uid,
                           foreign_keystore_metadata["keystore_owner"],
                           _short_format_datetime(foreign_keystore_metadata.get("keystore_creation_datetime")),])
        logger.info(table)


@foreign_keystores.command("delete")
@click.argument('keystore_uid', type=click.UUID)
@click.pass_context
def delete_foreign_keystore(ctx, keystore_uid):
    keystore_pool = _get_keystore_pool(ctx)
    path = keystore_pool._get_foreign_keystore_dir(keystore_uid)
    try:
        shutil.rmtree(path)
        logger.info("Foreign keystore %s successfully deleted" % keystore_uid)
    except OSError as exc:
        raise click.UsageError("Failed deletion of imported authentication device %s: %r" % (keystore_uid, exc))


@foreign_keystores.command("import")
@click.option("--from-usb", help="Fetch authenticators from plugged USB devices", is_flag=True)
@click.option("--from-path", help="Fetch authenticator from folder path", type=click.Path(
    exists=True, file_okay=False, dir_okay=True, readable=True, resolve_path=True, allow_dash=False
))
@click.option("--from-gateway", help="Fetch authenticator by uid from gateway", type=click.UUID)
@click.option("--include-private-keys", help="Import private keys when available", is_flag=True)
@click.pass_context
def import_foreign_keystores(ctx, from_usb, from_gateway, from_path, include_private_keys):

    if not from_usb and not from_gateway and not from_path:
        raise click.UsageError("No source selected for keystore import")

    keystore_pool = _get_keystore_pool(ctx)

    if from_usb:
        logger.info("Importing foreign keystores from USB devices, %s private keys" % ("with" if include_private_keys else "without"))
        results = operations.import_keystores_from_initialized_authdevices(
            keystore_pool,
            include_private_keys=include_private_keys)
        msg = "{foreign_keystore_count} new authenticators imported, {already_existing_keystore_count} updated, {corrupted_keystore_count} skipped because corrupted".format(**results)
        logger.info(msg)

    def _build_single_import_success_message(_keystore_metadata, _updated):
        _msg = "Authenticator {} (owner: {}) %s" % ("updated" if updated else "imported")
        return _msg.format(_keystore_metadata["keystore_uid"], _keystore_metadata["keystore_owner"])

    if from_path:
        logger.info("Importing foreign keystore from folder %s, %s private keys" % (from_path, "with" if include_private_keys else "without"))
        keystore_metadata, updated = operations.import_keystore_from_path(
            keystore_pool,
            keystore_path=from_path,
            include_private_keys=include_private_keys)
        msg = _build_single_import_success_message(keystore_metadata, updated)
        logger.info(msg)

    if from_gateway:
        #print(">>>>>>>>>>>>>", ctx.obj)
        gateway_url = ctx.obj["gateway-url"]
        if not gateway_url:
            raise click.UsageError("No web gateway URL specified for keystore import")
        logger.info("Importing foreign keystore %s from web gateway" % from_gateway)
        keystore_metadata, updated = operations.import_keystore_from_web_gateway(keystore_pool, gateway_url=gateway_url, keystore_uid=from_gateway)
        msg = _build_single_import_success_message(keystore_metadata, updated)
        logger.info(msg)


def _do_encrypt(payload, cryptoconf_fileobj, keystore_pool):  # FIXME REMOVE

    if not cryptoconf_fileobj:
        logger.warning("No cryptoconf provided, defaulting to simple example conf")
        cryptoconf = EXAMPLE_CRYPTOCONF
    else:
        cryptoconf = load_from_json_bytes(cryptoconf_fileobj.read())

    check_cryptoconf_sanity(cryptoconf)

    cryptainer = encrypt_payload_into_cryptainer(
        payload, cryptoconf=cryptoconf, cryptainer_metadata=None, keystore_pool=keystore_pool
    )
    return cryptainer


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
        logger.warning("No cryptoconf provided, defaulting to simple example conf")
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
    logger.info("Encryption of file '%s' finished" % input_medium.name)


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

    logger.info("Decryption finished to file '%s'" % output_medium.name)


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
#@click.option("-f", "--format", type=click.Choice(['pretty', 'json'], case_sensitive=False), default="pretty")
def list_cryptainers(ctx):
    cryptainer_storage = _get_cryptainer_storage(ctx)
    cryptainer_dicts = cryptainer_storage.list_cryptainer_properties(as_sorted_list=True, with_age=True, with_size=True)

    #if format == "json":
    #    json.dumps(cryptainer_dicts, indent=True, sort_keys=True)

    print("\nCryptainers:\n")
    for cryptainer_dict in cryptainer_dicts:
        print(INDENT, cryptainer_dict["name"])


@cryptainers.command("delete")
@click.argument('cryptainer_name')
@click.pass_context
def delete_cryptainer(ctx, cryptainer_name):
    cryptainer_storage = _get_cryptainer_storage(ctx)
    if not cryptainer_storage.is_valid_cryptainer_name(cryptainer_name):
        raise click.UsageError("Invalid cryptainer name %s" % cryptainer_name)
    cryptainer_storage.delete_cryptainer(cryptainer_name=cryptainer_name)
    logger.info("Cryptainer %s successfully deleted" % cryptainer_name)


@cryptainers.command("purge")
@click.pass_context
@click.option("--max-age", type=int, help="Maximum age of cryptainer, in days")
@click.option("--max-count", type=int, help="Maximum count of cryptainers in storage")
@click.option("--max-quota", type=int, help="Maximum total size of cryptainers, in MiBs")
def purge_cryptainers(ctx, max_age, max_count, max_quota):
    extra_kwargs = dict(
        max_cryptainer_age=(timedelta(days=max_age) if max_age is not None else None),
        max_cryptainer_count=max_count,  # Might be None
        max_cryptainer_quota=(max_quota * 1024**2 if max_quota else None),
    )

    extra_kwargs = {k:v for (k, v) in extra_kwargs.items() if v is not None}

    if not extra_kwargs:
        print("Aborting purge, since no criterion was provided as argument")  # FIXME use click.fail?
        return

    cryptainer_storage = _get_cryptainer_storage(ctx, **extra_kwargs)
    deleted_cryptainer_count = cryptainer_storage.purge_exceeding_cryptainers()
    logger.info("Cryptainers successfully deleted: %s" % deleted_cryptainer_count)


def main():
    """Launch CLI"""
    fake_prog_name = "python -m wacryptolib"  # Else __init__.py is used in help text...
    wacryptolib_cli(prog_name=fake_prog_name)
