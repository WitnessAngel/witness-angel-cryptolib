import functools
import logging
import os
import shutil
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

import click  # See https://click.palletsprojects.com/en/7.x/
import click_log
from click import BaseCommand
from click.utils import LazyFile
from prettytable import PrettyTable

from wacryptolib import operations
from wacryptolib.cipher import SUPPORTED_ASYMMETRIC_CIPHER_ALGOS, SUPPORTED_SYMMETRIC_CIPHER_ALGOS
from wacryptolib.cryptainer import (
    LOCAL_KEYFACTORY_TRUSTEE_MARKER,
    decrypt_payload_from_cryptainer,
    CRYPTAINER_SUFFIX,
    DECRYPTED_FILE_SUFFIX,
    SHARED_SECRET_ALGO_MARKER,
    check_cryptoconf_sanity,
    check_cryptainer_sanity,
    get_cryptoconf_summary,
    CryptainerStorage,
    CRYPTAINER_TRUSTEE_TYPES,
)
from wacryptolib.exceptions import ValidationError, DecryptionError, SchemaValidationError, KeystoreMetadataDoesNotExist
from wacryptolib.keystore import FilesystemKeystorePool, ReadonlyFilesystemKeystore
from wacryptolib.operations import _check_target_authenticator_parameters_validity
from wacryptolib.utilities import load_from_json_bytes, dump_to_json_str, get_nice_size, is_file_basename

# We setup the whole logging tree!
_root_logger = logging.getLogger()
click_log.basic_config(logging.getLogger())

logger = logging.getLogger(__name__)

# from pprint import pprint
# print("ENVIRONMENT")
# pprint(dict(os.environ))

if os.getenv("_WA_RANDOMIZE_CLI_APP_DIR"):  # Only for TESTING
    _internal_app_dir_parent = tempfile.mkdtemp().replace("\\", "/")
    logger.warning("CLI is using temp APP DIR PARENT: %s" % _internal_app_dir_parent)
else:
    _internal_app_dir_parent = "~"

_INTERNAL_APP_DIR_STR = os.path.join(_internal_app_dir_parent, ".witnessangel")  # With ~ for docstrings
Path(_INTERNAL_APP_DIR_STR).expanduser().mkdir(exist_ok=True)

_DEFAULT_KEYSTORE_POOL_STR = os.path.join(_INTERNAL_APP_DIR_STR, "keystore_pool")  # With ~ for docstrings
DEFAULT_KEYSTORE_POOL_PATH = Path(_DEFAULT_KEYSTORE_POOL_STR).expanduser().resolve()
_DEFAULT_CRYPTAINER_STORAGE_STR = os.path.join(_INTERNAL_APP_DIR_STR, "cryptainers")  # With ~ for docstrings
DEFAULT_CRYPTAINER_STORAGE_PATH = Path(_DEFAULT_CRYPTAINER_STORAGE_STR).expanduser().resolve()
INDENT = "  "
FORMAT_OPTION = click.option(
    "-f", "--format", type=click.Choice(["plain", "json"], case_sensitive=False), default="plain", show_default=True
)
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

# Used as fallback when no proper cryptoconf is provided
SIMPLE_EXAMPLE_CRYPTOCONF = dict(
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


def _short_format_datetime(dt):
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M")


def _convert_dict_to_table_of_properties(dictionary, key_list):
    table = PrettyTable(["Property", "Value"])
    selected_fields = [(k, dictionary[k]) for k in key_list]
    for selected_field in selected_fields:
        table.add_row(selected_field)
    return table


def _dump_as_safe_formatted_json(data_tree):
    return dump_to_json_str(data_tree, ensure_ascii=True, indent=2)


def _get_keystore_pool(ctx):
    keystore_pool_dir = ctx.obj["keystore_pool"]
    if not keystore_pool_dir:
        keystore_pool_dir = Path().joinpath(DEFAULT_KEYSTORE_POOL_PATH).resolve()
        logger.debug("No keystore-pool directory provided, defaulting to '%s'" % keystore_pool_dir)
        keystore_pool_dir.mkdir(exist_ok=True)
    return FilesystemKeystorePool(keystore_pool_dir)


def _get_cryptainer_storage(ctx, keystore_pool=None, offload_payload_ciphertext=True, **extra_kwargs):
    cryptainer_storage_dir_str = ctx.obj["cryptainer_storage"]
    if not cryptainer_storage_dir_str:
        cryptainer_storage_dir = Path().joinpath(DEFAULT_CRYPTAINER_STORAGE_PATH).resolve()
        logger.debug("No cryptainer-storage directory provided, defaulting to '%s'" % cryptainer_storage_dir)
        cryptainer_storage_dir.mkdir(exist_ok=True)
    else:
        cryptainer_storage_dir = Path(cryptainer_storage_dir_str)
    return CryptainerStorage(
        cryptainer_storage_dir,
        keystore_pool=keystore_pool,
        offload_payload_ciphertext=offload_payload_ciphertext,
        **extra_kwargs
    )


@click.group(context_settings=CONTEXT_SETTINGS)
@click_log.simple_verbosity_option(_root_logger)
@click.option(
    "-k",
    "--keystore-pool",
    default=None,
    help="Folder tree to store keystores (else %s is used)" % _DEFAULT_KEYSTORE_POOL_STR,
    type=click.Path(
        exists=True,
        file_okay=False,
        dir_okay=True,
        writable=True,
        readable=True,
        resolve_path=True,
        allow_dash=False,
        path_type=Path,
    ),
)
@click.option(
    "-c",
    "--cryptainer-storage",
    default=None,
    help="Folder to store cryptainers (else %s is used)" % _DEFAULT_CRYPTAINER_STORAGE_STR,
    type=click.Path(
        exists=True,
        file_okay=False,
        dir_okay=True,
        writable=True,
        readable=True,
        resolve_path=True,
        allow_dash=False,
        path_type=Path,
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
    """Flexible cryptographic toolkit for multi-tenant encryption and signature"""
    ctx.ensure_object(dict)
    ctx.obj["keystore_pool"] = keystore_pool
    ctx.obj["cryptainer_storage"] = cryptainer_storage
    ctx.obj["gateway_url"] = gateway_url


@wacryptolib_cli.group("authenticator")
def authenticator_group():
    """Manage authenticator trustees"""
    pass


def _retrieve_keystore_passphrase():
    keystore_passphrase = os.getenv("WA_PASSPHRASE")

    if keystore_passphrase:
        logger.info("Using passphrase specified as WA_PASSPHRASE environment variable")
    else:
        keystore_passphrase = click.prompt("Please enter a passphrase for the authenticator", hide_input=True)
    assert keystore_passphrase, keystore_passphrase  # MUST be non-empty now

    return keystore_passphrase


@authenticator_group.command("create")
@click.argument(
    "authenticator_dir",
    type=click.Path(
        exists=False,
        writable=True,
        resolve_path=True,
        path_type=Path,  # Beware, before python3.10 resolve_path is buggy on Windows
    ),
)
@click.option(
    "--keypair-count", default=3, help="Count of keypairs to generate (min 1)", type=click.INT, show_default=True
)
@click.option("--owner", help="Name of the authenticator owner", required=True)
@click.option("--passphrase-hint", help="Non-sensitive hint to help remember the passphrase", required=True)
@click.pass_context
def create_authenticator(ctx, authenticator_dir, keypair_count, owner, passphrase_hint):
    """
    Initialize an authenticator folder with a set of keypairs

    The target directory must not exist yet, but its parent directory must exist.

    Authenticator passphrase can be provided as WA_PASSPHRASE environment variable, else user will be prompted for it.

    No constraints are applied to the lengths of the passphrase or other fields, so beware of security considerations!
    """

    _check_target_authenticator_parameters_validity(
        authenticator_dir, keypair_count=keypair_count, exception_cls=click.UsageError
    )  # Early check, to not ask for passphrase in vain

    keystore_passphrase = _retrieve_keystore_passphrase()

    operations.create_authenticator(
        authenticator_dir,
        keypair_count=keypair_count,
        keystore_owner=owner,
        keystore_passphrase_hint=passphrase_hint,
        keystore_passphrase=keystore_passphrase,
    )

    logger.info(
        "Authenticator successfully initialized with %d keypairs in directory %s", keypair_count, authenticator_dir
    )


@authenticator_group.command("validate")
@click.argument(
    "authenticator_dir",
    type=click.Path(exists=True, dir_okay=True, file_okay=False, readable=True, resolve_path=True, path_type=Path),
)
@click.pass_context
def validate_authenticator(ctx, authenticator_dir):
    """
    Verify the metadata and keypairs of an authenticator folder

    Authenticator passphrase can be provided as WA_PASSPHRASE environment variable, else user will be prompted for it.
    """

    keystore_passphrase = _retrieve_keystore_passphrase()

    success = True

    try:
        results = operations.check_authenticator(authenticator_dir, keystore_passphrase=keystore_passphrase)
    except (KeystoreMetadataDoesNotExist, SchemaValidationError) as exc:
        click.echo("Authenticator metadata couldn't be loaded: %s" % exc)
        success = False

    else:
        authenticator_metadata = results["authenticator_metadata"]
        keypair_identifiers = results["keypair_identifiers"]
        missing_private_keys = results["missing_private_keys"]
        undecodable_private_keys = results["undecodable_private_keys"]

        def _format_keypair_ids_list(keypair_ids_list):
            return ", ".join("-".join(str(y) for y in x) for x in keypair_ids_list)

        click.echo(
            "Authenticator has UID %s and belongs to owner %s"
            % (authenticator_metadata["keystore_uid"], authenticator_metadata["keystore_owner"])
        )

        keystore_creation_datetime = authenticator_metadata.get("keystore_creation_datetime")
        if keystore_creation_datetime:
            click.echo("Creation date: %s" % keystore_creation_datetime.isoformat(sep=" ", timespec="seconds"))

        click.echo("Keypair count: %d" % len(keypair_identifiers))

        click.echo("")

        if not keypair_identifiers:
            click.echo("No keypairs found, there should be at least one")
            success = False
        if missing_private_keys:
            click.echo("Missing private keys: %s" % _format_keypair_ids_list(missing_private_keys))
            success = False
        if undecodable_private_keys:
            click.echo("Undecodable private keys: %s" % _format_keypair_ids_list(undecodable_private_keys))
            success = False

    if success:
        logger.info("Authenticator successfully checked, no integrity errors found")
    else:
        logger.error("Integrity errors were found in authenticator")
        sys.exit(1)


def _analyse_keystore_and_return_data(keystore_dir, format, skipped_fields=()):
    filesystem_keystore = ReadonlyFilesystemKeystore(keystore_dir)
    metadata_enriched = filesystem_keystore.get_keystore_metadata(include_keypair_identifiers=True)
    metadata_enriched.setdefault(
        "keystore_creation_datetime", None
    )  # Fixme do this at loading time and fix the Schema accordingly!

    # Restrict data to mask authenticator format, secret, etc.
    selected_field_list = [
        "keystore_uid",
        "keystore_owner",
        "keystore_passphrase_hint",
        "keystore_creation_datetime",
        "keypair_identifiers",
    ]
    selected_field_list = [k for k in selected_field_list if k not in skipped_fields]
    metadata_enriched = {k: metadata_enriched[k] for k in selected_field_list}

    if format == "json":
        # Even if empty, we output it
        return _dump_as_safe_formatted_json(metadata_enriched)

    # Change the nested list to a string for display
    metadata_enriched["keystore_creation_datetime"] = _short_format_datetime(
        metadata_enriched["keystore_creation_datetime"]
    )
    metadata_enriched["keypair_identifiers"] = "\n".join(
        "%s %s" % (x["key_algo"], x["keychain_uid"]) for x in metadata_enriched["keypair_identifiers"]
    )
    return _convert_dict_to_table_of_properties(metadata_enriched, key_list=selected_field_list)


@authenticator_group.command("view")
@click.argument(
    "authenticator_dir",
    type=click.Path(exists=True, dir_okay=True, file_okay=False, readable=True, resolve_path=True, path_type=Path),
)
@FORMAT_OPTION
@click.pass_context
def view_authenticator(ctx, authenticator_dir, format):
    """View metadata and public keypair identifiers of an authenticator

    The presence and validity of private keys isn't checked.
    """
    data = _analyse_keystore_and_return_data(authenticator_dir, format=format)
    click.echo(data)


@authenticator_group.command("delete")
@click.argument(
    "authenticator_dir",
    type=click.Path(
        exists=True, dir_okay=True, file_okay=False, writable=True, readable=True, resolve_path=True, path_type=Path
    ),
)
@click.pass_context
def delete_authenticator(ctx, authenticator_dir):
    """Delete an authenticator folder along with all its content"""
    try:
        operations.delete_authenticator(authenticator_dir)
    except Exception as exc:
        logger.error("Deletion failed: %s", exc)
        sys.exit(1)
    else:
        logger.info("Authenticator %s successfully deleted", authenticator_dir)


@wacryptolib_cli.command("encrypt")
@click.argument(
    "input_file",
    type=click.Path(
        exists=True, file_okay=True, dir_okay=True, readable=False, resolve_path=True, allow_dash=True, path_type=Path
    ),
)
@click.option("-o", "--output-basename", help="Basename of the cryptainer storage output file")
@click.option("-c", "--cryptoconf", default=None, help="Json crypotoconf file", type=click.File("rb"))
@click.option("--bundle", help="Combine cryptainer metadata and payload", is_flag=True)
@click.pass_context
def encrypt(ctx, input_file, output_basename, cryptoconf, bundle):
    """Turn a media file into a secure container"""

    offload_payload_ciphertext = not bundle

    if not cryptoconf:
        logger.warning("No cryptoconf provided, defaulting to simple and INSECURE example cryptoconf")
        cryptoconf = SIMPLE_EXAMPLE_CRYPTOCONF
    else:
        cryptoconf = load_from_json_bytes(cryptoconf.read())

    check_cryptoconf_sanity(cryptoconf)

    keystore_pool = _get_keystore_pool(ctx)

    is_stdin = os.fsdecode(input_file) == "-"
    if is_stdin and not output_basename:
        raise click.MissingParameter("Ouput basename must be provided when input file is STDIN")

    if output_basename:
        if not is_file_basename(output_basename):
            raise click.BadParameter("Output basename must not contain path separators")
        if output_basename.endswith(CRYPTAINER_SUFFIX):
            output_basename = output_basename[: -len(CRYPTAINER_SUFFIX)]  # Strip premature suffix

    output_basename = output_basename or input_file.name
    assert isinstance(output_basename, str), repr(output_basename)

    cryptainer_storage = _get_cryptainer_storage(
        ctx, keystore_pool=keystore_pool, offload_payload_ciphertext=offload_payload_ciphertext
    )

    with click.open_file(input_file, mode="rb") as payload_handle:  # Also handles "-" for STDIN
        output_cryptainer_name = cryptainer_storage.encrypt_file(
            filename_base=output_basename, payload=payload_handle, cryptainer_metadata=None, cryptoconf=cryptoconf
        )
        assert not payload_handle.closed, payload_handle  # We do not automatically alter the file handle

    # Redundant:
    # logger.info(
    #    "Encryption of file '%s' to storage cryptainer '%s' successfully finished"
    #    % (input_file.name, output_cryptainer_name)
    # )


@wacryptolib_cli.group("cryptoconf")
def cryptoconf_group():
    """Manage cryptographic configurations"""
    pass


@cryptoconf_group.group("generate-simple", chain=True)
@click.option("--keychain-uid", help="Default UID for asymmetric keys", required=False, type=click.UUID)
@click.pass_context
def generate_simple_cryptoconf(ctx, keychain_uid):
    """
    Generate a simple cryptoconf using subcommands
    """
    cryptoconf = {"payload_cipher_layers": []}
    if keychain_uid:
        cryptoconf["keychain_uid"] = keychain_uid
    ctx.obj["cryptoconf"] = cryptoconf


@generate_simple_cryptoconf.result_callback()
@click.pass_context
def display_cryptoconf(ctx, processors, keychain_uid):
    """Format and print a cryptoconf"""
    cryptoconf = ctx.obj["cryptoconf"]
    check_cryptoconf_sanity(cryptoconf)  # Safety
    click.echo(_dump_as_safe_formatted_json(cryptoconf))


@generate_simple_cryptoconf.command("add-payload-cipher-layer")
@click.option(
    "--sym-cipher-algo",
    help="Symmetric algorithms for payload encryption",
    required=True,
    type=click.Choice(SUPPORTED_SYMMETRIC_CIPHER_ALGOS, case_sensitive=False),
)  # MAKE IT A CHOICEFIELD!!!
@click.pass_context
def cryptoconf_add_payload_cipher_layer(ctx, sym_cipher_algo):
    """
    Add a layer of symmetric encryption of the data

    The random symmetric key used for that encryption will then have to be protected by asymmetric encryption.
    """
    payload_cipher_layer = {"payload_cipher_algo": sym_cipher_algo, "key_cipher_layers": [], "payload_signatures": []}
    ctx.obj["cryptoconf"]["payload_cipher_layers"].append(payload_cipher_layer)
    ctx.obj["current_add_key_shared_secret"] = None  # RESET


def _key_cipher_options(cmd):
    @click.option(
        "--asym-cipher-algo",
        help="Asymmetric algorithms for key encryption",
        required=True,
        type=click.Choice(SUPPORTED_ASYMMETRIC_CIPHER_ALGOS, case_sensitive=False),
    )
    @click.option(
        "--trustee-type",
        help="Kind of key-guardian used",
        required=True,
        type=click.Choice(
            [CRYPTAINER_TRUSTEE_TYPES.LOCAL_KEYFACTORY_TRUSTEE, CRYPTAINER_TRUSTEE_TYPES.AUTHENTICATOR_TRUSTEE],
            case_sensitive=False,
        ),
    )
    @click.option(
        "--keystore-uid", help="UID of the key-guardian (only for authenticators)", required=False, type=click.UUID
    )
    @click.option("--keychain-uid", help="Overridden UID for asymmetric key", required=False, type=click.UUID)
    @click.option(
        "--sym-cipher-algo",
        help="Optional intermediate symmetric cipher, to avoid stacking trustees",
        required=False,
        type=click.Choice(SUPPORTED_SYMMETRIC_CIPHER_ALGOS, case_sensitive=False),
    )
    @click.pass_context
    @functools.wraps(cmd)
    def wrapper_common_options(*args, **kwargs):
        return cmd(*args, **kwargs)

    return wrapper_common_options


def _build_key_cipher_layer(asym_cipher_algo, trustee_type, keystore_uid, sym_cipher_algo, keychain_uid=None):
    key_cipher_trustee = {"trustee_type": trustee_type}

    if trustee_type == CRYPTAINER_TRUSTEE_TYPES.AUTHENTICATOR_TRUSTEE:
        if not keystore_uid:
            raise click.BadParameter("Authenticator trustee requires a --keystore-uid value")
        key_cipher_trustee["keystore_uid"] = keystore_uid

    key_cipher_layer = {
        "key_cipher_algo": asym_cipher_algo,
        "key_cipher_trustee": key_cipher_trustee,
    }
    if keychain_uid:
        key_cipher_layer["keychain_uid"] = keychain_uid  # Local override

    if sym_cipher_algo:  # Hybrid encryption
        key_cipher_layer = {"key_cipher_algo": sym_cipher_algo, "key_cipher_layers": [key_cipher_layer]}
    return key_cipher_layer


@generate_simple_cryptoconf.command("add-key-cipher-layer")
@_key_cipher_options
def cryptoconf_add_key_cipher_layer(ctx, asym_cipher_algo, trustee_type, keystore_uid, keychain_uid, sym_cipher_algo):
    """
    Add a layer of asymmetric encryption of the key

    A symmetric cipher can also be used, resulting in a hybrid encryption scheme.
    """
    payload_cipher_layer = ctx.obj["cryptoconf"]["payload_cipher_layers"][-1]

    key_cipher_layer = _build_key_cipher_layer(
        asym_cipher_algo, trustee_type, keystore_uid, sym_cipher_algo, keychain_uid=keychain_uid
    )

    payload_cipher_layer["key_cipher_layers"].append(key_cipher_layer)
    ctx.obj["current_add_key_shared_secret"] = None  # RESET


@generate_simple_cryptoconf.command("add-key-shared-secret")
@click.option(
    "--threshold", help="Number of key-guardians required for decryption of the secret", required=True, type=click.INT
)
@click.pass_context
def cryptoconf_add_key_shared_secret(ctx, threshold):
    """
    Transform a key into a shared secret
    """
    if threshold < 1:
        raise click.BadParameter("Shared-secret shard threshold must be strictly positive")

    payload_cipher_layer = ctx.obj["cryptoconf"]["payload_cipher_layers"][-1]

    shared_secret = {
        "key_cipher_algo": SHARED_SECRET_ALGO_MARKER,
        "key_shared_secret_threshold": threshold,
        "key_shared_secret_shards": [],  # Will be filled by "add-key-shard" subcommands
    }
    payload_cipher_layer["key_cipher_layers"].append(shared_secret)
    ctx.obj["current_add_key_shared_secret"] = shared_secret


@generate_simple_cryptoconf.command("add-key-shard")
@_key_cipher_options
def cryptoconf_add_key_shared_secret_shard(
    ctx, asym_cipher_algo, trustee_type, keystore_uid, keychain_uid, sym_cipher_algo
):
    """
    Add a shard configuration to a shared secret
    """
    shared_secret = ctx.obj.get("current_add_key_shared_secret", None)

    if shared_secret is None:
        raise click.UsageError("Command add-key-shard can only be used after add-key-shared-secret")

    key_cipher_layer = _build_key_cipher_layer(
        asym_cipher_algo, trustee_type, keystore_uid, sym_cipher_algo, keychain_uid=keychain_uid
    )

    shared_secret["key_shared_secret_shards"].append(
        dict(key_cipher_layers=[key_cipher_layer])  # SINGLE layer for shards, for now
    )


@cryptoconf_group.command("validate")
@click.argument("cryptoconf_file", type=click.File("rb"))
@click.pass_context
def validate_cryptoconf(ctx, cryptoconf_file):
    """Ensure that a cryptoconf structure is valid"""
    try:
        cryptoconf = load_from_json_bytes(cryptoconf_file.read())
        check_cryptoconf_sanity(cryptoconf)
        logger.info("Cryptoconf file '%s' is valid" % cryptoconf_file.name)
    except ValidationError as exc:
        raise click.UsageError("Cryptoconf file '%s' is invalid: %r" % (cryptoconf_file.name, exc))


@cryptoconf_group.command("summarize")
@click.argument("cryptoconf_file", type=click.File("rb"))
@click.pass_context
def summarize_cryptoconf(ctx, cryptoconf_file):
    """Display a summary of a cryptoconf structure"""
    cryptoconf = load_from_json_bytes(cryptoconf_file.read())
    text_summary = get_cryptoconf_summary(cryptoconf)
    click.echo("\n" + text_summary, nl=False)


@wacryptolib_cli.group("foreign-keystore")
def foreign_keystore_group():
    """Manage locally imported keystores"""
    pass


@foreign_keystore_group.command("list")
@FORMAT_OPTION
@click.pass_context
def list_foreign_keystores(ctx, format):  # FIXME list count of public/private keys too!
    """List locally imported keystores"""
    keystore_pool = _get_keystore_pool(ctx)
    foreign_keystore_metadata_list = keystore_pool.get_all_foreign_keystore_metadata(include_keypair_identifiers=True)
    # print(foreign_keystore_metadata_list)

    foreign_keystores = []

    for foreign_keystore_uid, foreign_keystore_metadata in sorted(foreign_keystore_metadata_list.items()):
        foreign_keystores.append(
            dict(
                keystore_uid=foreign_keystore_uid,
                keystore_owner=foreign_keystore_metadata["keystore_owner"],
                keystore_creation_datetime=foreign_keystore_metadata.get("keystore_creation_datetime"),
                public_key_count=len(foreign_keystore_metadata["keypair_identifiers"]),
                private_key_count=len(
                    [x for x in foreign_keystore_metadata["keypair_identifiers"] if x["private_key_present"]]
                ),
            )
        )

    if format == "json":
        # Even if empty, we output it
        click.echo(_dump_as_safe_formatted_json(foreign_keystores))
        return

    assert format == "plain"

    if not foreign_keystore_metadata_list:
        logger.warning("No foreign keystores found")
        return

    table = PrettyTable(["Keystore UID", "Owner", "Public keys", "Private Keys", "Created at (UTC)"])
    # table.align = "l"  useless
    for keystore_data in foreign_keystores:
        table.add_row(
            [
                keystore_data["keystore_uid"],
                keystore_data["keystore_owner"],
                keystore_data["public_key_count"],
                keystore_data["private_key_count"],
                _short_format_datetime(keystore_data["keystore_creation_datetime"]),
            ]
        )
    click.echo(table)


@foreign_keystore_group.command("view")
@click.argument("keystore_uid", type=click.UUID)
@FORMAT_OPTION
@click.pass_context
def view_foreign_keystore(ctx, keystore_uid, format):
    """View metadata and public keypair identifiers of an imported keystore

    The presence and validity of private keys isn't checked.
    """
    keystore_pool = _get_keystore_pool(ctx)
    keystore_path = keystore_pool._get_foreign_keystore_dir(keystore_uid)

    if not keystore_path.is_dir():
        raise click.UsageError("Foreign keystore UID %s not found" % keystore_uid)

    data = _analyse_keystore_and_return_data(keystore_path, format=format, skipped_fields=("keystore_passphrase_hint",))
    click.echo(data)


@foreign_keystore_group.command("delete")
@click.argument("keystore_uid", type=click.UUID)
@click.pass_context
def delete_foreign_keystore(ctx, keystore_uid):
    """Delete a locally imported keystore"""
    keystore_pool = _get_keystore_pool(ctx)
    keystore_path = keystore_pool._get_foreign_keystore_dir(keystore_uid)
    try:
        shutil.rmtree(keystore_path)
        logger.info("Foreign keystore %s successfully deleted" % keystore_uid)
    except OSError as exc:
        raise click.UsageError("Failed deletion of imported authentication device %s: %r" % (keystore_uid, exc))


@foreign_keystore_group.command("import")
@click.option("--from-usb", help="Fetch authenticators from plugged USB devices", is_flag=True)
@click.option(
    "--from-path",
    help="Fetch authenticator from folder path",
    type=click.Path(
        exists=True, file_okay=False, dir_okay=True, readable=True, resolve_path=True, allow_dash=False, path_type=Path
    ),
)
@click.option("--from-gateway", help="Fetch authenticator by uid from gateway", type=click.UUID)
@click.option("--include-private-keys", help="Import private keys when available", is_flag=True)
@click.pass_context
def import_foreign_keystore(ctx, from_usb, from_gateway, from_path, include_private_keys):
    """Import a remote keystore"""

    if not from_usb and not from_gateway and not from_path:
        raise click.UsageError("No source selected for keystore import")

    keystore_pool = _get_keystore_pool(ctx)

    if from_usb:
        logger.info(
            "Importing foreign keystores from USB devices, %s private keys"
            % ("with" if include_private_keys else "without")
        )
        results = operations.import_keystores_from_initialized_authdevices(
            keystore_pool, include_private_keys=include_private_keys
        )
        msg = "{foreign_keystore_count} new authenticators imported, {already_existing_keystore_count} updated, {corrupted_keystore_count} skipped because corrupted".format(
            **results
        )
        logger.info(msg)

    def _build_single_import_success_message(_keystore_metadata, _updated):
        _msg = "Authenticator {} (owner: {}) %s" % ("updated" if updated else "imported")
        return _msg.format(_keystore_metadata["keystore_uid"], _keystore_metadata["keystore_owner"])

    if from_path:
        logger.info(
            "Importing foreign keystore from folder %s, %s private keys"
            % (from_path, "with" if include_private_keys else "without")
        )
        keystore_metadata, updated = operations.import_keystore_from_path(
            keystore_pool, keystore_path=from_path, include_private_keys=include_private_keys
        )
        msg = _build_single_import_success_message(keystore_metadata, updated)
        logger.info(msg)

    if from_gateway:
        # print(">>>>>>>>>>>>>", ctx.obj)
        gateway_url = ctx.obj["gateway_url"]
        if not gateway_url:
            raise click.UsageError("No web gateway URL specified for keystore import")
        logger.info("Importing foreign keystore %s from web gateway" % from_gateway)
        keystore_metadata, updated = operations.import_keystore_from_web_gateway(
            keystore_pool, gateway_url=gateway_url, keystore_uid=from_gateway
        )
        msg = _build_single_import_success_message(keystore_metadata, updated)
        logger.info(msg)


@wacryptolib_cli.group("cryptainer")
def cryptainer_group():
    """Manage encrypted containers"""
    pass


@cryptainer_group.command("list")
@FORMAT_OPTION
@click.pass_context
def list_cryptainers(ctx, format):
    """List local cryptainers"""
    cryptainer_storage = _get_cryptainer_storage(ctx)
    cryptainer_properties_list = cryptainer_storage.list_cryptainer_properties(
        as_sorted_list=True, with_creation_datetime=True, with_size=True, with_offloaded=True
    )

    for cryptainer_properties in cryptainer_properties_list:
        cryptainer_properties["name"] = str(cryptainer_properties["name"])  # Avoid Path objects here

    if format == "json":
        # Even if empty, we output it
        click.echo(_dump_as_safe_formatted_json(cryptainer_properties_list))
        return

    assert format == "plain"

    if not cryptainer_properties_list:
        logger.warning("No cryptainers found")
        return

    table = PrettyTable(["Name", "Size", "Offloaded", "Created at (UTC)"])
    for cryptainer_properties in cryptainer_properties_list:
        table.add_row(
            [
                cryptainer_properties["name"],
                get_nice_size(cryptainer_properties["size"]),
                "X" if cryptainer_properties["offloaded"] else "",
                _short_format_datetime(cryptainer_properties["creation_datetime"]),
            ]
        )
    click.echo(table)


@cryptainer_group.command("validate")
@click.argument("cryptainer_name")
@click.pass_context
def validate_cryptainer(ctx, cryptainer_name):
    """Validate a cryptainer structure"""
    try:
        cryptainer_storage = _get_cryptainer_storage(ctx)
        cryptainer = cryptainer_storage.load_cryptainer_from_storage(cryptainer_name, include_payload_ciphertext=True)
        check_cryptainer_sanity(cryptainer)
        logger.info("Cryptainer file '%s' is valid" % cryptainer_name)
    except ValidationError as exc:
        raise click.UsageError("Cryptainer file '%s' is invalid: %r" % (cryptainer_name, exc))


@cryptainer_group.command("summarize")
@click.argument("cryptainer_name")
@click.pass_context
def summarize_cryptainer(ctx, cryptainer_name):
    """Display a summary of a cryptainer structure"""
    cryptainer_storage = _get_cryptainer_storage(ctx)
    cryptainer = cryptainer_storage.load_cryptainer_from_storage(cryptainer_name, include_payload_ciphertext=True)
    text_summary = get_cryptoconf_summary(cryptainer)  # Works with cryptainers too
    click.echo("\n" + text_summary, nl=False)


@cryptainer_group.command("delete")
@click.argument("cryptainer_name")
@click.pass_context
def delete_cryptainer(ctx, cryptainer_name):
    """Delete a local cryptainer"""
    cryptainer_storage = _get_cryptainer_storage(ctx)
    if not cryptainer_storage.is_valid_cryptainer_name(cryptainer_name):
        raise click.UsageError("Invalid cryptainer name %s" % cryptainer_name)
    cryptainer_storage.delete_cryptainer(cryptainer_name=cryptainer_name)
    logger.info("Cryptainer %s successfully deleted" % cryptainer_name)


# FIXE move this OUT of cryptainer storage subcommand!!!!??? For symmetry
@cryptainer_group.command("decrypt")
@click.argument("cryptainer_name")
@click.option("-o", "--output-file", type=click.File("wb"))
@click.pass_context
def decrypt(ctx, cryptainer_name, output_file):
    """Turn a cryptainer back into the original media file

    This command is for test purposes only, since it only works with INSECURE cryptoconfs
    where private keys are locally available, and not protected by passphrases.

    For real world use cases, see the Witness Angel software suite (Authenticator, Revelation Station...).
    """

    if not output_file:
        if cryptainer_name.endswith(CRYPTAINER_SUFFIX):
            # This SHOULD be the case since we add the suffix ourselves on encryption
            output_file_name = cryptainer_name[: -len(CRYPTAINER_SUFFIX)]
        else:
            output_file_name = cryptainer_name + DECRYPTED_FILE_SUFFIX
        output_file = LazyFile(output_file_name, "wb")  # We output it in current directory...

    # click.echo("In decrypt: %s" % str(locals()))
    keystore_pool = _get_keystore_pool(ctx)

    cryptainer_storage = _get_cryptainer_storage(ctx)
    cryptainer = cryptainer_storage.load_cryptainer_from_storage(cryptainer_name, include_payload_ciphertext=True)

    check_cryptainer_sanity(cryptainer)

    medium_content, operation_report = decrypt_payload_from_cryptainer(
        cryptainer, keystore_pool=keystore_pool, passphrase_mapper=None
    )

    if operation_report:
        logger.info("Decryption report:")
        operation_report_text = operation_report.format_entries()
        click.echo(operation_report_text)
    else:
        logger.info("No decryption report was generated")

    if medium_content is None:
        raise DecryptionError("Content could not be decrypted")
    if not medium_content:
        raise DecryptionError("Decrypted content is empty")  # FIXME test this separately!

    with output_file:
        output_file.write(medium_content)

    logger.info(
        "Decryption of cryptainer '%s' to file '%s' successfully finished" % (cryptainer_name, output_file.name)
    )


@cryptainer_group.command("purge")
@click.pass_context
@click.option("--max-age", type=int, help="Maximum age of cryptainer, in days")
@click.option("--max-count", type=int, help="Maximum count of cryptainers in storage")
@click.option("--max-quota", type=int, help="Maximum total size of cryptainers, in MBs")
def purge_cryptainers(ctx, max_age, max_count, max_quota):
    """Delete oldest cryptainers per criteria"""

    extra_kwargs = dict(
        max_cryptainer_age=(timedelta(days=max_age) if max_age is not None else None),
        max_cryptainer_count=max_count,  # Might be None
        max_cryptainer_quota=(max_quota * 1024**2 if max_quota else None),  # Actually MiBs here...
    )

    extra_kwargs = {k: v for (k, v) in extra_kwargs.items() if v is not None}

    if not extra_kwargs:
        raise click.UsageError("Aborting purge, since no criterion was provided as argument")

    cryptainer_storage = _get_cryptainer_storage(ctx, **extra_kwargs)
    deleted_cryptainer_count = cryptainer_storage.purge_exceeding_cryptainers()
    logger.info("Cryptainers successfully deleted: %s" % deleted_cryptainer_count)


def main(prog_name=None):
    """Launch Flightbox CLI"""
    wacryptolib_cli(prog_name=prog_name)


if __debug__:
    for k, v in globals().copy().items():
        if isinstance(v, BaseCommand):
            assert v.__doc__, "%s has no dosctring" % k
