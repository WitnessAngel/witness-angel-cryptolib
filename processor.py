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


@cli.command()
@click.option("-i", "--input-medium", type=click.File('r', encoding=DEFAULT_ENCODING), required=True)
@click.option("-o", "--output-container", type=click.File('w', encoding=DEFAULT_ENCODING))
def encrypt(input_medium, output_container):
    """Turn a media file into a secure container."""
    if not output_container:
        output_container = LazyFile(input_medium.name + CONTAINER_SUFFIX, "w", encoding=DEFAULT_ENCODING)
    click.echo("In encrypt: %s" % str(locals()))

    # FIXME here compute real container data
    container_data = {"aa":33, "bb": {"toto": True}, "medium_content": input_medium.read()}

    with output_container:
        container_data_str = json.dump(container_data, fp=output_container, sort_keys=True, indent=4, cls=DjangoJSONEncoder)



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
    medium_content = container_data["medium_content"]

    with output_medium:
        output_medium.write(medium_content)




if __name__ == '__main__':
    cli()
