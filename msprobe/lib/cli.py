import click
import logging
from .exch import *

# Defining module independent options
@click.group()
# @click.option('--config', '-C', type=click.Path(exists=True), help='Path to an optional configuration file.')
# @click.option('--dump-config', '-dc', is_flag=True, help='Dump the effective configuration used.')
@click.help_option('--help', '-h')
@click.option('--user-agent', '-u', help='The User-Agent to use (Optional)', default="msprobe/1.0.1")
@click.option('--verbose', '-v', is_flag=True, help="Enables debugging information.")
@click.option('--target', '-t', help="Target apex domain.")
@click.option('--target-file', '-tf', type=click.File('rw'), help="File of target apex domains.")

def cli(user_agent, verbose, target, target_file):

    # Doing checks to ensure all TLV are defined correctly

    # Enabling verbose logging information
    if verbose:
        logging.basicConfig(level=logging.DEBUG)

    # Setting user-agent for requests
    if not user_agent:
        user_agent = "msprobe/1.0.1"
    
    # Ensuring that a target is specified on runtime
    if target is None and target_file is None:
        logging.error('No target specified.')
        click.secho('No target specified. Exiting!', fg='red')
        exit()

# Exchange discovery sub-command
@cli.group()
def exch():
    pass


if __name__ == '__main__':
    cli()
