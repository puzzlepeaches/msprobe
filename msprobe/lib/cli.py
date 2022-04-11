import click
import logging
from .exch.exch import *
from .rdp.rdp import *
from .adfs.adfs import *
from .skype.skype import *
from rich.console import Console
from rich.logging import RichHandler

# Initializing console for rich
console = Console()


@click.group()
def cli():
    pass


@click.command()
@click.option(
    "-v", "--verbose", default=False, required=False, show_default=True, is_flag=True
)
@click.argument("target")
def exch(target, verbose):

    # Setting up our console logging
    with console.status("[bold green]Exchange Module Executing...") as status:

        if verbose:
            logging.basicConfig(
                level="DEBUG",
                format="%(message)s",
                handlers=[RichHandler(rich_tracebacks=False, show_time=False)],
            )
            log = logging.getLogger("rich")
            status.stop()
            log.debug("Verbose logging enabled for module: exch")

        # First trying to find if an Exchange server exists
        exch_endpoint = exch_find(target)

        # Did we find anything
        if exch_endpoint is not None:

            # Checking if OWA and ECP exist
            owa_exists = find_owa(exch_endpoint)

            ecp_exists = find_ecp(exch_endpoint)

            # Getting current Exchange version
            exch_version = find_version(exch_endpoint, owa_exists, ecp_exists)

            # Getting NTLM endpoint information
            exch_ntlm_paths = exch_ntlm_pathfind(exch_endpoint)

            # If no NTLM endpoints found, set data to UNKNOWN, otherwise enumerate
            if len(exch_ntlm_paths) == 0:
                exch_ntlm_info = "UNKNOWN"
            elif len(exch_ntlm_paths) != 0:
                exch_ntlm_info = exch_ntlm_parse(exch_ntlm_paths)

            status.stop()

            # Displaying info we found
            exch_display(
                exch_endpoint,
                owa_exists,
                ecp_exists,
                exch_version,
                exch_ntlm_paths,
                exch_ntlm_info,
            )

        else:

            # Logging a failure if no Exchange instance found
            console.log(f"Exchange not found: {target}", style="bold red")
            status.stop()


@click.command()
@click.option(
    "-v", "--verbose", default=False, required=False, show_default=True, is_flag=True
)
@click.argument("target")
def rdp(target, verbose):

    # Setting up our console logging
    with console.status("[bold green]RD Web Module Executing...") as status:

        if verbose:
            logging.basicConfig(
                level="DEBUG",
                format="%(message)s",
                handlers=[RichHandler(rich_tracebacks=False, show_time=False)],
            )
            log = logging.getLogger("rich")
            status.stop()
            log.debug("Verbose logging enabled for module: rdp")

        # First trying to find if an RD Web server exists
        rdpw_endpoint = rdpw_find(target)

        # Did we find anything
        if rdpw_endpoint is not None:

            # Getting the instance version
            rdpw_version = rdpw_find_version(rdpw_endpoint)

            # Getting information about the instance
            rdpw_info = rdpw_get_info(rdpw_endpoint)

            # Getting NTLM endpoint information
            rdpw_ntlm_path = rdpw_ntlm_pathfind(rdpw_endpoint)
            if rdpw_ntlm_path is True:
                rdpw_ntlm_info = rdpw_ntlm_parse(rdpw_endpoint)

            status.stop()

            # Displaying what we found
            rdpw_display(
                rdpw_endpoint, rdpw_version, rdpw_info, rdpw_ntlm_path, rdpw_ntlm_info
            )

        else:

            # Logging a failure if no RD Web instance found
            console.log(f"RD Web not found: {target}", style="bold red")
            status.stop()


@click.command()
@click.option(
    "-v", "--verbose", default=False, required=False, show_default=True, is_flag=True
)
@click.argument("target")
def adfs(target, verbose):

    # Setting up our console logging
    with console.status("[bold green]ADFS Module Executing...") as status:

        if verbose:
            logging.basicConfig(
                level="DEBUG",
                format="%(message)s",
                handlers=[RichHandler(rich_tracebacks=False, show_time=False)],
            )
            log = logging.getLogger("rich")
            status.stop()
            log.debug("Verbose logging enabled for module: adfs")

        # First trying to find if an ADFS server exists
        adfs_endpoint = adfs_find(target)

        # Did we find anything
        if adfs_endpoint is not None:

            # Getting the instance version
            adfs_version = adfs_find_version(adfs_endpoint)

            # Getting information about ADFS services
            adfs_services = adfs_find_services(adfs_endpoint)

            # Getting information about self-service pw reset endpoint
            adfs_pwreset = find_adfs_pwreset(adfs_endpoint)

            # Getting NTLM endpoint information
            adfs_ntlm_paths = adfs_ntlm_pathfind(adfs_endpoint)
            if len(adfs_ntlm_paths) != 0:
                adfs_ntlm_data = adfs_ntlm_parse(adfs_ntlm_paths)
            else:
                adfs_ntlm_data = "UNKNOWN"

            status.stop()

            # Displaying what we found
            adfs_display(
                adfs_endpoint,
                adfs_version,
                adfs_services,
                adfs_pwreset,
                adfs_ntlm_paths,
                adfs_ntlm_data,
            )

        else:

            # Logging a failure if no RD Web instance found
            console.log(f"ADFS not found: {target}", style="bold red")
            status.stop()


@click.command()
@click.option(
    "-v", "--verbose", default=False, required=False, show_default=True, is_flag=True
)
@click.argument("target")
def skype(target, verbose):

    # Setting up our console logging
    with console.status("[bold green]Skype for Business Module Executing...") as status:

        if verbose:
            logging.basicConfig(
                level="DEBUG",
                format="%(message)s",
                datefmt="[%X]",
                handlers=[RichHandler(rich_tracebacks=False, show_time=False)],
            )
            log = logging.getLogger("rich")
            status.stop()
            log.debug("Verbose logging enabled for module: skype")

        # First trying to find if an SFB server exists
        sfb_endpoint = sfb_find(target)

        # Did we find anything
        if sfb_endpoint is not None:

            # Getting the instance version
            sfb_version = sfb_find_version(sfb_endpoint)

            # Getting information about the instance
            sfb_scheduler = sfb_find_scheduler(sfb_endpoint)
            sfb_chat = sfb_find_chat(sfb_endpoint)

            # Getting NTLM endpoint information
            sfb_ntlm_paths = sfb_ntlm_pathfind(sfb_endpoint)
            if len(sfb_ntlm_paths) != 0:
                sfb_ntlm_data = sfb_ntlm_parse(sfb_ntlm_paths)
            else:
                sfb_ntlm_data = "UNKNOWN"

            status.stop()

            # Displaying what we found
            sfb_display(
                sfb_endpoint,
                sfb_version,
                sfb_scheduler,
                sfb_chat,
                sfb_ntlm_paths,
                sfb_ntlm_data,
            )

        else:

            # Logging a failure if no SFB instance found
            console.log(
                f"Skype for Business not found: {target}", style="bold red")
            status.stop()


@click.command()
@click.option(
    "-v", "--verbose", default=False, required=False, show_default=True, is_flag=True
)
@click.argument("target")
@click.pass_context
def full(ctx, target, verbose):
    ctx.forward(exch)
    ctx.forward(rdp)
    ctx.forward(adfs)
    ctx.forward(skype)


# Defining commands
cli.add_command(exch)
cli.add_command(adfs)
cli.add_command(skype)
cli.add_command(rdp)
cli.add_command(full)

if __name__ == "__main__":
    cli()
