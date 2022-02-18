import click 
import logging
from .exch.exch import *
from .rdp.rdp import *
from .adfs.adfs import *
from .skype.skype import *
from rich.console import Console
from rich.logging import RichHandler
logging.getLogger(requests.packages.urllib3.__package__).setLevel(logging.ERROR)

# Initializing console for rich
console = Console()

@click.group()
def cli():
    pass


@click.command()
@click.option('-v','--verbose', default=False, required=False, show_default=True, is_flag=True)
@click.option('-vv','--debug', default=False, required=False, show_default=True, is_flag=True)
@click.argument('target')
def exch(target, verbose, debug):

    # Setting up our console logging
    with console.status("[bold green]Exchange Module Executing...") as status:

        if verbose:
            logging.basicConfig(level='INFO', format="%(message)s", handlers=[RichHandler(rich_tracebacks=True, show_time=False)])
            logging.getLogger("requests").setLevel(logging.CRITICAL)
            log = logging.getLogger("rich")
            status.stop()
            log.info("Verbose logging enabled for module: exch")

        if debug:
            logging.basicConfig(level='DEBUG', format="%(message)s", handlers=[RichHandler(rich_tracebacks=False, show_time=False)])
            log = logging.getLogger("rich")
            status.stop()
            log.debug("Debug logging enabled for module: exch")


        # First trying to find if an Exchange server exists
        log.info("Searching for Exchange endpoint...")
        exch_endpoint = exch_find(target)
        
        # Did we find anything
        if exch_endpoint is not None:
            
            log.info(f"Exchange found: {exch_endpoint}")

            # Checking if OWA and ECP exist
            log.info("Checking if OWA availible.")
            owa_exists = find_owa(exch_endpoint) 

            log.info("Checking if ECP availible.")
            ecp_exists = find_ecp(exch_endpoint)

            if owa_exists:
                log.info("OWA Found!")

            if ecp_exists:
                log.info("EAC Found!")

            # Getting current Exchange version
            log.info("Trying to find Exchange version.")
            exch_version = find_version(exch_endpoint, owa_exists, ecp_exists)

            if exch_version is not None:
                if exch_version != 'UNKNOWN':
                    log.info(f"Exchange version found: {exch_version}")

            # Getting NTLM endpoint information
            log.info("Searching for NTLM authentication endpoints.")
            exch_ntlm_paths = exch_ntlm_pathfind(exch_endpoint)

            # If no NTLM endpoints found, set data to UNKNOWN, otherwise enumerate
            if len(exch_ntlm_paths) == 0:
                log.info("No NTLM authentication endpoints found.")
                exch_ntlm_info = 'UNKNOWN'
            elif len(exch_ntlm_paths) != 0:
                log.info("NTLM authentication endpoints found!")
                exch_ntlm_info = exch_ntlm_parse(exch_ntlm_paths)
                log.info(f"Internal domain: {exch_ntlm_info}")

            status.stop()

            # Displaying info we found
            exch_display(exch_endpoint, owa_exists, ecp_exists, exch_version, exch_ntlm_paths, exch_ntlm_info)

        else:

            # Logging a failure if no Exchange instance found
            console.log(f'Exchange not found: {target}', style='bold red')
            status.stop()



@click.command()
@click.option('-v','--verbose', default=False, required=False, show_default=True, is_flag=True)
@click.option('-vv','--debug', default=False, required=False, show_default=True, is_flag=True)
@click.argument('target')
def rdp(target, verbose, debug):
    
    # Setting up our console logging
    with console.status("[bold green]RD Web Module Executing...") as status:

        if verbose:
            logging.basicConfig(level='INFO', format="%(message)s", handlers=[RichHandler(rich_tracebacks=True, show_time=False)])
            log = logging.getLogger("rich")
            status.stop()
            log.info("Verbose logging enabled for module: rdp")

        if debug:
            logging.basicConfig(level='DEBUG', format="%(message)s", handlers=[RichHandler(rich_tracebacks=True, show_time=False)])
            log = logging.getLogger("rich")
            status.stop()
            log.debug("Debug logging enabled for module: rdp")

        # First trying to find if an RD Web server exists
        log.info("Searching for RD Web endpoint")
        rdpw_endpoint = rdpw_find(target)
        

        # Did we find anything
        if rdpw_endpoint is not None:

            log.info("RD Web endpoint found!")

            # Getting the instance version 
            rdpw_version = rdpw_find_version(rdpw_endpoint)

            if rdpw_version is not None:
                log.info(f"RD Web version found: {rdpw_version}")

            # Getting information about the instance
            log.info("Searching for RD Web information")
            rdpw_info = rdpw_get_info(rdpw_endpoint)

            if rdpw_info is not None:
                log.info("Relevant information found.")
                for i,k in zip(rdpw_info[0::2], rdpw_info[1::2]):
                    log.info(f'{i}: {k}')

            # Getting NTLM endpoint information

            log.info("Trying to find and parse info from /rpc endpoint")
            rdpw_ntlm_path = rdpw_ntlm_pathfind(rdpw_endpoint)

            if rdpw_ntlm_path is True:
                log.info("Found /rpc endpoint.")
                rdpw_ntlm_info = rdpw_ntlm_parse(rdpw_endpoint)
                log.info("NTLM authentication parsed.")
                log.info(f"Internal domain: {rdpw_ntlm_info[0]}")

            
            status.stop()

            # Displaying what we found
            rdpw_display(rdpw_endpoint, rdpw_version, rdpw_info, rdpw_ntlm_path, rdpw_ntlm_info)

        else:

            # Logging a failure if no RD Web instance found
            console.log(f'RD Web not found: {target}', style='bold red')
            status.stop()


@click.command()
@click.option('-v','--verbose', default=False, required=False, show_default=True, is_flag=True)
@click.option('-vv','--debug', default=False, required=False, show_default=True, is_flag=True)
@click.argument('target')
def adfs(target, verbose, debug):
    
    # Setting up our console logging
    with console.status("[bold green]ADFS Module Executing...") as status:

        if verbose:
            logging.basicConfig(level='INFO', format="%(message)s", handlers=[RichHandler(rich_tracebacks=True, show_time=False)])
            log = logging.getLogger("rich")
            status.stop()
            log.info("Verbose logging enabled for module: adfs")

        if debug:
            logging.basicConfig(level='DEBUG', format="%(message)s", handlers=[RichHandler(rich_tracebacks=True, show_time=False)])
            log = logging.getLogger("rich")
            status.stop()
            log.debug("Debug logging enabled for module: adfs")

        # First trying to find if an ADFS server exists
        log.info("Searching for ADFS endpoint")
        adfs_endpoint = adfs_find(target)
        

        # Did we find anything
        if adfs_endpoint is not None:
            log.info(f"ADFS found: {adfs_endpoint}")

            # Getting the instance version 
            log.info("Getting ADFS version (year)")
            adfs_version = adfs_find_version(adfs_endpoint)
            log.info(f"ADFS version (year) found: {adfs_version}")

            # Getting information about ADFS services
            log.info("Checking if we can read service list while unauthed.")
            adfs_services = adfs_find_services(adfs_endpoint) 

            if adfs_services != "Not able to enumerate services.":
                log.info("Services readable, Displaying now! (This might be obnoxious)")
                for i in adfs_services:
                    log.info(f"Federated Service: {i}")
            else:
                log.info("Services not readable.")

            # Getting information about self-service pw reset endpoint
            log.info("Checking if ADFS self service password reset endpoint exposed.")
            adfs_pwreset = find_adfs_pwreset(adfs_endpoint)

            if adfs_pwreset is True:
                log.info("ADFS self service password reset accessible.")
            elif adfs_pwreset is False:
                log.info("ADFS self service password reset not accessible.")

            # Getting NTLM endpoint information
            log.info("Checking if we can hit NTLM authentication endpoints.")
            adfs_ntlm_paths = adfs_ntlm_pathfind(adfs_endpoint)

            if len(adfs_ntlm_paths) != 0:
                log.info("NTLM endpoints exposed!")
                adfs_ntlm_data = adfs_ntlm_parse(adfs_ntlm_paths)
                for i in adfs_ntlm_paths:
                    log.info(f"NTLM auth possible here: {i}")
                if adfs_ntlm_data is not None:
                    log.info(f"Internal domain: {adfs_ntlm_data}")
            else:
                log.info("Can't hit NTLM auth endpoints")
                adfs_ntlm_data = 'UNKNOWN'
            
            status.stop()

            # Displaying what we found
            adfs_display(adfs_endpoint, adfs_version, adfs_services, adfs_pwreset, adfs_ntlm_paths, adfs_ntlm_data)

        else:

            # Logging a failure if no RD Web instance found
            console.log(f'ADFS not found: {target}', style='bold red')
            status.stop()

@click.command()
@click.option('-v','--verbose', default=False, required=False, show_default=True, is_flag=True)
@click.option('-vv','--debug', default=False, required=False, show_default=True, is_flag=True)
@click.argument('target')
def skype(target, verbose, debug):
    
    # Setting up our console logging                                                           
    with console.status("[bold green]Skype for Business Module Executing...") as status:       

        if verbose:
            logging.basicConfig(level='INFO', format="%(message)s", handlers=[RichHandler(rich_tracebacks=True, show_time=False)])
            log = logging.getLogger("rich")
            status.stop()
            log.info("Verbose logging enabled for module: skype")

        if debug:
            logging.basicConfig(level='DEBUG', format="%(message)s", datefmt="[%X]", handlers=[RichHandler(rich_tracebacks=True, show_time=False)])
            log = logging.getLogger("rich")
            status.stop()
            log.debug("Debug logging enabled for module: skype")

        # First trying to find if an SFB server exists
        log.info("Searching for Skype for Business/Lync endpoint.")
        sfb_endpoint = sfb_find(target)

        # Did we find anything
        if sfb_endpoint is not None:
            log.info(f"SFB/Lync endpoint found: {sfb_endpoint}")

            # Getting the instance version 
            log.info("Trying to grab SFB/Lync version.")
            sfb_version = sfb_find_version(sfb_endpoint)

            if sfb_version != 'UNKNOWN':
                log.info(f"Version found: {sfb_version[0]} {sfb_version[1]}")
            else:
                log.info("Unable to enumerate version")

            # Getting information about the instance
            log.info("Checking if scheduler and persistent chat endpoints are available.")
            sfb_scheduler = sfb_find_scheduler(sfb_endpoint) 
            sfb_chat = sfb_find_chat(sfb_endpoint)

            if sfb_scheduler is True:
                log.info("Scheduler available.")
            else:
                log.info("Scheduler not available.")

            if sfb_chat is True:
                log.info("Persistent chat available.")
            else:
                log.info("Persistent chat not available.")

            # Getting NTLM endpoint information
            log.info("Checking if NTLM authentication endpoints exposed")
            sfb_ntlm_paths = sfb_ntlm_pathfind(sfb_endpoint)

            if len(sfb_ntlm_paths) != 0:
                log.info("NTLM authentication possible!")
                sfb_ntlm_data = sfb_ntlm_parse(sfb_ntlm_paths)
                log.info(f"Internal domain: {sfb_ntlm_data}")
            else:
                log.info("NTLM authentication not possible!")
                sfb_ntlm_data = 'UNKNOWN'

            
            status.stop()

            # Displaying what we found
            sfb_display(sfb_endpoint, sfb_version, sfb_scheduler, sfb_chat, sfb_ntlm_paths, sfb_ntlm_data)

        else:

            # Logging a failure if no SFB instance found
            console.log(f'Skype for Business not found: {target}', style='bold red')
            status.stop()

@click.command()
@click.option('-v','--verbose', default=False, required=False, show_default=True, is_flag=True)
@click.option('-vv','--debug', default=False, required=False, show_default=True, is_flag=True)
@click.argument('target')
@click.pass_context
def full(ctx, target, verbose, debug):
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

if __name__ == '__main__':
    cli()
