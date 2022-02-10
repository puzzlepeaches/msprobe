import fire
from rich.console import Console
import logging
from .exch.exch import *
from .rdp.rdp import *

console = Console()

def exch(target):
    
    # Setting up our console logging
    with console.status("[bold green]Exchange Module Executing...") as status:

        # First trying to find if an Exchange server exists
        exch_endpoint = find(target)
        

        # Did we find anything
        if exch_endpoint is not None:

            # Checking if OWA and ECP exist
            owa_exists = find_owa(exch_endpoint) 
            ecp_exists = find_ecp(exch_endpoint)

            # Getting current Exchange version
            exch_version = find_version(exch_endpoint, owa_exists, ecp_exists)

            # Getting NTLM endpoint information
            ntlm_paths = ntlm_pathfind(exch_endpoint)
            ntlm_info = ntlm_parse(ntlm_paths)

            status.stop()

            display(exch_endpoint, owa_exists, ecp_exists, exch_version, ntlm_paths, ntlm_info)

        else:

            # Logging a failure if no Exchange instance found
            console.log(f'Exchange not found: {target}', style='bold red')
            status.stop()



def rdp(target):
    
    # Setting up our console logging
    with console.status("[bold green]RD Web Module Executing...") as status:

        # First trying to find if an Exchange server exists
        rdweb_endpoint = find(target)
        

        # Did we find anything
        if rdweb_endpoint is not None:

            # Getting the instance version 
            rdweb_version = find_version(rdweb_endpoint)

            # Getting information about the instance
            rdweb_info = get_info(rdweb_endpoint)

            # Getting NTLM endpoint information
            ntlm_path = ntlm_pathfind(rdweb_endpoint)
            if ntlm_path is True:
                ntlm_info = ntlm_parse(rdweb_endpoint)

            
            status.stop()

            display(rdweb_endpoint, rdweb_version, rdweb_info, ntlm_path, ntlm_info)

        else:

            # Logging a failure if no Exchange instance found
            console.log(f'RD Web not found: {target}', style='bold red')
            status.stop()



def main():
    fire.Fire()
