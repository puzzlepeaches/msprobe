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
            exch_ntlm_info = exch_ntlm_parse(exch_ntlm_paths)

            status.stop()

            exch_display(exch_endpoint, owa_exists, ecp_exists, exch_version, exch_ntlm_paths, exch_ntlm_info)

        else:

            # Logging a failure if no Exchange instance found
            console.log(f'Exchange not found: {target}', style='bold red')
            status.stop()



def rdp(target):
    
    # Setting up our console logging
    with console.status("[bold green]RD Web Module Executing...") as status:

        # First trying to find if an Exchange server exists
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

            rdpw_display(rdpw_endpoint, rdpw_version, rdpw_info, rdpw_ntlm_path, rdpw_ntlm_info)

        else:

            # Logging a failure if no Exchange instance found
            console.log(f'RD Web not found: {target}', style='bold red')
            status.stop()



def main():
    fire.Fire()
