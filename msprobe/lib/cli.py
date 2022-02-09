import fire
from rich.console import Console
import logging
from .exch.exch import *

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

#if __name__ == '__main__':
#    fire.Fire()

def main():
    fire.Fire()
