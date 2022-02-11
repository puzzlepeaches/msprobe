import fire
from rich.console import Console
import logging
from .exch.exch import *
from .rdp.rdp import *
from .adfs.adfs import *

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

            # Displaying info we found
            exch_display(exch_endpoint, owa_exists, ecp_exists, exch_version, exch_ntlm_paths, exch_ntlm_info)

        else:

            # Logging a failure if no Exchange instance found
            console.log(f'Exchange not found: {target}', style='bold red')
            status.stop()



def rdp(target):
    
    # Setting up our console logging
    with console.status("[bold green]RD Web Module Executing...") as status:

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
            rdpw_display(rdpw_endpoint, rdpw_version, rdpw_info, rdpw_ntlm_path, rdpw_ntlm_info)

        else:

            # Logging a failure if no RD Web instance found
            console.log(f'RD Web not found: {target}', style='bold red')
            status.stop()


def adfs (target):
    
    # Setting up our console logging
    with console.status("[bold green]ADFS Module Executing...") as status:

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
                adfs_ntlm_data = []
            
            status.stop()

            # Displaying what we found

            adfs_display(adfs_endpoint, adfs_version, adfs_services, adfs_pwreset, adfs_ntlm_paths, adfs_ntlm_data)

        else:

            # Logging a failure if no RD Web instance found
            console.log(f'ADFS not found: {target}', style='bold red')
            status.stop()



def main():
    fire.Fire()
