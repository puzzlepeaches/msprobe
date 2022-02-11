import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from .ntlm import ntlmdecode
from rich.console import Console
from rich.table import Table


# Dealing with SSL Warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


# Using to find ADFS endpoints
def adfs_find(target):

    # Reading in potential subdomains
    sd = [line.strip() for line in open("lib/adfs/subs.txt")]

    for i in sd:

        # Crafting our potential URL
        url = f'https://{i}.{target}/FederationMetadata/2007-06/FederationMetadata.xml' 

        try:
            # Issuing request to URL
            response = requests.get(url, timeout=15, allow_redirects=False, verify=False) 

        except requests.ConnectionError:
            pass

        else:
            # Doing checks to make sure we get SAML XML data back from the endpoint
            if 'Content-Type' in response.headers:
                if response.headers['Content-Type'] == "application/samlmetadata+xml":
                    if response.status_code == 200:

                        # If everything checks out, parse out path and return the URL
                        url = f'https://{urlparse(url).hostname}'
                        return url

# Getting the version (year) displayed on the login page
def adfs_find_version(adfs_endpoint):

    # Crafting our URL
    url = f'{adfs_endpoint}/adfs/ls/?wa=wsignin1.0'

    try:
        # Issuing request to URL
        response = requests.get(url, timeout=3, allow_redirects=False, verify=False)

    except requests.ConnectionError:
        pass

    else:

        # Making sure everything checks out
        if response.status_code == 200:
            try:

                # Parsing the page content
                soup = BeautifulSoup(response.text, 'html.parser')

                # Extracting raw value from copyright field
                version_raw = soup.find("span",{"id":"copyright"}).get_text()
            
            # If something happens, just return UKNOWN
            except Exception:
                version = 'UNKOWN'
                return version

            else:

                # Pulling everything besides the year
                version = version_raw.strip('© ').strip('Microsoft')
                return version

# Looking for federated services associated with endpoints
# May not work depending of configuration
def adfs_find_services(adfs_endpoint):
    
    # Crafting our URL
    url = f'{adfs_endpoint}/adfs/ls/idpinitiatedsignon.aspx'
    services = []

    try: 

        # Issuing request
        response = requests.get(url, timeout=3, allow_redirects=False, verify=False)

    except requests.ConnectionError:
        pass

    else:

        # Making sure we got something back
        if response.status_code == 200:
            try:

                # Parsing the response
                soup = BeautifulSoup(response.text, 'html.parser')

                # First parsing out if the information we are looking for is even availible
                check_services = soup.find("div", {"id": "idp_SignInThisSiteStatusLabel"}).get_text()

            except requests.ConnectionError:
                pass

            else:

                # If sign in is required to list federated services, return an "error" message to the array
                if "Sign in to this site." in check_services:
                    services.append("Not able to enumerate services.")
                    return services

                else:
                     
                     # If we can read the list, pull everything from the dropdown menu
                     service = soup.find("select", {"name": "RelyingParty"})

                     # Parse out all listed federated services
                     for i in service.find_all('option'):

                         # Add services to our earlier defined array
                         services.append(i.text)

                     return services
               
# Function to check if the ADFS self service password reset endpoint is availible
def find_adfs_pwreset(adfs_endpoint):


    # Crafint our URL
    url = f'{adfs_endpoint}/adfs/portal/updatepassword'

    try:
        # Issuing request
        response = requests.get(url, timeout=3, allow_redirects=False, verify=False)

    except requests.ConnectionError:
        pass

    else:

        # Checking that we got something back and the page didn't return an error
        if response.status_code == 200 and 'Update Password' in response.text:
            return True
        else:
            return False

def adfs_ntlm_pathfind(adfs_endpoint):

    # Defining potential NTLM authentication paths
    endpoints = [ 
            "/adfs/services/trust/2005/windowstransport", 
            "/adfs/services/trust/2005/usernamemixed", 
            "/adfs/services/trust/13/usernamemixed", 
            "/adfs/services/trust/13/windowstransport"

    ]
    
    # Defining an empty array to add endpoints to
    valid_endpoints = []

    # Issue a request to each potential endpoint
    for e in endpoints:
        try:

            # Crafint our URL and issuing request
            url = f'{adfs_endpoint}{e}'
            response = requests.get(url, timeout=3, allow_redirects=False, verify=False)

        except requests.ConnectionError:
            pass

        else:

            # If we got a 401, NTLM auth is there
            if response.status_code == 401:
                valid_endpoints.append(url)
     
    return valid_endpoints


# Parsing data from found NTLM authentication endpoints
def adfs_ntlm_parse(adfs_ntlm_paths):

    # Defining empty array to store information 
    ntlm_data = []
    
    try:
        ntlm_header = {"Authorization": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="}
        response = requests.post(adfs_ntlm_paths[0], headers=ntlm_header, verify=False)
    except requests.ConnectionError:
        pass

    try:

        # Parsing what we need
        if response.status_code == 401:
            ntlm_info = ntlmdecode(response.headers["WWW-Authenticate"])
            ntlm_data.append(ntlm_info["NetBIOS_Domain_Name"])
            ntlm_data.append(ntlm_info["FQDN"])
            ntlm_data.append(ntlm_info["DNS_Domain_name"])
            return ntlm_data

    # Bad error handling 
    except Exception as a:
        print(f'Error occured: {a}')


def adfs_display(adfs_endpoint, adfs_version, adfs_services, adfs_pwreset, adfs_ntlm_paths, adfs_ntlm_data):
    console = Console()
    table_adfs = Table(show_header=False, pad_edge=True)
    table_adfs.add_column("Context")
    table_adfs.add_column("Info")

    table_adfs.add_row('URL', f'{adfs_endpoint}')
    table_adfs.add_row('VERSION', f'{adfs_version}')

    table_adfs.add_row('SSPWR', f'{adfs_pwreset}')


    if len(adfs_ntlm_paths) != 0:
        paths = "\n".join(item for item in adfs_ntlm_paths)
        table_adfs.add_row('URLS', f'{paths}')

    if len(adfs_ntlm_data) != 0:
        table_adfs.add_row('DOMAIN', f'{adfs_ntlm_data[0]}')

    if len(adfs_services) > 10:
        print('Services > 10')
        print('y to display all.')
        print('n to display 10.')
        reply = str(input(' (y/n): ')).lower().strip()
        if reply[:1] == 'y':
            services = "\n".join(item for item in adfs_services)
            table_adfs.add_row('SERVICES', f'{services}')
        elif reply[:1] == 'n':
            services = "\n".join(item for item in adfs_services[:10])
            table_adfs.add_row('SERVICES', f'{services}')
    else:
        services = "\n".join(item for item in adfs_services)
        table_adfs.add_row('SERVICES', f'{services}')

    console.print(table_adfs)
