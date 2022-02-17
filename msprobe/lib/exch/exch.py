import re
import requests 
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from .ntlm import ntlmdecode
from rich.console import Console
from rich.table import Table
import pkg_resources 


# Dealing with SSL Warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

def requests_retry_session(
    retries=1,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

# Finding instances of target application 
def exch_find(target):

    # Reading in potential subdomains
    resource = pkg_resources.resource_filename(__name__, 'subs.txt')
    sd = [line.strip() for line in open(resource)]

    # Crafting URL's and issuing requests
    for i in sd:
        url = f'https://{i}.{target}'
        try:
            response = requests_retry_session().get(url, timeout=5, allow_redirects=False, verify=False)

        except requests.ConnectionError:
            pass
        else:
            # Method for checking if discovered site is actually an Exchange instance
            try:
                location_header = urlparse(response.headers["Location"])
                url_path = location_header.path
                redirect_location = url_path.strip('/').split('/')[0]
            except KeyError:
                pass
            else:
                # If the redirect URL specified in Location header contains OWA, indicate that we found Exchange
                if redirect_location == "owa":
                    return url



# Checking if OWA pannel is availible 
def find_owa(exch_endpoint):
    try:
        r = requests_retry_session().get(f'{exch_endpoint}/owa', timeout=5, allow_redirects=True, verify=False)
    except requests.ConnectionError:
        return False
    else:
        if r.status_code == 200:
           return True

# Checking if ECP pannel is availible 
def find_ecp(exch_endpoint):
    try:
        r = requests_retry_session().get(f'{exch_endpoint}/ecp', timeout=5, allow_redirects=True, verify=False)
    except requests.ConnectionError:
        return False
    else: 
        if r.status_code == 200:
           return True


# Extracting the version of Exchange from favicon URL path in HTML source
# Refactor for efficency
def find_version(exch_endpoint, owa, ecp):

    # If OWA is availible we will try to grab it from there
    if owa == True:
        try:
            owa_response = requests_retry_session().get(f'{exch_endpoint}/owa', timeout=5, allow_redirects=True, verify=False)
        except requests.ConnectionError:
            print('Something went wrong determining version!')
            exit()
        else:
            soup = BeautifulSoup(owa_response.text, 'html.parser')
            version_path = soup.find("link",{"rel":"shortcut icon"})['href']
            find_version = re.findall("[-+]?\d*\.*\d+",version_path)
            exchange_version = ''.join(find_version)
            return exchange_version
    # If ECP is availible we will try to grab it from there
    elif ecp == True:
        try:
            ecp_response = requests_retry_session().get(f'{exch_endpoint}/ecp', timeout=5, allow_redirects=True, verify=False)
        except requests.ConnectionError:
            print('Something went wrong determining version!')
            exit()
        else:
            soup = BeautifulSoup(ecp_response.text, 'html.parser')
            version_path = soup.find("link",{"rel":"shortcut icon"})['href']
            find_version = re.findall("[-+]?\d*\.*\d+",version_path)
            exchange_version = ''.join(find_version)
            return exchange_version

    # Not sure what happened, returning UNKNOWN
    else:
        exchange_version = "UNKOWN"
        return exchange_version

def exch_ntlm_pathfind(exch_endpoint):

    # Reading in list of potential Exchange NTLM authentication endpoints
    np = [line.strip() for line in open("lib/exch/paths.txt")]

    # Creating an array to put found paths into
    ntlm_endpoints = []
    
    # Crafting our URL and checking for NTLM based authentication
    for i in np:
        url = f'{exch_endpoint}/{i}'
        
        try:
            response = requests_retry_session().get(url, timeout=5, allow_redirects=False, verify=False)
        except requests.ConnectionError:
            pass
        except response.status_code != 401:
            pass
        else:
            if response.status_code == 401:
                ntlm_endpoints.append(url)

    return ntlm_endpoints

def exch_ntlm_parse(ntlm_endpoints):

    # Defining array to store NTLM information
    #ntlm_data = []

    ntlm_header = {"Authorization": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="}
    response = requests.post(ntlm_endpoints[0], headers=ntlm_header, verify=False)

    try:
        if response.status_code == 401:
            ntlm_info = ntlmdecode(response.headers["WWW-Authenticate"])
            ntlm_data = ntlm_info["NetBIOS_Domain_Name"]
            #ntlm_data.append(ntlm_info["FQDN"])
            #ntlm_data.append(ntlm_info["DNS_Domain_name"])
            return ntlm_data
    except Exception as a:
        print('Something went wrong!')
        print('The Exchange server is most likely redirecting to O365!')
        print('OWA portal may still exist. Check with Nuclei!')
        print(f'Error Message: {a}')
        pass

def exch_display(exch_endpoint, owa_exists, ecp_exists, exch_version, exch_ntlm_paths, exch_ntlm_info):
    

    console = Console()
    table_exch = Table(show_header=False, pad_edge=True)
    table_exch.add_column("Context")
    table_exch.add_column("Info")

    table_exch.add_row('URL', f'{exch_endpoint}')
    table_exch.add_row('VERSION', f'{exch_version}')


    if owa_exists is True:
       table_exch.add_row('OWA', 'TRUE')
    elif owa_exists is False:
       table_exch.add_row('OWA', 'FALSE')

    if ecp_exists == True:
       table_exch.add_row('EAC', 'TRUE')
    elif owa_exists == False:
       table_exch.add_row('EAC', 'FALSE')

    table_exch.add_row('DOMAIN', f'{exch_ntlm_info}')

    paths = "\n".join(item for item in exch_ntlm_paths)
    table_exch.add_row('URLS ', f'{paths}')

    console.print(table_exch)

    

