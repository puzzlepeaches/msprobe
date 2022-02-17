import re
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from urllib.parse import urlparse
from bs4 import BeautifulSoup, Comment
from .ntlm import ntlmdecode
from rich.console import Console
from rich.table import Table
import pkg_resources
import json


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


# Finding skype for business endpoint
def sfb_find(target):
    resource = pkg_resources.resource_filename(__name__, 'subs.txt')
    sd = [line.strip() for line in open(resource)]

    for i in sd:
        url = f'https://{i}.{target}/dialin/'
        try:
            response = requests_retry_session().get(url, timeout=5, allow_redirects=True, verify=False)
        except requests.ConnectionError:
            pass
        except requests.ReadTimeout:
            pass
        else:
             if response.status_code == 200:
                 if response.headers['Content-Type'] == 'application/json':
                     if 'online.lync.com' not in response.json(): 
                        url = response.json()['_links']['self']['href']
                        url = f'https://{urlparse(url).hostname}'
                        if 'online.lync.com' not in url:
                            if 'skypeforbusiness.us' not in url:
                                return url

def sfb_find_version(sfb_endpoint):
    
    sched_url = f'{sfb_endpoint}/scheduler/'
    dialin_url = f'{sfb_endpoint}/dialin/'

    version_info = []

    try:
        sched_response = requests_retry_session().get(sched_url, timeout=5, allow_redirects=True, verify=False)
        dialin_response = requests_retry_session().get(dialin_url, timeout=5, allow_redirects=False, verify=False)
    except requests.ConnectionError:
        pass
    else:
        if dialin_response.status_code == 200:
            soup = BeautifulSoup(dialin_response.text, 'html.parser')
            version = soup.title.text
            if 'Dial-In' in version:
                version = version.split(" - ",1)[1]
                version_info.append(version)
            else:
                version_info.append(version)

        if sched_response.status_code == 200:
            soup = BeautifulSoup(sched_response.text, 'html.parser')
            comments = soup.find_all(string=lambda text:isinstance(text, Comment))
            for c in comments:
                if 'Web Scheduler Version' in c:
                    data = re.findall("[-+]?\d*\.*\d+", c)
                    build = ''.join(data)
                    version_info.append(build)
                else:
                    build = 'UNKNOWN'
                    version_info.append(build)
            

        else:
            version_info.append('UNKOWN')

    return version_info

            
def sfb_ntlm_pathfind(sfb_endpoint):

    endpoints = [
            "/abs",
            "/RequestHandlerExt/",
            "/RgsClients",
            "/RequestHandlerExt",
            "/WebTicket/WebTicketService.svc",
            "/WebTicket/",
            "/GroupExpansion",
            "/CertProv",
            "mcx"
    ]

    valid_endpoints = []

    # Issue a request to each potential endpoint
    for e in endpoints:
        try:

            # Crafint our URL and issuing request
            url = f'{sfb_endpoint}{e}'
            response = requests_retry_session().get(url, timeout=5, allow_redirects=False, verify=False)

        except requests.ConnectionError:
            pass

        else:

            # If we got a 401, NTLM auth is there
            try:
                if response.status_code == 401 and 'NTLM' in response.headers['WWW-Authenticate']:
                    valid_endpoints.append(url)
            except Exception:
                pass

    return valid_endpoints

def sfb_ntlm_parse(sfb_ntlm_paths):

    try:
        ntlm_header = {"Authorization": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="}
        response = requests_retry_session().post(sfb_ntlm_paths[0], headers=ntlm_header, verify=False, allow_redirects=True)

    except requests.ConnectionError:
        pass

    try:

        # Parsing what we need
        if response.status_code == 401 and 'NTLM' in response.headers['WWW-Authenticate']:
            ntlm_info = ntlmdecode(response.headers["WWW-Authenticate"])
            ntlm_data = ntlm_info["NetBIOS_Domain_Name"]
            # ntlm_data.append(ntlm_info["NetBIOS_Domain_Name"])
            # ntlm_data.append(ntlm_info["FQDN"])
            # ntlm_data.append(ntlm_info["DNS_Domain_name"])
            return ntlm_data

    # Bad error handling
    except Exception as a:
        print(f'Error occured: {a}')            
    
def sfb_find_scheduler(sfb_endpoint):

    # Crafint our URL
    url = f'{sfb_endpoint}/scheduler/'

    try:
        # Issuing request
        response = requests_retry_session().get(url, timeout=5, allow_redirects=True, verify=False)

    except requests.ConnectionError:
        pass

    else:

        # Checking that we got something back and the page didn't return an error
        if response.status_code == 200 and 'Web Scheduler' in response.text:
            return True
        else:
            return False

def sfb_find_chat(sfb_endpoint):

    # Crafint our URL
    url = f'{sfb_endpoint}/persistentchat/rm/'

    try:
        # Issuing request
        response = requests_retry_session().get(url, timeout=5, allow_redirects=False, verify=False)

    except requests.ConnectionError:
        pass

    else:

        # Checking that we got something back and the page didn't return an error
        if response.status_code == 200 and 'Manage PersistentChat Rooms' in response.text:
            return True
        else:
            return False

def sfb_display(sfb_endpoint, sfb_version, sfb_scheduler, sfb_chat, sfb_ntlm_paths, sfb_ntlm_data):
    console = Console()
    table_sfb = Table(show_header=False, pad_edge=True)
    table_sfb.add_column("Context")
    table_sfb.add_column("Info")

    table_sfb.add_row('URL', f'{sfb_endpoint}')

    if len(sfb_version) > 1:
        table_sfb.add_row('VERSION', f'{sfb_version[0]} ({sfb_version[1]})')

    table_sfb.add_row('Scheduler', f'{sfb_scheduler}')
    table_sfb.add_row('Chat', f'{sfb_chat}')

    if sfb_ntlm_data is not None:
        table_sfb.add_row('DOMAIN', f'{sfb_ntlm_data}')

    if len(sfb_ntlm_paths) != 0:
        paths = "\n".join(item for item in sfb_ntlm_paths)
        table_sfb.add_row('URLS', f'{paths}')


    console.print(table_sfb)
