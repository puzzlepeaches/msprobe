import requests
import hashlib
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

def find(target):

    # Reading in potential subdomains
    sd = [line.strip() for line in open("lib/rdp/subs.txt")]

    # Crafting URL's and issuing requests
    for i in sd:
        url = f'https://{i}.{target}/RDWeb/Pages/en-US/login.aspx'
        try:
            response = requests.get(url, timeout=3, allow_redirects=False, verify=False)
        except requests.ConnectionError:
            pass
        else:
            # Method for checking if discovered site is actually an Exchange instance
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                content = soup.get_text()
            except Exception:
                pass
            else:

                # If specified text in output, it is a vlid RD Web Access portal
                if "RD Web Access" in content: 

                    # Stripping the appended path from the url variable
                    url = f'https://{urlparse(url).hostname}'
                    return url

# Find the installed version of RD Web Access
# Largely pulled from here https://github.com/p0dalirius/RDWArecon
def find_version(url):

    # Defining image hashes cooresponding with the version of windows server running
    known_hashes = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty WS_h_c.png file",
            "9d7338e8b8bb104ae416f02eb6d586dda8bf37a5b71869e7d1c766e6b626d19e": "Blank WS_h_c.png file",
            "5a8a77dc7ffd463647987c0de6df2c870f42819ec03bbd02a3ea9601e2ed8a4b": "Windows Server 2008 R2",
            "ae66321b4a47868903c38cbfb3a7b426a7523943a6c3f9978f380b36aa79ee82": "Windows Server 2012",
            "4560591682d433c7fa190c6bf40827110e219929932dc6dc049697529c8a98bc": "Windows Server 2012 R2",
            "3d9b56811a5126a6d3b78a692c2278d588d495ee215173f752ce4cbf8102921c": "Windows Server 2012 R2",
            "3dbbeff5a0def7e0ba8ea383e5059eaa6acc37f7f8857218d44274fc029cfc4b": "Windows Server 2016",
            "fb1505aadeab42d82100c4d23d421f421c858feae98332c55a4b9595f4cea541": "Windows Server 2016",
            "2da4eb15fda2b7c80a94b9b2c5a3e104e2a9a2d9e9b3a222f5526c748fadf792": "Windows Server 2019",
            "256a6445e032875e611457374f08acb0565796c950eb9c254495d559600c0367": "Windows Server 2022"
            }

    # Crafting URL to extract hash from
    image = f'{url}/RDWeb/Pages/images/WS_h_c.png'

    try:
        response = requests.get(image, allow_redirects=True, verify=False, timeout=10)
        
        # Making sure we got a legit png
        if response.status_code == 200:
            if 'Content-Type' in response.headers and response.headers['Content-Type'] == "image/png":

                # Getting the sha256 hash for the returned image
                image_hash = hashlib.sha256(response.content).hexdigest()
                
                # Finding the hash in the dic defined above
                if image_hash in known_hashes.keys():
                    version = known_hashes[image_hash]

                    # Returning the version if found
                    return version

    # Else, if an exception is thrown we are going to return the value UNKOWN 
    except Exception:
        version = 'UNKNOWN'
        return version

# Getting information about the RD Web portal embedded in the login page
# Largely pulled from here https://github.com/p0dalirius/RDWArecon
def get_info(url):

    # Defining possible language values
    langs = ["de-DE", "en-GB", "en-US", "es-ES", "fr-FR", "it-IT", "ja-JP", "mk-MK", "nl-NL", "pt-BR", "ru-RU", "tr-TR"]

    # Defining potential information we want to pull from the login page
    info_values = ["WorkspaceFriendlyName", "WorkSpaceID", "RDPCertificates", "RedirectorName", "EventLogUploadAddress"]

    # Creating an empty array to store our findings in
    rdpweb_data = []

    # Checking multiple languages
    # This was done by the original author. Not sure if the returned information can change based on language or not. 
    # Take a look at this when time permits
    for lang in langs:

        # Crafting our URL
        info_url = f'{url}/RDWeb/Pages/{lang}/login.aspx'

        # Issuing request and parsing out all form values containing input
        try:
            response = requests.get(info_url, allow_redirects=False, verify=False, timeout=10)
            soup = BeautifulSoup(response.content, "lxml")
            form = soup.find('form', attrs={"id": "FrmLogin"})
            inputs = form.findAll('input')

            # Checking late in the process if the request even worked. Should probably do this earlier
            if response.status_code == 200:

                # Iterating through list of lines returned above containing input key
                for i in inputs:

                    # Only select keys containing name
                    if "name" in i.attrs.keys():

                        # Only select keys with a value variable
                        if "value" in i.attrs.keys():

                            # Iterating through list of relevant variables we defined above 
                            for b in info_values:

                                # If the name variable in inputs (AKA i) is also in our info_values, take a look 
                                if i['name'] in b:

                                    # Ignore value keys that are empty
                                    if i['value'] !=  "":

                                        # Setting the value for matching items in our predefined info_values
                                        value = i['value']

                                        # Throwing this into an array because my brain doesn't understand dicts yet
                                        rdpweb_data.append(b)
                                        rdpweb_data.append(value)
            return rdpweb_data

        except Exception:
            pass


def ntlm_pathfind(url):
    url = f'{url}/rpc'

    try:
        response = requests.get(url, timeout=15, allow_redirects=False, verify=False)
    except requests.ConnectionError:
        pass
    else:
          if response.status_code == 401:
              return True

def ntlm_parse(url):

    # Defining array to store NTLM information
    ntlm_data = []

    ntlm_header = {"Authorization": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="}
    response = requests.post(f'{url}/rpc', headers=ntlm_header, verify=False)

    try:
        if response.status_code == 401:
            ntlm_info = ntlmdecode(response.headers["WWW-Authenticate"])
            ntlm_data.append(ntlm_info["NetBIOS_Domain_Name"])
            ntlm_data.append(ntlm_info["FQDN"])
            ntlm_data.append(ntlm_info["DNS_Domain_name"])
            return ntlm_data
    except Exception as a:
        print(f'Error occured: {a}')


# url = find(target)
# version = find_version(url)
# info = get_info(url)
# rpc = ntlm_pathfind(url)
# ntlm = ntlm_parse(url)
# 
# print(f'RDWEB URL: {url}')
# print(f'OS Version: {version}')
# print(f'NTLM Availible: {rpc}')
# 
# print(f'DOMAIN: {ntlm[0]}')
# print(f'HOSTNAME: {ntlm[1]}')
# print(f'FQDN: {ntlm[2]}')
# 
# for i,k in zip(info[0::2], info[1::2]):
#     print(f'{i}: {k}')
