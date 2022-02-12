import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from ntlm import ntlmdecode
from rich.console import Console
from rich.table import Table
import pkg_resources


# Dealing with SSL Warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


# Finding skype for business endpoint
def sfb_find(target):
    resource = pkg_resources.resource_filename(__name__, 'subs.txt')
    sd = [line.strip() for line in open(resource)]

    for i in sd:
        url = f'https://{i}.{target}/WebTicket/WebTicketService.svc/Auth'
        try:
            response = requests.get(url, timeout=15, allow_redirects=False, verify=False)
        except requests.ConnectionError:
            pass
        else:

            # Server responds differently if on-prem or in lync
            # Empty GET request to the endpoint gives 400 but if in cloud throws a 403
            if response.status_code == 400 and response.headers['Content-Length'] == '0':
                url = f'https://{urlparse(url).hostname}'
                return url

# def sfb_find_version(sbs_endpoint):
    


# Onprem
target = 'unesco.org'

# MS Hosted
# target = 'spireon.com'
sfb_endpoint = sbs_find(target)
print(sfb_endpoint)
