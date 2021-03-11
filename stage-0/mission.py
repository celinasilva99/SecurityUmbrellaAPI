#!/usr/bin/env python

import requests
import json
import sys
from pathlib import Path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pprint import pprint
from datetime import datetime

here = Path(__file__).parent.absolute()
repository_root = (here / ".." ).resolve()
sys.path.insert(0, str(repository_root))

import env

inv_url = env.UMBRELLA.get("inv_url")
inv_token = env.UMBRELLA.get("inv_token")
en_url = env.UMBRELLA.get("en_url")
en_key = env.UMBRELLA.get("inv_key")
#Use a domain of your choice
domain = "www.internetbadguys.com"

#Construct the API request to the Umbrella Investigate API to query for the status of the domain
url = f"{inv_url}/domains/categorization/{domain}?showLabels"
headers = {"Authorization": f'Bearer {inv_token}'}
response = requests.get(url, headers=headers)
time = datetime.now().isoformat()
#And don't forget to check for errors that may have occured!

#Make sure the right data in the correct format is chosen, you can use print statements to debug your code
domain_status = response.json()[domain]["status"]

url_enforce = f"{en_url}/events?customerKey={en_key}"
headers_enforce = {'Content-Type': 'application/json'}
data = {
"alertTime": time + "Z",
"deviceId": "ba6a59f4-e692-4724-ba36-c28132c761de",
"deviceVersion": "13.7a",
"dstDomain": domain,
"dstUrl": "http://" + domain + "/",
"eventTime": time + "Z",
"protocolVersion": "1.0a",
"providerName": "Security Platform"
    }

if domain_status == 1:
    print(f"The domain {domain} is found CLEAN")
elif domain_status == -1:
    print(f"The domain {domain} is found MALICIOUS")
    response_enforce = requests.post(url_enforce,data=json.dumps(data),headers= headers_enforce)
    print(response_enforce)
elif domain_status == 0:
    print(f"The domain {domain} is found UNDEFINED")

print("This is how the response data from Umbrella Investigate looks like: \n")
pprint(response.json(), indent=4)


url = f"{inv_url}/whois/{domain}/history"

headers = {
    "Authorization": f'Bearer {inv_token}',
    "Accept": "application/json"}

response = requests.get(url, headers=headers).json()

pprint(response,indent=4)