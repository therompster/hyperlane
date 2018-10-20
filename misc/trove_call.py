####LOGGING####

import requests
import logging
import json
import time

# These two lines enable debugging at httplib level (requests->urllib3->http.client)
# You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
# The only thing missing will be the response.body which is not logged.
#try:
#    import http.client as http_client
#except ImportError:
#    # Python 2
#    import httplib as http_client
#http_client.HTTPConnection.debuglevel = 1
#
## You must initialize logging, otherwise you'll not see debug output.
#logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True
#

#################################################
################### Get Token OS ###############
#url = "http://10.29.114.45:5000/v3/auth/tokens"
url = "http://10.29.114.56:5000/v3/auth/tokens"
data = {
    "auth": {
        "identity": {
            "methods": [
                "password"
            ],
            "password": {
                "user": {
                    "id": "cc06e6c4494e4c7287ed4dc6e6a0a804",
                    "password": "K@ngar0o1!00"
                }
            }
        },
        "scope": {
            "project": {
                "id": "5403ac818d0b4e0f94140e686b482994"
            }
        }
    }
}
headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
r = requests.post(url, data=json.dumps(data), headers=headers)
#print(r.headers)
#print(json.dumps(r.headers['X-Subject-Token']))
my_token = json.dumps(r.headers['X-Subject-Token'])
my_token = my_token.replace('"', '')
#print(my_token)
time.sleep(1)
####################################################
#######Create Trove Instance for use cloud-bolt####
url2 = "http://10.29.114.140:8779/v1.0/5403ac818d0b4e0f94140e686b482994/instances"
data2 = {
    "instance": {
        "databases": [
            {
                "character_set": "utf8",
                "collate": "utf8_general_ci",
                "name": "test_rami"
            }
        ],
        "flavorRef": "8c551377-a38c-4d4c-be92-555226036c20",
        "name": "rami-test",
        "users": [
            {
                "databases": [
                    {
                        "name": "test_rami"
                    }
                ],
                "name": "rmansour",
                "password": "rmansour"
            }
        ],
        "volume": {
            "size": 2
        },
        "datastore": {
            "version": "5.6",
            "type": "percona"
        }
    }
}

headers = {'Content-type': 'application/json', 'X-Auth-Token': my_token}
r2 = requests.post(url2, data=json.dumps(data2), headers=headers)
#print(r2)

####################################################
#######Get IP of new instance####################### MAKE SURE TO CHANGE THIS WHEN DOING FUNCTIONS TO TAKE NAME OF SERVER INSTANCE TO FIND IP################
url2 = "http://10.29.114.45:8774/v2.1/5403ac818d0b4e0f94140e686b482994/servers/detail?name=rami-test"

headers = {'Content-type': 'application/json', 'X-Auth-Token': my_token}
r2 = requests.get(url2, headers=headers)
response = r2.content
json = json.loads(response.decode("utf-8"))
name = json['servers'][0]['name']
ip = json['servers'][0]['addresses']['internal_portal_project'][0]['addr']
print(ip)

