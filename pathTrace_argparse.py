import argparse
import requests
import base64
import json
import sys
import urllib3
import getpass
from http import HTTPStatus
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
              'content-type': "application/json",
              'x-auth-token': ""
          }
"""
parser = argparse.ArgumentParser(description = "Path Trace from DNAC API")
parser.add_argument('-s', '--source', type=str, metavar='', required=True, help="Source IP Address")
parser.add_argument('-d', '--destination', type=str, metavar='', required=True, help="Destination IP Address")
args = parser.parse_args()
group = parser.add_mutually_exclusive_group()
group.add_argument('de', '-- detail', action = 'store_true', hel="Get path detail")

network_device_url = "https://10.20.99.22/api/v1/network-device"
interface_url = "https://10.20.99.22/api/v1/interface"
flow_analysis_url = "https://10.20.99.22/api/v1/flow-analysis"

network_device_respone = requests.get(network_device_url,
                headers={"X-Auth-Token": "%s" % tokenString, "Content-type": "application/json"}, verify=False)
print(network_device_respone.text)

body = {"destIP": "10.20.99.24", "sourceIP": "10.123.0.7"}
pathTrace_response = requests.post(flow_analysis_url, headers={"X-Auth-Token": "%s" % tokenString, "Content-type": "application/json"}, verify=False,
                                      json=body)
print(pathTrace_response.text)
"""

def getToken(dnacAddress, username, password):
    """
    Get Token by use username and password , Token will use to authenticate
    every time when call any APIs.
    """

    tokenUrl = "https://{}/api/system/v1/auth/token".format(dnacAddress)

    token_responese = requests.post(tokenUrl, auth=HTTPBasicAuth(username, password),
                                headers=headers, verify=False)

    return token_responese.json()['Token']

def verify_host(host, ipAddress):
    """
    Check any host reachable or not.
    """
    if len(host) == 0:
        print("Error: No host with IP address {} was found".format(ipAddress))
        sys.exit(1)
    if len(host) > 1:
        print("Error: Multiple hosts with IP address {} were found".format(ipAddress))
        print(json.dumps(host, indent=2))
        sys.exit(1)

def host_detail(dnacAddress, accessToken, ipAddress):
    """
    Get host detail.
    """
    url = "https://{}/api/v1/host".format(dnacAddress)
    headers["x-auth-token"] = accessToken
    filter = []
    filter.append("hostIp={}".format(ipAddress))

    #Check host
    if len(filter) > 0:
        url += "?" + "&".join(filter)
    host_detail_response = requests.get(url, headers=headers, verify=False)

    #Check host as network device
    if len(host_detail_response.json()["response"]) == 0:
        url = "https://{}/api/v1/network-device".format(dnacAddress)
        headers["x-auth-token"] = accessToken
        filter = []
        filter.append("managementIpAddress={}".format(ipAddress))
        url += "?" + "&".join(filter)
        host_detail_response = requests.get(url, headers=headers, verify=False)

    #Return host detail in json format
    return host_detail_response.json()["response"]

def print_host_details (host):

    if 'role' not in host.keys():
        print("This is Host not network device")
    if 'role' in host.keys():
        print("This is Network Device not Host")

# The Program Start here.
if __name__ == '__main__':

    dnac_ipAddress = input("Please Enter DNAC IP Address : ")
    dnac_username = input("Please Enter DNAC Username : ")
    dnac_password = getpass.getpass("Please Enter DNAC Password : ")
    token = getToken(dnac_ipAddress, dnac_username, dnac_password)
    source_host_detail = host_detail(dnac_ipAddress, token, "1.20.151.254")
    verify_source_host = verify_host(source_host_detail, "1.20.151.254")
    print_source_detail = print_host_details(source_host_detail[0])
