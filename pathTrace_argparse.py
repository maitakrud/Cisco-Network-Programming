import argparse
from getToken import *
"""
parser = argparse.ArgumentParser(description = "Path Trace from DNAC API")
parser.add_argument('-s', '--source', type=str, metavar='', required=True, help="Source IP Address")
parser.add_argument('-d', '--destination', type=str, metavar='', required=True, help="Destination IP Address")
args = parser.parse_args()
group = parser.add_mutually_exclusive_group()
group.add_argument('de', '-- detail', action = 'store_true', hel="Get path detail")
"""
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
