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

network_device_respone = requests.get(network_device_url,
                headers={"X-Auth-Token": "%s" % tokenString}, verify=False)
print(network_device_respone.text)
