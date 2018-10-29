import argparse
import requests
import base64
import json
import sys
import urllib3
import getpass
from http import HTTPStatus
from requests.auth import HTTPBasicAuth
from time import sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
              'content-type': "application/json",
              'x-auth-token': ""
          }

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

def print_host_details (host, dnacAddress, accessToken):

    if 'role' not in host.keys():

        if host["hostType"] == "wired":

            url = "https://{}/api/v1/network-device".format(dnacAddress)
            headers["x-auth-token"] = accessToken
            url += "/{}".format(host['connectedNetworkDeviceId'])
            connected_device = requests.get(url, headers=headers, verify=False)
            connected_device = connected_device.json()["response"]

            url = "https://{}/api/v1/interface".format(dnacAddress)
            headers["x-auth-token"] = accessToken
            url += "/{}".format(host['connectedInterfaceId'])
            connected_interface = requests.get(url, headers=headers, verify=False)
            connected_interface = connected_interface.json()["response"]

            print("This is Host not network device")
            print("Device IP Address: {}".format(host['hostIp']))
            print("Device Mac Address: {}".format(host['hostMac']))
            print("Connected Type: {}".format(host['hostType']))
            print("Connected Device Hostname: {}".format(host['connectedNetworkDeviceName']))
            print("Connected Device IP Address: {}".format(host['connectedNetworkDeviceIpAddress']))
            print("Connected Device Type: {}".format(connected_device['type']))
            print("Connected Device Interface: {}".format(host['connectedInterfaceName']))
            print("Connected Device Interface Speed: {}".format(connected_interface['speed']))
            print("Connected Device Interface Duplex: {}".format(connected_interface['duplex']))
            print("Connected Device Interface Description: {}".format(connected_interface['description']))
            print("Connected Device Interface Port mode: {}".format(connected_interface['portMode']))
            print("Connected Device Interface Port type: {}".format(connected_interface['portType']))
            print("Connected Device Interface VLAN ID: {}".format(connected_interface['vlanId']))
            print("Connected Device Interface Native VLAN ID: {}".format(connected_interface['nativeVlanId']))

        else:
            print("Wireless")

    if 'role' in host.keys():
        print("Device Hostname: {}".format(host['hostname']))
        print("Device Type: {}".format(host['type']))
        print("Device Family: {}".format(host['family']))
        print("Decice Role: {}".format(host['role']))
        print("Management IP Address: {}".format(host['managementIpAddress']))
        print("Mac Address: {}".format(host['macAddress']))
        print("Software Type: {}".format(host['softwareType']))
        print("Software Version: {}".format(host['softwareVersion']))
        print("Serial Number: {}".format(host['serialNumber']))
        if host['associatedWlcIp'] != '':
            print("Associated Wireless LAN Controller: {}".format(host['associatedWlcIp']))
        print("---------------------------------")

def run_flow_analysis (dnacAddress, accessToken, source_ip, destination_ip):

    url = "https://{}/api/v1/flow-analysis".format(dnacAddress)
    headers["x-auth-token"] = accessToken
    body = {"destIP": destination_ip, "sourceIP": source_ip}
    response = requests.post(url, headers=headers, verify=False,
                                      json=body)

    # Verify successfully initiated.
    if response.status_code != 202:
        print("Error: Flow Analysis Initiation Failed")
        print(initiate_response.text)
        sys.exit(1)

    # Check status of analysis and wait until completed
    flowAnalysisId = response.json()["response"]["flowAnalysisId"]
    detail_url = url + "/{}".format(flowAnalysisId)
    detail_response = requests.get(detail_url, headers=headers, verify=False)
    while not detail_response.json()["response"]["request"]["status"] == "COMPLETED":  # noqa: E501
        print("Flow analysis not complete yet, waiting 5 seconds")
        sleep(5)
        detail_response = requests.get(detail_url, headers=headers,
                                       verify=False)

    # Return the flow analysis details
    return detail_response.json()["response"]

def print_flow_analysis(dnacAddress, accessToken, flow_detail):

    hops_number = flow_detail['networkElementsInfo']
    print("Total Hops number: {}".format(len(hops_number)))
    print()
    print("---------------------------------")
    print("Flow Detail")
    for i, hop in enumerate(hops_number):
        print("************************")
        if 'name' not in hops_number[i].keys():
            print("The First Hops is Host")
            print("Host IP: {}".format(hops_number[i]["ip"]))
            print("Host Type: {}".format(hops_number[i]["type"]))

        else:
            print("Hop {}: Network Device Name : {}".format(i+1, hops_number[i]["name"]))
            # If the hop is "UNKNOWN" continue along
            if hops_number[i]["name"] == "UNKNOWN":
                print()
                continue
                print("Device IP: {}".format(hops_number[i]["ip"]))
                print("Device Role: {}".format(hops_number[i]["type"]))

        # If type is an Access Point, skip interface details
            if hops_number[i]["type"] == "Unified AP":
                continue

                print()

            ingress_url = "https://{}/api/v1/interface".format(dnacAddress)
            headers["x-auth-token"] = accessToken
            ingress_url += "/{}".format(hops_number[i]["ingressInterface"]["physicalInterface"]["id"])
            ingress_interface = requests.get(ingress_url, headers=headers, verify=False)
            ingress_interface = ingress_interface.json()["response"]

            print("Ingress Interface")
            print("---------------------------------")
            print(ingress_interface)

            if 'egressInterface' in hops_number[i].keys():
                egress_url = "https://{}/api/v1/interface".format(dnacAddress)
                headers["x-auth-token"] = accessToken
                egress_url += "/{}".format(hops_number[i]["egressInterface"]["physicalInterface"]["id"])
                egress_interface = requests.get(ingress_url, headers=headers, verify=False)
                egress_interface = egress_interface.json()["response"]

                print("Egress Interface")
                print("---------------------------------")
                print(egress_interface)

                print()
            else:
                print("Path Trace reach Destination device")

# The Program Start here.
if __name__ == '__main__':

    parser = argparse.ArgumentParser(description = "Path Trace from DNAC API")
    parser.add_argument('-s', '--source', type=str, metavar='', required=True, help="Source IP Address")
    parser.add_argument('-d', '--destination', type=str, metavar='', required=True, help="Destination IP Address")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-de', '--detail', action = 'store_true', help="Get path detail")
    args = parser.parse_args()

    if args.detail:
        dnac_ipAddress = input("Please Enter DNAC IP Address : ")
        dnac_username = input("Please Enter DNAC Username : ")
        dnac_password = getpass.getpass("Please Enter DNAC Password : ")
        token = getToken(dnac_ipAddress, dnac_username, dnac_password)
        source_host_detail = host_detail(dnac_ipAddress, token, args.source)
        verify_source_host = verify_host(source_host_detail, args.source)
        print("---------------------------------")
        print("Source Detail")
        print_source_detail = print_host_details(source_host_detail[0], dnac_ipAddress, token)
        print("")
        print("---------------------------------")
        print("Destination Detail")
        destination_host_detail = host_detail(dnac_ipAddress, token, args.destination)
        verify_destination_host = verify_host(source_host_detail, args.destination)
        print_destination_detail = print_host_details(destination_host_detail[0], dnac_ipAddress, token)

        start_flow_analysis = run_flow_analysis(dnac_ipAddress, token, args.source, args.destination)
        print_flow_analysis_details = print_flow_analysis(dnac_ipAddress, token, start_flow_analysis)

    else:
        print("EZ")
