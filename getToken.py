import requests
import base64

    usrPass = "admin:Metro@2018"
    usrPassEncode = base64.b64encode(usrPass)

    url = "https://10.20.99.22/api/system/v1/auth/token"
    response = requests.request("POST", url, auth=HTTPBasicAuth(),
                                headers={"Authorization": "Basic %s" % usrPassEncode}, verify=False)
