 #!/usr/bin/python
 # -*- coding: utf-8 -*-

import requests
import base64
from requests.auth import HTTPBasicAuth

url = "https://10.20.99.22/api/system/v1/auth/token"
usrPass = ("admin:Metro@2018").encode('utf-8')
b64Val = base64.b64encode(usrPass)
b64ValDecode = b64Val.decode('utf-8')

r=requests.post(url,
                headers={"Authorization": "Basic %s" % b64ValDecode}, verify=False)
print(r.text)
