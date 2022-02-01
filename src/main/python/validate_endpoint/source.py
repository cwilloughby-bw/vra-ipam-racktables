"""
Copyright (c) 2020 VMware, Inc.

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""

import requests
from vra_ipam_utils.ipam import IPAM
from vra_ipam_utils.exceptions import InvalidCertificateException
import logging
import pymysql


'''
Example payload:

"inputs": {
    "authCredentialsLink": "/core/auth/credentials/13c9cbade08950755898c4b89c4a0",
    "endpointProperties": {
      "hostName": "sampleipam.sof-mbu.eng.vmware.com"
    }
  }
'''
def handler(context, inputs):

    ipam = IPAM(context, inputs)
    IPAM.do_validate_endpoint = do_validate_endpoint

    return ipam.validate_endpoint()

def do_validate_endpoint(self, auth_credentials, cert):
    # Your implemention goes here

    username = auth_credentials["privateKeyId"]
    password = auth_credentials["privateKey"]
    hostname = self.inputs["endpointProperties"]["hostName"]
    databasename = self.inputs["endpointProperties"]["databaseName"]

    try:
        # response = requests.get("https://" + self.inputs["endpointProperties"]["hostName"], verify=cert, auth=(username, password))
        db = pymysql.connect(host=hostname,user=username,password=password,database=databasename)
        cursor = db.cursor()
        cursor.execute("SELECT VERSION()")
        response = cursor.fetchone()

        if response is not None:
            return {
                "message": "Validated successfully",
            }
        else:
            raise Exception(f"Invalid response to SELECT VERSION: {str(response)}")
    except Exception as e:
        if "Unknown database" in str(e):
            raise Exception(f"Couldn't find database {str(databasename)} on server {str(hostname)}")

        raise e
