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
import logging
import pymysql
import ipaddress
import secrets

'''
Example payload:

"inputs": {
    "endpoint": {
      "id": "f097759d8736675585c4c5d272cd",
      "authCredentialsLink": "/core/auth/credentials/13c9cbade08950755898c4b89c4a0",
      "endpointProperties": {
        "hostName": "sampleipam.sof-mbu.eng.vmware.com",
        "certificate": "-----BEGIN CERTIFICATE-----\nMIID0jCCArqgAwIBAgIQQaJF55UCb58f9KgQLD/QgTANBgkqhkiG9w0BAQUFADCB\niTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1\nbm55dmFsZTERMA8GA1UEChMISW5mb2Jsb3gxFDASBgNVBAsTC0VuZ2luZWVyaW5n\nMSgwJgYDVQQDEx9pbmZvYmxveC5zb2YtbWJ1LmVuZy52bXdhcmUuY29tMB4XDTE5\nMDEyOTEzMDExMloXDTIwMDEyOTEzMDExMlowgYkxCzAJBgNVBAYTAlVTMRMwEQYD\nVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHEwlTdW5ueXZhbGUxETAPBgNVBAoTCElu\nZm9ibG94MRQwEgYDVQQLEwtFbmdpbmVlcmluZzEoMCYGA1UEAxMfaW5mb2Jsb3gu\nc29mLW1idS5lbmcudm13YXJlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAMMLNTqbAri6rt/H8iC4UgRdN0qj+wk0R2blmD9h1BiZJTeQk1r9i2rz\nzUOZHvE8Bld8m8xJ+nysWHaoFFGTX8bOd/p20oJBGbCLqXtoLMMBGAlP7nzWGBXH\nBYUS7kMv/CG+PSX0uuB0pRbhwOFq8Y69m4HRnn2X0WJGuu+v0FmRK/1m/kCacHga\nMBKaIgbwN72rW1t/MK0ijogmLR1ASY4FlMn7OBHIEUzO+dWFBh+gPDjoBECTTH8W\n5AK9TnYdxwAtJRYWmnVqtLoT3bImtSfI4YLUtpr9r13Kv5FkYVbXov1KBrQPbYyp\n72uT2ZgDJT4YUuWyKpMppgw1VcG3MosCAwEAAaM0MDIwMAYDVR0RBCkwJ4cEChda\nCoIfaW5mb2Jsb3guc29mLW1idS5lbmcudm13YXJlLmNvbTANBgkqhkiG9w0BAQUF\nAAOCAQEAXFPIh00VI55Sdfx+czbBb4rJz3c1xgN7pbV46K0nGI8S6ufAQPgLvZJ6\ng2T/mpo0FTuWCz1IE9PC28276vwv+xJZQwQyoUq4lhT6At84NWN+ZdLEe+aBAq+Y\nxUcIWzcKv8WdnlS5DRQxnw6pQCBdisnaFoEIzngQV8oYeIemW4Hcmb//yeykbZKJ\n0GTtK5Pud+kCkYmMHpmhH21q+3aRIcdzOYIoXhdzmIKG0Och97HthqpvRfOeWQ/A\nPDbxqQ2R/3D0gt9jWPCG7c0lB8Ynl24jLBB0RhY6mBrYpFbtXBQSEciUDRJVB2zL\nV8nJiMdhj+Q+ZmtSwhNRvi2qvWAUJQ==\n-----END CERTIFICATE-----\n"
      }
    },
    "pagingAndSorting": {
      "maxResults": 1000,
      "pageToken": "789c55905d6e02310c84df7d91452a456481168ec04b55950344f9db55dadd384abc056e5f3b42adfa12299f279ec9ac7c5670e9b0045a4ad2430c93af7a465f3bc83d4f9e3aa8976e6681ce660c827770de2aa1a68c72dfc3cae74393999b2e4df302e72691373aa60199bd827398efac18810f87a952591c61817c849513999df0b6c11436d6d400effcfacc14f2099cd6768913c5a435a0fd0c8e20ab2dbcd147564a2228c93b60b99ae2d94efde6ac640a09d9331130c539367078c41c915067ac9122268dc350439bf3379e9bc01b32025e9bd111aa65c829e89e83f0135ba740572c5f525c73f95faa608e39e55e62c6fcbd37de9775b891212a758d59bceb7a0eb30d7c7f6cd35c1399984291053b30f29fc5feed6cedf7adfe21962ab17b8ebde5089b1fec0d97d7-e5c4e5a1d726f600c22ebfd9f186148a1449755fd79a69ceabfe2aa"
    }
  }
'''
def handler(context, inputs):

    ipam = IPAM(context, inputs)
    IPAM.do_get_ip_ranges = do_get_ip_ranges

    return ipam.get_ip_ranges()

def do_get_ip_ranges(self, auth_credentials, cert):
    # Your implemention goes here
    username = auth_credentials["privateKeyId"]
    password = auth_credentials["privateKey"]
    hostname = self.inputs["endpoint"]["endpointProperties"]["hostName"]
    databasename = self.inputs["endpoint"]["endpointProperties"]["databaseName"]

    ## If many IP ranges are expected on the IPAM server, it is considered a best practice
    ## to return them page by page instead of all at once.
    ## The vRA IPAM Service will propagate a pageToken string with each consecutive request
    ## until all pages are exhausted
    pageToken = self.inputs['pagingAndSorting'].get('pageToken', None) ## The first request that vRA sends is with 'None' pageToken
    pageSize = self.inputs['pagingAndSorting'].get('maxResults', 1000)

    db = pymysql.connect(host=hostname,user=username,password=password,database=databasename)
    cursor = db.cursor()
    ## This function makes the appropriate SQL queries to the Racktables DB to fetch all networks, and their pertinant information.
    ## This function returns a list of objects, where each object is either an IPv4 or IPv6 network.
    allNetworkRanges = fetchRangesFromRacktables(cursor)

    ## This function returns a dict, where each key is a random hex string (For the page token), and the value is a list of networks.
    chunkedRanges = ipamResponseChunker(allNetworkRanges, pageSize)

    ## Plug your implementation here to collect all the ranges from the external IPAM system
    result_ranges, next_page_token = collect_ranges(chunkedRanges, pageToken)

    result = {
        "ipRanges": allNetworkRanges
    }

    ## Return the next page token so that vRA can process the first page and then fetch the second page or ranges with the next request
    # if next_page_token is not None:
    #     result["nextPageToken"] = next_page_token

    return result

def networkListChunker(inputList, size):
    size = max(1, size)
    return (inputList[i:i+size] for i in range(0, len(inputList), size))

def ipamResponseChunker(inputList, size):
    responsePages = {}
    chunkGen = networkListChunker(inputList, size)
    for chunk in chunkGen:
        responsePages[secrets.token_hex(16)] = chunk
    return responsePages

def fetchRangesFromRacktables(dbCursor):
    ipv4NetworkSql = """SELECT ipv4net.id, INET_NTOA(ipv4net.ip) as network, ipv4net.mask as subnetPrefixLength, INET_NTOA(ia.ip) as gateway, ipv4net.name, ipv4net.comment as description, GROUP_CONCAT(concat(ptt.tag,":", ctt.tag) SEPARATOR ",")  as tags
    FROM IPv4Network ipv4net
    LEFT OUTER JOIN IPv4Address ia ON ia.name = 'gateway' AND ia.ip&(-1<<32-ipv4net.mask) = ipv4net.ip&(-1<<32-ipv4net.mask)
    LEFT OUTER JOIN TagStorage ts ON ipv4net.id = ts.entity_id AND ts.entity_realm = "ipv4net"
    LEFT OUTER JOIN TagTree ctt ON ts.tag_id = ctt.id
    LEFT OUTER JOIN TagTree ptt ON ctt.parent_id = ptt.id
    GROUP BY ipv4net.id;"""

    ipv6NetworkSql = """SELECT ipv6net.id, INET6_NTOA(ipv6net.ip) as network, ipv6net.mask as subnetPrefixLength, INET_NTOA(ia.ip) as gateway, ipv6net.name, ipv6net.comment as description, GROUP_CONCAT(concat(ptt.tag,":", ctt.tag) SEPARATOR ",")  as tags
    FROM IPv6Network ipv6net
    LEFT OUTER JOIN IPv6Address ia ON ia.name = 'gateway' AND ia.ip&(-1<<128-ipv6net.mask) = ipv6net.ip&(-1<<128-ipv6net.mask)
    LEFT OUTER JOIN TagStorage ts ON ipv6net.id = ts.entity_id AND ts.entity_realm = "ipv6net"
    LEFT OUTER JOIN TagTree ctt ON ts.tag_id = ctt.id
    LEFT OUTER JOIN TagTree ptt ON ctt.parent_id = ptt.id
    GROUP BY ipv6net.id;"""

    allNetworkRanges = []

    dbCursor.execute(ipv4NetworkSql)
    ipv4Networks = dbCursor.fetchall()

    for ipv4Network in ipv4Networks:
        ipv4NetworkObject = ipaddress.ip_network(ipv4Network[1]+'/'+str(ipv4Network[2]))
        if (ipv4Network[2] == 32):
            # This is just a single address, not a network.
            logging.info('Found a /32 "Network": {}, this is likely invalid, and should be removed from RackTables'.format(str(ipv4NetworkObject)))
        else:
            tags = []
            if (ipv4Network[6] != None):
                splitTags = ipv4Network[6].split(',')
                for splitTag in splitTags:
                    tag = {}
                    tagKv = splitTag.split(':')
                    tag['key'] = tagKv[0]
                    tag['value'] = tagKv[1]
                    tags.append(tag)
            responseObject = {
                'id':ipv4Network[0],
                'name':ipv4Network[4],
                'startIPAddress':str(list(ipv4NetworkObject.hosts())[0]),
                'endIPAddress':str(list(ipv4NetworkObject.hosts())[-1]),
                'description':ipv4Network[5],
                'ipVersion':'IPv4',
                'addressSpaceId':'default',
                'subnetPrefixLength':ipv4Network[2],
                'gatewayAddress':ipv4Network[3],
                'domain':'',
                'tags':tags,
                'properties':{}
                }
            logging.debug(responseObject)
            allNetworkRanges.append(responseObject)

    # dbCursor.execute(ipv6NetworkSql)
    # ipv6Networks = dbCursor.fetchall()

    # for ipv6Network in ipv6Networks:
    #     ipv6NetworkObject = ipaddress.ip_network(ipv6Network[1]+'/'+str(ipv6Network[2]))
    #     if (ipv6Network[2] == 128):
    #         # This is just a single address, not a network.
    #         print("/128 network found, ignoring")
    #     else:
    #         tags = []
    #         if (ipv6Network[6] != None):
    #             tags = ipv6Network[6].split(',')
    #         responseObject = {
    #             'id':ipv6Network[0],
    #             'name':ipv6Network[4],
    #             'startIPAddress':str(ipv6NetworkObject.network_address + 1),
    #             'endIPAddress':str(ipv6NetworkObject.broadcast_address - 1),
    #             'description':ipv6Network[5],
    #             'ipVersion':'IPv6',
    #             'addressSpaceId':'default',
    #             'subnetPrefixLength':ipv6Network[2],
    #             'dnsServerAddresses': [],
    #             'gatewayAddress':ipv6Network[3],
    #             'domain':'',
    #             'tags':tags,
    #             'properties':{}
    #             }
    #         logging.debug(responseObject)
    #         allNetworkRanges.append(responseObject)
    
    return allNetworkRanges

def collect_ranges(ranges, pageToken):
    logging.info("collect_range was called with pageToken {}".format(pageToken))

    result = []
    next_page_token = None
    if pageToken is None:
        result = ranges[list(ranges.keys())[0]]
        next_page_token = list(ranges.keys())[1]
    else:
        result = ranges[pageToken]
        next_page_token = list(ranges.keys())[list(ranges.keys()).index(pageToken)+1]

    return result, next_page_token
