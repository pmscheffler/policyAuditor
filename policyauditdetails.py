from math import fabs
from xml.etree.ElementInclude import include
import requests
import json
import pprint
import urllib3
import datetime
import getopt, sys

urllib3.disable_warnings()


def auditPolicies(argv):
    bigip_host = "hostname or IP"
    username = "admin"
    hiddenpassword = "SomePassword"
    policyName = ""

    try:
        opts, args = getopt.getopt(argv, "?h:u:p:n:", ["host=", "user=", "password=", "name="])
    except getopt.GetoptError:
        print('Show policy audit details.')
        print('-? policyauditdetails.py')
        print('-h <hostname or ip> (host=)')
        print('-u <username> (username=)')
        print('-p <password> (password=)')
        print('-n <policyfilter> (name=)')
        print('Format is policyName = "?$filter=name eq policy-name"')
        print('Leave it blank and it will iterate thru all of the policies')
        print('or if you use a wildcard it will go thru a subset')
        print('or the actual name will pull one policy')
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-?":
            print('Show policy audit details.')
            print('-? policyauditdetails.py')
            print('-h <hostname or ip> (host=)')
            print('-u <username> (username=)')
            print('-p <password> (password=)')
            print('-n <policyfilter> (name=)')
            print('Format is policyName = "?$filter=name eq policy-name"')
            print('Leave it blank and it will iterate thru all of the policies')
            print('or if you use a wildcard it will go thru a subset')
            print('or the actual name will pull one policy')
            sys.exit(1)
        elif opt in ("-h", "--host"):
            bigip_host = arg
        elif opt in ("-u", "--username"):
            username = arg
        elif opt in ("-p", "--password"):
            hiddenpassword = arg
        elif opt in ("-n", "--name"):
            policyName = arg

    url = "https://" + bigip_host + "/mgmt/shared/authn/login"

    payload = json.dumps({
        "username": username,
        "password": hiddenpassword,
        "loginProviderName": "tmos"
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request(
        "POST", url, headers=headers, data=payload, verify=False)

    data = json.loads(response.text)

    authToken = data['token']['token']

    url = "https://" + bigip_host + "/mgmt/tm/asm/policies" + policyName

    payload = {}
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': authToken
    }

    response = requests.request(
        "GET", url, headers=headers, data=payload, verify=False)
    policyData = json.loads(response.text)

    for policy in policyData['items']:
        policyID = policy['id']
        policyName = policy['name']
        print("\n*********\nPolicy: " + policyName)
        url = "https://" + bigip_host + "/mgmt/tm/asm/policies/" + policyID + "/audit-logs/"

        payload = ""

        response = requests.request(
            "GET", url, headers=headers, data=payload, verify=False, timeout=3600)

        auditRecs = json.loads(response.text)
        for auditItem in auditRecs['items']:
            pcDescription = auditItem['description']
            pcEventType = auditItem['eventType']
            pcTimeStamp = policy['lastUpdateMicros']

            print("\nPolicy change info (" + pcEventType + "): " + "\nChange Detail:" +
                  pcDescription + "\nOn: " + str(datetime.datetime.fromtimestamp(pcTimeStamp/1000000.0)))

if __name__ == "__main__":
    auditPolicies(sys.argv[1:])

