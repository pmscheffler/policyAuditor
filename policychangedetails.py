from math import fabs
from xml.etree.ElementInclude import include
import requests
import json
import pprint, getopt, sys 

def policyChangeDetails(argv):
    bigip_host = "yourhost"
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
# pprint.pprint(data['token']['token'])

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
        policyName = policy['name']
        policyLastChange = policy['versionLastChange']
        policyTimeStamp = policy['versionDatetime']

        print("\n*********\n\nPolicy change info: " + policyName + "\nChange Detail:" + policyLastChange + "\nOn: " + policyTimeStamp)

policyChangeDetails()

if __name__ == "__main__":
    policyChangeDetails(sys.argv[1:])