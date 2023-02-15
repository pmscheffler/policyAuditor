# F5 BIG-IP AWAF Policy Audit Logs

## Introduction

This is a quick Python script which allows the user to request the audit logs stored on the BIG-IP AWAF device for a given Security Policy.

Companion to the DevCentral Article: 
[https://community.f5.com/t5/technical-articles/auditing-security-policy-updates/ta-p/310386]

The parameters are: 
  * -h/host for the management port 
  * -u/user for the user 
  * -p/password  (note that there's a call to get an Auto Token)
  * -n/name or -d/id for either the Policy Name or the Policy ID

**Note** that this is offereed as an example and no warranty or other protections are offered...
please use with care



