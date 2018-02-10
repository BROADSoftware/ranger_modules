#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, BROADSoftware
#
# This software is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software. If not, see <http://www.gnu.org/licenses/>.


DOCUMENTATION = '''
---
module: ranger_storm_policies
short_description: Manage definition of Storm Policy in Apache Ranger
description:
     - This module will allow you to manage Storm policies in Apache Ranger. 
     - Please refer to Apache Ranger documentation for authorization policy concept and usage.
options:
  admin_url:
    description:
      - The Ranger base URL to access Ranger API. Same host:port as the Ranger Admin GUI. Typically http://myranger.server.com:6080 or https://myranger.server.com:6182  
    required: true
    default: None
    aliases: []
  admin_username:
    description:
      - The user name to log on the Ranger Admin. Must have enough rights to manage policies.
    required: true
    default: None
    aliases: []
  admin_password:
    description:
      - The password associated with the admin_username
    required: true
    default: None
    aliases: []
  validate_certs:
    description:
      - Useful if Ranger Admin connection is using SSL. If no, SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.
    required: false
    default: True
    aliases: []
  ca_bundle_file:
    description:
      - Useful if Ranger Admin connection is using SSL. Allow to specify a CA_BUNDLE file, a file that contains root and intermediate certificates to validate the Ranger Admin certificate.
      - In its simplest case, it could be a file containing the server certificate in .pem format.
      - This file will be looked up on the remote system, on which this module will be executed. 
    required: false
    default: None
    aliases: []
  service_name:
    description:
      - In most cases, you should not need to set this parameter. It define the Ranger Admin Storm service, typically <yourClusterName>_storm. 
      - It must be set if there are several such services defined in your Ranger Admin configuration, to select the one you intend to use.  
    required: false
    default: None
    aliases: []
  state:
    description:
      - Whether to install (present) or remove (absent) these policies
    required: false
    default: present
    choices: [ present, absent ]
  policies:
    description:
      - The list of policies you want to be defined by this operation.
    required: true
    default: None
    aliases: []
  policies[0..n].name:
    description:
      - The name of the policy. Must be unique across the system.
    required: true
    default: None
    aliases: []
  policies[0..n].topologies:
    description:
      - A list of Storm topologies this policy will apply on. Accept wildcard characters '*' and '?'
    required: true
    default: None
    aliases: []
  policies[0..n].enabled:
    description:
      - Whether this policy is enabled.
    required: false
    default: True
    aliases: []
  policies[0..n].audit:
    description:
      - Whether this policy is audited
    required: false
    default: True
    aliases: []
  policies[0..n].permissions:
    description:
      - A list of permissions associated to this policy
    required: True
    default: None
    aliases: []
  policies[0..n].permissions[0..n].users:
    description:
      - A list of users this permission will apply on.
    required: false
    default: None
    aliases: []
  policies[0..n].permissions[0..n].groups:
    description:
      - A list of groups this permission will apply on.
    required: false
    default: None
    aliases: []
  policies[0..n].permissions[0..n].accesses:
    description:
      - A list of access right granted by this permission.
    required: True
    default: None
    aliases: []
  policies[0..n].permissions[0..n].delegate_admin:
    description:
      - When a policy is assigned to a user or a group of users those users become the delegated admin. The delegated admin can update, delete the policies. 
    required: false
    default: False
    aliases: []
      
author:
    - "Serge ALEXANDRE"

'''


EXAMPLES = '''

- hosts: edge_node1
  vars: 
    stormAdminAccesses: 
      - 'submitTopology'
      - 'fileUpload'
      - 'fileDownload'
      - 'killTopology'
      - 'rebalance'
      - 'activate'
      - 'deactivate'
      - 'getTopologyConf'
      - 'getTopology'
      - 'getUserTopology'
      - 'getTopologyInfo'
      - 'uploadNewCredentials'
  roles:
  - ranger_modules
  tasks:
  - name: Copy ca_bundle
    copy: src=../hdp13_ranger_cert.pem dest=/etc/security/hdp13_ranger_cert.pem owner=root mode=0400
  
  - name: Test ranger_yarn
    ranger_storm_policies:
      state: present
      admin_url: https://ranger.mycompany.com:6182
      admin_username: admin
      admin_password: admin
      validate_certs: no
      policies:
      - name: test3
        topologies:
        - topology1
        audit: true
        enabled: true
        permissions:
        - users:
          - jim
          - john
          groups: 
          - grp1
          accesses:
          - submitTopology
          - killTopology
          - activate
          - deactivate
          - getTopology
        - users:
          - admin 
          accesses: "{{ stormAdminAccesses }}"
          delegate_admin: true
    no_log: True
      
          
'''
import warnings
from sets import Set

HAS_REQUESTS = False

try:
    import requests
    from requests.auth import HTTPBasicAuth
    HAS_REQUESTS = True
except (ImportError, AttributeError):
    # AttributeError if __version__ is not present
    pass


# Global, to allow access from error
module = None
logs = []
logLevel = 'None'
 
    
def log(level, message):
    x = level+':' + message
    logs.append(x)
        
def debug(message):
    if logLevel == 'debug' or logLevel == "info":
        log("DEBUG", message)
 
def info(message):
    if logLevel == "info" :
        log("INFO", message)
 
 
 
class RangerAPI:
    
    def __init__(self, endpoint, username, password, verify):
        self.endpoint = endpoint
        self.username = username
        self.password = password
        self.verify = verify
        self.serviceNamesByType = None
        self.auth = HTTPBasicAuth(self.username, self.password)
        warnings.filterwarnings("ignore", ".*Unverified HTTPS.*")
        warnings.filterwarnings("ignore", ".*Certificate has no `subjectAltName`.*")

    
    def get(self, path):
        url = self.endpoint + "/" + path
        resp = requests.get(url, auth = self.auth, verify=self.verify)
        debug("HTTP GET({})  --> {}".format(url, resp.status_code))
        if resp.status_code == 200:
            result = resp.json()
            return result
        else:
            error("Invalid returned http code '{0}' when calling GET on '{1}'".format(resp.status_code, url))
    
    
    
    def getServiceNameByType(self, stype, candidate=None):
        if self.serviceNamesByType == None:
            self.serviceNamesByType = {}
            services = self.get("service/public/v2/api/service")
            for service in services:
                if not service["type"] in self.serviceNamesByType:
                    self.serviceNamesByType[service['type']] = []
                self.serviceNamesByType[service['type']].append(service['name'])
            #logger.debug(self.serviceNamesByType)
        if stype not in self.serviceNamesByType:
            error("Service type '{0}' is not defined in this Ranger instance".format(stype) )
        serviceNames = self.serviceNamesByType[stype]
        if candidate != None:
            if candidate not in serviceNames:
                error("Service {0} is not defined on this Ranger instance".format(candidate))
            return candidate
        else:
            if len(serviceNames) != 1:
                error("There is several choice for '{0}' service: {1}. Please configure one explicitly!".format(stype, serviceNames))
            return serviceNames[0]

    def getPolicy(self, service, policyName):
        return self.get("service/public/v2/api/service/{0}/policy?policyName={1}".format(service, policyName))
         
    def createPolicy(self, policy):
        url = self.endpoint + '/service/public/v2/api/policy'
        resp = requests.post(url, auth = self.auth, json=policy, headers={'content-type': 'application/json'}, verify=self.verify)
        debug("HTTP POST({})  --> {}".format(url, resp.status_code))        
        if resp.status_code != 200:
            error("Invalid returned http code '{0}' when calling POST on '{1}': {2}".format(resp.status_code, url, resp.text))
        
    def deletePolicy(self, pid):
        url = "{0}/service/public/v2/api/policy/{1}".format(self.endpoint, pid)
        resp = requests.delete(url, auth = self.auth, verify=self.verify)
        debug("HTTP DELETE({})  --> {}".format(url, resp.status_code))        
        if resp.status_code < 200 and resp.status_code > 299:
            error("Invalid returned http code '{0}' when calling DELETE on '{1}: {2}'".format(resp.status_code, url, resp.text))
            
    def updatePolicy(self, policy):
        url = "{0}/service/public/v2/api/policy/{1}".format(self.endpoint, policy["id"])
        resp = requests.put(url, auth = self.auth, json=policy, headers={'content-type': 'application/json'}, verify=self.verify)
        debug("HTTP PUT({})  --> {}".format(url, resp.status_code))        
        if resp.status_code != 200:
            error("Invalid returned http code '{0}' when calling PUT on '{1}': {2}".format(resp.status_code, url, resp.text))
    
    def close(self):
        pass
    
# ---------------------------------------------------------------------------------


def digdiff(left, right):
    result = {
        "missingOnLeft": [],
        "missingOnRight": [],
        "differsByValue": [],
        "differsByType": []
    }
    diffValue(left, right, "", result)
    return result


def diffValue(left, right, path, result):
    #print "diffValue(left:{0}   right:{1})".format(left, right)
    if right == None:
        if left != None:
            result["differsByValue"].append(path)
        else:
            pass
    else:
        if left == None:
            result["differsByValue"].append(path)
        elif isinstance(left, dict):
            if isinstance(right, dict):
                diffDict(left, right, path, result)
            else:
                result["differsByType"].append(path)
        elif isinstance(left, list):
            if isinstance(right, list):
                diffList(left, right, path, result)
            else:
                result["differsByType"].append(path)
        else:
            # left is a scalar
            left = normalizeType(left)
            right = normalizeType(right)
            if type(left) != type(right):
                #print "********************* type(left):{0}   type(right):{1}".format(type(left), type(right))
                result["differsByType"].append(path)
            else:
                if left != right:
                    result["differsByValue"].append(path)
                else:
                    pass
            
def normalizeType(value):
    """
    Try to normalize o type, to be able to compare them
    """
    if isinstance(value, unicode):
        return str(value)
    else:
        return value
    
    

def diffDict(left, right, path, result):
    #print "diffDict(left:{0}   right:{1})".format(left, right)
    for kl in left:
        path2 = path + "." + kl
        if kl in right:
            diffValue(left[kl], right[kl], path2, result)
        else:
            result['missingOnRight'].append(path2)
    for kr in right:
        path2 = path + "." + kr
        if kr in left:
            pass
        else:
            result['missingOnLeft'].append(path2)
            
            
def diffList(left, right, path, result):
    for x in range(len(left)):
        path2 = path + '[' + str(x) + ']'
        if x >= len(right):
            result['missingOnRight'].append(path2)
        else:
            diffValue(left[x], right[x], path2, result)
    for x in range(len(left), len(right)):
        path2 = path + '[' + str(x) + ']'
        result['missingOnLeft'].append(path2)
        

    
# ---------------------------------------------------------------------------------


ALLOWED_MISSING_ON_RIGHT = Set([".version", ".policyType", ".guid"])

def isPolicyIdentical(old, new):
    result = digdiff(old, new)
    #misc.ppprint(old)
    #misc.ppprint(new)
    debug("missingOnLeft:{}".format(result['missingOnLeft']))
    debug("missingOnRight:{}".format(result['missingOnRight']))
    debug("differsByType:{}".format(result['differsByType']))
    debug("differsByValue:{}".format(result['differsByValue']))
    if len(result['missingOnLeft']) > 0 or len(result['differsByType']) > 0 or len(result['differsByValue']) > 0:
        return False
    else:
        for missing in result["missingOnRight"]:
            if not missing in ALLOWED_MISSING_ON_RIGHT:
                return False
        return True


        
# --------------------------------------------------------- Grooming helper function

def checkListOfStrNotEmpty(base, attr, prefix):
    if attr not in base:
        error("{0}: Missing attribute '{1}'".format(prefix, attr))
    if not isinstance(base[attr], list):
        error("{0}: Attribute '{1}' if of wrong type. Must by a list".format(prefix, attr))
    if len(base[attr]) == 0:
        error("{0}: Attribute '{1}': Must have at least one items".format(prefix, attr))
    for v in base[attr]:
        if not isinstance(v, basestring) or len(v) == 0:
            error("{0}: All items of list '{1}' must be non null string".format(prefix, attr))


def checkListOfStr(base, attr, prefix):
    if attr not in base:
        base[attr] = []
    else:
        if not isinstance(base[attr], list):
            error("{0}: Attribute '{1}' if of wrong type. Must by a list".format(prefix, attr))
        for v in base[attr]:
            if not isinstance(v, basestring) or len(v) == 0:
                error("{0}: All items of list '{1}' must be non null string".format(prefix, attr))

def checkTypeWithDefault(base, attr, typ, default, prefix):
    if attr not in base:
        base[attr] = default
    else:
        if not isinstance(base[attr], typ):
            error("{0}: Attribute '{1}' if of wrong type. Must by a {2}".format(prefix, attr, typ))
    
def checkEnumWithDefault(base, attr, candidates, default, prefix):
    if attr not in base:
        base[attr] = default
    else:
        if not isinstance(base[attr], basestring):
            error("{0}: Attribute '{1}' if of wrong type. Must by a string".format(prefix, attr))
        else:
            if not base[attr] in candidates:
                error("{0}: Attribute '{1}' must be one of the following: {2}".format(prefix, attr, candidates))
                
def checkValidAttr(base, validAttrSet, prefix):
    for attr in base:
        if attr not in validAttrSet: 
            error("{0}: Invalid attribute '{1}'. Must be one of {2}".format(prefix, attr, validAttrSet))                           



def groom(policy):
    """
    Check and Normalize target policy expression
    """
    if 'name' not in policy:
        error("There is at least one Storm policy without name!")
    if not isinstance(policy["name"], basestring):
        error("Storm policy: Attribute 'name' if of wrong type. Must by a string")
    prefix = "Storm policy '{0}': ".format(policy['name'])


    checkValidAttr(policy, ['name', 'topologies', 'state', 'audit', 'enabled', 'permissions'], prefix)

    checkListOfStrNotEmpty(policy, "topologies", prefix)        

    checkTypeWithDefault(policy, "audit", bool, True, prefix)
    checkTypeWithDefault(policy, "enabled", bool, True, prefix)

    checkTypeWithDefault(policy, "permissions", list, [], prefix)

    for permission in policy['permissions']:
        checkValidAttr(permission, ['users', 'groups', 'accesses', 'delegate_admin'], prefix)
        checkListOfStr(permission, 'users', prefix)
        checkListOfStr(permission, 'groups', prefix)
        checkListOfStr(permission, 'accesses', prefix)
        checkTypeWithDefault(permission, 'delegate_admin', bool, False, prefix)


def newPolicy(tgtPolicy, service):
    policy = {
        'allowExceptions': [],
        'dataMaskPolicyItems': [],
        'denyExceptions': [],
        'denyPolicyItems': [],
        'isAuditEnabled': tgtPolicy['audit'],
        'isEnabled': tgtPolicy['enabled'],
        'name': tgtPolicy['name'],
        'policyItems': [],
        'resources': { 
            "topology": { 
                "isExcludes": False,
                "isRecursive": False,
                "values": tgtPolicy["topologies"]
            }
        },
        'rowFilterPolicyItems': [],
        'service': service
    }
    for p in tgtPolicy['permissions']:
        tp = {}
        tp['accesses'] = []
        tp['conditions'] = []
        tp['delegateAdmin'] = p['delegate_admin']
        tp['groups'] = p['groups']
        tp['users'] = p['users']
        for a in p['accesses']:
            tp['accesses'].append({ "isAllowed": True, "type": a })
        policy['policyItems'].append(tp)
    return policy

    
rangerAPI = None

def cleanup():
    if rangerAPI != None:
        rangerAPI.close()
    

def error(message):
    cleanup()
    module.fail_json(msg = message, logs=logs)    

class Parameters:
    pass
               
               
def checkParameters(p):
    pass               
                
def main():
    
    global module
    module = AnsibleModule(
        argument_spec = dict(
            state = dict(required=False, choices=['present','absent'], default="present"),
            admin_url = dict(required=True, type='str'),
            admin_username = dict(required=True, type='str'),
            admin_password = dict(required=True, type='str'),
            validate_certs = dict(required=False, type='bool', default=True),
            ca_bundle_file = dict(required=False, type='str'),
            service_name = dict(required=False, type='str'),
            policies = dict(required=True, type='list'),
            log_level = dict(required=False, default="None")
        ),
        supports_check_mode=True
    )
    
    if not HAS_REQUESTS:
        module.fail_json(msg="python-requests package is not installed")    

    p = Parameters()
    p.state = module.params['state']
    p.adminUrl = module.params['admin_url']
    p.adminUsername = module.params['admin_username']
    p.adminPassword = module.params['admin_password']
    p.validateCerts = module.params['validate_certs']
    p.ca_bundleFile = module.params['ca_bundle_file']
    p.serviceName = module.params['service_name']
    p.policies = module.params['policies']
    p.logLevel = module.params['log_level']
    p.changed = False

    global  logLevel
    logLevel = p.logLevel

    checkParameters(p)
        
    if p.ca_bundleFile != None:
        verify = p.ca_bundleFile
    else:
        verify = p.validateCerts
    
    global rangerAPI
    rangerAPI =  RangerAPI(p.adminUrl, p.adminUsername , p.adminPassword , verify)

    result = {}
    stormServiceName = rangerAPI.getServiceNameByType("storm", p.serviceName)
    # Perform check before effective operation
    for tgtPolicy in p.policies:
        groom(tgtPolicy)    
    for tgtPolicy in p.policies:
        policyName = tgtPolicy['name']
        result[policyName] = {}
        oldPolicies = rangerAPI.getPolicy(stormServiceName, policyName)
        debug("oldPolicies: " + repr(oldPolicies))
        #misc.ppprint(oldPolicies)
        if len(oldPolicies) > 1:
            error("More than one policy with name '{0}' !".format(policyName))
        if p.state == 'present':
            if len(oldPolicies) == 0:
                policy = newPolicy(tgtPolicy, stormServiceName)
                #misc.ppprint(p)
                rangerAPI.createPolicy(policy)
                result[policyName]['action'] = "created"
                p.changed = True
            else:
                oldPolicy = oldPolicies[0]
                pid = oldPolicy["id"]
                policy = newPolicy(tgtPolicy, stormServiceName)
                policy["id"] = pid
                result[policyName]['id'] = pid
                if isPolicyIdentical(oldPolicy, policy):
                    result[policyName]['action'] = "none"
                else:
                    result[policyName]['action'] = "updated"
                    rangerAPI.updatePolicy(policy)
                    p.changed = True
                #misc.ppprint(oldPolicy)
        elif p.state == 'absent':
            if len(oldPolicies) == 1:
                rangerAPI.deletePolicy(oldPolicies[0]["id"])
                result[policyName]['action'] = "deleted"
                p.changed = True
            else:
                result[policyName]['action'] = "none"
    
    cleanup()
    module.exit_json(
        changed = p.changed,
        policies = result,
        logs = logs
    )



from ansible.module_utils.basic import *  #@UnusedWildImport

if __name__ == '__main__':
    main()

