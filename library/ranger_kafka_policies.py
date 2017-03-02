#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, BROADSoftware
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
module: ranger_kafka_policies
version_added: "historical"
short_description: Manager definition of Kafka Policy in Apache Ranger
description:
     - xxxxxx 
options:
  ranger_admin_url:
    description:
      - xxxxx
    required: true
    default: null
    aliases: []
      
author:
    - "Serge ALEXANDRE"

'''


EXAMPLES = '''


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
        if resp.status_code != 200:
            error("Invalid returned http code '{0}' when calling POST on '{1}': {2}".format(resp.status_code, url, resp.text))
        
    def deletePolicy(self, pid):
        url = "{0}/service/public/v2/api/policy/{1}".format(self.endpoint, pid)
        resp = requests.delete(url, auth = self.auth, verify=self.verify)
        if resp.status_code < 200 and resp.status_code > 299:
            error("Invalid returned http code '{0}' when calling DELETE on '{1}: {2}'".format(resp.status_code, url, resp.text))
            
    def updatePolicy(self, policy):
        url = "{0}/service/public/v2/api/policy/{1}".format(self.endpoint, policy["id"])
        resp = requests.put(url, auth = self.auth, json=policy, headers={'content-type': 'application/json'}, verify=self.verify)
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


ALLOWED_MISSING_ON_RIGHT = Set([".version", ".policyType"])

def isPolicyIdentical(old, new):
    result = digdiff(old, new)
    #misc.ppprint(old)
    #misc.ppprint(new)
    if len(result['missingOnLeft']) > 0 or len(result['differsByType']) > 0 or len(result['differsByValue']) > 0:
        return False
    else:
        for missing in result["missingOnRight"]:
            if not missing in ALLOWED_MISSING_ON_RIGHT:
                return False
        return True
        

MANDATORY_ATTRS = [ "name",  "topics"]

def groom(policy):
    """
    Check and Normalize target policy expression
    """
    if 'name' not in policy:
        error("There is an Kafka policy without name!")
    prefix = "Kafka policy '{0}': ".format(policy['name'])
        
    for attr in MANDATORY_ATTRS:
        if attr not in policy:
            error("{0}Missing attribute '{1}'".format(prefix, attr))
        else:
            if isinstance(policy[attr], list):
                if len(policy[attr]) == 0:
                    error("{0}Attribute '{1}' is a list which must have at least one value".format(prefix, attr))
                else:
                    if len(str(policy[attr])[0]) == 0:
                        error("{0}Attribute '{1}' list value can't be empty".format(prefix, attr))
            else:
                if len(policy[attr]) == 0:
                    error("{0}Attribute '{1}' can't be empty".format(prefix, attr))
    
    if 'audit' not in policy:
        policy['audit'] = True
    if 'enabled' not in policy:
        policy['enabled'] = True
    if 'permissions' not in policy:
        policy['permissions'] = []
    else:
        for p in policy['permissions']:
            if 'users' not in p:
                p['users'] = []
            if 'groups' not in p:
                p['groups'] = []
            if 'accesses' not in p:
                p['accesses'] = []
            if 'delegate_admin' not in p:
                p['delegate_admin'] = False



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
            "topic": { 
                "isExcludes": False,
                "isRecursive": False,
                "values": tgtPolicy["topics"]
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
            tp['accesses'].append({ "isAllowed": True, "type": a.lower() })
        if 'ip_ranges' in p:
            tp['conditions'].append({ "type": "ip-range", "values": p['ip_ranges']})
        policy['policyItems'].append(tp)
    return policy
    
    
rangerAPI = None

def cleanup():
    if rangerAPI != None:
        rangerAPI.close()
    

def error(message):
    cleanup()
    module.fail_json(msg = message)    

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
            policies = dict(required=True, type='list')
            #policy_name = dict(required=True, type='str'),
            #enabled = dict(required=False, type='bool', default=True),
            #audit = dict(required=False, type='bool', default=True),
            #topics = dict(required=True, type='list'),
            #permissions = dict(required=False, type='list'),
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
    #p.policyName = module.params['policy_name']
    #p.enabled = module.params['enabled']
    #p.audit = module.params['audit']
    #p.topics = module.params['topics']
    #p.permissions = module.params['permissions']
    #p.checkMode = module.check_mode
    p.changed = False

    checkParameters(p)
    
    if p.ca_bundleFile != None:
        verify = p.ca_bundleFile
    else:
        verify = p.validateCerts
    
    global rangerAPI
    rangerAPI =  RangerAPI(p.adminUrl, p.adminUsername , p.adminPassword , verify)


    kafkaServiceName = rangerAPI.getServiceNameByType("kafka", p.serviceName)
    # Perform check before effective operation
    for tgtPolicy in p.policies:
        groom(tgtPolicy)    
    for tgtPolicy in p.policies:
        policyName = tgtPolicy['name']
        oldPolicies = rangerAPI.getPolicy(kafkaServiceName, policyName)
        #misc.ppprint(oldPolicies)
        if len(oldPolicies) > 1:
            error("More than one policy with name '{0}' !".format(policyName))
        if p.state == 'present':
            if len(oldPolicies) == 0:
                policy = newPolicy(tgtPolicy, kafkaServiceName)
                #misc.ppprint(p)
                rangerAPI.createPolicy(policy)
                p.changed = True
            else:
                oldPolicy = oldPolicies[0]
                pid = oldPolicy["id"]
                policy = newPolicy(tgtPolicy, kafkaServiceName)
                policy["id"] = pid
                if isPolicyIdentical(oldPolicy, policy):
                    pass
                else:
                    rangerAPI.updatePolicy(policy)
                    p.changed = True
                #misc.ppprint(oldPolicy)
        elif p.state == 'absent':
            if len(oldPolicies) == 1:
                rangerAPI.deletePolicy(oldPolicies[0]["id"])
                p.changed = True
    
    cleanup()
    module.exit_json(
        #topics = p.topics,
        #permissions = p.permissions,
        #policies = p.policies,
        changed = p.changed
    )



from ansible.module_utils.basic import *  #@UnusedWildImport

if __name__ == '__main__':
    main()

