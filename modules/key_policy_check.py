import sys
import boto3
import json

#Module processes KMS Key Policies to check for potential cross-account usage.

def get_key_account(key_arn):
    
    split_arn = key_arn.split(":")
    key_account = split_arn[4]

    return key_account

def get_key_policy(session, key_region, input_key_arn):
    try:
        kms_client = session.client('kms', region_name=key_region)
        str_key_policy = kms_client.get_key_policy(
            KeyId = input_key_arn
        )
        return str_key_policy
    except:
        sys.exit("Error getting key policy")

def parse_policy(raw_key_policy):
    key_policy = json.loads(raw_key_policy['Policy'])
    return key_policy 

def check_external_principal(statement, key_account):

    principals = statement['Principal']
    ext_principals = []

    if principals == "*":
        #TODO: Check Conditions
        ext_principals.extend(["*"])

    elif principals.get('AWS'):
        principals_list = []
        if type(principals['AWS']) == list:
            #Only 1 entry for principals
            principals_list = principals['AWS']
        else:
            principals_list.append(principals['AWS'])
            
        for principal in principals_list:
            if principal == "*":
                ext_principals.append("*")
            else:
                split_arn = principal.split(":")
                try:
                    arn_account = split_arn[4]
                    if not arn_account == key_account:
                        ext_principals.append(principal)
                except IndexError:
                    print("Index Error for one of the Key Policy Principals " + principal)
    
    else:
        return []

    return ext_principals
    #TODO: Federated, CanonicalUser, and Service
    #TODO: Conditions

def find_external_accounts(key_policy, key_account): 

    statement_block = key_policy['Statement']
    ext_accounts = []
    for statement in statement_block:
        effect = statement['Effect']
        
        if effect == 'Allow':
            #Cannot use NotPrincipal with Allow
            ext_principals = check_external_principal(statement, key_account)
            ext_accounts.extend(ext_principals)
            #Principal is external
        action = statement['Action']
        
        #resource = statement['Resource']
        #principal = statement['Principal'] #Can this be optional?
        #condition = statement.get('Condition')
    return ext_accounts
