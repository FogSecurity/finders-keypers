import sys
import boto3
import json

#Module processes KMS Key Policies to check for potential cross-account usage.


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

def check_external_principal(statement):

    principals = statement['Principal']

    print(principals)    
    # Potential Options AWS, CanonicalUser, Service, Federated, *
    #Canonical User

    #Account ID in Principal

    #Asterisk

    #Available Conditions

def find_external_accounts(key_policy): 

    statement_block = key_policy['Statement']

    for statement in statement_block:
        effect = statement['Effect']
        
        if effect == 'Allow':
            
            #Cannot use NotPrincipal with Allow
            check_external_principal(statement)

            #Principal is external

            #Condition is external
        action = statement['Action']
        resource = statement['Resource']
        principal = statement['Principal'] #Can this be optional?
        condition = statement.get('Condition')


