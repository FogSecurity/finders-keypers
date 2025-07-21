import sys
import boto3
import json

#Module processes KMS Key Policies to check for potential cross-account usage.


def get_key_policy(session, key_region, input_key_arn):
    try:
        kms_client = session.client('kms', region_name=key_region)
        key_policy = kms_client.get_key_policy(
            KeyId = input_key_arn
        )
        return key_policy
    except:
        sys.exit("Error getting key policy")

def parse_policy(raw_key_policy):
    key_policy = json.loads(raw_key_policy['Policy'])
    return key_policy                    
