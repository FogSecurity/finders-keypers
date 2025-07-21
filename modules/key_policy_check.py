import sys
import boto3

#Module processes KMS Key Policies to check for potential cross-account usage.

def parse_policy(session, key_region, input_key_arn):
    try:
        kms_client = session.client('kms', region_name=key_region)
        key_policy = kms_client.get_key_policy(
            KeyId = input_key_arn
        )
        print(key_policy)
    except:
        sys.exit("Error getting key policy")



#def check_policy