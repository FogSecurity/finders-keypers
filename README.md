# Finders Keypers (AWS KMS Key Usage Finder)
This CLI tool will take an AWS KMS Key as input and output resources encrpyted with the specified KMS Key.  A full listing of supported resources and services can be found below.

This tool supports both AWS Customer Managed KMS Keys and AWS Managed KMS Keys.  Keep in mind that `DescribeKey` can be a mutating operation by AWS to create AWS Managed keys from a predefined AWS alias with no key ID.  It is non-mutating for Customer Managed Keys.

Use cases include:
- Security and Audit for KMS Key and Resources
- Data Protection with Encryption
- Discovering blast radius of a specific KMS Key
- Changing a KMS Key or Rotating Key Material
- Check Default Settings in AWS that create new resources with the KMS Key
- Audit Resources that a KMS Key may grant access to.

For support and feedback, email <info@fogsecurity.io>

Blog Post: [https://www.fogsecurity.io/blog/introducing-finders-keypers-a-tool-to-discover-usage-and-blast-radius-of-encryption-keys-in-aws](https://www.fogsecurity.io/blog/introducing-finders-keypers-a-tool-to-discover-usage-and-blast-radius-of-encryption-keys-in-aws)

## How to run

### Running

```
 python3 finders_keypers.py --keyarn arn:aws:kms:us-east-1:123412341234:key/aaaaaaaa-aaaa-1111-aaaa-aaaa1111aaaa 

```

Input:
* `-keyarn` followed by a fully qualified key ARN such as `arn:aws:kms:us-east-1:123412341234:key/aaaaaaaa-aaaa-1111-aaaa-aaaa1111aaaa `

We recommend configuring the AWS profile for credentials and the AWS region.  To see how to configure credentials for AWS, see AWS CLI documentation on [credentials here.](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html)

The tool will scan resources for KMS Key Usage and output the following:
* Total Number of Resources encrypted with KMS Key Provided (same region as KMS Key).
* ARN, resource identifier, or description (if ARN is unavailable)

```
python3 finders_keypers.py --keyarn arn:aws:kms:us-east-1:123412341234:key/aaaaaaaa-aaaa-1111-aaaa-aaaa1111aaaa                   

Total Number of Resources encrypted with KMS Key Provided: 5
example-bucket-finderskeypers
vol-12341234123412345
vol-43214321432154321
arn:aws:dynamodb:us-east-1:123412341234:table/my-first-dynamodb-table
arn:aws:ssm:us-east-1:123412341234:parameter/sample-parameter

```

Key Usage Finder can be run in `--verbose` mode which will output more details on resources including:
* Service Name, Resource Type, ARN (or resource identifier), and encryption context.

```
python3 finders_keypers.py --keyarn arn:aws:kms:us-east-1:123412341234:key/aaaaaaaa-aaaa-1111-aaaa-aaaa1111aaaa --verbose                       

Total Number of Resources encrypted with KMS Key Provided: 6
{'Service': 'Glue', 'Resource': 'Data Catalog', 'ARN': 'ARN', 'Context': 'Connection Password Encryption'}
{'Service': 'DynamoDB', 'Resource': 'DynamoDB Table', 'ARN': 'arn:aws:dynamodb:us-east-1:123412341234:table/sample-table-dynamodb-own-encryption', 'Context': 'Encryption at Rest'}
{'Service': 'DocumentDB', 'Resource': 'DocumentDB Cluster', 'ARN': 'arn:aws:rds:us-east-1:123412341234:cluster:docdb-2024-05-13-15-22-33', 'Context': 'Encryption at Rest'}
{'Service': 'S3', 'Resource': 'S3 Bucket', 'ARN': 'sample-bucket-encryption', 'Context': 'Encryption at Rest'}
{'Service': 'EC2', 'Resource': 'EBS Volume', 'ARN': 'vol-12345123451234567', 'Context': 'Encryption at Rest'}
{'Service': 'Secrets Manager', 'Resource': 'Secret', 'ARN': 'arn:aws:secretsmanager:us-east-1:123412341234:secret:test-reference-secret', 'Context': 'Encryption at Rest'}

```

### Requirements and Installation

* Python & Boto3
* AWS Credentials and Access.

For IAM Permissions, Finders Keypers does not require non-read permissions (such as create, delete, or modification).  We recommend least privilege permissions.  Minimum permissions can be found in the [iam/](iam/) folder.  The AWS managed - job function `ReadOnlyAccess` policy can be used with Finders Keypers.  We recommend also checking KMS key policies, organizational policies such as RCPs and SCPs if there are access issues and to ensure Finders Keypers has access.

Requirements can be installed via pip3 install and the `requirements.txt` file.  A python virtual environment can be used if desired.

```
pip3 install -r requirements.txt
```

For AWS Credentials and setting up the AWS CLI, see AWS CLI documentation on [credentials here](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html)

## Current Support: 

### Limitations:

* This tool does not support discovering cross-account usage of KMS Keys.  Example: Resource in Account B encrypted by a KMS Key in Account A.
* Currently, this tool does not support Multi-Region Keys.  This does support regional keys, so depending on MRK setup, this tool may return some results.
* Currently this tool only supports a fully qualified KMS Key ARN as input.

### Supported Services:

Currently supports 21 AWS Services and 28 different resource types.

#### AWS Compute:

- Amazon EBS
  
#### AWS Database:

- Amazon RDS
- Amazon Aurora (RDS)
- Amazon DynamoDB
- Amazon QLDB (Quantum Ledger Database)
- Amazon Timestream
- Amazon Neptune
- Amazon DocumentDB
- Amazon Keyspaces (for Apache Cassandra)
- Amazon Elasticache

#### AWS Analytics:

- Amazon Redshift
- Amazon Redshift Serverless
- AWS Glue

#### AWS Storage:

- AWS S3
- Amazon Elastic File System (EFS)
- Amazon FSx

#### AWS Secrets and Configuration Storage:
- Amazon Systems Manager Parameter Store
- AWS Secrets Manager

#### AWS Application Integration:
- Amazon Simple Queue Service (SQS)
- Amazon Simple Notification Service (SNS)
- Amazon MQ

### Supported Resources:
- S3 Buckets
- EFS File Systems
- Aurora Instances
- Aurora Clusters
- RDS Instances
- RDS Clusters
- Neptune Instances
- Neptune Clusters
- DocumentDB Instances
- DocumentDB Clusters
- DocumentDB Elastic Clusters
- DynamoDB Tables
- Glue Data Catalog Encryption Settings (Account-Level)
- EBS Volumes
- QLDB Ledgers
- Redshift Clusters
- Redshift Serverless Namespaces
- SSM Parameter Store Parameters (SecureString)
- Secrets Manager Secrets
- Timestream for LiveAnalytics Database
- Keyspace Tables
- Elasticache Serverless Caches
- Elasticache Replication Groups (Caches)
- SQS Queues
- SNS Topics
- FSx File System
- RabbitMQ Broker
- ActiveMQ Broker
