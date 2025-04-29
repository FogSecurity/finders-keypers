import sys
import boto3
import logging


def find_kms_key_usage(session, key_region, input_key_arn, key_resources):

    try:
        kms_client = session.client('kms', region_name=key_region)
        key_description = kms_client.describe_key(
            KeyId = input_key_arn
        )
    except kms_client.exceptions.NotFoundException:
        sys.exit("Check Key ARN and access, key ARN not found")

    #Check for Managed Key
    #See https://github.com/FogSecurity/aws-managed-kms-keys for Managed Key Informationelasticache
    if key_description['KeyMetadata']['KeyManager'] == 'AWS':
        #AWS Managed Key should only have 1 alias.
        alias = find_key_aliases(session, key_region, input_key_arn)

        if str(alias[0]).startswith('alias/aws/'):
            service = alias[0][10:]  # Remove alias/aws/

            try:
                func = f"find_{service}_key_usage(session, key_region, input_key_arn, key_resources)"
                exec(func)
            except Exception as e:
                logging.error(
                    f"A managed key check for the {service} has not been defined yet.")
        else:
            logging.error(
                f"A conflict between KeyMetadata and the alias has occurred in {alias[0]} with KeyManager: {key_description['KeyMetadata']['KeyManager']}")

    else:
    #Non Managed Key can be used across multiple services.
        try:
            find_glue_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with Glue Module: {e}")

        try:
            find_s3_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with S3 Module: {e}")

        try:
            find_ebs_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with EBS Module: {e}")

        try:
            find_qldb_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with QLDB Module: {e}")

        try:
            find_keyspaces_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with Keyspaces Module: {e}")

        try:
            find_timestream_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with Timestream Module: {e}")

        try:
            find_dynamodb_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with DynamoDB Module: {e}")

        try:
            find_neptune_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with Neptune Module: {e}")

        try:
            find_secretsmanager_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with Secrets Manager Module: {e}")

        try:
            find_ssm_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with SSM Module: {e}")

        try:
            find_redshift_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with Redshift Module: {e}")

        try:
            find_redshiftserverless_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with Redshift Serverless Module: {e}")

        try:
            find_elasticfilesystem_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with EFS Module: {e}")

        try:
            find_elasticache_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with Elasticache Module: {e}")

        try:
            find_docdb_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with DocumentDB Module: {e}")

        try:
            find_rds_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with RDS Module: {e}")

        try: 
            find_sqs_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with SQS Module: {e}")

        try:
            find_sns_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with SNS Module: {e}")

        try:
            find_fsx_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with FSx Module: {e}")

        try:
            find_mq_key_usage(session, key_region, input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with MQ Module: {e}")

        try:
            find_acm_key_usage(session, key_region,
                               input_key_arn, key_resources)
        except Exception as e:
            logging.error(f"Error with ACM Module: {e}")

def key_resources_append(service, resource, arn, context, key_resources):
    key_resources.append({
        'Service': service,
        'Resource': resource,
        'arn': arn,
        'Context': context
    })

def find_key_aliases(session, key_region, input_key_arn):

    kms_client = session.client('kms', region_name=key_region)

    key_alias_results = (
        kms_client.get_paginator('list_aliases')
        .paginate(KeyId=input_key_arn)
        .build_full_result()
    )

    key_aliases = []
    #key_aliases_arns = []

    for key in key_alias_results['Aliases']:
        key_aliases.append(key['AliasName'])
        #key_aliases_arns.append(key['AliasArn'])
    
    return key_aliases


def find_acm_key_usage(session, key_region, input_key_arn, key_resources):
    acm_pca_client = session.client('acm-pca', region_name=key_region)

    ca_list_response = acm_pca_client.list_certificate_authorities()
    for ca_summary in ca_list_response.get('CertificateAuthorities', []):
        ca_arn = ca_summary['Arn']

        ca_details = acm_pca_client.describe_certificate_authority(CertificateAuthorityArn=ca_arn)
        kms_key_id = ca_details['CertificateAuthority'].get('KeyId')
        if kms_key_id == input_key_arn:
            key_resources_append('ACM Private CA', 'Certificate Authority', ca_arn, 'CA Key Material Encryption', key_resources)

def find_ebs_key_usage(session, key_region, input_key_arn, key_resources):
    #EBS Volumes
    #TODO: EBS Default Encryption Setting

    ec2_client = session.client('ec2', region_name=key_region)

    ebs_volumes_results = (
        ec2_client.get_paginator('describe_volumes')
        .paginate()
        .build_full_result()
    )

    for volume in ebs_volumes_results['Volumes']:
        volume_key = volume.get('KmsKeyId')
        if volume_key == input_key_arn:
            key_resources_append('EC2', 'EBS Volume', volume['VolumeId'], 'Encryption At Rest', key_resources)
        
def find_glue_key_usage(session, key_region, input_key_arn, key_resources):
    
    #Glue Data Catalog
    glue_client = session.client('glue', region_name=key_region)
    data_catalog_encryption_settings = glue_client.get_data_catalog_encryption_settings()

    data_catalog_encryption_key_arn = data_catalog_encryption_settings['DataCatalogEncryptionSettings']['EncryptionAtRest']['SseAwsKmsKeyId']
    if data_catalog_encryption_key_arn == input_key_arn:
        key_resources_append('Glue', 'Data Catalog', 'Glue Data Catalog', 'Encryption at Rest', key_resources)

    conn_pass_enc_key = data_catalog_encryption_settings['DataCatalogEncryptionSettings']['ConnectionPasswordEncryption']['AwsKmsKeyId']
    if conn_pass_enc_key == input_key_arn:
        key_resources_append('Glue', 'Data Catalog', 'Glue Data Catalog Password Encryption', 'Connection Password Encryption', key_resources)


def find_dynamodb_key_usage(session, key_region, input_key_arn, key_resources):
    # DynamoDB Tables
    # TODO: Dynamo DAX Cluster - Service Default Keys

    dynamodb_client = session.client('dynamodb', region_name=key_region)

    #Describe Table only works for current version of global tables - 2019
    dynamo_list_results = (
        dynamodb_client.get_paginator('list_tables')
        .paginate()
        .build_full_result()
    )

    for table in dynamo_list_results['TableNames']:
        dynamo_table = dynamodb_client.describe_table(
            TableName=table 
        )
        #SSEDescription may not have data if default.
        sse_description = dynamo_table['Table'].get('SSEDescription', 'default')

        if sse_description != 'default':
            table_encryption_key = sse_description.get('KMSMasterKeyArn')
            if table_encryption_key == input_key_arn:
                key_resources_append('DynamoDB', 'DynamoDB Table', dynamo_table['Table']['TableArn'], 'Encryption At Rest', key_resources)


def find_s3_key_usage(session, key_region, input_key_arn, key_resources):

    #S3 Bucket Encryption (Does not check objects yet)
    s3_client = session.client('s3')

    s3_buckets_results = s3_client.list_buckets()
        
    for bucket in s3_buckets_results['Buckets']:
        bucket_encryption_response  = s3_client.get_bucket_encryption(
            Bucket=bucket['Name']
        )
        bucket_encryption = bucket_encryption_response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']
        encryption_key = bucket_encryption.get('KMSMasterKeyID')

        if encryption_key == input_key_arn:
            key_resources_append('S3', 'S3 Bucket', bucket['Name'], 'Encryption At Rest', key_resources)

def find_qldb_key_usage(session, key_region, input_key_arn, key_resources):

    # QLDB Ledgers

    qldb_client = session.client('qldb',  region_name=key_region)

    ##TODO: Fix this for pagination.  Returns error but should paginate: operation cannot be paginated
    
    qldb_ledgers_results = qldb_client.list_ledgers()

    for ledger in qldb_ledgers_results['Ledgers']:
        ledger_description = qldb_client.describe_ledger(Name=ledger['Name'])
        ledger_encryption_desc = ledger_description.get('EncryptionDescription')
        if ledger_encryption_desc:
            ledger_key = ledger_encryption_desc.get('KmsKeyArn')
            if ledger_key == input_key_arn:
                key_resources_append('QLDB', 'QLDB Ledger', ledger_description['Arn'], 'Encryption At Rest', key_resources)


def find_keyspaces_key_usage(session, key_region, input_key_arn, key_resources):
    '''
    Amazon Keyspaces
    Keyspace Tables
    '''
    keyspaces_client = session.client('keyspaces', region_name=key_region)

    keyspaces_keyspace_results = [
        keyspaces_client.get_paginator('list_keyspaces')
        .paginate()
        .build_full_result()
    ]

    #Remove Amazon Keyspaces system keyspaces

    system_keyspaces = ['system', 'system_schema', 'system_schema_mcs', 'system_multiregion_info']

    for keyspace in keyspaces_keyspace_results[0]['keyspaces']:
        if keyspace['keyspaceName'] not in system_keyspaces:
            keyspaces_tables_results = [
                keyspaces_client.get_paginator('list_tables')
                .paginate(
                    keyspaceName = keyspace['keyspaceName']
                )
                .build_full_result()
            ]

            for table in keyspaces_tables_results[0]['tables']:
                table_config = keyspaces_client.get_table(
                    keyspaceName = table['keyspaceName'],
                    tableName = table['tableName']
                )

                if table_config['encryptionSpecification']['type'] == 'CUSTOMER_MANAGED_KMS_KEY':
                    if table_config['encryptionSpecification']['kmsKeyIdentifier'] == input_key_arn:
                        key_resources_append('Keyspaces', 'Keyspaces Table', table['resourceArn'], 'Encryption At Rest', key_resources) 

def find_neptune_key_usage(session, key_region, input_key_arn, key_resources):
    
    #Neptune Instances and Neptune Clusters

    neptune_client = session.client('neptune', region_name=key_region)

    neptune_instances_results = (
        neptune_client.get_paginator('describe_db_instances')
        .paginate(
            Filters=[{
                'Name': 'engine',
                'Values': ['neptune']
            }]
        )
        .build_full_result()
    )

    for instance in neptune_instances_results['DBInstances']:
        instance_arn = instance['DBInstanceArn']
        
        if instance['StorageEncrypted'] is True:
            if instance['KmsKeyId'] == input_key_arn:
                key_resources_append('Neptune', 'Neptune Instance', instance_arn, 'Encryption At Rest', key_resources)

    neptune_clusters_results = (
        neptune_client.get_paginator('describe_db_clusters')
        .paginate(
            Filters=[{
                'Name': 'engine',
                'Values': ['neptune']
            }]
        )
        .build_full_result()
    )

    for cluster in neptune_clusters_results['DBClusters']:
        cluster_arn = cluster['DBClusterArn']
        
        if cluster['StorageEncrypted'] is True:
            if cluster['KmsKeyId'] == input_key_arn:
                key_resources_append('Neptune', 'Neptune Culster', cluster_arn, 'Encryption At Rest', key_resources)

def find_secretsmanager_key_usage(session, key_region, input_key_arn, key_resources):
 
    #Secrets
    
    secretsmanager_client = session.client('secretsmanager', region_name=key_region)

    secret_results = (
        secretsmanager_client.get_paginator('list_secrets')
        .paginate()
        .build_full_result()
    )

    for secret in secret_results['SecretList']:
        if secret.get('KmsKeyId') == input_key_arn:
            key_resources_append('Secrets Manager', 'Secret', secret.get('ARN'), 'Encryption At Rest', key_resources) 


def find_ssm_key_usage(session, key_region, input_key_arn, key_resources):
    
    #Parameter Store Parameters (SecureString)

    key_aliases = find_key_aliases(session, key_region, input_key_arn)

    kms_client = session.client('kms', region_name=key_region)
    key_description = kms_client.describe_key(
        KeyId = input_key_arn
    )

    key_id = key_description['KeyMetadata']['KeyId']
    ssm_client = session.client('ssm',  region_name=key_region)

    parameter_key_input = key_aliases
    parameter_key_input.append(key_id)

    ssm_parameter_results = (
        ssm_client.get_paginator('describe_parameters')
        .paginate(ParameterFilters=[{'Key':'KeyId', 'Values':parameter_key_input}])
        .build_full_result()
    )

    for parameter in ssm_parameter_results['Parameters']:
        #if parameter.get('KeyId') == input_key_arn:
        key_resources_append('SSM Parameter Store', 'SecureString Parameter', parameter.get('ARN'), 'Encryption At Rest', key_resources) 

def find_timestream_key_usage(session, key_region, input_key_arn, key_resources):

    #Timestream Live Analytics Databases
    #TODO: Timestream for InfluxDB

    timestream_client = session.client('timestream-write', region_name=key_region)

    #TODO: Fix for pagination
    timestream_database_results = timestream_client.list_databases()

    for database in timestream_database_results['Databases']:
        if database.get('KmsKeyId') == input_key_arn:
            key_resources_append('Timestream', 'Timestream Database', database.get['Arn'], 'Encryption At Rest', key_resources) 

def find_redshiftserverless_key_usage(session, key_region, input_key_arn, key_resources):

    #Redshift Serverless Namespaces

    redshift_serverless_client = session.client('redshift-serverless', region_name=key_region)

    redshift_serverless_namespaces_results = (
        redshift_serverless_client.get_paginator('list_namespaces')
        .paginate()
        .build_full_result()
    )

    for namespace in redshift_serverless_namespaces_results['namespaces']:
        if namespace.get('kmsKeyId') == input_key_arn:
            key_resources_append('Redshift Serverless', 'Redshift Serverless Namespace', namespace['namespaceArn'], 'Encryption At Rest', key_resources) 

def find_redshift_key_usage(session, key_region, input_key_arn, key_resources):

    #Redshift Clusters

    redshift_client = session.client('redshift', region_name=key_region)

    redshift_clusters_results = (
        redshift_client.get_paginator('describe_clusters')
        .paginate()
        .build_full_result()
    )

    for cluster in redshift_clusters_results['Clusters']:
        if cluster.get('KmsKeyId') == input_key_arn:
            key_resources_append('Redshift', 'Redshift Cluster', cluster['ClusterIdentifier'], 'Encryption At Rest', key_resources) 

def find_elasticfilesystem_key_usage(session, key_region, input_key_arn, key_resources):

    #EFS File Systems
    efs_client = session.client('efs', region_name=key_region)

    efs_filesystem_results = (
        efs_client.get_paginator('describe_file_systems')
        .paginate()
        .build_full_result()
    )

    for filesystem in efs_filesystem_results['FileSystems']:
        if filesystem.get('Encrypted'):
            if filesystem.get('KmsKeyId') == input_key_arn:
                key_resources_append('Elastic File System', 'EFS File System', filesystem.get('FileSystemArn'), 'Encryption At Rest' , key_resources)

def find_elasticache_key_usage(session, key_region, input_key_arn, key_resources):
    '''
    Amazon ElastiCache
    '''

    elasticache_client = session.client('elasticache', region_name=key_region)

    elasticache_serverless_cache_results = (
        elasticache_client.get_paginator('describe_serverless_caches')
        .paginate()
        .build_full_result()
        )

    for serverless_cache in elasticache_serverless_cache_results['ServerlessCaches']:
        if 'KmsKeyId' in serverless_cache:
            if serverless_cache['KmsKeyId'] == input_key_arn:
                key_resources_append('Elasticache', 'Serverless Cache', serverless_cache['ARN'], 'Encryption At Rest', key_resources) 

    #Replication Groups

    elasticache_replication_group_results = (
        elasticache_client.get_paginator('describe_replication_groups')
        .paginate()
        .build_full_result()
    )

    for replication_group in elasticache_replication_group_results['ReplicationGroups']:
        if replication_group['AtRestEncryptionEnabled']:
            if replication_group['KmsKeyId'] == input_key_arn:
                key_resources_append('Elasticache', 'Replication Group', replication_group['ARN'], 'Encryption At Rest', key_resources) 

def find_docdb_key_usage(session, key_region, input_key_arn, key_resources):
    #DocDB Instances
    
    docdb_client = session.client('docdb', region_name=key_region)
    docdb_elastic_client = session.client('docdb-elastic', region_name=key_region)

    docdb_instances_results = (
        docdb_client.get_paginator('describe_db_instances')
        .paginate(
            Filters=[{
                'Name': 'engine',
                'Values': ['docdb']
            }]
        )
        .build_full_result()
    )

    for instance in docdb_instances_results['DBInstances']:
        instance_arn = instance['DBInstanceArn']
        
        #Instance encryption
        if instance['StorageEncrypted'] is True:
            if instance['KmsKeyId'] == input_key_arn:
                key_resources_append('DocumentDB', 'DocumentDB Instance', instance_arn, 'Encryption At Rest', key_resources)

    docdb_clusters_results = (
        docdb_client.get_paginator('describe_db_clusters')
        .paginate(
            Filters=[{
                'Name': 'engine',
                'Values': ['docdb']
            }]
        )
        .build_full_result()
    )

    for cluster in docdb_clusters_results['DBClusters']:
        cluster_arn = cluster['DBClusterArn']
        
        if cluster['StorageEncrypted'] is True:
            if cluster['KmsKeyId'] == input_key_arn:
                key_resources_append('DocumentDB', 'DocumentDB Cluster', cluster_arn, 'Encryption At Rest', key_resources)
                
    docdb_elastic_clusters_results = (
        docdb_elastic_client.get_paginator('list_clusters')
        .paginate()
        .build_full_result()
    )

    for cluster in docdb_elastic_clusters_results['clusters']:
        cluster_data = docdb_elastic_client.get_cluster(
            clusterArn = cluster['clusterArn']
        )

        if cluster_data['cluster']['kmsKeyId'] == input_key_arn:
            key_resources_append('DocumentDB', 'DocumentDB Elastic Cluster', cluster['clusterArn'], 'Encryption At Rest', key_resources)


def find_rds_key_usage(session, key_region, input_key_arn, key_resources):
    # RDS Instances
    # RDS Clusters
    #TODO: RDS PerformanceInsightsKMSKeyId
    # TODO: RDS ActivityStreamKmsKeyId
    # RDS MasterUser Secret covered in Secrets Manager
    
    '''
        TODO: Check other key identifiers for RDS.  Could be possible that it's not just the Key ID.
        The Amazon Web Services KMS key identifier is the key ARN, key ID, alias ARN, or alias name for the KMS key.   
    '''

    rds_client = session.client('rds', region_name=key_region)

    #RDS Engines: https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-engine-versions.html
    rds_engines = [
    'custom-oracle-ee',
    'custom-oracle-ee-cdb',
    'custom-oracle-se2',
    'custom-oracle-se2-cdb',
    'db2-ae',
    'db2-se',
    'mariadb',
    'mysql',
    'oracle-ee',
    'oracle-ee-cdb',
    'oracle-se2',
    'oracle-se2-cdb',
    'postgres',
    'sqlserver-ee',
    'sqlserver-se',
    'sqlserver-ex',
    'sqlserver-web']

    rds_instances_results = (
        rds_client.get_paginator('describe_db_instances')
        .paginate(
            Filters=[{
                'Name': 'engine',
                'Values': rds_engines
            }]
        )
        .build_full_result()
    )

    for instance in rds_instances_results['DBInstances']:
        instance_arn = instance['DBInstanceArn']
        
        #Instance encryption
        if instance['StorageEncrypted'] is True:
            if instance['KmsKeyId'] == input_key_arn:
                key_resources_append('RDS', 'RDS Instance', instance_arn, 'Encryption At Rest', key_resources)

    aurora_instances_results = (
        rds_client.get_paginator('describe_db_instances')
        .paginate(
            Filters=[{
                'Name': 'engine',
                'Values': ['aurora-mysql', 'aurora-postgresql']
            }]
        )
        .build_full_result()
    )

    for instance in aurora_instances_results['DBInstances']:
        instance_arn = instance['DBInstanceArn']
        
        #Instance encryption
        if instance['StorageEncrypted'] is True:
            if instance['KmsKeyId'] == input_key_arn:
                key_resources_append('RDS Aurora', 'RDS Aurora Instance', instance_arn, 'Encryption At Rest', key_resources)  
            
    rds_cluster_results = (
        rds_client.get_paginator('describe_db_clusters')
        .paginate(
            Filters=[{
                'Name': 'engine',
                'Values': rds_engines
            }]
        )
        .build_full_result()
    )  

    for cluster in rds_cluster_results['DBClusters']:
        cluster_arn = cluster['DBClusterArn']

        if cluster['StorageEncrypted'] is True:
            if cluster['KmsKeyId'] == input_key_arn:
                key_resources_append('RDS', 'RDS Cluster', cluster_arn, 'Encryption At Rest', key_resources)
                
    aurora_cluster_results = (
        rds_client.get_paginator('describe_db_clusters')
        .paginate(
            Filters=[{
                'Name': 'engine',
                'Values': ['aurora-mysql', 'aurora-postgresql']
            }]
        )
        .build_full_result()
    )  

    for cluster in aurora_cluster_results['DBClusters']:
        cluster_arn = cluster['DBClusterArn']

        if cluster['StorageEncrypted'] is True:
            if cluster['KmsKeyId'] == input_key_arn:
                key_resources_append('RDS Aurora', 'RDS Aurora Cluster', cluster_arn, 'Encryption At Rest', key_resources)

def find_sqs_key_usage(session, key_region, input_key_arn, key_resources):
    sqs_client = session.client('sqs', region_name=key_region)

    sqs_queue_results = (
        sqs_client.get_paginator('list_queues')
        .paginate()
        .build_full_result()
    )

    key_aliases = find_key_aliases(session, key_region, input_key_arn)

    key_descriptors = key_aliases
    key_descriptors.append(input_key_arn)

    #Get Key ID, not ARN.
    kms_client = session.client('kms', region_name=key_region)
    key_description = kms_client.describe_key(
        KeyId = input_key_arn
    )
    key_id = key_description['KeyMetadata']['KeyId'] 

    key_descriptors.append(key_id)

    for queue in sqs_queue_results['QueueUrls']:
        queue_attributes = sqs_client.get_queue_attributes(
            QueueUrl = queue,
            AttributeNames = [
                'QueueArn',
                'KmsMasterKeyId',
                'SqsManagedSseEnabled'
            ]
        )
        
        if queue_attributes['Attributes'].get('KmsMasterKeyId') in key_descriptors:
            key_resources_append('SQS', 'SQS Queue', queue_attributes['Attributes']['QueueArn'], 'Encryption At Rest', key_resources)            

def find_sns_key_usage(session, key_region, input_key_arn, key_resources):
    sns_client = session.client('sns', region_name=key_region)

    sns_topic_results = (
        sns_client.get_paginator('list_topics')
        .paginate()
        .build_full_result()
    )
    for topic in sns_topic_results['Topics']:
        topic_attributes = sns_client.get_topic_attributes(
            TopicArn=topic['TopicArn']
        )

        if topic_attributes['Attributes'].get('KmsMasterKeyId') == input_key_arn:
            key_resources_append('SNS', 'SNS Topic', topic['TopicArn'], 'Encryption At Rest', key_resources)


def find_fsx_key_usage(session, key_region, input_key_arn, key_resources):
    fsx_client = session.client('fsx', region_name=key_region)

    fsx_filesystem_results = (
        fsx_client.get_paginator('describe_file_systems')
        .paginate()
        .build_full_result()
    )

    for filesystem in fsx_filesystem_results['FileSystems']:
        if filesystem['KmsKeyId'] == input_key_arn:
            key_resources_append('FSx', 'FSx File System', filesystem['ResourceARN'], 'Encryption At Rest', key_resources)

def find_mq_key_usage(session, key_region, input_key_arn, key_resources):
    mq_client = session.client('mq', region_name=key_region)

    mq_broker_results = (
        mq_client.get_paginator('list_brokers')
        .paginate()
        .build_full_result()
    )

    for broker in mq_broker_results['BrokerSummaries']:
        broker_description = mq_client.describe_broker(
            BrokerId=broker['BrokerId']
        )
        
        if broker_description['EncryptionOptions'].get('KmsKeyId') == input_key_arn:
            key_resources_append('MQ', 'MQ Broker', broker['BrokerArn'], 'Encryption At Rest', key_resources)