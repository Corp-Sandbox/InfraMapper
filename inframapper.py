#!/usr/bin/python3
'''
InfraMapper
v0.1 - POC release to test boto3 capabilities and use of diagrams module.
'''
from collections import defaultdict
from diagrams import Cluster, Diagram
from diagrams.aws.compute import EC2
from diagrams.aws.general import GenericFirewall
from tqdm import tqdm
import boto3

access_key = input("Enter the access key: ")
secret_key = input("Enter the secret key: ")
role_arn = input("Enter MFA role ARN: ")
mfa_serial = input("Enter MFA serial: ")

session = boto3.Session(
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
)

mfa_TOTP = input("Enter the MFA code: ")

client = session.client('sts')

# Call the assume_role method of the STSConnection object and pass the role
# ARN and a role session name.
assumed_role_object = client.assume_role(
    RoleArn=role_arn,
    RoleSessionName='mysession',
    DurationSeconds=3600,
    SerialNumber=mfa_serial,
    TokenCode=mfa_TOTP,
)

# From the response that contains the assumed role, get the temporary
# credentials that can be used to make subsequent API calls
credentials=assumed_role_object['Credentials']

regions = [
    'us-east-1',
    'us-east-2',
    'eu-west-1',
    'eu-west-2'
]

with Diagram('EC2 Infra Map', show=True, direction="TB"):

    # Create empty list variables
    egress_rules = []
    ingress_rules = []

    # Query topology
    # Region
    # ---- VPC
    # -------- Subnet
    # ------------ Instance

    for region in tqdm(regions):
        with Cluster(region):

            # Create regional ec2 resource object
            ec2 = boto3.resource('ec2',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )

            vpcs = ec2.vpcs.filter() # Get all VPCs in region

            for vpc in vpcs:
                with Cluster(vpc.vpc_id):
                    subnet_query = ec2.subnets.filter(Filters=[
                        {
                            'Name': 'vpc-id',
                            'Values': [vpc.vpc_id]
                        }
                    ])
                    for subnet in subnet_query:
                        with Cluster(f"{subnet.subnet_id} ({subnet.cidr_block})"):

                            instance_query = ec2.instances.filter(Filters=[
                                {
                                    'Name': 'subnet-id',
                                    'Values': [subnet.subnet_id]
                                }
                            ])

                            instances = []

                            for instance in instance_query:
                                if instance.tags is not None:
                                    for tag in instance.tags:
                                        if 'Name' in tag['Key']:
                                            name = tag['Value']
                                else:
                                    name = instance.instance_id

                                item = EC2(name)
                                instances.append(item)

                                # Security Group Processing
                                for security_group in instance.security_groups:
                                    sg_object = ec2.SecurityGroup(security_group['GroupId'])
                                    for rule in sg_object.ip_permissions_egress:
                                        for ip_range in rule['IpRanges']:
                                            rule_dict = {
                                                'EC2Instance': item,
                                                'CidrRange': ip_range['CidrIp'],
                                                'IpProtocol': rule['IpProtocol']
                                            }

                                            if rule['IpProtocol'] != '-1':
                                                rule_dict['FromPort'] = rule['FromPort']
                                                rule_dict['ToPort'] = rule['ToPort']
                                            egress_rules.append(rule_dict)
                                    for rule in sg_object.ip_permissions:
                                        for ip_range in rule['IpRanges']:
                                            rule_dict = {
                                                'EC2Instance': item,
                                                'CidrRange': ip_range['CidrIp'],
                                                'IpProtocol': rule['IpProtocol']
                                            }

                                            if rule['IpProtocol'] != '-1':
                                                rule_dict['FromPort'] = rule['FromPort']
                                                rule_dict['ToPort'] = rule['ToPort']
                                            ingress_rules.append(rule_dict)

    sources = defaultdict()
    destinations = defaultdict()

    for rule in egress_rules:
        if rule['CidrRange'] not in destinations.keys():
            destinations[rule['CidrRange']] = {
                'Object': GenericFirewall(rule['CidrRange']),
                'Instances': [rule['EC2Instance']]
            }
        else:
            if rule['EC2Instance'] not in destinations[rule['CidrRange']]['Instances']:
                destinations[rule['CidrRange']]['Instances'].append(rule['EC2Instance'])

    for rule in ingress_rules:
        if rule['CidrRange'] not in sources.keys():
            sources[rule['CidrRange']] = {
                'Object': GenericFirewall(rule['CidrRange']),
                'Instances': [rule['EC2Instance']]
            }
        else:
            if rule['EC2Instance'] not in sources[rule['CidrRange']]['Instances']:
                sources[rule['CidrRange']]['Instances'].append(rule['EC2Instance'])

    for source in sources:
        sources[source]['Object'] >> sources[source]['Instances'] # pylint: disable=pointless-statement

    for destination in destinations:
        destinations[destination]['Instances'] >> destinations[destination]['Object'] # pylint: disable=pointless-statement
