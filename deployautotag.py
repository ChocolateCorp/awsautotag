# -*- coding: utf-8 -*-

import boto3
import json
import random

from botocore.exceptions import ClientError
from datetime import datetime


CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'


def get_random_string(length=12, allowed_chars=CHARS):
    """Generate random string of given length with allowed chars."""
    return ''.join(random.choice(allowed_chars) for _ in range(length))


def get_account_id():
    """Retrieve principal account id."""
    return boto3.client('sts').get_caller_identity().get('Account')


def create_bucket(name):
    """Create s3 bucket and attach cloudtrail policy."""
    s3 = boto3.client('s3')
    bucket = '%s-%s' % (name, get_random_string())

    bucketPolicy = {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "AWSCloudTrailAclCheck20150319",
          "Effect": "Allow",
          "Principal": {"Service": "cloudtrail.amazonaws.com"},
          "Action": "s3:GetBucketAcl",
          "Resource": "arn:aws:s3:::%s" % bucket
        },
        {
          "Sid": "AWSCloudTrailWrite20150319",
          "Effect": "Allow",
          "Principal": {"Service": "cloudtrail.amazonaws.com"},
          "Action": "s3:PutObject",
          "Resource": "arn:aws:s3:::%s/AWSLogs/%s/*" % (bucket,
                                                        get_account_id()),
          "Condition": {"StringEquals": {"s3:x-amz-acl":
              "bucket-owner-full-control"}
          }
        }
      ]
    }

    response = s3.create_bucket(
        Bucket=bucket
    )

    response = s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(policy)
    )

    print("S3 bucket named %s created and policy attached." % bucket)
    return bucket


def create_role(roleName, policyName, rolePolicy):
    """Create or retrieve role and attach inline policy."""
    iam = boto3.client('iam')
    policyDoc = {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Principal" : {"Service" : ["lambda.amazonaws.com"]},
          "Action" : ["sts:AssumeRole"]
        }
      ]
    }

    roles = [role['RoleName'] for role in iam.list_roles()['Roles']]
    if roleName in roles:
        print('Role %s exists' % roleName)
        role = iam.get_role(
            RoleName=roleName
        )['Role']
    else:
        role = iam.create_role(
            RoleName=roleName,
            AssumeRolePolicyDocument=json.dumps(policyDoc)
         )['Role']
        print('Created role %s' % roleName)

    policies = iam.list_role_policies(RoleName=roleName)['PolicyNames']
    if policyName not in policies:
        iam.put_role_policy(
            RoleName=roleName,
            PolicyName=policyName,
            PolicyDocument=json.dumps(rolePolicy)
        )
        print('Put role policy %s' % policyName)

    return role['Arn']


def enable_cloud_trail(bucket, name):
    """Create and enable cloud trail if it does not exist already."""
    cloudtrail = boto3.client('cloudtrail')

    try:
        cloudtrail.create_trail(
            Name=name,
            S3BucketName=bucket,
            IncludeGlobalServiceEvents=True,
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True,
        )

        cloudtrail.start_logging(Name=name)
        print("Cloud trail enabled and logging.")
    except ClientError as e:
        if 'TrailAlreadyExists' in e.message:
            print('Trail already exists')

    return name


def upload_file(bucket, filename):
    """Upload file to given s3 bucket and overwrite if exists."""
    client = boto3.client('s3')

    with open(filename, 'rb') as data:
        client.upload_fileobj(data, bucket, filename)

    print("Cloud formation template with name %s uploaded." % filename)
    return filename


def cloud_formation(bucket, template, function, region, role):
    """Deploy cloud formation to given region."""
    client = boto3.client('cloudformation', region_name=region)

    url = 'https://s3.amazonaws.com/{bucket}/{template}'.format(bucket=bucket,
                                                            template=template)
    response = client.create_stack(
        StackName='AutoTagResources',
        TemplateURL=url,
        DisableRollback=False,
        Capabilities=['CAPABILITY_IAM'],
        Parameters=[
            {'ParameterKey': 'LambdaRoleArn', 'Para  meterValue': role},
            {'ParameterKey': 'LambdaFunction', 'ParameterValue': function},
        ]
    )

    print("Successfully configured auto tag in %s" % region)


def get_available_regions(service):
    """List available regions for service."""
    s = boto3.session.Session()
    return s.get_available_regions(service)


if __name__ == "__main__":
    rolePolicy = {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Sid" : "Stmt1458923097000",
          "Effect" : "Allow",
          "Action" : ["cloudtrail:LookupEvents"],
          "Resource" : ["*"]
        },
        {
          "Sid" : "Stmt1458923121000",
          "Effect" : "Allow",
          "Action" : [
            "ec2:CreateTags",
            "ec2:Describe*",
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ],
          "Resource" : ["*"]
        }
      ]
    }

    # Create role with inline policy
    role = create_role(roleName='LambdaAutoTagRole',
                       policyName='LambdaAutoTagPolicy',
                       rolePolicy=rolePolicy)

    # Create bucket
    bucket = create_bucket(name='autotag-resources')

    # Enable cloud trail for all regions
    cloud_trail = enable_cloud_trail(bucket, 'AutoTagResources')

    # Upload cloud formation template to s3 bucket
    template = upload_file(bucket, 'AutoTag.template')

    # Read lambda function
    with open('autotag.py', 'rb') as f:
        function = f.read()

    # Deploy cloud formation to all lambda available regions
    for region in get_available_regions('lamdba'):
        cloud_formation(bucket, template, function, region, role)

