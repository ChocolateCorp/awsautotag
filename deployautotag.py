# -*- coding: utf-8 -*-

import boto3
import json
import random

from datetime import datetime


CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'

BUCKET_POLICY = """{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "AWSCloudTrailAclCheck20150319",
      "Effect": "Allow",
      "Principal": {{"Service": "cloudtrail.amazonaws.com"}},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::{bucket}"
    }},
    {{
      "Sid": "AWSCloudTrailWrite20150319",
      "Effect": "Allow",
      "Principal": {{"Service": "cloudtrail.amazonaws.com"}},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::{bucket}/AWSLogs/{account}/*",
      "Condition": {{"StringEquals": {{"s3:x-amz-acl":
          "bucket-owner-full-control"}}
      }}
    }}
  ]
}}"""

ROLE_ASSUME_POLICY = """{
  "Version" : "2012-10-17",
  "Statement" : [
    {
      "Effect" : "Allow",
      "Principal" : {"Service" : ["lambda.amazonaws.com"]},
      "Action" : ["sts:AssumeRole"]
    }
  ]
}"""

ROLE_POLICY = """{
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
}"""

def get_random_string(length=12, allowed_chars=CHARS):
        return ''.join(random.choice(allowed_chars) for _ in range(length))


def get_account_id():
    return boto3.client('sts').get_caller_identity().get('Account')


def create_bucket():
    s3 = boto3.client('s3')
    bucket = 'autotag-%s-resources' % get_random_string()

    response = s3.create_bucket(
        Bucket=bucket
    )

    policy = BUCKET_POLICY.format(bucket=bucket, account=get_account_id())
    response = s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(json.loads(policy))
    )

    print("S3 bucket named %s created and policy attached." % bucket)
    return bucket


def create_role():
    iam = boto3.client('iam')
    role_name = 'LambdaAutoTagRole'
    policy_name = 'LambdaAutoTagResourcesPolicy'

    response = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=ROLE_ASSUME_POLICY
    )
    role_arn = response['Role']['Arn']
    print('Created role %s' % role_name)

    response = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=ROLE_POLICY
    )
    print('Created policy %s' % policy_name)

    response = iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn=response['Policy']['Arn']
    )
    print('Attached role policy')
    return role_arn


def enable_cloud_trail(bucket):
    cloudtrail = boto3.client('cloudtrail')

    name = 'AutoTagResources'
    response = cloudtrail.create_trail(
            Name=name,
            S3BucketName=bucket,
            IncludeGlobalServiceEvents=True,
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True,
    )

    response = cloudtrail.start_logging(
            Name=name
    )

    print("Cloud trail enabled and logging.")
    return name


def upload_file(bucket, filename):
    client = boto3.client('s3')

    with open(filename, 'rb') as data:
        client.upload_fileobj(data, bucket, filename)

    print("Cloud formation template with name %s uploaded." % filename)
    return filename


def cloud_formation(bucket, template, function, region, role):
    client = boto3.client('cloudformation', region_name=region)

    url = 'https://s3.amazonaws.com/{bucket}/{template}'.format(bucket=bucket,
                                                            template=template)
    response = client.create_stack(
        StackName='AutoTagResources',
        TemplateURL=url,
        DisableRollback=False,
        Capabilities=['CAPABILITY_IAM'],
        Parameters=[
            {'ParameterKey': 'LambdaRoleArn', 'ParameterValue': role},
            {'ParameterKey': 'LambdaFunction', 'ParameterValue': function},
        ]
    )

    print("Successfully configured auto tag in %s" % region)


def get_available_regions(service):
    # List available regions for service
    s = boto3.session.Session()
    return s.get_available_regions(service)


if __name__ == "__main__":
    role = create_role()
    bucket = create_bucket()
    cloud_trail = enable_cloud_trail(bucket)
    template = upload_file(bucket, 'AutoTag.template')

    with open('autotag.py', 'rb') as f:
        function = f.read()

    for region in ['us-west-1',]:
        cloud_formation(bucket, template, function, region, role)

