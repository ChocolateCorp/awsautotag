# -*- coding: utf-8 -*-

import boto3
import json
import random

from constants import CHARS, POLICY
from datetime import datetime


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

    policy = POLICY.format(bucket=bucket, account=get_account_id())
    response = s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(json.loads(policy))
    )

    print("S3 bucket named %s created and policy attached." % bucket)
    return bucket


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


def upload_template(template):
    client = boto3.client('s3')

    key = '{date}-{name}'.format(date=datetime.now().strftime('%Y%m%d'),
                                 name=template)
    with open(template, 'rb') as data:
        client.upload_fileobj(data, bucket, key)

    print("Cloud formation template with name %s uploaded." % key)
    return key


def cloud_formation(bucket, template):
    client = boto3.client('cloudformation')

    url = 'https://s3.amazonaws.com/{bucket}/{template}'.format(bucket=bucket,
                                                            template=template)
    response = client.create_stack(
        StackName='AutoTagResources',
        TemplateURL=url,
        DisableRollback=False,
        Capabilities=['CAPABILITY_IAM'],
    )

    print("Successfully configured cloud auto tag env.")


if __name__ == "__main__":
    bucket = create_bucket()
    cloud_trail = enable_cloud_trail(bucket)
    template = upload_template('AutoTag.template')
    cloud_formation(bucket, template)

