import boto3
import json


MAX_RESULTS = 50
cloud_trail = boto3.client('cloudtrail')
ec2 = boto3.resource('ec2')
event_triggers = [
    'CreateVolume',
    'RunInstances',
    'CreateImage',
    'CreateSnapshot'
]

results_left = True
token = None
while results_left:
    if token:
        events = cloud_trail.lookup_events(
            MaxResults=MAX_RESULTS,
            NextToken=token
        )
    else:
        events = cloud_trail.lookup_events(
            MaxResults=MAX_RESULTS
        )

    if 'NextToken' in events:
        token = events['NextToken']
    else:
        token = None
        results_left = False

    for event in events['Events']:
        resources = []

        if event['EventName'] in event_triggers:
            event_name = event['EventName']
            detail = json.loads(event['CloudTrailEvent'])

            region = detail['awsRegion']
            arn = detail['userIdentity']['arn']
            principal = detail['userIdentity']['principalId']
            userType = detail['userIdentity']['type']

            if userType == 'IAMUser':
                user = detail['userIdentity']['userName']

            elif userType == 'Root':
                user = principal

            else:
                user = principal.split(':')[-1]

            if event_name == 'CreateVolume':
                resources.append(
                    {'id': detail['responseElements']['volumeId'],
                     'type': 'vol',
                     'region': region,
                     'user': user,
                     'principal': principal}
                )

            elif event_name == 'RunInstances':
                items = detail['responseElements']['instancesSet']['items']
                for item in items:
                    resources.append(
                        {'id': item['instanceId'],
                         'type': 'instance',
                         'region': region,
                         'user': user,
                         'principal': principal}
                    )

            elif event_name == 'CreateImage':
                resources.append(
                    {'id': detail['responseElements']['imageId'],
                     'type': 'image',
                     'region': region,
                     'user': user,
                     'principal': principal}
                )

            elif event_name == 'CreateSnapshot':
                resources.append(
                    {'id': detail['responseElements']['snapshotId'],
                     'type': 'snapshot',
                     'region': region,
                     'user': user,
                     'principal': principal}
                )

            if resources:
                print(resources)
