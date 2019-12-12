#!/usr/bin/python

'''
ex. 
Update Record with Autoscale Group Name
python dns_controller.py --member_type public --autoscale_group test-dns-appAutoscaleGroup-1XZQ28FJWI14A --record www.aws.demo.f5example.com --zone_id Z2TDVMJCP88JBN

Update Record via Tag:
python dns_controller.py --member_type public --tag_key aws:autoscaling:groupName --tag_value test-dns-appAutoscaleGroup-1XZQ28FJWI14A --record www.aws.demo.f5example.com --zone_id Z2TDVMJCP88JBN 

Update GTM Pool via Autoscale Group Name
python dns_controller.py --member_type "public" \
    --autoscale_group "test-dns-appAutoscaleGroup-1XZQ28FJWI14A" \
    --gtm_api_addr "10.11.6.1" \
    --gtm_api_port "443" \
    --gtm_username "admin" \
    --gtm_password "XXXXXXXXXXXXXXX" \
    --gtm_partition "Common" \
    --gtm_datacenter "AWS-WEST-2" \
    --gtm_generic_host "gh_aws_us_west_2_auto" \
    --gtm_vs_port "http" \
    --gtm_vs_monitor "tcp" \
    --gtm_pool_name "autoscale_pool_aws_us_west_2" \
    --gtm_pool_monitor "demo-app-http" \



# From Lambda
# Exampe SNS Message
{
    "Progress": 50,
    "AccountId": "XXXXXXXXXXXXXXX",
    "Description": "Terminating EC2 instance: i-0dc044595776dad84",
    "RequestId": "76b837cd-f461-4c5f-bab2-2b750863b760",
    "EndTime": "2017-10-28T00:04:29.243Z",
    "AutoScalingGroupARN": "arn:aws:autoscaling:us-west-2:XXXXXXXXXXX:autoScalingGroup:860cc0d1-5450-4f37-80d4-a84ac04619c9:autoScalingGroupName/test-lambda-appAutoscaleGroup-1JS082N7OZT2",
    "ActivityId": "76b837cd-f461-4c5f-bab2-2b750863b760",
    "StartTime": "2017-10-28T00:03:27.260Z",
    "Service": "AWS Auto Scaling",
    "Time": "2017-10-28T00:04:29.243Z",
    "EC2InstanceId": "i-0dc044595776dad84",
    "StatusCode": "InProgress",
    "StatusMessage": "",
    "Details": {
        "Subnet ID": "subnet-b8441add",
        "Availability Zone": "us-west-2b"
    },
    "AutoScalingGroupName": "test-lambda-appAutoscaleGroup-1JS082N7OZT2",
    "Cause": "At 2017-10-28T00:03:15Z a user request update of AutoScalingGroup constraints to min: 0, max: 0, desired: 0 changing the desired capacity from 2 to 0.  At 2017-10-28T00:03:27Z an instance was taken out of service in response to a difference between desired and actual capacity, shrinking the capacity from 2 to 0.  At 2017-10-28T00:03:27Z instance i-0dc044595776dad84 was selected for termination.  At 2017-10-28T00:03:27Z instance i-03f64f3d8ef7fffe9 was selected for termination.",
    "Event": "autoscaling:EC2_INSTANCE_TERMINATE"
}


Ref:
https://iangilham.com/2016/03/22/Sns-trigger-lambda-via-cloudformation.html

'''

from __future__ import print_function




import os
import sys
import time
from optparse import OptionParser
from datetime import datetime
import subprocess

# Add any custom packages not in default lambda container
sys.path.insert(0, "./vendored")

from botocore.exceptions import ClientError
import boto3
import json

import requests
requests.packages.urllib3.disable_warnings()

import logging
log = logging.getLogger()
log.setLevel(logging.DEBUG)


class DatetimeEncoder(json.JSONEncoder):
    def default(self, obj):
        try:
            return super(DatetimeEncoder, obj).default(obj)
        except TypeError:
            return str(obj)


class AutoscaleGroup:
    
    """Object to Return Autoscale Group Members via name or Tag"""

    def __init__(self, region):

        self.region = region
        self.asg_client = boto3.client('autoscaling', region_name=self.region )
        self.ec2_client = boto3.client('ec2', region_name=self.region )

        self.member_type = None
        self.asg_name = None
        self.tags = None
        self.debug_logging = None
        # self.member_ips 

    def get_address_mappings(self):

        # instance_id_list = []
        # private_ip_list = []       
        # public_ip_list = []
        members = {}

        if self.asg_name:

            asg_active_num_instances = 0

            auto_scaling_group_response = self.asg_client.describe_auto_scaling_groups(
                AutoScalingGroupNames=[
                    self.asg_name
                ]
            )

            if self.debug_logging == True:
                print ("auto_scaling_group_response: " + str(auto_scaling_group_response) )

            if auto_scaling_group_response:

                asg_active_num_instances = len(auto_scaling_group_response["AutoScalingGroups"][0]['Instances'])
                # if debug_logging == True:
                #     print "asg_active_num_instances: "  +  str(asg_active_num_instances)

                if asg_active_num_instances > 0:
                    for i in range(0,asg_active_num_instances):
                        #print auto_scaling_group_response["AutoScalingGroups"][0]['Instances'][i]
                        instance_id = auto_scaling_group_response["AutoScalingGroups"][0]['Instances'][i]["InstanceId"]
                        #instance_id_list.append(auto_scaling_group_response["AutoScalingGroups"][0]['Instances'][i]["InstanceId"])
                        instance_id_response = self.ec2_client.describe_instances(
                                InstanceIds=[ instance_id ]
                        )
                        private_ip = instance_id_response["Reservations"][0]["Instances"][0]["PrivateIpAddress"]
                        public_ip = instance_id_response["Reservations"][0]["Instances"][0]["PublicIpAddress"]

                        if self.debug_logging == True:
                            print ("instance_id: " + instance_id)
                            print ("private_ip: " + private_ip)
                            print ("public_ip: " + public_ip)

                        if self.member_type == "public":
                            members[instance_id] = public_ip
                        else:
                            members[instance_id] = private_ip


        if self.tags:

            tag_key = self.tags['tag_key']
            tag_value = self.tags['tag_value']

            if self.debug_logging == True:            
                print ("Tag Filter : " + str(tag_value))

            # filters = [{ 'Name': 'tag:Name','Values': [tag_value] }]
            filters = [{  
                'Name': 'tag:' + tag_key,
                'Values': [tag_value]
                }]

            reservations_response = self.ec2_client.describe_instances(Filters=filters)

            if self.debug_logging == True:   
                print (json.dumps(reservations_response['Reservations'], cls=DatetimeEncoder, indent=2))

            for reservation in reservations_response['Reservations']:

                instances = reservation["Instances"]

                for instance in instances:
                    # if debug_logging == True:  
                    #     print instance
                    if instance['State']['Name'] == "running":
                        #instance_id_list.append(instance["InstanceId"])
                        if instance.get("PrivateIpAddress"):
                            if self.member_type == "private":
                                members[instance["InstanceId"]] = instance["PrivateIpAddress"]
                                #private_ip_list.append(instance["PrivateIpAddress"])
                            # if debug_logging == True:
                            #         print instance["InstanceId"] + ": " + instance["PrivateIpAddress"]
                        if instance.get("PublicIpAddress"):
                            if self.member_type == "public":
                                members[instance["InstanceId"]] = instance["PublicIpAddress"]
                            #public_ip_list.append(instance["PublicIpAddress"])
                            # if debug_logging == True:   
                            #         print instance["InstanceId"] + ": " + instance["PublicIpAddress"]

        if self.debug_logging == True:
            print ("members: "  + str(members) )

        return members


class Route53Record: 
    """Object to Manage Route53 Record"""

    def __init__(self, region):
        self.region = region
        self.route53_client = boto3.client('route53', self.region)

        self.zone_id = None
        self.record = None
        # self.member_list = get_record()
        self.debug_logging = None

    def create_health_check ( self, member, port , monitor_type ):
        '''
        generally expect one member in form of
        { 
            "instance_id": "id-abasdfsdf", 
            "address": "1.1.1.1",
        }

        {
            "HealthCheckConfig": {
                "IPAddress": "52.10.128.69",
                "EnableSNI": false,
                "Inverted": false,
                "MeasureLatency": false,
                "RequestInterval": 30,
                "Type": "HTTP",
                "Port": 80,
                "FailureThreshold": 3
            },
            "HealthCheckVersion": 5,
            "Id": "c92812a3-7117-4141-826e-cc2c074f6383"
        },
        '''
        enable_sni = False
        monitor_type = monitor_type
        if monitor_type == "HTTPS":
            enable_sni = True

        resp = ""
        try:
            resp = self.route53_client.create_health_check(
                    CallerReference=member['instance_id'],
                    HealthCheckConfig={
                        'IPAddress': member['address'],
                        'Port': int(port),
                        'Type': monitor_type,
                        'RequestInterval': 30,
                        'FailureThreshold': 3,
                        'MeasureLatency': False,
                        'Inverted': False,
                        'EnableSNI': enable_sni
                    }
            )
        except Exception, ex:
            print ("Failed to create Health Check: An exception of type " + type(ex).__name__ + \
                                    " with message " + str(sys.exc_info()[1]) )

        if self.debug_logging == True:  
            print (resp)

        if resp and resp['ResponseMetadata']['HTTPStatusCode'] == 200|201:

            health_check_id = resp['HealthCheck']['Id']
            # print ("Health Check Create Successfull. ID: " + health_check_id )
            # Tag Health Check with Instnace Id
            resp = self.route53_client.change_tags_for_resource(
                        ResourceType='healthcheck',
                        ResourceId=health_check_id,
                        AddTags=[
                            {
                                'Key': 'Name',
                                'Value': member['instance_id']
                            },
                            {
                                'Key': 'record',
                                'Value': self.record
                            },
                            {
                                'Key': 'zone_id',
                                'Value': self.zone_id
                            },
                            {
                                'Key': 'region',
                                'Value': self.region
                            }
                        ]
                    )

            return health_check_id


    def create_multivalue_record (self, member, health_check_id ):

        '''
        generally expect one member in form of
        { 
            "instance_id": "id-abasdfsdf", 
            "address": "1.1.1.1"
        }

        '''
        # Can create mulitple IPs for single A record although 
        # won't use it that way
        records = []
        records.append({'Value': member['address'] })

        record_set = {
          "Comment": "Add Member to Autoscale Group",
          "Changes": [
            {
              "Action": "UPSERT",
              "ResourceRecordSet": {
                "Name": self.record,
                "Type": "A",
                "TTL": 30,
                "MultiValueAnswer": True,
                "SetIdentifier": member['instance_id'],
                "ResourceRecords": records,
                "HealthCheckId": health_check_id
              }
            }
          ]
        }

        if self.debug_logging == True:
            print ("json_payload: " + str(record_set))

        resp = ""
        try:
            resp = self.route53_client.change_resource_record_sets(
                    HostedZoneId=self.zone_id,
                    ChangeBatch=record_set
                   )
        except Exception, ex:
            print ("Failed to Add Virtual Servers to Route53 record: An exception of type " + type(ex).__name__ + \
                                    " with message " + str(sys.exc_info()[1]) )
        if self.debug_logging == True:  
            print (resp)
        if resp['ResponseMetadata']['HTTPStatusCode'] in [ 200 , 201 ]:
            print ("Update Successfull")
            return resp


    def list_records (self):
        '''
        ### TODO: Need to add paging if > 100 records
        '''

        resp = ""
        try:
            resp = self.route53_client.list_resource_record_sets(
                    HostedZoneId=self.zone_id,
                    StartRecordName=self.record,
                    StartRecordType='A'
            )
        except Exception, ex:
            print ("Failed to list records: An exception of type " + type(ex).__name__ + \
                                    " with message " + str(sys.exc_info()[1]) )
        if self.debug_logging == True:  
            print (resp)

        if resp and resp['ResponseMetadata']['HTTPStatusCode'] in [ 200, 201 ]:
            return resp['ResourceRecordSets']

    def delete_health_check (self, health_check_id ):


        resp = ""
        try:
            resp = self.route53_client.delete_health_check( HealthCheckId=health_check_id )
        except Exception, ex:
            print ("Failed to Delete Health Check record: An exception of type " + type(ex).__name__ + \
                                    " with message " + str(sys.exc_info()[1]) )

        if self.debug_logging == True:  
            print (resp)

        if resp and resp['ResponseMetadata']['HTTPStatusCode'] in [ 200 , 201 ]:
            print ("Update Successfull")
            return resp
        else:
            return false

    def delete_record (self, instance_id ):

        records = self.list_records()
        health_check_id = ""
        record_to_delete = None
        delete_record = False
        delete_health_check = False

        for record in records:
            if 'SetIdentifier' in record:
                if record['SetIdentifier'] == instance_id:
                    record_to_delete = record
                    print (record)
                    health_check_id = record['HealthCheckId']
                    print ( "Health Check for " + instance_id + " = " + health_check_id )

        record_set = {
          "Comment": "Delete Member From Autoscale Group",
          "Changes": [
            {
              "Action": "DELETE",
              "ResourceRecordSet": record_to_delete
            }
          ]
        }

        if self.debug_logging == True:
            print ("json_payload: " + str(record_set))

        resp = ""
        try:
            resp = self.route53_client.change_resource_record_sets(
                    HostedZoneId=self.zone_id,
                    ChangeBatch=record_set
                   )
        except Exception, ex:
            print ("Failed to Delete Route53 record: An exception of type " + type(ex).__name__ + \
                                    " with message " + str(sys.exc_info()[1]) )

        if self.debug_logging == True:  
            print (resp)

        if resp and resp['ResponseMetadata']['HTTPStatusCode'] in [ 200 , 201 ]:
            print ("Delete Record Successfull")
            delete_record = True

        if health_check_id: 
                delete_health_check = self.delete_health_check ( health_check_id )
        
        if delete_record and delete_health_check:
            return True
        else:
            return False

class GTMPool:

    """Object to manage GTM Pool """

    def __init__(self, gtm_api_addr, gtm_api_port, gtm_username, gtm_password, partition):
        self.debug_logging = None
        self.base_url = "https://"  + str(gtm_api_addr) + ":" + str(gtm_api_port) + "/mgmt/tm/"
        self.gtm_username = gtm_username
        self.gtm_password = gtm_password
        self.partition = partition
        self.gtm_datacenter = None
        self.gtm_generic_host = None
        self.vs_port = None
        self.vs_monitor = None
        self.pool_name = None
        self.pool_monitor = None


    def update_server (self, vs_names, vs_addresses ):

        #https://support.f5.com/kb/en-us/solutions/public/14000/900/sol14924
        #modify gtm server gh_aws_us_east_1 virtual-servers replace-all-with { i-1bb68e8b { destination 54.88.137.211:https } }
        #curl -sk -u admin:admin -H "Content-Type: application/json" -X POST -d '{"name":"gh_aws_us_east_1","product":"generic-host","virtualServerDiscovery":"disabled","datacenter":"/Common/ITC - Seattle","addresses":[{"name":"1.1.1.1","deviceName":"gh_aws_us_east_1"}],"virtualServers": [{"name": "i-1bb68e8b", "destination": "54.88.137.211:443"}]}' https://10.11.6.1/mgmt/tm/gtm/server

        if self.debug_logging == True:
            print ("Updating GTM Generic Server...")
        finalURL = self.base_url + "gtm/server/~" + self.partition + "~" + str(self.gtm_generic_host)
        payload = {}
        payload['name'] = self.gtm_generic_host
        payload['partition'] = self.partition
        payload['product'] = "generic-host"
        payload['datacenter'] = "/" + self.partition + "/" + self.gtm_datacenter
        payload['virtualServerDiscovery'] = "disabled"
        payload['monitor'] = "/" + self.partition + "/" + self.vs_monitor

        virtual_servers = []
        for i in range(0,len(vs_names)):
            vs = {
                        'name' : str(vs_names[i]),
                        'destination' : str(vs_addresses[i]) + ":" + self.vs_port
                     }
            virtual_servers.append(vs)

        payload['virtualServers'] = virtual_servers

        json_payload = json.dumps(payload)

        if self.debug_logging == True:
            print ("json_payload: " + str(json_payload))

        resp = ""
        try:
            resp = requests.put(finalURL, auth=(self.gtm_username, self.gtm_password), verify=False, data=json_payload)
        except Exception, ex:
            print ("Failed to Add Virtual Servers: An exception of type " + type(ex).__name__ + \
                                    " with message " + str(sys.exc_info()[1]) )
            if self.debug_logging == True:
                print ("response code: " + resp.code)
                print ("response: " + resp.content)

    def update_pool (self, vs_names ):
        if self.debug_logging == True:  
            print ("Updating GTM Pool...")
        #modify gtm pool autoscale_pool_aws_us_east_1 members replace-all-with { gh_aws_us_east_1:i-1bb68e8b }

        finalURL = self.base_url + "gtm/pool/a/~" + self.partition + "~" + self.pool_name
        payload = {}
        payload['name'] = self.pool_name
        payload['partition'] = self.partition
        payload['loadBalancingMode'] = 'round-robin'
        payload['monitor'] = "/" + self.partition + "/" + self.pool_monitor
        members = [ { 'name' : '%s:%s' % (self.gtm_generic_host, member) } for member in vs_names ]
        payload['members'] = members

        json_payload = json.dumps(payload)

        if self.debug_logging == True:
            print ("json_payload: " + str(json_payload))

        resp = ""
        try:
            resp = requests.put(finalURL, auth=(self.gtm_username, self.gtm_password), verify=False, data=json_payload)
        except Exception, ex:
            print ("Failed to Add Virtual Servers to GTM Pool: An exception of type " + type(ex).__name__ + \
                                    " with message " + str(sys.exc_info()[1]) )
            if self.debug_logging == True:
                print ("response code: " + resp.code)
                print ("response: " + resp.content)


def lambda_handler(event, context):

    # print('boto3 version: %s' % boto3.__version__)

    # Grab Environmental Variables
    # Passed via Cloudformation or manually
    e = dict(os.environ.items())
    # print(e)

    print("Received event: " + json.dumps(event))

    message = event['Records'][0]['Sns']['Message']
    #print(message)
    json_message = json.loads(message)

    if 'region' in e:
        region = e['region']
    else:
        # ex. arn:aws:sns:us-west-2:452013943082:demo1-bigip-SNSTopic-1PCUSL1C6L91W:c4d61164-1e74-4176-bc59-8e130bd14151
        region = event['Records'][0]['EventSubscriptionArn'].split(':')[3]

    # Update Record with Public or Private
    if 'member_type' in e:
        member_type = e['member_type']
    else:
        #default to public
        member_type = "public"

    # If Passing Tags
    tag_key = ""
    tag_value = ""
    if 'tag_key' in e:
        tag_key = e['tag_key']
        tag_value = e['tag_value']

    # Get autoscale group to poll from SNS message itself
    asg_name = ""
    if 'AutoScalingGroupName' in json_message:
        asg_name = json_message['AutoScalingGroupName']
    
    if 'Event' in json_message:
        lifecycle_event = json_message['Event']
    
    if 'EC2InstanceId' in json_message: 
        ec2_id = json_message['EC2InstanceId']

    if 'Details' in json_message:
        details = json_message['Details']
        if 'Availability Zone' in details:
            az = details['Availability Zone']
            region = az[:-1]

    if (asg_name and tag_value):
        print ("Must use either autoscale group name OR tag filter")
        sys.exit()

    # If updating Route53 record
    zone_id = ""
    record = ""
    if 'zone_id' in e:
        zone_id = e['zone_id']
        record = e['record']

    # 
    if 'vs_port' in e:
        vs_port = e['vs_port']
    else:
        vs_port = "443"

    if 'vs_monitor' in e:
        vs_monitor = e['vs_monitor']
    elif vs_port == "80":
        # Safe assumption
        vs_monitor = "HTTP"
    else:
        # default to SSL
        vs_monitor = "HTTPS"

    # If updating GTM 
    # Variables like Admin Creds may be configured post-deploy
    # Access to GTM API required
    # This script better le
    gtm_api_addr = ""
    if 'gtm_api_addr' in e:

        gtm_api_addr = e['gtm_api_addr']
        gtm_api_port = e['gtm_api_port']
        gtm_username = e['gtm_username']
        gtm_password = e['gtm_password']
        gtm_partition = e['gtm_partition']

        gtm_datacenter = e['gtm_datacenter']
        gtm_generic_host = e['gtm_generic_host']
        vs_port = e['vs_port']
        vs_monitor = e['vs_monitor']
        pool_name = e['pool_name']
        pool_monitor = e['pool_monitor']


    # Finally poll Autoscale Group for members via Name or Tag
    asg = AutoscaleGroup(region=region)
    asg.member_type = member_type
    if asg_name:
        asg.asg_name = asg_name
    if tag_key:
        asg.tags = { "tag_key": tag_key, "tag_value": tag_value }
    members = asg.get_address_mappings()

    # member_list = ["1.1.1.1", "1.1.1.2"]
    print (members)

    # If updating Route53 Record
    if zone_id:
        r53 = Route53Record(region=region)
        r53.zone_id = zone_id
        r53.record = record
        r53.debug_logging = False

        # if lifecycle_event = "EC2_INSTANCE_LAUNCH":
        # There are couple of initial events
        # like "autoscaling:TEST_NOTIFICATION"
        # that don't see autoscaling:EC2_INSTANCE_LAUNCH for first instances
        # so do on every event for now. Effect is just poll ASG and populate 
        # records with whatever is there and should be idempotent
        for instance_id,address in members.items():
            member = { "instance_id": instance_id, "address": address }
            health_check_id = r53.create_health_check( member, vs_port, vs_monitor)
            if health_check_id:
                r53.create_multivalue_record( member, health_check_id )
        if lifecycle_event == "autoscaling:EC2_INSTANCE_TERMINATE":
            # cleanup record. If event is lost, could result in orphaned records/health checks.
            r53.delete_record( ec2_id )


    # If updating GTM Pool
    if gtm_api_addr:
        vs_names = []
        vs_addresses = []
        for instance_id,address in members.items():
            vs_names.append(instance_id)
            vs_addresses.append(address)
        gtm = GTMPool(gtm_api_addr, gtm_api_port, gtm_username, gtm_password, gtm_partition)
        gtm.gtm_datacenter = gtm_datacenter
        gtm.gtm_generic_host = gtm_generic_host
        gtm.vs_port = vs_port
        gtm.vs_monitor = vs_monitor
        gtm.pool_name = pool_name
        gtm.pool_monitor = pool_monitor
        gtm.update_server( vs_names, vs_addresses )
        gtm.update_pool( vs_names )



def main ():

    parser = OptionParser()
    parser.add_option("-r", "--region", action="store", type="string", dest="region", help="aws region" )
    parser.add_option("-u", "--gtm_username", action="store", type="string", dest="gtm_username", help="Big-IP GTM admin username" )
    parser.add_option("-p", "--gtm_password", action="store", type="string", dest="gtm_password", help="Big-IP GTM admin password" )
    parser.add_option("--gtm_api_addr", action="store", type="string", dest="gtm_api_addr", help="GTM Rest API Ip" )
    parser.add_option("--gtm_api_port", action="store", type="string", dest="gtm_api_port", help="GTM Rest API Port", default=443 )
    parser.add_option("--gtm_partition", action="store", type="string", dest="gtm_partition", help="GTM Partition" )
    parser.add_option("--gtm_datacenter", action="store", type="string", dest="gtm_datacenter", help="GTM Datacenter" )
    parser.add_option("--gtm_generic_host", action="store", type="string", dest="gtm_generic_host", help="GTM Generic Host" )
    parser.add_option("--gtm_vs_port", action="store", type="string", dest="gtm_vs_port", help="GTM Virtual Server Port" )
    parser.add_option("--gtm_vs_monitor", action="store", type="string", dest="gtm_vs_monitor", help="GTM Virtual Server Monitor" )
    parser.add_option("--gtm_pool_name", action="store", type="string", dest="gtm_pool_name", help="GTM Pool Name" )
    parser.add_option("--gtm_pool_monitor", action="store", type="string", dest="gtm_pool_monitor", help="GTM Pool Monitor" )
    parser.add_option("--member_type", action="store", type="string", dest="member_type", default="private", help="return private or public ip" )
    parser.add_option("-a", "--autoscale_group", action="store", type="string", dest="autoscale_group", help="bigip autoscale group name" )
    parser.add_option("--tag_key", action="store", type="string", dest="tag_key", help="tag key. ex. Name" )
    parser.add_option("--tag_value", action="store", type="string", dest="tag_value", help="uique tag value. ex. www*" )
    parser.add_option("--zone_id", action="store", type="string", dest="zone_id", help="Route 53 zone Id. ex. Z2TDVMJCP88JBN" )
    parser.add_option("--record", action="store", type="string", dest="record", help="ex. www.demo.f5example.com." )
    parser.add_option("--vs_port", action="store", type="int", dest="vs_port", help="Route 53 Monitor Port" )
    parser.add_option("--vs_monitor", action="store", type="string", dest="vs_monitor", help="Route 53 Monitor Type. ex. HTTP" )
    parser.add_option("--id_to_delete", action="store", type="string", dest="id_to_delete", help="instance_id to delete" )
    parser.add_option("-l", "--debug_logging", action="store", type="string", dest="debug_logging", default=False, help="debug logging: True or False" )

    (options, args) = parser.parse_args()

    debug_logging = False
    #setEnvironmentVariables()
    if options.debug_logging == "True":
        debug_logging = True

    region = options.region

    member_type = options.member_type

    # ASG Name or Tag
    asg_name = options.autoscale_group
    tag_key = options.tag_key
    tag_value = options.tag_value

    # Route 53
    if options.zone_id:
        zone_id = options.zone_id
        record = options.record
        vs_port = options.vs_port
        vs_monitor = options.vs_monitor
        id_to_delete = options.id_to_delete

    # If updating GTM Pool
    if options.gtm_api_addr:
        # GTM info
        gtm_username = options.gtm_username
        gtm_password = options.gtm_password
        gtm_api_addr = options.gtm_api_addr
        gtm_api_port = options.gtm_api_port
        gtm_partition = options.gtm_partition

        gtm_datacenter = options.gtm_datacenter
        gtm_generic_host = options.gtm_generic_host
        vs_port = options.gtm_vs_port
        vs_monitor = options.gtm_vs_monitor
        pool_name = options.gtm_pool_name
        pool_monitor = options.gtm_pool_monitor

    if (asg_name and tag_value):
        print ("Must use either autoscale group name OR tag filter")
        sys.exit()


    # Grab Address List from Autoscale Group
    asg = AutoscaleGroup(region=region)
    asg.member_type = member_type
    if asg_name:
        asg.asg_name = asg_name
    if tag_key:
        asg.tags = { "tag_key": tag_key, "tag_value": tag_value }
    members = asg.get_address_mappings()

    # member_list = ["1.1.1.1", "1.1.1.2"]
    print (members)

    # If updating Route53 Record
    if options.zone_id:
        r53 = Route53Record(region=region)
        r53.zone_id = zone_id
        r53.record = record
        r53.debug_logging = False
        for instance_id,address in members.items():
            member = { "instance_id": instance_id, "address": address }
            health_check_id = r53.create_health_check( member, vs_port, vs_monitor)
            if health_check_id:
                r53.create_multivalue_record(member, health_check_id )
        if id_to_delete:
            r53.delete_record( id_to_delete )

    # If updating GTM Pool
    if options.gtm_api_addr:
        vs_names = []
        vs_addresses = []
        for instance_id,address in members.items():
            vs_names.append(instance_id)
            vs_addresses.append(address)
        gtm = GTMPool(gtm_api_addr, gtm_api_port, gtm_username, gtm_password, gtm_partition)
        gtm.gtm_datacenter = gtm_datacenter
        gtm.gtm_generic_host = gtm_generic_host
        gtm.vs_port = vs_port
        gtm.vs_monitor = vs_monitor
        gtm.pool_name = pool_name
        gtm.pool_monitor = pool_monitor
        gtm.update_server( vs_names, vs_addresses )
        gtm.update_pool( vs_names )

if __name__ == '__main__':
    main()

