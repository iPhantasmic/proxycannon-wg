#!/usr/bin/env python3

import boto3
import sys
import os
import subprocess
import argparse
import datetime
import time
import re
import signal
import requests

# check Python version is >= 3.7 for boto3 support
if sys.version_info.major != 3 or sys.version_info.minor < 7:
    print("This script needs Python >= 3.7. You are running Python %s" % sys.version)
    exit()

########################################################################################################################
# Global Variables and Config
########################################################################################################################
# Data structure for list of exit_nodes
# exit_nodes[exit_node_id] = {'cloud_id': instance.id, 'pub_ip': instance.ip_address, 'priv_ip': instance.priv_ip_addr}
exit_nodes = {}
new_exit_nodes = {}

# AWS Resource Definitions
name = "exit-node"
keyName = "proxycannon"
securityGroup = "exit-node-sec-group"
security_group_id = ""
ec2_conn = None
MAC = requests.get("http://169.254.169.254/latest/meta-data/network/interfaces/macs/").text
subnet_id = requests.get("http://169.254.169.254/latest/meta-data/network/interfaces/macs/" + MAC + "/subnet-id").text

# Last ran command for routing management
route_cmd = ""
# Global variable for preventing race condition after SIGINT
isRunning = True


########################################################################################################################
# Custom print()
########################################################################################################################
def error(msg):
    print("[!!!] " + str(msg))


def success(msg):
    print("[*] " + str(msg))


def warning(msg):
    print("[!] " + str(msg))


def debug(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("[i] " + str(timestamp) + " : " + str(msg))


########################################################################################################################
# Handle SIGINT & Teardown
########################################################################################################################
def cleanup(proxy=None, cannon=None):
    global exit_nodes
    global ec2_conn
    global security_group_id
    global isRunning
    debug("\nSIGINT received, terminating IP rotation...")
    isRunning = False
    ####################################################################################################################
    # Teardown Control-Server Routing
    ####################################################################################################################

    del_routes(exit_nodes)
    if len(new_exit_nodes) != 0:
        del_routes(new_exit_nodes)

    ####################################################################################################################
    # Teardown Cloud Resources
    ####################################################################################################################

    # Destroy EC2 instances
    waiter = ec2_conn.get_waiter('instance_terminated')
    terminate_exit_nodes(exit_nodes)
    waiter.wait(InstanceIds=[node["cloud_id"] for node in exit_nodes], WaiterConfig={'MaxAttempts': 20})

    if len(new_exit_nodes) != 0:
        terminate_exit_nodes(new_exit_nodes)
        waiter.wait(InstanceIds=[node["cloud_id"] for node in new_exit_nodes], WaiterConfig={'MaxAttempts': 20})

    # Destroy Security Group
    try:
        response = ec2_conn.delete_security_group(GroupId=security_group_id)
        debug("%s (exit-node-sec-group) deleted!" % security_group_id)
    except Exception as e:
        error("Failed to delete Security Group because: %s" % e)

    ec2_conn.close()
    success("Thanks for using proxycannon-wg, see you again real soon!")


########################################################################################################################
# System and Program Arguments
########################################################################################################################
parser = argparse.ArgumentParser()
parser.add_argument('-id', '--image-id', nargs='?', default='ami-04d9e855d716f9c99',
                    help="Amazon AMI image ID.  Example: ami-04d9e855d716f9c99. If not set, ami-04d9e855d716f9c99.")
parser.add_argument('-t', '--image-type', nargs='?', default='t2.nano',
                    help="Amazon AMI image type Example: t2.nano. If not set, defaults to t2.nano.")
parser.add_argument('-r', '--region', nargs='?', default='ap-southeast-1',
                    help="Select the region: Example: ap-southeast-1. If not set, defaults to ap-southeast-1.")
parser.add_argument('-i', nargs='?', type=int, default=5,
                    help="Sets the interval (in minutes) for IP set rotation. If not set, defaults to 5 minutes.")
parser.add_argument('num_of_instances', type=int, help="The number of exit nodes you'd like to launch.")
args = parser.parse_args()


########################################################################################################################
# Sanity Checks and Setup
########################################################################################################################
# Check if running as root
debug("Checking for root / sudo privileges")
if os.geteuid() != 0:
    homeDir = os.getenv("HOME")
    warning("You are not running as root!")
else:
    homeDir = os.system("getent passwd $SUDO_USER | cut -d: -f6")

# Check args
if args.num_of_instances < 1:
    error("You need to launch at least 1 instance!")
    exit()

# Check for AWS Credentials file
aws_creds = homeDir + "/.aws/credentials"
if os.path.isfile(aws_creds):
    for line in open(aws_creds):
        pattern = re.findall("^aws_access_key_id = (.*)\n", line, re.DOTALL)
        if pattern:
            aws_access_key_id = pattern[0]
        pattern = re.findall("^aws_secret_access_key = (.*)\n", line, re.DOTALL)
        if pattern:
            aws_secret_access_key = pattern[0]
else:
    error("AWS credential file does not exist")
    exit()

# Define SIGINT Handler
signal.signal(signal.SIGINT, cleanup)


########################################################################################################################
# The Magic
########################################################################################################################
def connect_to_ec2():
    """Returns boto3 client object after connecting to Amazon EC2"""
    # boto3.set_stream_logger('botocore')  # for debugging purposes
    conn = None
    try:
        debug("Connecting to Amazon EC2")
        conn = boto3.client("ec2", region_name="ap-southeast-1", aws_access_key_id=aws_access_key_id,
                            aws_secret_access_key=aws_secret_access_key)
    except Exception as e:
        error("Failed to connect to Amazon EC2 because: %s" % e)
        exit()

    return conn


def create_sec_group():
    """Creates security group for the Exit Nodes with allow-all FW and returns SG ID"""
    global ec2_conn
    response = None
    sg_id = None

    try:
        response = ec2_conn.describe_vpcs()
    except Exception as e:
        error("Failed to retrieve VPC ID because: %s" % e)
    vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')

    try:
        sg = ec2_conn.create_security_group(GroupName=securityGroup,
                                            Description="SG for proxycannon exit nodes",
                                            VpcId=vpc_id)
        sg_id = sg['GroupId']
        response = ec2_conn.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'FromPort': 0,
                    'ToPort': 0,
                    'IpProtocol': '-1',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        )
    except Exception as e:
        error("Creating Amazon Security Group failed because: %s" % e)
        exit()

    success('Security Group %s created in %s' % (sg_id, vpc_id))
    return sg_id


def create_exit_nodes(num: int) -> list:
    """Creates and returns list of Exit Nodes (and corresponding management data)"""
    global ec2_conn
    global security_group_id
    global subnet_id

    # creates instances with node setup script in UserData
    reservations = ec2_conn.run_instances(
        ImageId=args.image_id,
        MinCount=num,
        MaxCount=num,
        InstanceType=args.image_type,
        KeyName=keyName,
        SecurityGroupIds=[security_group_id],
        SubnetId=subnet_id,
        TagSpecifications=[{'ResourceType': 'instance', 'Tags': [{'Key': 'Name', "Value": "exit-node"}]}],
        UserData="#!/bin/bash\nsudo sysctl -w net.ipv4.ip_forward=1\nsudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
    )

    instances = reservations["Instances"]
    instance_ids = list()
    for instance in instances:
        instance_ids.append(instance["InstanceId"])
        try:
            # Set SourceDestCheck to False for Exit Nodes to route packets properly
            ec2_conn.modify_instance_attribute(InstanceId=instance['InstanceId'], SourceDestCheck={'Value': False})
            success("Successfully set SourceDestCheck to False for Exit Nodes!")
        except Exception as e:
            error("Setting SourceDestCheck to False for %s failed because: %s" % (instance["InstanceId"], e))

    # wait for instances to be running
    debug("Created the following instances: " + str(instance_ids))
    waiter = ec2_conn.get_waiter('instance_running')
    waiter.wait(InstanceIds=instance_ids, WaiterConfig={'MaxAttempts': 20})  # waits for up to 5 mins

    # store data of instances for resource management
    new_nodes = list()
    response = ec2_conn.describe_instances(InstanceIds=instance_ids)
    for instance in response["Reservations"][0]["Instances"]:
        new_nodes.append({"cloud_id": instance["InstanceId"], "pub_ip": instance["PublicIpAddress"],
                          "priv_ip": instance["PrivateIpAddress"]})

    return new_nodes


def terminate_exit_nodes(nodes: list):
    """Terminates the Exit Nodes with provided InstanceId in list()"""
    global ec2_conn

    instance_ids = list()
    for node in nodes:
        instance_ids.append(node["cloud_id"])

    debug("Terminating the following instances: " + str(instance_ids))
    try:
        response = ec2_conn.terminate_instances(InstanceIds=instance_ids)
        success("Instances have been terminated!")
    except Exception as e:
        error("Terminating instances failed because: %s. Consider terminating manually!" % e)


def add_routes(nodes: list):
    """Updates ip route to utilise new Exit Nodes"""
    global route_cmd

    if len(route_cmd) == 0:
        route_cmd = "sudo ip route add default proto static scope global table loadb "
    else:
        route_cmd = "sudo ip route replace default proto static scope global table loadb "

    for node in nodes:
        route_cmd += "nexthop via " + node["priv_ip"] + " weight 100 "

    os.system(route_cmd)
    debug("Command ran: \"" + route_cmd + "\"")


def del_routes(nodes: list):
    """Clears ip route for loadb table"""
    global route_cmd

    if len(route_cmd) == 0:
        warning("Attempted route deletion with no last ran route_cmd.")
    route_cmd = "sudo ip route del default proto static scope global table loadb "

    for node in nodes:
        route_cmd += "nexthop via " + node["priv_ip"] + " weight 100 "

    os.system(route_cmd)
    debug("Command ran: \"" + route_cmd + "\"")


def main():
    """Entrypoint and IP rotation logic"""
    global ec2_conn
    global security_group_id
    global exit_nodes
    global new_exit_nodes

    # check if IP forwarding and FIB multi-path routing is enabled, else exit()
    result = subprocess.run(["cat", "/proc/sys/net/ipv4/ip_forward"], stdout=subprocess.PIPE).stdout.decode("utf-8")
    if result != "1\n":
        warning("IPv4 Forwarding not enabled!!! Enabling now...")
        os.system("echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf")
        os.system("sudo sysctl -p")
        debug("IPv4 Forwarding has been enabled!")
    else:
        success("IPv4 Forwarding is already enabled!")

    result = subprocess.run(["cat", "/proc/sys/net/ipv4/fib_multipath_hash_policy"], stdout=subprocess.PIPE).stdout.decode("utf-8")
    if result != "1\n":
        warning("fib_multipath_hash_policy not enabled!!! Enabling now...")
        os.system("sudo sysctl -w net.ipv4.fib_multipath_hash_policy=1")
        debug("fib_multipath_hash_policy has been enabled!")
    else:
        success("fib_multipath_hash_policy is already enabled!")

    ec2_conn = connect_to_ec2()
    security_group_id = create_sec_group()
    exit_nodes = create_exit_nodes(args.num_of_instances)
    add_routes(exit_nodes)

    while True:
        if not isRunning:
            exit()
        # sleeps for specified minutes before next IP set rotation
        time.sleep(args.i * 60)
        debug("Starting an IP rotation now!")
        new_exit_nodes = create_exit_nodes(args.num_of_instances)
        # once new nodes ready (ensure minimal downtime):
        del_routes(exit_nodes)
        add_routes(new_exit_nodes)
        terminate_exit_nodes(exit_nodes)
        exit_nodes = new_exit_nodes.copy()
        new_exit_nodes.clear()
        debug("Waiting for next IP rotation!")


if __name__ == "__main__":
    main()
