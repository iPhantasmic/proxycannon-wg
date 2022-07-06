#!/usr/bin/env python3

from google.cloud import compute_v1
import google.auth
import google.auth.exceptions
import google.api_core.exceptions
import sys
import os
import subprocess
import argparse
import datetime
import time
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
# exit_nodes[exit_node_id] = {'cloud_id': instance.name, 'priv_ip': instance.priv_ip_addr}
exit_nodes = []
new_exit_nodes = []

# GCP Resource Definitions
project = "proxycannon"
name = "exit-node"
template_name = "exit-nodes"
UBUNTU_IMAGE = compute_v1.ImagesClient().get_from_family(project="ubuntu-os-cloud",
                                                         family="ubuntu-2204-lts").self_link[38:]
SA_EMAIL = requests.get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
                        headers={"Metadata-Flavor": "Google"}).text
ZONE = requests.get("http://metadata.google.internal/computeMetadata/v1/instance/zone",
                    headers={"Metadata-Flavor": "Google"}).text.split("/")[-1]

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
def cleanup():
    global exit_nodes
    global isRunning
    debug("\nSIGINT received, terminating IP rotation...")
    isRunning = False
    ####################################################################################################################
    # Teardown Control-Server Routing
    ####################################################################################################################

    debug("Deleting local static routes...")
    del_routes(exit_nodes)
    if len(new_exit_nodes) != 0:
        del_routes(new_exit_nodes)

    ####################################################################################################################
    # Teardown Cloud Resources
    ####################################################################################################################

    # Destroy Managed Instance Group
    debug("Deleting exit-nodes Managed Instance Group...")
    command = ["gcloud", "compute", "instance-groups", "managed", "delete", "--zone=" + ZONE, "exit-nodes"]
    completed_process = subprocess.run(command, capture_output=True)
    if completed_process.returncode != 0:
        error("Terminating instances failed because: " + completed_process.stderr.decode("utf-8")
              + "\nConsider terminating manually!")

    success("Thanks for using proxycannon-wg, see you again real soon!")


########################################################################################################################
# System and Program Arguments
########################################################################################################################
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interval', nargs='?', type=int, default=5,
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

# Check for GCP Credentials
try:
    project_id = google.auth.default()[1]
except google.auth.exceptions.DefaultCredentialsError:
    print("[!!!] Failed to connect to GCP due to DefaultCredentialsError! Please set GOOGLE_APPLICATION_CREDENTIALS!")
    exit()

# Check if IP forwarding is enabled
result = subprocess.run(["cat", "/proc/sys/net/ipv4/ip_forward"], stdout=subprocess.PIPE).stdout.decode("utf-8")
if result != "1\n":
    warning("IPv4 Forwarding not enabled!!! Enabling now...")
    os.system("echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf")
    os.system("sudo sysctl -p")
    debug("IPv4 Forwarding has been enabled!")
else:
    success("IPv4 Forwarding is already enabled!")

# Check if fib_multipath_hash_policy is enabled
result = subprocess.run(["cat", "/proc/sys/net/ipv4/fib_multipath_hash_policy"], stdout=subprocess.PIPE).stdout.decode(
    "utf-8")
if result != "1\n":
    warning("fib_multipath_hash_policy not enabled!!! Enabling now...")
    os.system("sudo sysctl -w net.ipv4.fib_multipath_hash_policy=1")
    debug("fib_multipath_hash_policy has been enabled!")
else:
    success("fib_multipath_hash_policy is already enabled!")

# Check if loadb table is used
result = subprocess.run(["ip", "rule"], stdout=subprocess.PIPE).stdout.decode("utf-8")
if result.find("from 10.10.10.0/24 lookup loadb") == -1:
    warning("WireGuard subnet does not use loadb routing table!!! Adding now...")
    os.system("sudo ip rule add from 10.10.10.0/24 table loadb")
    debug("Added ip rule!")
else:
    success("loadb already used by WireGuard subnet!")

# Check if SNAT from ens4 is enabled
result = subprocess.run(["sudo", "iptables", "-t", "nat", "-S", "POSTROUTING"], stdout=subprocess.PIPE).stdout.decode(
    "utf-8")
if result.find("-A POSTROUTING -o ens4 -j MASQUERADE") == -1:
    warning("SNAT routing not enabled!!! Enabling now...")
    os.system("sudo iptables -t nat -A POSTROUTING -o ens4 -j MASQUERADE")
    debug("SNAT from ens4 has been enabled!")
else:
    success("SNAT routing is already enabled!")


# Define SIGINT Handler
signal.signal(signal.SIGINT, cleanup)


########################################################################################################################
# The Magic
########################################################################################################################
def create_instance_template():
    """Creates an instance template named exit-nodes"""
    global SA_EMAIL
    global UBUNTU_IMAGE
    global ZONE
    global template_name

    # fetch exit-node instance template
    completed_process = subprocess.run(["gcloud", "compute", "instance-templates", "describe", "exit-nodes"],
                                       capture_output=True)
    if completed_process.returncode != 0:
        # exit-node instance template does not exist
        debug("exit-node instance template not found, creating now!")
        command = ["gcloud", "compute", "instance-templates", "create", template_name, "--project=proxycannon",
                   "--machine-type=e2-micro", "--network-interface=network=default,network-tier=PREMIUM,address=",
                   "--metadata=startup-script=#!/bin/bash\nsudo sysctl -w net.ipv4.ip_forward=1\n" +
                   "sudo iptables -t nat -A POSTROUTING -o ens4 -j MASQUERADE",
                   "--can-ip-forward", "--maintenance-policy=MIGRATE", "--provisioning-model=STANDARD",
                   "--service-account=" + SA_EMAIL, "--scopes=https://www.googleapis.com/auth/devstorage.read_only," +
                   "https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring.write," +
                   "https://www.googleapis.com/auth/servicecontrol," +
                   "https://www.googleapis.com/auth/service.management.readonly," +
                   "https://www.googleapis.com/auth/trace.append",
                   "--create-disk=auto-delete=yes,boot=yes,device-name=exit-node," +
                   "image=" + UBUNTU_IMAGE + ",mode=rw,size=10,type=pd-balanced",
                   "--no-shielded-secure-boot", "--shielded-vtpm", "--shielded-integrity-monitoring",
                   "--reservation-affinity=any"]
        # create instance template
        completed_process = subprocess.run(command, capture_output=True)
        if completed_process.returncode != 0:
            error("Failed to create Instance Template due to: " + completed_process.stderr.decode("utf-8"))
            exit()

        success("exit-node instance template created successfully!")
    else:
        # exit-node instance template already exists
        success("exit-node instance template already exists!")


def create_instance_group(num: int) -> list:
    """Creates a Managed Instance Group containing our Exit Nodes (and corresponding management data)"""

    debug("Creating an exit-node Managed Instance Group now...")
    # create Managed Instance Group named: exit-nodes
    command = ["gcloud", "compute", "instance-groups", "managed", "create", "exit-nodes",
               "--project=proxycannon", "--base-instance-name=exit-nodes", "--size=" + str(num),
               "--template=exit-nodes", "--zone=" + ZONE]
    completed_process = subprocess.run(command, capture_output=True)
    if completed_process.returncode != 0:
        error("Failed to create Managed Instance Group due to: " + completed_process.stderr.decode("utf-8"))
        exit()

    # wait until MIG has all instances up
    command = ["gcloud", "compute", "instance-groups", "managed", "wait-until", "--stable", "exit-nodes",
               "--zone=" + ZONE]
    completed_process = subprocess.run(command, capture_output=True)

    # store data of instances for resource management
    command = ["gcloud", "compute", "instances", "list", "--filter=name~^exit-nodes",
               "--format=value(name,networkInterfaces[0].networkIP)"]
    completed_process = subprocess.run(command, capture_output=True)
    if completed_process.returncode != 0:
        error("Failed to retrieve Instance metadata due to: " + completed_process.stderr.decode("utf-8"))
        exit()

    instances = completed_process.stdout.decode("utf-8").replace("\t", " ")[:-1].split("\n")
    new_nodes = list()
    instance_ids = list()
    for instance in instances:
        data = instance.split(" ")
        instance_ids.append(data[0])
        new_nodes.append({"cloud_id": data[0], "priv_ip": data[1]})

    debug("Created the following instances: " + str(instance_ids))

    return new_nodes


def add_exit_nodes(num: int, current: list) -> list:
    """Modifies our Managed Instance Group to double the current number of Exit Nodes"""

    # resize exit-nodes to 2x of current size
    command = ["gcloud", "compute", "instance-groups", "managed", "resize", "exit-nodes", "--size=" + str(num * 2),
               "--zone=" + ZONE]
    completed_process = subprocess.run(command, capture_output=True)
    if completed_process.returncode != 0:
        error("Failed to resize Managed Instance Group due to: " + completed_process.stderr.decode("utf-8"))
        exit()

    # wait until MIG has all instances up
    command = ["gcloud", "compute", "instance-groups", "managed", "wait-until", "--stable", "exit-nodes",
               "--zone=" + ZONE]
    completed_process = subprocess.run(command, capture_output=True)

    # store data of instances for resource management
    command = ["gcloud", "compute", "instances", "list", "--filter=name~^exit-nodes",
               "--format=value(name,networkInterfaces[0].networkIP)"]
    completed_process = subprocess.run(command, capture_output=True)
    if completed_process.returncode != 0:
        error("Failed to retrieve Instance metadata due to: " + completed_process.stderr.decode("utf-8"))
        exit()

    instances = completed_process.stdout.decode("utf-8").replace("\t", " ")[:-1].split("\n")
    current_instance_ids = [node["cloud_id"] for node in current]
    new_nodes = list()
    instance_ids = list()
    for instance in instances:
        data = instance.split(" ")
        if data[0] not in current_instance_ids:
            instance_ids.append(data[0])
            new_nodes.append({"cloud_id": data[0], "priv_ip": data[1]})

    debug("Created the following instances: " + str(instance_ids))
    return new_nodes


def delete_exit_nodes(nodes: list):
    """Deletes the Exit Nodes with provided InstanceId in list()"""

    instance_ids = ""
    for node in nodes:
        instance_ids += node["cloud_id"] + ","
    instance_ids = instance_ids[:-1]

    # resize the MIG by deleting the exit-nodes
    debug("Terminating the following instances: " + instance_ids)
    command = ["gcloud", "compute", "instance-groups", "managed", "delete-instances", "exit-nodes", "--zone=" + ZONE,
               "--instances=" + instance_ids]
    completed_process = subprocess.run(command, capture_output=True)

    if completed_process.returncode != 0:
        error("Terminating instances failed because: " + completed_process.stderr.decode("utf-8")
              + ". Consider terminating manually")

    success("Instances are terminating!")


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
    global exit_nodes
    global new_exit_nodes

    create_instance_template()
    exit_nodes = create_instance_group(args.num_of_instances)
    # add_routes(exit_nodes)

    while True:
        if not isRunning:
            exit()
        # sleeps for specified minutes before next IP set rotation
        time.sleep(args.interval * 60)
        if not isRunning:
            exit()
        debug("Starting an IP rotation now!")
        new_exit_nodes = add_exit_nodes(args.num_of_instances, exit_nodes)
        # once new nodes ready (ensure minimal downtime):
    #     del_routes(exit_nodes)
    #     add_routes(new_exit_nodes)
        delete_exit_nodes(exit_nodes)
        exit_nodes = new_exit_nodes.copy()
        new_exit_nodes.clear()
        debug("Waiting for next IP rotation!")


if __name__ == "__main__":
    main()
