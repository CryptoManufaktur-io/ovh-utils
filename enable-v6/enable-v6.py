#!/usr/bin/env python3
import ovh
import netifaces
import ipaddress
import socket
import os
import sys
import argparse
import signal
import time
import subprocess


def handle_sigint(signum, frame):
    signal.signal(signum, signal.SIG_IGN)
    print("\nExited with Ctrl-C")
    sys.exit(0)


def test_ipv6_connectivity():
    try:
        # Run the ping command to Google's IPv6 DNS server
        subprocess.run(
            ["ping", "-6", "-c", "1", "2001:4860:4860::8888"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def get_env_variable(var_name):
    value = os.getenv(var_name)
    if not value:
        raise EnvironmentError(f"Error: Environment variable {var_name} is not set.")
    return value


def modify_network_interfaces(interface_name, ipV6, gatewayV6):
    file_path = "/etc/network/interfaces.d/50-cloud-init"

    # Prepare the modifications
    new_section = f"""
iface {interface_name} inet6 static
  address {ipV6}
  dns-nameservers 2001:4860:4860::8888 2001:41d0:3:163::1
  gateway {gatewayV6}
"""

    # Read the file content
    with open(file_path, "r") as file:
        lines = file.readlines()

    # Modify the content
    modified_lines = []
    found_iface = False
    for line in lines:
        modified_lines.append(line)
        if line.strip() == f"iface {interface_name} inet dhcp":
            found_iface = True
            modified_lines.append("  accept_ra 0\n")

    if not found_iface:
        print(f"iface {interface_name} inet dhcp not found in {file_path}.")
        return False
    else:
        # Add the new section at the end of the file
        modified_lines.append(new_section)

    # Write the modified content to a temporary file
    temp_file_path = "/tmp/50-cloud-init-modified"
    with open(temp_file_path, "w") as temp_file:
        temp_file.writelines(modified_lines)

    # Use sudo to move the modified file back to the original location
    try:
        subprocess.run(["sudo", "mv", temp_file_path, file_path], check=True)
        print(f"Modified {file_path} successfully.")
        return True
    except subprocess.CalledProcessError:
        print(
            f"Failed to modify the network interfaces file {file_path}. Please check your permissions."
        )
        return False


def modify_netplan_interfaces(interface_name, ipV6, gatewayV6):
    # Prepare the content of the file
    content = f"""
network:
    version: 2
    ethernets:
        {interface_name}:
            accept-ra: false
            addresses:
            - {ipV6}
            match:
                name: {interface_name}
            nameservers:
                addresses:
                - 2001:4860:4860::8888
                - 2001:41d0:3:163::1
            routes:
            -   to: default
                via: {gatewayV6}
            -   to: {gatewayV6}/128
                via: '::'
"""

    # Write the content to a temporary file
    temp_file_path = "/tmp/51-cloud-init-ipv6.yaml"
    with open(temp_file_path, "w") as temp_file:
        temp_file.write(content)

    # Use sudo to move the temporary file to the target location
    file_path = "/etc/netplan/51-cloud-init-ipv6.yaml"
    try:
        subprocess.run(["sudo", "mv", temp_file_path, file_path], check=True)
        print(f"Created {file_path} successfully.")
    except subprocess.CalledProcessError:
        print(
            f"Failed to create the netplan configuration file {file_path}. Please check your permissions."
        )
        return False
    try:
        subprocess.run(["sudo", "chown", "root:root", file_path], check=True)
    except subprocess.CalledProcessError:
        print(
            f"Failed to chown the netplan configuration file {file_path}. Please check your permissions."
        )
        return False
    try:
        subprocess.run(["sudo", "chmod", "600", file_path], check=True)
        return True
    except subprocess.CalledProcessError:
        print(
            f"Failed to chmod the netplan configuration file {file_path}. Please check your permissions."
        )
        return False


signal.signal(signal.SIGINT, handle_sigint)

parser = argparse.ArgumentParser(description="OVH IPv6 script")
parser.add_argument(
    "--endpoint",
    type=str,
    default="ovh-us",
    help="OVH API endpoint (default: 'ovh-us')",
)
args = parser.parse_args()

try:
    application_key = get_env_variable("OVH_APP_KEY")
    application_secret = get_env_variable("OVH_APP_SECRET")
    consumer_key = get_env_variable("OVH_CONSUMER_KEY")
except EnvironmentError as e:
    sys.exit(e)

client = ovh.Client(
    endpoint=args.endpoint,
    application_key=application_key,
    application_secret=application_secret,
    consumer_key=consumer_key,
)

hostname = socket.gethostname()
servers = client.get("/dedicated/server")

print("Querying OVH API to find this server")
for server in servers:
    for i in range(1, 3):
        try:
            serverDict = client.get(f"/dedicated/server/{server}")
            break
        except Exception as e:
            if i == 3:
                print(f"Failed OVH API call three times, error {e}")
                sys.exit(1)
            else:
                print(f"Failed OVH API call {i} times, error {e}")
                print("Sleeping for 10 seconds before retrying")
                time.sleep(10)

    alias = serverDict.get("iam", {}).get("displayName")
    if alias == hostname:
        print("Found", alias)
        break

ipV4 = serverDict.get("ip")

interface_name = None
for iface in netifaces.interfaces():
    addresses = netifaces.ifaddresses(iface)
    ipv4_info = addresses.get(netifaces.AF_INET, [])
    for ipv4 in ipv4_info:
        if ipv4.get("addr") == ipV4:
            interface_name = iface
            break

if interface_name is None:
    print(f"No interface found with IPv4 address {ipV4}")
    print("This is likely a bug")
    sys.exit(1)

addresses = netifaces.ifaddresses(interface_name)
ipv6_info = addresses.get(netifaces.AF_INET6, [])
for ipv6 in ipv6_info:
    ipv6_addr = ipv6.get("addr")
    if ipv6_addr:
        # Remove any scope identifier (e.g., "%eth0") from the IPv6 address
        ipv6_addr = ipv6_addr.split("%")[0]
        # Check if the IPv6 address is a public address
        if not ipaddress.ip_address(ipv6_addr).is_private:
            print(f"Public IPv6 address for interface {interface_name}: {ipv6_addr}")
            print("IPv6 is already enabled")
            if not test_ipv6_connectivity:
                print(
                    "But ping to 2001:4860:4860::8888 fails. This configuration is broken."
                )
                sys.exit(1)
            else:
                sys.exit(0)

print(f"No public IPv6 address found on interface {interface_name}")

serverNetwork = client.get(f"/dedicated/server/{server}/specifications/network")
ipV6 = serverNetwork.get("routing", {}).get("ipv6", {}).get("ip")
networkV6 = ipaddress.IPv6Network(ipV6, strict=False)
ipV6 = networkV6.network_address.compressed + f"/{networkV6.prefixlen}"
gatewayV6 = serverNetwork.get("routing", {}).get("ipv6", {}).get("gateway")
gatewayV6 = ipaddress.IPv6Address(gatewayV6).compressed

if os.path.exists("/etc/netplan/50-cloud-init.yaml"):
    print(f"Configuring static IPv6 {ipV6} with gateway {gatewayV6} via /etc/netplan")
    if not modify_netplan_interfaces(interface_name, ipV6, gatewayV6):
        print("Exiting")
        sys.exit(1)
    # Use sudo to apply netplan
    try:
        subprocess.run(["sudo", "netplan", "apply"], check=True)
        print("Netplan apply successful.")
    except subprocess.CalledProcessError:
        print("Failed to apply new config to netplan.")
        sys.exit(1)
elif os.path.exists("/etc/network/interfaces.d/50-cloud-init"):
    print(f"Configuring static IPv6 {ipV6} with gateway {gatewayV6} via /etc/network")
    if not modify_network_interfaces(interface_name, ipV6, gatewayV6):
        print("Exiting")
        sys.exit(1)
    # Use sudo to restart networking
    try:
        subprocess.run(["sudo", "/etc/init.d/networking", "restart"], check=True)
        print("Network restart successful.")
    except subprocess.CalledProcessError:
        print("Failed to restart networking.")
        sys.exit(1)
else:
    print(
        "Found neither /etc/network/interfaces.d/50-cloud-init nor /etc/netplan/50-cloud-init.yaml"
    )
    print("Unsure how to proceed. Aborting.")
    sys.exit(1)

addresses = netifaces.ifaddresses(interface_name)
ipv6_info = addresses.get(netifaces.AF_INET6, [])
for ipv6 in ipv6_info:
    ipv6_addr = ipv6.get("addr")
    if ipv6_addr:
        # Remove any scope identifier (e.g., "%eth0") from the IPv6 address
        ipv6_addr = ipv6_addr.split("%")[0]
        # Check if the IPv6 address is a public address
        if not ipaddress.ip_address(ipv6_addr).is_private:
            print(f"Public IPv6 address for interface {interface_name}: {ipv6_addr}")
            print("IPv6 successfully enabled")
            if not test_ipv6_connectivity:
                print(
                    "But ping to 2001:4860:4860::8888 fails. This configuration is broken."
                )
                sys.exit(1)
            else:
                sys.exit(0)
