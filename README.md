# network_and_port_scanner

This Python script is a network scanner that performs ARP pinging to discover active hosts, detects their operating systems, looks up MAC address vendors, and optionally scans specified ports to identify open services.

Features
ARP Ping Scan: Finds active devices in a specified IP range.
Operating System Detection: Attempts to determine the OS of each device based on IP TTL values.
Vendor Lookup: Retrieves the manufacturer of a device based on its MAC address.
Port Scanning: Checks for open TCP ports on identified devices.
Service Identification: Maps open ports to their corresponding service names.
Requirements
Python 3.x
scapy library
requests library
