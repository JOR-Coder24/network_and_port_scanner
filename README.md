# Network Scanner and Port Scanner

This script is a network scanner and port scanner designed to perform the following tasks:
- Discover active hosts in a given IP range using ARP ping.
- Retrieve information about active hosts, such as their IP address, MAC address, vendor, and operating system.
- Scan specified ports on the discovered hosts to identify open ports and their associated services.

## Requirements
Before running the script, make sure you have the following Python packages installed:
- `scapy`: For network scanning and crafting packets.
- `requests`: To make HTTP requests to an API to retrieve the vendor information based on MAC addresses.
- `socket`: For retrieving service names by port numbers.

You can install the required dependencies using the following command:
```bash
pip install scapy requests
```

## Usage

### Command-Line Arguments

- `target_ip` (required): The target IP address or network range to scan. It can be a single IP address (e.g. `192.168.1.1`) or a network range in CIDR notation (e.g. `192.168.1.0/24`).
  
- `--ports` (optional): A comma-separated list of port numbers or a port range (e.g., `22,80,443` or `1-1024`). If not specified, port scanning is skipped.

### Example 1: Basic Scan (ARP ping only)
```bash
python scanner.py 192.168.1.1
```
This will perform an ARP ping scan on the target IP address and display the discovered active hosts along with their IP addresses, MAC addresses, vendor information, and detected operating systems.

### Example 2: Scan with Port Range
```bash
python scanner.py 192.168.1.1 --ports 22,80,443
```
This will perform an ARP ping scan on the target IP address and then scan ports 22, 80, and 443 on each active host.

### Example 3: Scan with Port Range (1-1024)
```bash
python scanner.py 192.168.1.0/24 --ports 1-1024
```
This will perform an ARP ping scan on the entire `192.168.1.0/24` subnet and scan ports 1-1024 on the discovered hosts.

## Functions

### `get_vendor(mac_address)`
- Retrieves the vendor associated with the given MAC address by querying the `https://api.macvendors.com` API.
- Returns the vendor name or "Unknown" if no vendor is found.

### `detect_os(ip)`
- Sends an ICMP packet to the given IP address to determine the operating system based on the TTL value of the response.
- Possible OSes detected include "Linux/Unix", "Windows", "Cisco", or "Unknown".

### `arp_ping(ip_range)`
- Performs an ARP ping scan over the given IP range (e.g., `192.168.1.0/24`) to find active hosts.
- Returns a list of dictionaries containing the IP address, MAC address, vendor, and OS of each active host.

### `get_service(port)`
- Given a port number, this function returns the corresponding service name (e.g., "http" for port 80).
- Returns "Unknown" if the port does not correspond to a known service.

### `scan_ports(ip, ports)`
- Scans the specified ports on the given IP address to check for open ports.
- Returns a list of open ports.

### `display_results(results)`
- Displays the results of the ARP ping scan, showing the IP address, MAC address, vendor, and OS of each active host.

### `display_ports(ip, open_ports)`
- Displays the open ports on a given IP address, along with their associated service names.

### `parse_ports(port_range)`
- Parses a port range (e.g., `22,80,443` or `1-1024`) and returns a list of port numbers.
- Raises a `ValueError` if the range is invalid.

## Example Output

### ARP Scan Results:
```
IP Address        MAC Address        Vendor            OS
------------------------------------------------------------
192.168.1.2       aa:bb:cc:dd:ee:ff  Cisco             Linux/Unix or MacOS or Solaris
192.168.1.3       11:22:33:44:55:66  Apple             Windows
```

### Port Scan Results:
```
Open ports on 192.168.1.2:
---------------------
Port 22 (ssh)
Port 80 (http)

Open ports on 192.168.1.3:
---------------------
Port 443 (https)
```

## Error Handling
The script includes basic error handling for network and request exceptions. In the case of a failed network scan or vendor lookup, the script will report "Unknown" for missing information.

## Notes
- The ARP ping scan works within local networks and requires access to the target network.
- The port scan may take some time depending on the number of ports and hosts being scanned.

