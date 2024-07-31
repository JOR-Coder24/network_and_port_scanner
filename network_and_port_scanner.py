import scapy.all as scapy
import argparse
import requests
import socket
from scapy.layers.inet import IP, TCP, ICMP

def get_vendor(mac_address):
    """Retrieve the vendor of a given MAC address."""
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown"
    except requests.RequestException:
        return "Unknown"

def detect_os(ip):
    """Detect the operating system of a device based on its IP."""
    pkt = IP(dst=ip)/ICMP()
    try:
        response = scapy.sr1(pkt, timeout=2, verbose=False)
        if response:
            ttl = response[IP].ttl
            if ttl <= 64:
                return "Linux/Unix or MacOS or Solaris"
            elif ttl <= 128:
                return "Windows"
            elif ttl <= 255:
                return "Cisco"
            else:
                return "Unknown"
        else:
            return "No response"
    except Exception as e:
        return f"Error: {e}"

def arp_ping(ip_range):
    """Perform ARP ping scan on a given IP range to find active hosts."""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
    except Exception as e:
        print(f"Error performing ARP scan: {e}")
        return []

    results = []
    for element in answered_list:
        ip_address = element[1].psrc
        mac_address = element[1].hwsrc
        vendor = get_vendor(mac_address)
        os = detect_os(ip_address)
        result = {"ip": ip_address, "mac": mac_address, "vendor": vendor, "os": os}
        results.append(result)
    return results

def get_service(port):
    """Get the service name for a given port."""
    try:
        service = socket.getservbyport(port)
        return service
    except OSError:
        return "Unknown"

def display_results(results):
    """Display the results of the network scan."""
    print("IP Address\t\tMAC Address\t\t\tVendor\t\t\tOS")
    print("------------------------------------------------------------")
    for result in results:
        print(f"{result['ip']}\t\t{result['mac']}\t\t{result['vendor']}\t\t{result['os']}")

def scan_ports(ip, ports):
    """Scan specified ports on a given IP address."""
    open_ports = []
    for port in ports:
        pkt = IP(dst=ip)/TCP(dport=port, flags="S")
        try:
            response = scapy.sr1(pkt, timeout=3, verbose=False)
            if response and response.haslayer(TCP) and response[TCP].flags == "SA":
                open_ports.append(port)
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports

def display_ports(ip, open_ports):
    """Display the open ports on a given IP address."""
    print(f"\nOpen ports on {ip}:")
    print("---------------------")
    for port in open_ports:
        service = get_service(port)
        print(f"Port {port} ({service})")

def parse_ports(port_range):
    """Parse the port range or comma-separated list into a list of ports."""
    ports = []
    if '-' in port_range:
        start_port, end_port = port_range.split('-')
        try:
            start_port = int(start_port)
            end_port = int(end_port)
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError
            ports = range(start_port, end_port + 1)
        except ValueError:
            raise ValueError("Invalid port range. Must be in the form 'start-end' and within 1-65535.")
    else:
        ports = [int(port) for port in port_range.split(',')]
    return ports

# Set up argument parser
parser = argparse.ArgumentParser(description="Network Scanner and Port Scanner")
parser.add_argument("target_ip", help="Target IP address or network range (e.g. 192.168.1.1/24)")
parser.add_argument("--ports", help="Comma-separated list of ports or a range (e.g. 22,80,443 or 1-1024). If not specified, port scanning is skipped.", type=str, default="")
args = parser.parse_args()

# Run ARP ping scan with the provided target IP
scan_results = arp_ping(args.target_ip)
display_results(scan_results)

# Determine if port scanning should be performed
if args.ports:
    try:
        ports = parse_ports(args.ports)
        for result in scan_results:
            open_ports = scan_ports(result['ip'], ports)
            display_ports(result['ip'], open_ports)
    except ValueError as e:
        print(e)
        exit(1)
else:
    print("\nNo ports specified for scanning. Skipping port scan.")