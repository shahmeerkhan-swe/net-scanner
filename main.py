from scapy.all import ARP, Ether, srp 
from tabulate import tabulate
from datetime import datetime
import ipaddress
import socket
import requests
import csv

vendor_cache = {}

def scan_network(network):
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=1, verbose=0)[0]

    devices = []
    for sent, received in result: 
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def get_hostname(ip):
    try:
        socket.setdefaulttimeout(1.0)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout, OSError): 
        return "Unknown"
    
def get_vendor(mac):
    prefix = mac.upper().replace(':', '')[:6]

    if prefix in vendor_cache: 
        return vendor_cache[prefix]
    
    url = f"https://api.maclookup.app/v2/macs/{mac}"
    try: 
        response = requests.get(url, timeout=2)
        if response.status_code == 200: 
            data = response.json()
            vendor = data.get("company", "Unknown")
        else: 
            vendor = "Unknown"
    except requests.RequestException: 
        vendor = "Unknown"

    vendor_cache[prefix] = vendor
    return vendor


def print_devices(devices):
    table = []
    for device in devices: 
        ip = device['ip']
        mac = device['mac']
        hostname = get_hostname(ip)
        vendor = get_vendor(mac)
        table.append([ip, mac, hostname, vendor])

    headers = ["IP Address", "MAC Address", "Hostname", "Vendor"]
    print(tabulate(table, headers=headers, tablefmt="pretty"))

def export_to_csv(devices, filename=None):
    if filename is None: 
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"scan_{timestamp}.csv"

    with open(filename, mode='w', newline='') as file: 
        writer = csv.writer(file)
        writer.writerow(["IP", "MAC", "Hostname", "Vendor"])
        
        for device in devices: 
            ip = device['ip']
            mac = device['mac']
            hostname = get_hostname(ip)
            vendor = get_vendor(mac)
            writer.writerow([ip, mac, hostname, vendor])

    print(f"\n[+] Scan results saved to {filename}")


if __name__ == "__main__":
    target_range = "192.168.1.0/24"
    devices = scan_network(target_range)
    print_devices(devices)
    export_to_csv(devices)