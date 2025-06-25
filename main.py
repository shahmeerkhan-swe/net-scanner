from scapy.all import ARP, Ether, srp 
from tabulate import tabulate
from datetime import datetime
import ipaddress
import socket
import requests
import csv


def scan_network(network):
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result: 
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror: 
        return "Unknown"
    except Exception: 
        return "Unknown"
    
def get_vendor(mac):
    url = f"https://api.maclookup.app/v2/macs/{mac}"

    try: 
        response = requests.get(url, timeout=5)
        if response.status_code == 200: 
            data = response.json()
            return data.get("company", "Unknown")
        else: 
            return "Unknown"
    except: 
        return "Unknown"


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