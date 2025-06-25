from scapy.all import ARP, Ether, srp 
import ipaddress
import socket

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

def print_devices(devices):
    print("Devices on the network:")
    print("{:<20} {:<20} {:<30}".format("IP", "MAC", "Hostname"))
    print("-" * 70)

    for device in devices: 
        hostname = get_hostname(device['ip'])
        if not hostname: 
            hostname = "Unknown"
        print("{:20} {:<20} {:<30}".format(device['ip'], device['mac'], hostname))


if __name__ == "__main__":
    target_range = "192.168.1.0/24"
    devices = scan_network(target_range)
    print_devices(devices)