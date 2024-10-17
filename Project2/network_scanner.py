from scapy.all import ARP, Ether, srp
import nmap

def scapy_scan(network_range):
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def nmap_scan(network_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments='-sn')
    devices = []
    for host in nm.all_hosts():
        devices.append({'ip': host, 'mac': nm[host]['addresses'].get('mac', 'N/A')})
    return devices
