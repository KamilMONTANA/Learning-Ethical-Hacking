from scapy.all import sniff, ARP, Ether

IP_MAC_Map = {}

def processPacket(packet):
    # Ensure the packet has both Ether and ARP layers
    if Ether in packet and ARP in packet:
        src_IP = packet[ARP].psrc
        src_MAC = packet[Ether].src

        # Check if this MAC address has been seen with a different IP address before
        if src_MAC in IP_MAC_Map:
            if IP_MAC_Map[src_MAC] != src_IP:
                old_IP = IP_MAC_Map[src_MAC]  # No need for try-except as the condition ensures the key exists
                message = ("\nPossible ARP attack detected!\n"
                           "It is possible that the machine with IP address {0} is pretending to be {1}\n"
                           .format(old_IP, src_IP))
                print(message)
        else:
            # Update the mapping of MAC to IP if it's a new or consistent mapping
            IP_MAC_Map[src_MAC] = src_IP

# Sniff indefinitely for ARP packets, and use processPacket as the callback function
sniff(count=0, filter="arp", store=0, prn=processPacket)


