from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to process each captured packet
def packet_analyzer(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Packet: {packet.summary()}")
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}")

        # Check if the packet contains a TCP segment
        if protocol == 6 and TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"TCP Packet: Source Port: {sport}, Destination Port: {dport}")
        # Check if the packet contains a UDP segment
        elif protocol == 17 and UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"UDP Packet: Source Port: {sport}, Destination Port: {dport}")
        # Check if the packet is ICMP
        elif protocol == 1 and ICMP in packet:
            print("ICMP Packet")

        print("\n-----------------------------\n")

# Sniff network packets (the iface argument is optional, it specifies the network interface)
def start_sniffing(interface=None):
    print(f"Sniffing on interface: {interface}")
    # Start sniffing and apply the packet_analyzer function on each packet
    sniff(iface=interface, prn=packet_analyzer, store=False)

# Example usage:
if __name__ == "__main__":
    # Replace 'eth0' with your interface (use None for default)
    start_sniffing(interface=None)
