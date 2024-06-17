import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        else:
            protocol_name = "Unknown"

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol_name}")

        if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                print(f"Payload: {decoded_payload}")
            except (IndexError, UnicodeDecodeError):
                print("Payload: Unable to decode payload.")
        else:
            print("Payload:")

def start_sniffing():
    scapy.sniff(store=False, prn=packet_callback)

start_sniffing()