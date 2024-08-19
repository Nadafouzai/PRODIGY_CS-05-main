import scapy.all as scapy

def handle_payload(payload):
    """Decode and print the payload."""
    try:
        decoded_payload = payload.decode('utf-8', 'ignore')
        return decoded_payload
    except UnicodeDecodeError:
        return "Unable to decode payload."

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        ip_layer = packet[scapy.IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Translate protocol number to protocol name
        protocol_name = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }.get(protocol, 'Unknown')

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol_name}")

        if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
            transport_layer = packet.getlayer(scapy.TCP) or packet.getlayer(scapy.UDP)
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                decoded_payload = handle_payload(payload)
                print(f"{protocol_name} Payload: {decoded_payload}")
            else:
                print(f"No Raw payload for {protocol_name}.")

def start_sniffing():
    """Start sniffing network packets."""
    print("Starting packet sniffing. Press Ctrl+C to stop.")
    scapy.sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffing()
