# packet_features.py
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw

# Define feature names consistently
FEATURE_NAMES = [
    'src_port', 'dst_port', 'protocol',
    'pkt_len', 'ip_hdr_len', 'ip_flags', 'ip_ttl',
    'tcp_hdr_len', 'tcp_flags', 'tcp_window',
    'udp_hdr_len',
    'icmp_type', 'icmp_code',
    'payload_len', 'entropy'
]

def calculate_entropy(payload):
    """Calculates the entropy of the payload bytes."""
    if not payload:
        return 0.0
    byte_arr = np.frombuffer(payload, dtype=np.uint8)
    counts = np.bincount(byte_arr, minlength=256)
    probabilities = counts / len(byte_arr)
    # Filter out zero probabilities before taking log
    probabilities = probabilities[probabilities > 0]
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return entropy / 8.0 # Normalize to be between 0 and 1

def extract_features(packet):
    """
    Extracts features from a Scapy packet.
    Returns a dictionary of features or None if packet is not IP.
    """
    features = {name: 0 for name in FEATURE_NAMES} # Initialize with zeros

    if not packet.haslayer(IP):
        return None # Focus on IP packets for now

    ip_layer = packet.getlayer(IP)
    features['pkt_len'] = len(packet)
    features['ip_hdr_len'] = ip_layer.ihl * 4 # IHL is in 4-byte words
    features['ip_flags'] = int(ip_layer.flags)
    features['ip_ttl'] = ip_layer.ttl
    features['protocol'] = ip_layer.proto

    payload = bytes(ip_layer.payload) # Default payload is IP's payload

    # --- TCP Features ---
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        features['src_port'] = tcp_layer.sport
        features['dst_port'] = tcp_layer.dport
        features['tcp_hdr_len'] = tcp_layer.dataofs * 4 # Data Offset in 4-byte words
        features['tcp_flags'] = int(tcp_layer.flags)
        features['tcp_window'] = tcp_layer.window
        payload = bytes(tcp_layer.payload)

    # --- UDP Features ---
    elif packet.haslayer(UDP):
        udp_layer = packet.getlayer(UDP)
        features['src_port'] = udp_layer.sport
        features['dst_port'] = udp_layer.dport
        features['udp_hdr_len'] = udp_layer.len # Includes header and data
        payload = bytes(udp_layer.payload)

    # --- ICMP Features ---
    elif packet.haslayer(ICMP):
        icmp_layer = packet.getlayer(ICMP)
        features['icmp_type'] = icmp_layer.type
        features['icmp_code'] = icmp_layer.code
        payload = bytes(icmp_layer.payload)

    # --- Payload Features ---
    features['payload_len'] = len(payload)
    features['entropy'] = calculate_entropy(payload)

    return features

if __name__ == '__main__':
    # Example usage (for testing)
    from scapy.all import rdpcap
    # Create or load a sample pcap file (e.g., 'test.pcap')
    try:
        packets = rdpcap('test.pcap', count=5)
        for pkt in packets:
            f = extract_features(pkt)
            if f:
                print(f)
            else:
                print("Non-IP packet skipped.")
    except FileNotFoundError:
        print("Create a 'test.pcap' file with some packets to run this example.")
