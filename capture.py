from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime


class PacketCapture:
    def __init__(self):
        self.packets = []

    def add_packet(self, packet_data):
        if packet_data:
            self.packets.append(packet_data)

    def get_all_packets(self):
        return self.packets

    def clear(self):
        self.packets = []


def start_sniffing(interface=None, packet_count=0):
    collector = PacketCapture()

    def packet_handler(packet):
        packet_data = process_packet(packet)
        collector.add_packet(packet_data)
        if packet_data:
            print(
                f"[{packet_data['protocol']}] {packet_data['src_ip']}:{packet_data['src_port']} → {packet_data['dst_ip']}:{packet_data['dst_port']}"
            )

    print(f"Starting packet capture on {interface or 'default interface'}...")
    sniff(
        iface=interface,
        filter="tcp or udp or icmp",
        prn=packet_handler,
        count=packet_count,
        store=False,
    )
    return collector


def process_packet(packet):
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    protocol = None
    tcp_flags = None
    timestamp = datetime.now()
    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

    try:
        if IP in packet:
            ip_layer = packet[IP]
            protocol = proto_map.get(ip_layer.proto, "Unknown")
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        else:
            return None
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = packet[TCP].flags
        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        if ICMP in packet:
            src_port = None
            dst_port = None
        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "tcp_flags": tcp_flags,
        }

    except Exception as e:
        print(f"Error processing packet: {e}")
        return None


if __name__ == "__main__":
    # Test with capturing 10 packets
    collector = start_sniffing(packet_count=10)
    print(f"\nCaptured {len(collector.get_all_packets())} packets")