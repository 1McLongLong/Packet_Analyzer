from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import sys
import os

# Add the analyzers directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), "analyzers"))
from analyzers.port_scan import PortScanDetector


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


def start_sniffing_with_detection(interface=None, packet_count=0):
    """
    Start capturing packets with port scan detection
    """
    collector = PacketCapture()
    detector = PortScanDetector(unique_ports_threshold=25, time_window=60)

    packet_counter = 0

    def packet_handler(packet):
        nonlocal packet_counter
        packet_data = process_packet(packet)

        if packet_data:
            collector.add_packet(packet_data)
            detector.track_packet(packet_data)

            packet_counter += 1

            # Check for scans every 10 packets
            if packet_counter % 10 == 0:
                scans = detector.detect_scans()
                if scans:
                    print("\n" + "=" * 60)
                    print("⚠️  PORT SCAN DETECTED!")
                    print("=" * 60)
                    for scan in scans:
                        print(f"Source: {scan['src_ip']}")
                        print(f"Target: {scan['dst_ip']}")
                        print(f"Unique Ports: {scan['unique_ports']}")
                        print(f"Total Attempts: {scan['total_attempts']}")
                        print(f"Ports: {scan['ports_hit'][:10]}...")  # Show first 10
                        print("-" * 60)

                # Cleanup old data
                detector.cleanup_old_data()

            # Print normal packet info
            print(
                f"[{packet_data['protocol']}] {packet_data['src_ip']}:{packet_data['src_port']} → {packet_data['dst_ip']}:{packet_data['dst_port']}"
            )

    print(f"Starting packet capture with port scan detection...")
    print(
        f"Threshold: {detector.unique_ports_threshold} unique ports in {detector.time_window}s"
    )
    print("-" * 60)

    sniff(
        iface=interface,
        filter="tcp or udp or icmp",
        prn=packet_handler,
        count=packet_count,
        store=False,
    )

    return collector, detector


if __name__ == "__main__":
    collector, detector = start_sniffing_with_detection(interface="lo0", packet_count=100)
    print(f"\nCaptured {len(collector.get_all_packets())} packets")
