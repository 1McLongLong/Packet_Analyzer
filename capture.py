from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import sys
import os

# Add the analyzers directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), "analyzers"))
from analyzers.port_scan import PortScanDetector
from analyzers.exfiltration import DataExfiltrationDetector
from analyzers.tcp_anomaly import SynFloodDetector
from utils.threat_intel import ThreatIntelChecker
import config


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
    length = len(packet)

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
            "length": length,
        }

    except Exception as e:
        print(f"Error processing packet: {e}")
        return None


def print_threat_intel(ti):
    """Print threat intel results for an alert."""
    if "error" in ti:
        print(f"Threat Intel:  Error - {ti['error']}")
    elif ti.get("is_private"):
        print(f"Threat Intel:  Private/Local IP")
    elif ti["is_malicious"]:
        print(f"\u26a0\ufe0f  KNOWN MALICIOUS IP!")
        print(f"   Abuse Score: {ti['abuse_confidence_score']}%")
        print(f"   Reports:     {ti['total_reports']}")
        print(f"   Country:     {ti.get('country_code', 'Unknown')}")
        print(f"   ISP:         {ti.get('isp', 'Unknown')}")
    else:
        print(f"Threat Intel:  Clean (Score: {ti['abuse_confidence_score']}%)")


def start_sniffing_with_detection(interface=None, packet_count=0):
    """
    Start capturing packets with multiple detectors
    """
    collector = PacketCapture()
    port_scan_detector = PortScanDetector(unique_ports_threshold=25, time_window=60)
    exfil_detector = DataExfiltrationDetector(
        volume_threshold_mb=config.EXFIL_VOLUME_THRESHOLD_MB,
        time_window=config.EXFIL_TIME_WINDOW,
        sustained_threshold_mb=config.EXFIL_SUSTAINED_THRESHOLD_MB,
    )
    syn_flood_detector = SynFloodDetector(
        syn_threshold=config.SYN_FLOOD_THRESHOLD,
        time_window=config.SYN_FLOOD_TIME_WINDOW,
    )

    packet_counter = 0

    def packet_handler(packet):
        nonlocal packet_counter
        packet_data = process_packet(packet)

        if packet_data:
            collector.add_packet(packet_data)

            # Track with all detectors
            port_scan_detector.track_packet(packet_data)
            exfil_detector.track_packet(packet_data)
            syn_flood_detector.track_packet(packet_data)

            packet_counter += 1

            # Check for threats every 20 packets
            if packet_counter % 20 == 0:

                threat_intel = None
                if config.THREAT_INTEL_ENABLED and config.ABUSEIPDB_API_KEY:
                    threat_intel = ThreatIntelChecker(
                        api_key=config.ABUSEIPDB_API_KEY,
                        cache_duration=config.THREAT_INTEL_CACHE_DURATION,
                    )
                # Check port scans
                scans = port_scan_detector.detect_scans()
                for scan in scans:
                    # Check source IP reputation
                    if threat_intel:
                        rep = threat_intel.check_ip(scan["src_ip"])
                        scan["threat_intel"] = rep

                    # Print alert
                    print("\n" + "=" * 60)
                    print("⚠️  PORT SCAN DETECTED!")
                    print("=" * 60)
                    print(f"Source IP:     {scan['src_ip']}")
                    print(f"Target IP:     {scan['dst_ip']}")
                    print(f"Unique Ports:  {scan['unique_ports']}")
                    print(f"Total Attempts: {scan['total_attempts']}")

                    if "threat_intel" in scan:
                        print_threat_intel(scan["threat_intel"])

                    print("-" * 60)

                # Check data exfiltration
                exfil_alerts = exfil_detector.detect_exfiltration()
                for alert in exfil_alerts:
                    # Check destination IP reputation
                    if threat_intel:
                        rep = threat_intel.check_ip(alert["dst_ip"])
                        alert["threat_intel"] = rep

                    # Print alert
                    print("\n" + "=" * 60)
                    print("🚨 DATA EXFILTRATION DETECTED!")
                    print("=" * 60)
                    print(f"Alert Type:    {alert['type']}")
                    print(f"Source IP:     {alert['src_ip']}")
                    print(f"Destination:   {alert['dst_ip']}")
                    print(f"Data Volume:   {alert['total_mb']} MB")
                    print(f"Transfer Rate: {alert['transfer_rate_mb_min']} MB/min")

                    if "threat_intel" in alert:
                        print_threat_intel(alert["threat_intel"])

                    print("-" * 60)

                # Check SYN floods
                syn_alerts = syn_flood_detector.detect_syn_flood()
                for alert in syn_alerts:
                    if threat_intel:
                        rep = threat_intel.check_ip(alert["src_ip"])
                        alert["threat_intel"] = rep

                    print("\n" + "=" * 60)
                    print("🔥 SYN FLOOD DETECTED!")
                    print("=" * 60)
                    print(f"Source IP:     {alert['src_ip']}")
                    print(
                        f"Total SYNs:    {alert['total_syns']} in {alert['time_window']}s"
                    )
                    print(f"SYN Rate:      {alert['syn_rate_per_sec']} SYN/sec")
                    print(f"Targets Hit:   {alert['target_count']}")
                    for target, count in alert["targets"].items():
                        print(f"  → {target}: {count} SYNs")

                    if "threat_intel" in alert:
                        print_threat_intel(alert["threat_intel"])

                    print("-" * 60)

                # Check flag anomalies (XMAS, NULL, FIN, SYN+FIN scans)
                flag_alerts = syn_flood_detector.detect_flag_anomalies()
                for alert in flag_alerts:
                    if threat_intel:
                        rep = threat_intel.check_ip(alert["src_ip"])
                        alert["threat_intel"] = rep

                    print("\n" + "=" * 60)
                    print(f"🚩 SUSPICIOUS TCP FLAGS: {alert['flag_type']}")
                    print("=" * 60)
                    print(f"Description:   {alert['description']}")
                    print(f"Source IP:     {alert['src_ip']}")
                    print(f"Packets:       {alert['packet_count']}")
                    print(f"Unique Targets: {alert['unique_targets']}")
                    print(f"Unique Ports:  {alert['unique_ports']}")
                    if alert["sample_ports"]:
                        print(f"Ports:         {alert['sample_ports']}")

                    if "threat_intel" in alert:
                        print_threat_intel(alert["threat_intel"])

                    print("-" * 60)

                # Cleanup old data
                port_scan_detector.cleanup_old_data()
                exfil_detector.cleanup_old_data()
                syn_flood_detector.cleanup_old_data()

            # Print packet info (less verbose)
            if packet_counter % 10 == 0:
                print(
                    f"[Packets: {packet_counter}] Latest: {packet_data['src_ip']} → {packet_data['dst_ip']}"
                )

    print(f"Starting Network Traffic Analyzer...")
    print(
        f"Port Scan Detection: {port_scan_detector.unique_ports_threshold} ports in {port_scan_detector.time_window}s"
    )
    print(
        f"Data Exfil Detection: {exfil_detector.volume_threshold_mb}MB in {exfil_detector.time_window}s"
    )
    print(
        f"SYN Flood Detection: {syn_flood_detector.syn_threshold} SYNs in {syn_flood_detector.time_window}s"
    )
    print(f"Flag Anomaly Detection: XMAS, NULL, FIN, SYN+FIN scans")
    print("-" * 60)

    sniff(
        iface=interface,
        filter="tcp or udp or icmp",
        prn=packet_handler,
        count=packet_count,
        store=False,
    )

    return collector, port_scan_detector, exfil_detector, syn_flood_detector


if __name__ == "__main__":
    collector, ps_detector, exfil_detector, syn_detector = (
        start_sniffing_with_detection(interface=None, packet_count=1000)
    )
    print(f"\nTotal packets captured: {len(collector.get_all_packets())}")
