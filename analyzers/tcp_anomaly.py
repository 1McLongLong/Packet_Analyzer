from datetime import datetime, timedelta
from collections import defaultdict


class SynFloodDetector:
    def __init__(
        self,
        syn_threshold=100,
        time_window=10,
    ):
        self.syn_threshold = syn_threshold
        self.time_window = time_window

        self.syn_tracker = defaultdict(lambda: defaultdict(list))

        self.flag_tracker = defaultdict(lambda: defaultdict(list))

    SUSPICIOUS_FLAGS = {
        "XMAS": {"F", "P", "U"},
        "NULL": set(),
        "FIN_ONLY": {"F"},
        "SYN_FIN": {"S", "F"},
        "URG_ONLY": {"U"},
        "PSH_ONLY": {"P"},
    }

    def _parse_flags(self, tcp_flags):
        if tcp_flags is None:
            return set()
        return set(str(tcp_flags))

    def track_packet(self, packet_data):
        if packet_data["protocol"] != "TCP" or packet_data["tcp_flags"] is None:
            return

        src_ip = packet_data["src_ip"]
        dst_ip = packet_data["dst_ip"]
        dst_port = packet_data["dst_port"]
        timestamp = packet_data["timestamp"]
        flags = self._parse_flags(packet_data["tcp_flags"])

        if "S" in flags and "A" not in flags:
            self.syn_tracker[src_ip][dst_ip].append(timestamp)

        for flag_name, flag_set in self.SUSPICIOUS_FLAGS.items():
            if flags == flag_set:
                self.flag_tracker[src_ip][flag_name].append(
                    {
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "timestamp": timestamp,
                    }
                )

    def detect_syn_flood(self):
        alerts = []
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)

        for src_ip, targets in self.syn_tracker.items():
            total_syns = 0
            target_details = {}

            for dst_ip, timestamps in targets.items():
                recent = [ts for ts in timestamps if ts >= cutoff_time]
                if recent:
                    total_syns += len(recent)
                    target_details[dst_ip] = len(recent)

            if total_syns >= self.syn_threshold:
                syn_rate = total_syns / self.time_window

                alerts.append(
                    {
                        "type": "syn_flood",
                        "src_ip": src_ip,
                        "total_syns": total_syns,
                        "syn_rate_per_sec": round(syn_rate, 1),
                        "targets": target_details,
                        "target_count": len(target_details),
                        "time_window": self.time_window,
                        "timestamp": current_time,
                    }
                )

        return alerts

    def detect_flag_anomalies(self):
        alerts = []
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)

        flag_descriptions = {
            "XMAS": "XMAS Scan (FIN+PSH+URG) - Reconnaissance technique",
            "NULL": "NULL Scan (no flags) - Stealth reconnaissance",
            "FIN_ONLY": "FIN Scan - Stealth port scanning",
            "SYN_FIN": "SYN+FIN (invalid) - Firewall evasion attempt",
            "URG_ONLY": "URG-only flag - Unusual/suspicious traffic",
            "PSH_ONLY": "PSH-only flag - Unusual/suspicious traffic",
        }

        for src_ip, flag_types in self.flag_tracker.items():
            for flag_name, entries in flag_types.items():
                recent = [e for e in entries if e["timestamp"] >= cutoff_time]

                if not recent:
                    continue

                unique_targets = set(e["dst_ip"] for e in recent)
                unique_ports = set(e["dst_port"] for e in recent)

                alerts.append(
                    {
                        "type": "flag_anomaly",
                        "flag_type": flag_name,
                        "description": flag_descriptions.get(
                            flag_name, "Unknown flag pattern"
                        ),
                        "src_ip": src_ip,
                        "packet_count": len(recent),
                        "unique_targets": len(unique_targets),
                        "unique_ports": len(unique_ports),
                        "sample_ports": sorted(unique_ports)[:10],
                        "timestamp": current_time,
                    }
                )

        return alerts

    def cleanup_old_data(self):
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)

        for src_ip in list(self.syn_tracker.keys()):
            for dst_ip in list(self.syn_tracker[src_ip].keys()):
                recent = [
                    ts for ts in self.syn_tracker[src_ip][dst_ip] if ts >= cutoff_time
                ]
                if recent:
                    self.syn_tracker[src_ip][dst_ip] = recent
                else:
                    del self.syn_tracker[src_ip][dst_ip]
            if not self.syn_tracker[src_ip]:
                del self.syn_tracker[src_ip]

        for src_ip in list(self.flag_tracker.keys()):
            for flag_name in list(self.flag_tracker[src_ip].keys()):
                recent = [
                    e
                    for e in self.flag_tracker[src_ip][flag_name]
                    if e["timestamp"] >= cutoff_time
                ]
                if recent:
                    self.flag_tracker[src_ip][flag_name] = recent
                else:
                    del self.flag_tracker[src_ip][flag_name]
            if not self.flag_tracker[src_ip]:
                del self.flag_tracker[src_ip]
