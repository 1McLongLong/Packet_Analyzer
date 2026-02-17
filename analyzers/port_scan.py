from datetime import datetime, timedelta


class PortScanDetector:
    def __init__(self, unique_ports_threshold=25, time_window=60):
        self.unique_ports_threshold = unique_ports_threshold
        self.time_window = time_window
        self.scan_tracker = {}

    def track_packet(self, packet_data):
        if packet_data["protocol"] != "TCP":
            return

        src_ip = packet_data["src_ip"]
        dst_ip = packet_data["dst_ip"]
        dst_port = packet_data["dst_port"]
        timestamp = packet_data["timestamp"]

        if src_ip not in self.scan_tracker:
            self.scan_tracker[src_ip] = {}

        if dst_ip not in self.scan_tracker[src_ip]:
            self.scan_tracker[src_ip][dst_ip] = {"ports": [], "timestamps": []}

        self.scan_tracker[src_ip][dst_ip]["ports"].append(dst_port)
        self.scan_tracker[src_ip][dst_ip]["timestamps"].append(timestamp)

    def detect_scans(self):
        scans_detected = []
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)

        for src_ip, targets in self.scan_tracker.items():
            for dst_ip, data in targets.items():
                ports = data["ports"]
                timestamps = data["timestamps"]

                recent_ports = []
                for i, ts in enumerate(timestamps):
                    if ts >= cutoff_time:
                        recent_ports.append(ports[i])

                unique_ports = len(set(recent_ports))

                if unique_ports >= self.unique_ports_threshold:
                    scans_detected.append(
                        {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "unique_ports": unique_ports,
                            "total_attempts": len(recent_ports),
                            "ports_hit": sorted(set(recent_ports)),
                            "timestamp": current_time,
                        }
                    )

        return scans_detected

    def cleanup_old_data(self):
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)

        for src_ip in list(self.scan_tracker.keys()):
            for dst_ip in list(self.scan_tracker[src_ip].keys()):
                data = self.scan_tracker[src_ip][dst_ip]

                recent_indices = [
                    i for i, ts in enumerate(data["timestamps"]) if ts >= cutoff_time
                ]

                if recent_indices:
                    data["ports"] = [data["ports"][i] for i in recent_indices]
                    data["timestamps"] = [data["timestamps"][i] for i in recent_indices]
                else:
                    del self.scan_tracker[src_ip][dst_ip]

            if not self.scan_tracker[src_ip]:
                del self.scan_tracker[src_ip]
