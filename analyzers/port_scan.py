from datetime import datetime, timedelta


class PortScanDetector:
    def __init__(self, unique_ports_threshold=25, time_window=60):
        """
        Initialize port scan detector

        Args:
            unique_ports_threshold: Number of unique ports to trigger alert
            time_window: Time window in seconds to analyze
        """
        self.unique_ports_threshold = unique_ports_threshold
        self.time_window = time_window
        self.scan_tracker = {}

    def track_packet(self, packet_data):
        """
        Track a packet for port scan detection

        Args:
            packet_data: Dictionary with packet information
        """
        # Only track TCP packets with SYN flag
        if packet_data["protocol"] != "TCP":
            return

        src_ip = packet_data["src_ip"]
        dst_ip = packet_data["dst_ip"]
        dst_port = packet_data["dst_port"]
        timestamp = packet_data["timestamp"]

        # Initialize nested dictionaries if needed
        if src_ip not in self.scan_tracker:
            self.scan_tracker[src_ip] = {}

        if dst_ip not in self.scan_tracker[src_ip]:
            self.scan_tracker[src_ip][dst_ip] = {"ports": [], "timestamps": []}

        # Add port and timestamp
        self.scan_tracker[src_ip][dst_ip]["ports"].append(dst_port)
        self.scan_tracker[src_ip][dst_ip]["timestamps"].append(timestamp)

    def detect_scans(self):
        """
        Analyze tracked connections for port scans

        Returns:
            List of detected scans with details
        """
        scans_detected = []
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)

        # Loop through all source IPs
        for src_ip, targets in self.scan_tracker.items():
            # Loop through all target IPs for this source
            for dst_ip, data in targets.items():
                ports = data["ports"]
                timestamps = data["timestamps"]

                # Filter to get only recent activity
                recent_ports = []
                for i, ts in enumerate(timestamps):
                    if ts >= cutoff_time:
                        recent_ports.append(ports[i])

                # Count unique ports
                unique_ports = len(set(recent_ports))

                # Check if threshold exceeded
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
        """
        Remove data older than time_window to prevent memory buildup
        """
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)

        for src_ip in list(self.scan_tracker.keys()):
            for dst_ip in list(self.scan_tracker[src_ip].keys()):
                data = self.scan_tracker[src_ip][dst_ip]

                # Keep only recent timestamps and their corresponding ports
                recent_indices = [
                    i for i, ts in enumerate(data["timestamps"]) if ts >= cutoff_time
                ]

                if recent_indices:
                    data["ports"] = [data["ports"][i] for i in recent_indices]
                    data["timestamps"] = [data["timestamps"][i] for i in recent_indices]
                else:
                    # Remove this target if no recent data
                    del self.scan_tracker[src_ip][dst_ip]

            # Remove source IP if no targets left
            if not self.scan_tracker[src_ip]:
                del self.scan_tracker[src_ip]
