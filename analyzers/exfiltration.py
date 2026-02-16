from datetime import datetime, timedelta
from collections import defaultdict


class DataExfiltrationDetector:
    def __init__(
        self,
        volume_threshold_mb,
        time_window,
        sustained_threshold_mb,
    ):
        """
        Initialize data exfiltration detector

        Args:
            volume_threshold_mb: Total MB to trigger alert
            time_window: Time window in seconds
            sustained_threshold_mb: MB per minute for sustained transfer alert
        """
        self.volume_threshold_mb = volume_threshold_mb
        self.time_window = time_window
        self.sustained_threshold_mb = sustained_threshold_mb

        # Track data transfers: {src_ip: {dst_ip: [(timestamp, bytes), ...]}}
        self.transfer_tracker = defaultdict(lambda: defaultdict(list))

    def track_packet(self, packet_data):
        """
        Track packet for data exfiltration

        Args:
            packet_data: Dictionary with packet information
        """
        src_ip = packet_data["src_ip"]
        dst_ip = packet_data["dst_ip"]
        timestamp = packet_data["timestamp"]

        # Estimate packet size (rough estimate)
        # In real implementation, you'd get actual packet length from Scapy
        actual_bytes = packet_data["length"]  # Average MTU size

        self.transfer_tracker[src_ip][dst_ip].append(
            {"timestamp": timestamp, "bytes": actual_bytes}
        )

    def detect_exfiltration(self):
        """
        Analyze tracked transfers for data exfiltration

        Returns:
            List of detected exfiltration attempts
        """
        alerts = []
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)

        for src_ip, destinations in self.transfer_tracker.items():
            for dst_ip, transfers in destinations.items():
                # Filter recent transfers
                recent_transfers = [
                    t for t in transfers if t["timestamp"] >= cutoff_time
                ]

                if not recent_transfers:
                    continue

                # Calculate total bytes transferred
                total_bytes = sum(t["bytes"] for t in recent_transfers)
                total_mb = total_bytes / (1024 * 1024)

                # Check volume threshold
                if total_mb >= self.volume_threshold_mb:
                    # Calculate transfer rate
                    time_span = (
                        recent_transfers[-1]["timestamp"]
                        - recent_transfers[0]["timestamp"]
                    ).total_seconds()

                    if time_span > 0:
                        mb_per_second = total_mb / time_span
                        mb_per_minute = mb_per_second * 60
                    else:
                        mb_per_minute = 0

                    alerts.append(
                        {
                            "type": "high_volume",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "total_mb": round(total_mb, 2),
                            "transfer_rate_mb_min": round(mb_per_minute, 2),
                            "packet_count": len(recent_transfers),
                            "time_window": self.time_window,
                            "timestamp": current_time,
                        }
                    )

                # Check for sustained transfer
                elif len(recent_transfers) > 100:  # Sustained activity
                    mb_per_minute = (total_mb / self.time_window) * 60

                    if mb_per_minute >= self.sustained_threshold_mb:
                        alerts.append(
                            {
                                "type": "sustained_transfer",
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "total_mb": round(total_mb, 2),
                                "transfer_rate_mb_min": round(mb_per_minute, 2),
                                "packet_count": len(recent_transfers),
                                "timestamp": current_time,
                            }
                        )

        return alerts

    def cleanup_old_data(self):
        """
        Remove data older than time_window
        """
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)

        for src_ip in list(self.transfer_tracker.keys()):
            for dst_ip in list(self.transfer_tracker[src_ip].keys()):
                # Keep only recent transfers
                recent = [
                    t
                    for t in self.transfer_tracker[src_ip][dst_ip]
                    if t["timestamp"] >= cutoff_time
                ]

                if recent:
                    self.transfer_tracker[src_ip][dst_ip] = recent
                else:
                    del self.transfer_tracker[src_ip][dst_ip]

            if not self.transfer_tracker[src_ip]:
                del self.transfer_tracker[src_ip]
