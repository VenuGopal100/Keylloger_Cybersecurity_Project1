"""
websocket_detector.py - WebSocket connection detector and blocker
"""
import asyncio
import socket
import threading
import time
from datetime import datetime
import json
import subprocess
import sys


class WebSocketDetector:
    def __init__(self):
        self.detected_connections = []
        self.blocked_connections = []
        self.monitoring = False
        self.suspicious_ports = [8765, 8766, 8767, 8888, 8080]  # Common WebSocket ports
        self.whitelist = ['127.0.0.1']  # Localhost is safe

    def start_monitoring(self):
        """Start monitoring for WebSocket connections"""
        self.monitoring = True
        monitor_thread = threading.Thread(target=self._monitor_connections, daemon=True)
        monitor_thread.start()
        print("[WebSocket Detector] Monitoring started")

    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False

    def _monitor_connections(self):
        """Monitor network connections for WebSocket activity"""
        while self.monitoring:
            try:
                self._check_connections()
                time.sleep(2)  # Check every 2 seconds
            except Exception as e:
                print(f"[WebSocket Detector] Error: {e}")
                time.sleep(2)

    def _check_connections(self):
        """Check for suspicious WebSocket connections"""
        try:
            # Get current network connections
            if sys.platform == "win32":
                # Windows netstat
                result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=10)
            else:
                # Linux/Mac netstat
                result = subprocess.run(['netstat', '-an', '-t'], capture_output=True, text=True, timeout=10)

            lines = result.stdout.split('\n')

            for line in lines:
                for port in self.suspicious_ports:
                    if f":{port}" in line and "ESTABLISHED" in line:
                        # Parse connection info
                        parts = line.split()
                        if len(parts) >= 4:
                            local_addr, foreign_addr = parts[1], parts[2]

                            # Check if it's a new suspicious connection
                            if any(blocked.get('foreign_addr') == foreign_addr for blocked in self.blocked_connections):
                                continue

                            # Check if already detected
                            if not any(
                                    detected.get('foreign_addr') == foreign_addr for detected in self.detected_connections):
                                connection_info = {
                                    'timestamp': datetime.now().isoformat(),
                                    'local_addr': local_addr,
                                    'foreign_addr': foreign_addr,
                                    'port': port,
                                    'status': 'detected'
                                }
                                self.detected_connections.append(connection_info)
                                print(f"[WebSocket Detector] Suspicious WebSocket connection detected: {foreign_addr}")

                                # Auto-block if not in whitelist
                                if not self._is_whitelisted(foreign_addr):
                                    self.block_connection(foreign_addr, port)

            # Keep only recent connections (last 100)
            if len(self.detected_connections) > 100:
                self.detected_connections = self.detected_connections[-50:]

        except subprocess.TimeoutExpired:
            print("[WebSocket Detector] Connection check timed out")
        except Exception as e:
            print(f"[WebSocket Detector] Connection check error: {e}")

    def _is_whitelisted(self, address):
        """Check if address is in whitelist"""
        for whitelisted in self.whitelist:
            if whitelisted in address:
                return True
        return False

    def block_connection(self, foreign_addr, port):
        """Block a WebSocket connection"""
        try:
            # Add to blocked list
            block_info = {
                'timestamp': datetime.now().isoformat(),
                'foreign_addr': foreign_addr,
                'port': port,
                'action': 'blocked'
            }
            self.blocked_connections.append(block_info)

            print(f"[WebSocket Detector] Blocked WebSocket connection: {foreign_addr}:{port}")

            # Simulate blocking (in real implementation, you'd use firewall rules)
            self._simulate_block(foreign_addr, port)

            return True

        except Exception as e:
            print(f"[WebSocket Detector] Block error: {e}")
            return False

    def _simulate_block(self, foreign_addr, port):
        """Simulate blocking a connection"""
        try:
            # In a real implementation, you would:
            # 1. Add firewall rule to block the IP
            # 2. Kill the connection
            # 3. Notify security system

            print(f"[WebSocket Detector] SIMULATION: Blocked {foreign_addr} on port {port}")

            # For demonstration, we'll just log the action
            with open('websocket_blocks.log', 'a') as f:
                f.write(f"{datetime.now().isoformat()} - BLOCKED: {foreign_addr}:{port}\n")

        except Exception as e:
            print(f"[WebSocket Detector] Simulate block error: {e}")

    def get_detection_summary(self):
        """Get summary of detected and blocked connections"""
        return {
            'total_detected': len(self.detected_connections),
            'total_blocked': len(self.blocked_connections),
            'recent_detections': self.detected_connections[-10:],
            'recent_blocks': self.blocked_connections[-10:]
        }

    def manual_block(self, ip_address, port):
        """Manually block an IP address and port"""
        return self.block_connection(ip_address, port)


# Global detector instance
websocket_detector = WebSocketDetector()