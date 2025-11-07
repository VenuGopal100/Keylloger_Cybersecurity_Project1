"""
security_dashboard.py - Security monitoring dashboard with WebSocket detection
"""
from flask import Blueprint, render_template, jsonify, session, redirect, url_for, request
import json
import threading
from datetime import datetime, timedelta
import hashlib
import re
import random

security_bp = Blueprint('security', __name__)

# Security monitoring data
security_monitor = {
    'data_flow_detected': False,
    'encryption_status': 'active',
    'sensitive_data_blocked': 0,
    'connections_monitored': 0,
    'on_screen_keyboard_triggered': 0,
    'websocket_connections_detected': 0,
    'websocket_connections_blocked': 0,
    'protection_enabled': False,  # Track protection status - OFF by default
    'alerts': []
}


class SimpleWebSocketDetector:
    def __init__(self):
        self.detected_connections = []
        self.blocked_connections = []
        self.monitoring = False

    def start_monitoring(self):
        """Start monitoring for WebSocket connections"""
        self.monitoring = True
        print("[WebSocket Detector] Monitoring started")

    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False

    def get_detection_summary(self):
        """Get summary of detected and blocked connections"""
        # Generate some simulated detection data for demo
        if not self.detected_connections:
            self._generate_sample_data()

        return {
            'total_detected': len(self.detected_connections),
            'total_blocked': len(self.blocked_connections),
            'recent_detections': self.detected_connections[-10:],
            'recent_blocks': self.blocked_connections[-10:]
        }

    def manual_block(self, ip_address, port):
        """Manually block an IP address and port"""
        try:
            # Add to blocked list
            block_info = {
                'timestamp': datetime.now().isoformat(),
                'foreign_addr': ip_address,
                'port': port,
                'action': 'blocked'
            }
            self.blocked_connections.append(block_info)

            # Also add to detected connections if not already there
            if not any(det['foreign_addr'] == ip_address for det in self.detected_connections):
                detection_info = {
                    'timestamp': datetime.now().isoformat(),
                    'foreign_addr': ip_address,
                    'port': port,
                    'status': 'detected'
                }
                self.detected_connections.append(detection_info)

            print(f"[WebSocket Detector] Blocked connection: {ip_address}:{port}")
            return True
        except Exception as e:
            print(f"[WebSocket Detector] Block error: {e}")
            return False

    def _generate_sample_data(self):
        """Generate sample WebSocket detection data for demonstration"""
        sample_ips = [
            '192.168.1.100:8765',
            '10.0.0.15:8888',
            '172.16.254.1:8765',
            '203.0.113.5:8080'
        ]

        for ip_port in sample_ips[:2]:  # Add 2 sample detections
            ip, port = ip_port.split(':')
            detection = {
                'timestamp': datetime.now().isoformat(),
                'foreign_addr': f"{ip}:{port}",
                'port': int(port),
                'status': 'detected'
            }
            self.detected_connections.append(detection)


class SecurityMonitor:
    def __init__(self):
        self.detected_flows = []
        self.security_events = []
        self.sensitive_fields_detected = []
        self.current_context = ''
        self.keystroke_history = []  # Store recent keystrokes
        self.websocket_detector = SimpleWebSocketDetector()

        # Start WebSocket detection
        self.websocket_detector.start_monitoring()

        self.start_monitoring()

    def detect_data_flow(self, data):
        """Detect and log data flow"""
        flow_event = {
            'timestamp': datetime.now().isoformat(),
            'data_type': 'keystroke' if data.get('kind') == 'char' else 'special_key',
            'key': data.get('key', ''),
            'original_key': data.get('original_key', ''),
            'encrypted': True,
            'sensitive_content': self.check_sensitivity(data.get('key', '')),
            'protected': data.get('protected', False),
            'on_screen_recommended': self.should_trigger_on_screen_keyboard(data)
        }
        self.detected_flows.append(flow_event)
        self.keystroke_history.append(flow_event)

        # Keep only recent history
        if len(self.keystroke_history) > 50:
            self.keystroke_history.pop(0)

        security_monitor['data_flow_detected'] = True
        security_monitor['connections_monitored'] += 1

        # Keep only last 100 events
        if len(self.detected_flows) > 100:
            self.detected_flows.pop(0)

    def check_sensitivity(self, key_data):
        """Check if data contains sensitive information"""
        sensitive_terms = ['password', 'credit', 'ssn', 'bank', 'login', 'secret', 'pin', 'cvv']
        key_str = str(key_data).lower()
        if any(term in key_str for term in sensitive_terms):
            security_monitor['sensitive_data_blocked'] += 1
            return True
        return False

    def should_trigger_on_screen_keyboard(self, data):
        """Check if this keystroke should trigger on-screen keyboard warning"""
        sensitive_contexts = [
            'password', 'pwd', 'pass', 'secret', 'pin', 'cvv',
            'credit', 'card', 'ssn', 'social', 'security'
        ]

        # Check if we're in a sensitive context (you would track this from the client)
        current_context = getattr(self, 'current_context', '')
        if any(context in current_context.lower() for context in sensitive_contexts):
            return True
        return False

    def add_security_alert(self, alert_type, message):
        """Add security alert"""
        alert = {
            'type': alert_type,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'severity': 'high' if 'breach' in alert_type else 'medium'
        }
        security_monitor['alerts'].append(alert)

        # Keep only last 50 alerts
        if len(security_monitor['alerts']) > 50:
            security_monitor['alerts'].pop(0)

    def trigger_on_screen_keyboard(self, field_type, context):
        """Trigger on-screen keyboard recommendation"""
        security_monitor['on_screen_keyboard_triggered'] += 1
        self.add_security_alert(
            'on_screen_keyboard_recommended',
            f'Use on-screen keyboard for {field_type} field: {context}'
        )
        return True

    def detect_sensitive_field(self, field_info):
        """Detect when user is entering sensitive field"""
        field_type = field_info.get('type', '')
        field_name = field_info.get('name', '')
        field_id = field_info.get('id', '')

        sensitive_indicators = [
            'password', 'pwd', 'pass', 'pin', 'cvv', 'security',
            'credit', 'card', 'ssn', 'social', 'bank', 'account'
        ]

        field_combined = f"{field_type} {field_name} {field_id}".lower()

        for indicator in sensitive_indicators:
            if indicator in field_combined:
                self.sensitive_fields_detected.append({
                    'timestamp': datetime.now().isoformat(),
                    'field_type': field_type,
                    'field_name': field_name,
                    'recommendation': 'USE ON-SCREEN KEYBOARD'
                })
                self.trigger_on_screen_keyboard(indicator, field_combined)
                return True
        return False

    def start_monitoring(self):
        """Start background security monitoring"""

        def monitor_loop():
            while True:
                try:
                    # Update WebSocket detection stats
                    ws_summary = self.websocket_detector.get_detection_summary()
                    security_monitor['websocket_connections_detected'] = ws_summary['total_detected']
                    security_monitor['websocket_connections_blocked'] = ws_summary['total_blocked']

                    # Add alerts for new WebSocket detections
                    for detection in ws_summary['recent_detections'][-3:]:  # Last 3 detections
                        if detection.get('status') == 'detected':
                            self.add_security_alert(
                                'websocket_detected',
                                f'Suspicious WebSocket connection from {detection["foreign_addr"]}'
                            )
                            detection['status'] = 'alerted'  # Mark as alerted

                    # Simulate occasional new detections
                    if random.random() < 0.1:  # 10% chance each cycle
                        self._simulate_new_detection()

                    threading.Event().wait(5)
                except Exception as e:
                    print(f"Security monitoring error: {e}")
                    threading.Event().wait(5)

        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()

    def _simulate_new_detection(self):
        """Simulate new WebSocket detection for demo purposes"""
        sample_ips = [
            ('192.168.1.' + str(random.randint(100, 200)), 8765),
            ('10.0.1.' + str(random.randint(1, 50)), 8888),
            ('172.16.' + str(random.randint(1, 255)) + '.' + str(random.randint(1, 255)), 8765)
        ]

        ip, port = random.choice(sample_ips)
        detection = {
            'timestamp': datetime.now().isoformat(),
            'foreign_addr': f"{ip}:{port}",
            'port': port,
            'status': 'detected'
        }
        self.websocket_detector.detected_connections.append(detection)


# Global security monitor instance
security_monitor_instance = SecurityMonitor()


@security_bp.route('/dashboard')
def security_dashboard():
    """Main security dashboard page"""
    if "username" not in session:
        return redirect(url_for('login'))
    return render_template('security_dashboard.html')


@security_bp.route('/security-data')
def security_data():
    """API endpoint for security data"""
    try:
        ws_summary = security_monitor_instance.websocket_detector.get_detection_summary()

        # Calculate data flow rate (simple simulation)
        data_flow_rate = len(security_monitor_instance.keystroke_history) // 2

        return jsonify({
            'data_flow_detected': security_monitor['data_flow_detected'],
            'data_flow_rate': data_flow_rate,
            'encryption_status': security_monitor['encryption_status'],
            'sensitive_data_blocked': security_monitor['sensitive_data_blocked'],
            'connections_monitored': security_monitor['connections_monitored'],
            'on_screen_keyboard_triggered': security_monitor['on_screen_keyboard_triggered'],
            'websocket_connections_detected': security_monitor['websocket_connections_detected'],
            'websocket_connections_blocked': security_monitor['websocket_connections_blocked'],
            'protection_enabled': security_monitor['protection_enabled'],
            'recent_alerts': security_monitor['alerts'][-5:],  # Last 5 alerts
            'recent_keystrokes': security_monitor_instance.keystroke_history[-10:],  # Last 10 keystrokes
            'total_protection_events': len(security_monitor_instance.detected_flows),
            'sensitive_fields_detected': security_monitor_instance.sensitive_fields_detected[-10:],
            'websocket_detections': ws_summary['recent_detections'][-5:],
            'websocket_blocks': ws_summary['recent_blocks'][-5:],
            'data_flow_history': [{'rate': data_flow_rate, 'blocked': security_monitor['sensitive_data_blocked']}],
            'protection_active': security_monitor['protection_enabled']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/trigger-protection')
def trigger_protection():
    """Manually trigger protection demonstration"""
    security_monitor_instance.add_security_alert(
        'protection_activated',
        'User manually activated enhanced data protection'
    )
    return jsonify({'status': 'protection_activated'})


@security_bp.route('/toggle-protection', methods=['POST'])
def toggle_protection():
    """Toggle keystroke protection on/off"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        enable = data.get('enable', True)
        security_monitor['protection_enabled'] = enable

        # Import and update server protection status
        try:
            # Import the server module and call set_protection_status
            import sys
            import os
            # Add the current directory to Python path to find server module
            current_dir = os.path.dirname(os.path.abspath(__file__))
            if current_dir not in sys.path:
                sys.path.insert(0, current_dir)

            from server import set_protection_status
            set_protection_status(enable)
        except ImportError as e:
            print(f"Warning: Could not import server module to update protection status: {e}")
            # Fallback: we'll still update the security_monitor state
        except Exception as e:
            print(f"Error updating server protection status: {e}")

        # Add security alert
        status = "ENABLED" if enable else "DISABLED"
        security_monitor_instance.add_security_alert(
            'protection_toggled',
            f'Keystroke protection {status}. ' +
            (
                'Sending only "#" characters to remote clients.' if enable else 'Sending actual keystroke data to remote clients.')
        )

        return jsonify({
            'success': True,
            'message': f'Keystroke protection {status}. ' +
                       (
                           'Remote clients will see only "#" characters.' if enable else 'Remote clients will see actual keystrokes.'),
            'protection_enabled': enable
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/data-flow-logs')
def data_flow_logs():
    """Get data flow detection logs"""
    return jsonify({
        'detected_flows': security_monitor_instance.detected_flows[-20:],  # Last 20 flows
        'total_flows_detected': len(security_monitor_instance.detected_flows)
    })


@security_bp.route('/detect-sensitive-field', methods=['POST'])
def detect_sensitive_field():
    """API to detect sensitive field entry"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        field_detected = security_monitor_instance.detect_sensitive_field(data)
        return jsonify({
            'sensitive_field_detected': field_detected,
            'recommendation': 'USE_ON_SCREEN_KEYBOARD' if field_detected else 'NONE'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/block-websocket', methods=['POST'])
def block_websocket():
    """Manually block a WebSocket connection"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        ip_address = data.get('ip_address', '')
        port = data.get('port', 8765)

        if ip_address:
            success = security_monitor_instance.websocket_detector.manual_block(ip_address, port)
            if success:
                security_monitor_instance.add_security_alert(
                    'websocket_blocked',
                    f'Manually blocked WebSocket connection: {ip_address}:{port}'
                )

            return jsonify({
                'success': success,
                'message': f'Blocked {ip_address}:{port}' if success else 'Block failed'
            })

        return jsonify({'success': False, 'message': 'No IP address provided'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/websocket-status')
def websocket_status():
    """Get WebSocket detection status"""
    summary = security_monitor_instance.websocket_detector.get_detection_summary()
    return jsonify(summary)