
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for sessions

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import and register security dashboard
try:
    from security_dashboard import security_bp

    app.register_blueprint(security_bp)
    logger.info("Security dashboard blueprint registered successfully")
except ImportError as e:
    logger.error(f"Failed to import security dashboard: {e}")
except Exception as e:
    logger.error(f"Error registering security blueprint: {e}")

# Create a simple WebSocket detector replacement
class SimpleWebSocketDetector:
    def __init__(self):
        self.detected_connections = []
        self.blocked_connections = []
        self.monitoring = False

    def start_monitoring(self):
        """Start monitoring for WebSocket connections"""
        self.monitoring = True
        logger.info("Simple WebSocket monitoring started")

    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False

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
        try:
            # Add to blocked list
            block_info = {
                'timestamp': '2023-01-01T00:00:00',  # Placeholder timestamp
                'foreign_addr': ip_address,
                'port': port,
                'action': 'blocked'
            }
            self.blocked_connections.append(block_info)
            logger.info(f"Blocked WebSocket connection: {ip_address}:{port}")
            return True
        except Exception as e:
            logger.error(f"Block error: {e}")
            return False

# Create global detector instance
websocket_detector = SimpleWebSocketDetector()

# Dummy users for demonstration
USERS = {
    "admin": "password123",
    "user": "userpass"
}

# Template directory configuration
app.template_folder = 'templates'


# --------- Routes ---------

# Login page
@app.route("/", methods=["GET", "POST"])
def login():
    try:
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()

            if not username or not password:
                flash("Please enter both username and password", "danger")
                return render_template("login.html")

            if username in USERS and USERS[username] == password:
                session["username"] = username
                flash(f"Welcome {username}!", "success")
                return redirect(url_for("selection"))
            else:
                flash("Invalid username or password", "danger")

        return render_template("login.html")
    except Exception as e:
        logger.error(f"Login error: {e}")
        flash("An error occurred during login", "danger")
        return render_template("login.html")


# Simulation selection page
@app.route("/selection")
def selection():
    if "username" not in session:
        flash("Please log in first", "warning")
        return redirect(url_for("login"))

    try:
        return render_template("selection.html")
    except Exception as e:
        logger.error(f"Selection page error: {e}")
        flash("Error loading selection page", "danger")
        return redirect(url_for("login"))


# Banking simulation
@app.route("/bank")
def bank():
    if "username" not in session:
        flash("Please log in first", "warning")
        return redirect(url_for("login"))

    try:
        return render_template("bank.html")
    except Exception as e:
        logger.error(f"Bank page error: {e}")
        flash("Error loading banking simulation", "danger")
        return redirect(url_for("selection"))


# Keylogger simulation (safe demo)
@app.route("/keylogger")
def keylogger():
    if "username" not in session:
        flash("Please log in first", "warning")
        return redirect(url_for("login"))

    try:
        return render_template("keylogger.html")
    except Exception as e:
        logger.error(f"Keylogger page error: {e}")
        flash("Error loading keylogger simulation", "danger")
        return redirect(url_for("selection"))


# Chat simulation
@app.route("/chat")
def chat():
    if "username" not in session:
        flash("Please log in first", "warning")
        return redirect(url_for("login"))

    try:
        return render_template("chat.html")
    except Exception as e:
        logger.error(f"Chat page error: {e}")
        flash("Error loading chat simulation", "danger")
        return redirect(url_for("selection"))


# Security Dashboard
@app.route("/security")
def security():
    if "username" not in session:
        flash("Please log in first", "warning")
        return redirect(url_for("login"))

    try:
        return render_template("security_dashboard.html")
    except Exception as e:
        logger.error(f"Security dashboard error: {e}")
        flash("Error loading security dashboard", "danger")
        return redirect(url_for("selection"))


# On-Screen Keyboard
@app.route("/on-screen-keyboard")
def on_screen_keyboard():
    """On-screen keyboard page"""
    if "username" not in session:
        flash("Please log in first", "warning")
        return redirect(url_for("login"))

    try:
        return render_template("on_screen_keyboard.html")
    except Exception as e:
        logger.error(f"On-screen keyboard page error: {e}")
        flash("Error loading on-screen keyboard", "danger")
        return redirect(url_for("selection"))


# WebSocket Detection Status
@app.route("/websocket-status")
def websocket_status_page():
    """WebSocket detection status page"""
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        summary = websocket_detector.get_detection_summary()
        return jsonify(summary)
    except Exception as e:
        logger.error(f"WebSocket status error: {e}")
        return jsonify({"error": "Failed to get WebSocket status"}), 500


# Logout
@app.route("/logout")
def logout():
    try:
        username = session.get("username", "User")
        session.pop("username", None)
        flash(f"Goodbye {username}! You have been logged out.", "info")
    except Exception as e:
        logger.error(f"Logout error: {e}")
        flash("Error during logout", "warning")

    return redirect(url_for("login"))


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error="Page not found"), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error="Internal server error"), 500


# Health check endpoint
@app.route("/health")
def health_check():
    return jsonify({"status": "healthy", "service": "client_app"})


# --------- Run App ---------
if __name__ == "__main__":
    try:
        # Start WebSocket detection when app starts
        websocket_detector.start_monitoring()
        logger.info("WebSocket monitoring started")

        # Run the Flask app
        app.run(host="0.0.0.0", port=5000, debug=True)

    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        print(f"Critical error: {e}")
