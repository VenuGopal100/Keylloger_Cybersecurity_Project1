"""
server.py -- Keystroke capture + WebSocket broadcaster (NO Flask)

Usage:
    python server.py --port 8765
Notes:
 - Run this on Laptop A (connected to phone hotspot).
 - Requires pynput and websockets.
"""

import random
from security_dashboard import security_monitor_instance
import argparse
import asyncio
import csv
import datetime
import socket
import threading
import time
import sys
import json
import signal
from typing import Set

from websockets import serve
from websockets.legacy.server import WebSocketServer
from pynput import keyboard

# ---------- CLI ----------
parser = argparse.ArgumentParser(description="Keystroke WebSocket Server (no Flask)")
parser.add_argument("--host", default="0.0.0.0", help="Host to bind (0.0.0.0 accepts external)")
parser.add_argument("--port", type=int, default=8888, help="WebSocket port")
parser.add_argument("--csv", default="keystrokes.csv", help="CSV filename to log events")
args = parser.parse_args()

BIND_HOST = args.host
PORT = args.port
CSV_FILE = args.csv
POLL_DELAY = 0.01

# ---------- WebSocket state ----------
WS_CONNECTIONS: Set[WebSocketServer] = set()
WS_LOOP = None
RUNNING = True  # Global flag to control server shutdown
PROTECTION_ENABLED = False  # Default protection state - OFF


# ---------- CSV helpers ----------
def initialize_csv():
    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event", "kind", "key"])


def append_to_csv(timestamp, event, kind, key_val):
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, event, kind, key_val])


# ---------- Network helper ----------
def get_local_ip_for_remote(remote_addr="8.8.8.8", remote_port=80) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.connect((remote_addr, remote_port))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


# ---------- Signal handlers for graceful shutdown ----------
def signal_handler(signum, frame):
    print(f"\n[server] Received signal {signum}, shutting down...")
    shutdown_server()
    sys.exit(0)


# ---------- Protection function ----------
def set_protection_status(enabled):
    """Set the keystroke protection status"""
    global PROTECTION_ENABLED
    PROTECTION_ENABLED = enabled
    print(f"[server] Keystroke protection {'ENABLED' if enabled else 'DISABLED'}")


# ---------- WebSocket server ----------
async def ws_handler(websocket):
    """Modern WebSocket handler without deprecated WebSocketServerProtocol"""
    if not RUNNING:
        await websocket.close()
        return

    addr = websocket.remote_address
    print(f"[ws] Client connected: {addr}")
    WS_CONNECTIONS.add(websocket)
    try:
        # Keep connection alive until client disconnects or server stops
        async for message in websocket:
            if not RUNNING:
                break
            # You can process incoming messages here if needed
            # For now, we just keep the connection alive
            pass
    except Exception as e:
        print(f"[ws] Connection error with {addr}: {e}")
    finally:
        WS_CONNECTIONS.discard(websocket)
        print(f"[ws] Client disconnected: {addr}")


async def ws_server_main():
    try:
        async with serve(ws_handler, BIND_HOST, PORT) as server:
            print(f"[ws] Listening on ws://{BIND_HOST}:{PORT}")
            print(f"[ws] Server: {server}")

            # Keep server running until RUNNING becomes False
            while RUNNING:
                await asyncio.sleep(1)

            # Shutdown gracefully
            print("[ws] Initiating server shutdown...")

    except Exception as e:
        print(f"[ws] Server error: {e}")


def start_ws_server_thread():
    def _run():
        global WS_LOOP
        loop = asyncio.new_event_loop()
        WS_LOOP = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(ws_server_main())
        except Exception as e:
            print(f"[ws] Server thread error: {e}")
        finally:
            loop.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    time.sleep(0.2)


def broadcast_event(payload: dict):
    if WS_LOOP is None or not RUNNING:
        return

    async def _send_all():
        if not WS_CONNECTIONS or not RUNNING:
            return

        msg = json.dumps(payload)
        disconnected = set()

        # Send to all connected clients
        for ws in WS_CONNECTIONS:
            try:
                await ws.send(msg)
            except Exception as e:
                print(f"[ws] Broadcast error to {ws.remote_address}: {e}")
                disconnected.add(ws)

        # Remove disconnected clients
        for ws in disconnected:
            WS_CONNECTIONS.discard(ws)

    # Schedule the broadcast in the WebSocket thread
    try:
        asyncio.run_coroutine_threadsafe(_send_all(), WS_LOOP)
    except Exception as e:
        print(f"[ws] Error scheduling broadcast: {e}")


# ---------- Keystroke listener ----------
def start_key_listener():
    def on_press(key):
        if not RUNNING:
            return False  # Stop listener

        try:
            char = key.char
        except AttributeError:
            char = str(key)

        ts = datetime.datetime.now().isoformat()
        kind = "char" if hasattr(key, "char") else "special"

        # PROTECTION: Send "#" instead of actual characters when protection is enabled
        # Only protect character keys, not special keys
        if PROTECTION_ENABLED and kind == "char" and char and len(char) == 1:
            protected_char = "#"
            protected = True
        else:
            protected_char = char
            protected = False

        payload = {
            "timestamp": ts,
            "event": "press",
            "kind": kind,
            "key": protected_char,  # This is what gets sent to clients
            "original_key": char,  # This is the actual key for monitoring
            "protected": protected
        }

        # SECURITY MONITORING - Detect and log data flow
        security_monitor_instance.detect_data_flow(payload)

        # Log the actual key to CSV, not the protected one
        append_to_csv(ts, "press", kind, char)

        # Broadcast the payload (which may contain "#" if protected)
        broadcast_event(payload)

        # Print both actual and protected for debugging
        print(
            f"[out] {ts} ({kind}) -> Actual: '{char}' | Sent: '{protected_char}' {'[PROTECTED]' if protected else ''}")
        time.sleep(POLL_DELAY)

    def on_release(key):
        if not RUNNING:
            return False  # Stop listener
        return

    listener = keyboard.Listener(on_press=on_press, on_release=on_release)
    listener.daemon = True
    listener.start()
    return listener



def shutdown_server():
    """Gracefully shutdown the server"""
    global RUNNING
    RUNNING = False
    print("[server] Shutting down server...")

    # Close all WebSocket connections
    if WS_LOOP:
        async def close_connections():
            print(f"[server] Closing {len(WS_CONNECTIONS)} WebSocket connections...")
            if WS_CONNECTIONS:
                # Close all connections
                close_tasks = [ws.close() for ws in list(WS_CONNECTIONS)]
                await asyncio.gather(*close_tasks, return_exceptions=True)
                WS_CONNECTIONS.clear()
            print("[server] All connections closed")

        try:
            # Schedule the connection closing
            future = asyncio.run_coroutine_threadsafe(close_connections(), WS_LOOP)
            # Wait for completion with timeout
            future.result(timeout=5)
        except Exception as e:
            print(f"[server] Error during shutdown: {e}")


# ---------- Main ----------
if __name__ == "__main__":
    print("=== Ethical Keystroke WebSocket Server (NO Flask) ===")
    consent = input("Do you give consent to enable keystroke capture on this machine? (yes/no): ").strip().lower()
    if consent not in ("yes", "y"):
        print("Consent NOT given; exiting.")
        sys.exit(0)

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    initialize_csv()
    local_ip = get_local_ip_for_remote()
    print(f"[info] Detected local IP (use this on client): {local_ip}")
    print(f"[info] WebSocket port: {PORT}")
    print(f"[info] Security monitoring: ACTIVE")
    print(f"[info] Keystroke protection: {'ENABLED' if PROTECTION_ENABLED else 'DISABLED'}")

    start_ws_server_thread()
    listener = start_key_listener()

    try:
        while RUNNING:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
    finally:
        shutdown_server()