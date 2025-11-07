"""
client.py -- Keystroke WebSocket client (no Flask)

Usage:
    python client.py --server ws://192.168.43.102:8765
"""

import argparse
import asyncio
import json
import sys
import time
import websockets

parser = argparse.ArgumentParser()
parser.add_argument("--server", required=True, help="WebSocket server URL e.g. ws://10.209.25.68:8765")
parser.add_argument("--reconnect-delay", type=float, default=2.0)
args = parser.parse_args()


async def listen_forever(server_url, reconnect_delay=2.0):
    """Connect to a WebSocket server and print received messages indefinitely."""
    uri = server_url
    while True:
        try:
            print(f"[client] Connecting to {uri} ...")
            async with websockets.connect(uri) as ws:
                print("[client] Connected. Waiting for keystroke events...")
                async for msg in ws:
                    try:
                        evt = json.loads(msg)
                    except Exception:
                        print("[client] non-json:", msg)
                        continue
                    ts = evt.get("timestamp")
                    kind = evt.get("kind")
                    key = evt.get("key")
                    print(f"[{ts}] ({kind}) -> {key}")
        except KeyboardInterrupt:
            print("[client] Interrupted by user. Exiting.")
            return
        except Exception as e:
            print(f"[client] Connection error: {e}. Reconnecting in {reconnect_delay}s ...")
            time.sleep(reconnect_delay)

def attack_function():
    """
    Simulate attack data continuously.
    Replace this with your real attack logic.
    """
    i = 0
    while True:
        i += 1
        yield f"Simulated attack event #{i}"
        time.sleep(1)


if __name__ == "__main__":
    try:
        asyncio.run(listen_forever(args.server, args.reconnect_delay))
    except Exception as e:
        print("Fatal:", e)
        sys.exit(1)
