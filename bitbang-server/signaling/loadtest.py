#!/usr/bin/env python3
"""Load test for the BitBang signaling server.

Simulates N devices registering and M clients connecting to each device.
Tests the full signaling flow (register, challenge, offer, answer) without
actual WebRTC — just the message relay path.

Usage:
    python loadtest.py                      # 10 devices, 1 client each
    python loadtest.py --devices 50         # 50 devices, 1 client each
    python loadtest.py --devices 20 --clients-per-device 5
    python loadtest.py --server localhost:8081
"""

import argparse
import asyncio
import base64
import hashlib
import json
import os
import ssl
import time
import statistics
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Disable SSL verification for local testing
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

try:
    import websockets
except ImportError:
    print("pip install websockets")
    raise SystemExit(1)


def generate_identity():
    """Generate an RSA key pair and derive UID."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    uid = hashlib.sha256(public_bytes).hexdigest()[:32]
    public_key_b64 = base64.b64encode(public_bytes).decode("ascii")
    return private_key, uid, public_key_b64


# Domain separation tag — must match AUTH_DOMAIN in signaling.py.
# Prevents cross-protocol attacks where a signature produced for auth could
# be reused as a signature in another context (e.g. firmware verification).
AUTH_DOMAIN = b"bitbang-auth-v1:"

# Must match PROTOCOL_VERSION in signaling.py
PROTOCOL_VERSION = 2


def sign_challenge(private_key, nonce):
    """Sign a domain-separated challenge nonce."""
    return private_key.sign(AUTH_DOMAIN + nonce, padding.PKCS1v15(), hashes.SHA256())


class Stats:
    def __init__(self):
        self.device_register_times = []
        self.client_connect_times = []
        self.device_failures = 0
        self.client_failures = 0

    def summary(self):
        lines = []
        lines.append(f"\n{'='*50}")
        lines.append(f"RESULTS")
        lines.append(f"{'='*50}")

        total_devices = len(self.device_register_times) + self.device_failures
        lines.append(f"Devices: {len(self.device_register_times)}/{total_devices} registered")
        if self.device_register_times:
            lines.append(f"  min: {min(self.device_register_times)*1000:.0f}ms  "
                         f"median: {statistics.median(self.device_register_times)*1000:.0f}ms  "
                         f"max: {max(self.device_register_times)*1000:.0f}ms")

        total_clients = len(self.client_connect_times) + self.client_failures
        lines.append(f"Clients: {len(self.client_connect_times)}/{total_clients} connected")
        if self.client_connect_times:
            lines.append(f"  min: {min(self.client_connect_times)*1000:.0f}ms  "
                         f"median: {statistics.median(self.client_connect_times)*1000:.0f}ms  "
                         f"max: {max(self.client_connect_times)*1000:.0f}ms")

        if self.device_failures or self.client_failures:
            lines.append(f"Failures: {self.device_failures} devices, {self.client_failures} clients")

        return "\n".join(lines)



async def simulate_client(server, uid, stats):
    """Simulate a client: connect, send request, receive offer, send answer."""
    uri = f"wss://{server}/ws/client/{uid}"

    t0 = time.time()
    try:
        async with websockets.connect(uri, ssl=SSL_CTX) as ws:
            # Send connection request
            await ws.send(json.dumps({"type": "request", "uid": uid}))

            # Wait for offer
            while True:
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
                if msg["type"] == "offer":
                    # Send fake answer
                    await ws.send(json.dumps({
                        "type": "answer",
                        "uid": uid,
                        "sdp": "v=0\r\nfake-answer-for-loadtest\r\n",
                    }))
                    elapsed = time.time() - t0
                    stats.client_connect_times.append(elapsed)
                    break
                elif msg["type"] == "error":
                    raise RuntimeError(msg.get("message", "connection error"))

    except Exception as e:
        stats.client_failures += 1
        print(f"  Client -> {uid[:8]} failed: {e}")


async def run_load_test(server, num_devices, clients_per_device, batch_size):
    stats = Stats()
    total_clients = num_devices * clients_per_device

    print(f"Target: wss://{server}")
    print(f"Devices: {num_devices}, Clients per device: {clients_per_device}")
    print(f"Total connections: {num_devices + total_clients}")
    print(f"Batch size: {batch_size}")
    print()

    # Generate all identities upfront (CPU-bound, no I/O)
    print(f"Generating {num_devices} RSA key pairs...")
    t0 = time.time()
    identities = [generate_identity() for _ in range(num_devices)]
    print(f"  Done in {time.time() - t0:.1f}s")

    # Phase 1: Register devices in batches
    print(f"Registering {num_devices} devices (batches of {batch_size})...")
    t0 = time.time()
    device_ready_events = [asyncio.Event() for _ in range(num_devices)]
    device_tasks = []

    for batch_start in range(0, num_devices, batch_size):
        batch_end = min(batch_start + batch_size, num_devices)
        batch_tasks = []
        for i in range(batch_start, batch_end):
            private_key, uid, pub_b64 = identities[i]
            task = asyncio.create_task(
                _run_device(server, private_key, uid, pub_b64,
                            stats, device_ready_events[i])
            )
            device_tasks.append(task)
            batch_tasks.append(device_ready_events[i].wait())
        await asyncio.gather(*batch_tasks)
        print(f"  {batch_end}/{num_devices} registered")

    reg_time = time.time() - t0
    print(f"  All devices registered in {reg_time:.1f}s")

    # Phase 2: Connect clients in batches
    if clients_per_device > 0:
        print(f"Connecting {total_clients} clients (batches of {batch_size})...")
        t1 = time.time()

        # Build list of all (uid, index) pairs
        client_targets = []
        for private_key, uid, _ in identities:
            for _ in range(clients_per_device):
                client_targets.append(uid)

        for batch_start in range(0, len(client_targets), batch_size):
            batch = client_targets[batch_start:batch_start + batch_size]
            await asyncio.gather(*[simulate_client(server, uid, stats) for uid in batch])
            done = min(batch_start + batch_size, len(client_targets))
            failed_so_far = stats.client_failures
            print(f"  {done}/{total_clients} done ({failed_so_far} failures)")

        client_time = time.time() - t1
        print(f"  All clients done in {client_time:.1f}s")

    # Clean up device tasks
    for task in device_tasks:
        task.cancel()
    await asyncio.gather(*device_tasks, return_exceptions=True)

    print(stats.summary())


async def _run_device(server, private_key, uid, public_key_b64, stats, ready_event):
    """Device simulation with pre-generated identity."""
    uri = f"wss://{server}/ws/device/{uid}"

    t0 = time.time()
    try:
        async with websockets.connect(uri, ssl=SSL_CTX) as ws:
            await ws.send(json.dumps({
                "type": "register",
                "uid": uid,
                "public_key": public_key_b64,
                "protocol": PROTOCOL_VERSION,
            }))

            while True:
                msg = json.loads(await ws.recv())
                if msg["type"] == "challenge":
                    nonce = base64.b64decode(msg["nonce"])
                    sig = sign_challenge(private_key, nonce)
                    await ws.send(json.dumps({
                        "type": "challenge_response",
                        "signature": base64.b64encode(sig).decode("ascii"),
                    }))
                elif msg["type"] == "registered":
                    stats.device_register_times.append(time.time() - t0)
                    ready_event.set()
                    break
                elif msg["type"] == "error":
                    raise RuntimeError(msg.get("message", "registration error"))

            # Handle client requests until cancelled
            while True:
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=60))
                if msg["type"] == "request":
                    await ws.send(json.dumps({
                        "type": "offer",
                        "sdp": "v=0\r\nfake-sdp\r\n",
                        "client_id": msg["client_id"],
                        "streams": {},
                    }))
                elif msg["type"] == "answer":
                    pass
                elif msg["type"] == "candidate":
                    pass

    except asyncio.CancelledError:
        pass  # Normal shutdown
    except asyncio.TimeoutError:
        pass  # No more clients
    except Exception as e:
        stats.device_failures += 1
        print(f"  Device {uid[:8]} failed: {e}")
        ready_event.set()  # Unblock waiters


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BitBang signaling server load test")
    parser.add_argument("--server", default="localhost:8081", help="Server host:port")
    parser.add_argument("--devices", type=int, default=10, help="Number of devices")
    parser.add_argument("--clients-per-device", type=int, default=1, help="Clients per device")
    parser.add_argument("--batch", type=int, default=50, help="Concurrent connections per batch")
    args = parser.parse_args()

    asyncio.run(run_load_test(args.server, args.devices, args.clients_per_device, args.batch))
