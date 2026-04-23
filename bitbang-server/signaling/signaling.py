from quart import Quart, send_file, websocket, jsonify
import time
import traceback
import logging
from hypercorn.asyncio import serve
from hypercorn.config import Config
import asyncio
import json
import uuid
import signal
import os
import re
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

log = logging.getLogger('bitbang')

# UID format: 32 hex characters (128-bit hash of public key)
UID_PATTERN = re.compile(r'^[a-f0-9]{32}$')


def validate_uid(uid: str) -> bool:
    """Check if UID matches expected format."""
    return bool(UID_PATTERN.match(uid))


def uid_from_public_key_bytes(public_bytes: bytes) -> str:
    """Derive UID from DER-encoded public key."""
    return hashlib.sha256(public_bytes).hexdigest()[:32]


def verify_signature(public_key, nonce: bytes, signature: bytes) -> bool:
    """Verify challenge signature."""
    try:
        public_key.verify(
            signature,
            nonce,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


VERSION = '0.1.0'

HOST = '0.0.0.0'
HTML_PORT = int(os.environ.get('PORT', '8081'))

# SWSP protocol versioning. PROTOCOL_VERSION is what this server supports.
# MINIMUM_PROTOCOL_VERSION is the oldest version accepted from devices.
# Devices below the minimum receive a 'protocol_too_old' error with no retry.
PROTOCOL_VERSION = 1
MINIMUM_PROTOCOL_VERSION = 1


class SignalingServer:
    def __init__(self):
        self.app = Quart(__name__, template_folder='.')
        self.devices = {}            # uid -> websocket
        self.device_ice_servers = {} # uid -> ice_servers list (custom TURN config)
        self.clients = {}            # client_id -> websocket
        self.shutdown_event = None

        # Coturn TURN REST API — generates ephemeral credentials per connection
        self.coturn_host = os.environ.get('COTURN_HOST')
        self.coturn_secret = os.environ.get('COTURN_SECRET')
        self.coturn_ttl = int(os.environ.get('COTURN_TTL', '86400'))

        self._register_routes()

    # -- Routes -----------------------------------------------------------

    def _register_routes(self):
        @self.app.route('/favicon.ico')
        async def favicon():
            return await send_file('favicon.png', mimetype='image/png')

        @self.app.route('/status')
        async def status():
            return jsonify({
                'version': VERSION,
                'protocol': PROTOCOL_VERSION,
                'min_protocol': MINIMUM_PROTOCOL_VERSION,
                'devices': len(self.devices),
                'clients': len(self.clients),
            })

        @self.app.route('/__bitbang__/<path:filename>')
        async def bitbang_assets(filename):
            if filename == 'favicon.ico':
                return await send_file('favicon.png', mimetype='image/png')
            if filename in ('sw.js', 'bootstrap.js', 'ws-shim.js', 'xhr-shim.js'):
                response = await send_file(filename)
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                if filename == 'sw.js':
                    response.headers['Service-Worker-Allowed'] = '/'
                return response
            return 'Not found', 404

        @self.app.route('/<uid>', strict_slashes=False)
        @self.app.route('/<uid>/<path:subpath>')
        async def uid_route(uid, subpath=None):
            if uid.endswith(".js"):
                return await send_file(uid)
            return await send_file('bootstrap.html')

        @self.app.websocket('/ws/device/<uid>')
        async def ws_device(uid):
            await self._handle_device_connection(uid)

        @self.app.websocket('/ws/client/<uid>')
        async def ws_client(uid):
            await self._handle_client_connection(uid)

    # -- Helpers ----------------------------------------------------------

    async def _send_error(self, ws, message):
        await ws.send(json.dumps({'type': 'error', 'message': message}))

    async def _forward_to_device(self, target_uid, msg):
        """Forward a message to a device. Returns True on success.
        Removes the device from the registry if the send fails."""
        if target_uid not in self.devices:
            return False
        try:
            await self.devices[target_uid].send(json.dumps(msg))
            return True
        except Exception:
            del self.devices[target_uid]
            return False

    # -- Device authentication --------------------------------------------

    async def _authenticate_device(self, uid, ws):
        """Validate UID, verify public key ownership via challenge-response.
        Returns the register message on success, None on failure."""
        if not validate_uid(uid):
            await self._send_error(ws, 'Invalid UID format')
            return None

        data = await ws.receive()
        msg = json.loads(data)

        if msg.get('type') != 'register':
            await self._send_error(ws, 'Expected register message')
            return None

        # Check protocol version
        device_protocol = msg.get('protocol', 0)
        if device_protocol < MINIMUM_PROTOCOL_VERSION:
            log.warning(f"Device {uid}: protocol {device_protocol} < minimum {MINIMUM_PROTOCOL_VERSION}")
            await self._send_error(ws, 'protocol_too_old')
            return None

        public_key_b64 = msg.get('public_key')
        if not public_key_b64:
            await self._send_error(ws, 'Missing public_key')
            return None

        try:
            public_bytes = base64.b64decode(public_key_b64)
            derived_uid = uid_from_public_key_bytes(public_bytes)
        except Exception:
            await self._send_error(ws, 'Invalid public_key format')
            return None

        if derived_uid != uid:
            await self._send_error(ws, 'UID does not match public key')
            return None

        # Issue challenge
        public_key = serialization.load_der_public_key(public_bytes, backend=default_backend())
        nonce = os.urandom(32)
        await ws.send(json.dumps({
            'type': 'challenge',
            'nonce': base64.b64encode(nonce).decode('ascii')
        }))

        data = await ws.receive()
        resp = json.loads(data)

        if resp.get('type') != 'challenge_response':
            await self._send_error(ws, 'Expected challenge_response')
            return None

        try:
            signature = base64.b64decode(resp['signature'])
        except Exception:
            await self._send_error(ws, 'Invalid signature format')
            return None

        if not verify_signature(public_key, nonce, signature):
            await self._send_error(ws, 'Invalid signature')
            return None

        return msg

    # -- Device connection handler ----------------------------------------

    async def _handle_device_connection(self, uid):
        connect_time = time.time()
        my_ws = websocket._get_current_object()

        try:
            reg_msg = await self._authenticate_device(uid, websocket)
            if not reg_msg:
                return

            # Reject if another instance is already connected with this UID
            if uid in self.devices:
                log.warning(f"Device {uid}: Rejected - already connected")
                await self._send_error(websocket, 'UID already connected')
                return

            # Register device
            self.devices[uid] = my_ws
            custom_ice = reg_msg.get('ice_servers')
            if custom_ice:
                self.device_ice_servers[uid] = custom_ice
                log.info(f"Device registered: {uid} (custom TURN) at {time.strftime('%H:%M:%S')}")
            else:
                self.device_ice_servers.pop(uid, None)
                log.info(f"Device registered: {uid} at {time.strftime('%H:%M:%S')}")
            await websocket.send(json.dumps({'type': 'registered'}))

            # Message relay loop
            await self._device_message_loop(uid)

        except asyncio.CancelledError:
            duration = time.time() - connect_time
            log.info(f"Device {uid}: Shutting down after {duration:.0f}s")
        except Exception as e:
            duration = time.time() - connect_time
            log.error(f"Device {uid}: Fatal error after {duration:.0f}s: {e}")
            traceback.print_exc()
        finally:
            if uid in self.devices and self.devices[uid] == my_ws:
                del self.devices[uid]
                self.device_ice_servers.pop(uid, None)
                duration = time.time() - connect_time
                log.info(f"Device disconnected: {uid} (was connected for {duration:.0f}s)")

    async def _device_message_loop(self, uid):
        """Relay messages from device to the appropriate client."""
        while True:
            try:
                data = await websocket.receive()
                msg = json.loads(data)
                msg_type = msg.get('type')
                client_id = msg.get('client_id')

                if msg_type == 'offer':
                    if client_id and client_id in self.clients:
                        forward_msg = {
                            'type': 'offer',
                            'sdp': msg['sdp'],
                            'client_id': client_id,
                            'streams': msg.get('streams', {}),
                            'ice_servers': self.get_ice_servers_for_device(uid),
                        }
                        if 'device_name' in msg:
                            forward_msg['device_name'] = msg['device_name']
                        await self.clients[client_id].send(json.dumps(forward_msg))
                        log.info(f"Forwarded offer from {uid} to client {client_id} (streams: {list(forward_msg['streams'].keys())})")
                    else:
                        log.warning(f"Client {client_id} not found for offer from {uid}")

                elif msg_type == 'answer':
                    if client_id and client_id in self.clients:
                        await self.clients[client_id].send(json.dumps(msg))
                        log.debug(f"Forwarded answer from {uid} to client {client_id}")
                    else:
                        log.warning(f"Client {client_id} not found for answer from {uid}")

                elif msg_type == 'candidate':
                    if client_id and client_id in self.clients:
                        await self.clients[client_id].send(json.dumps(msg))
                        log.debug(f"Forwarded candidate from {uid} to client {client_id}")

            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.error(f"Device {uid}: Error in message loop: {e}")
                traceback.print_exc()
                break

    # -- Client connection handler ----------------------------------------

    async def _handle_client_connection(self, uid):
        client_id = f"{uid}_{str(uuid.uuid4())[:8]}"
        self.clients[client_id] = websocket._get_current_object()
        target_uid = uid
        log.info(f"Client connected: {client_id} -> {target_uid}")

        try:
            if target_uid not in self.devices:
                await asyncio.sleep(3)  # slow down UID enumeration attempts
                await self._send_error(websocket, 'Device not found')
                return

            await self._client_message_loop(client_id, target_uid)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error(f"Client {client_id} error: {e}")
            traceback.print_exc()
        finally:
            if client_id in self.clients:
                del self.clients[client_id]
                log.info(f"Client disconnected: {client_id}")

    async def _client_message_loop(self, client_id, target_uid):
        """Relay messages from client to the target device."""
        while True:
            data = await websocket.receive()
            try:
                msg = json.loads(data)
            except (json.JSONDecodeError, TypeError) as e:
                log.warning(f"Client {client_id}: Invalid JSON: {e}")
                continue

            msg_type = msg.get('type')
            msg['client_id'] = client_id

            if msg_type == 'request':
                ice_servers = self.get_ice_servers_for_device(target_uid)
                if ice_servers:
                    msg['ice_servers'] = ice_servers
                if await self._forward_to_device(target_uid, msg):
                    turn_status = "with TURN" if ice_servers else "direct only (no TURN credentials)"
                    log.info(f"Forwarded request from client {client_id} to {target_uid} ({turn_status})")
                else:
                    await self._send_error(websocket, 'Device not found')

            elif msg_type == 'answer':
                if await self._forward_to_device(target_uid, msg):
                    log.debug(f"Forwarded answer from client {client_id} to {target_uid}")
                else:
                    await self._send_error(websocket, 'Device not found')

            elif msg_type == 'candidate':
                if not await self._forward_to_device(target_uid, msg):
                    pass  # Silently drop — device gone
                else:
                    log.debug(f"Forwarded candidate from client {client_id} to {target_uid}")

    # -- TURN credentials -------------------------------------------------

    def _generate_coturn_credentials(self):
        """Generate ephemeral TURN credentials using TURN REST API (RFC 7635).

        coturn validates these using the same shared secret — no database or
        API calls needed. Credentials are short-lived (default 24h).
        """
        expiry = int(time.time()) + self.coturn_ttl
        username = str(expiry)
        password = base64.b64encode(
            hmac.new(self.coturn_secret.encode(), username.encode(), hashlib.sha1).digest()
        ).decode()
        return [
            {"urls": f"stun:{self.coturn_host}:3478"},
            {"urls": [f"turn:{self.coturn_host}:3478", f"turns:{self.coturn_host}:5349"],
             "username": username, "credential": password}
        ]

    def get_ice_servers(self):
        """Generate fresh TURN credentials for a connection, or empty if not configured."""
        if self.coturn_host and self.coturn_secret:
            return self._generate_coturn_credentials()
        return []

    def get_ice_servers_for_device(self, uid):
        """Return device-specific ICE servers if set, otherwise fall back to coturn."""
        return self.device_ice_servers.get(uid) or self.get_ice_servers()

    # -- Server startup ---------------------------------------------------

    async def run_servers(self):
        if self.coturn_host and self.coturn_secret:
            log.info(f"TURN: Using coturn ({self.coturn_host}, credential TTL: {self.coturn_ttl}s)")
        else:
            log.info("TURN: No TURN server configured - devices must provide their own ICE servers")

        shutdown_event = asyncio.Event()
        self.shutdown_event = shutdown_event

        def signal_handler():
            log.info("Shutting down...")
            shutdown_event.set()
            loop.call_later(2, lambda: os._exit(0))

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)

        config = Config()
        config.bind = [f"{HOST}:{HTML_PORT}"]
        config.websocket_ping_interval = 60
        config.keep_alive_timeout = 300
        config.graceful_timeout = 2

        await serve(self.app, config, shutdown_trigger=shutdown_event.wait)


if __name__ == '__main__':
    import sys

    # LOG_LEVEL env var: DEBUG shows every candidate/answer, INFO (default) shows
    # connections and offers only, WARNING shows only problems
    level = getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper(), logging.INFO)

    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('signaling.log'),
        ]
    )
    # Redirect print() to the log file too
    class LogWriter:
        def write(self, msg):
            if msg.strip():
                logging.info(msg.strip())
        def flush(self):
            pass
    sys.stdout = LogWriter()
    sys.stderr = LogWriter()

    ps = SignalingServer()
    try:
        asyncio.run(ps.run_servers())
    except KeyboardInterrupt:
        pass
