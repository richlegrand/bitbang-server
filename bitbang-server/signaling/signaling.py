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
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519
from cryptography.hazmat.backends import default_backend

# Minimum acceptable RSA key size. 2048 is the modern floor for new keys
# (NIST SP 800-57). Smaller keys are rejected at registration time.
MIN_RSA_KEY_SIZE = 2048

# Supported EC curve. Only P-256 is accepted for ECDSA auth — other curves
# require an explicit decision and protocol review.
SUPPORTED_EC_CURVE = "secp256r1"

log = logging.getLogger('bitbang')

# UID format: 32 hex characters (128-bit hash of public key)
UID_PATTERN = re.compile(r'^[a-f0-9]{32}$')

# Domain separation tag prepended to the challenge nonce before signing.
# Prevents cross-protocol attacks: without this prefix, a malicious server
# could send nonce = SHA256(arbitrary_payload) and reuse the device's
# signature in another context (e.g. firmware verification) that uses the
# same RSA key. Binding every signature to its purpose makes a signature
# from one context structurally invalid in any other.
# Bumped only if the signing scheme itself changes (padding/hash/structure),
# not when the surrounding protocol version changes.
AUTH_DOMAIN = b"bitbang-auth-v1:"


def validate_uid(uid: str) -> bool:
    """Check if UID matches expected format."""
    return bool(UID_PATTERN.match(uid))


def uid_from_public_key_bytes(public_bytes: bytes) -> str:
    """Derive UID from DER-encoded public key."""
    return hashlib.sha256(public_bytes).hexdigest()[:32]


def validate_public_key(public_key):
    """Validate a parsed public key against the protocol's supported types.

    Returns None if acceptable, else a short error string suitable for sending
    back to the device. The DER SubjectPublicKeyInfo encoding self-describes
    the algorithm, so we trust the parsed object's type rather than carrying
    a separate wire field.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < MIN_RSA_KEY_SIZE:
            return f'RSA key too small ({public_key.key_size} < {MIN_RSA_KEY_SIZE})'
        return None
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name != SUPPORTED_EC_CURVE:
            return f'Unsupported EC curve: {public_key.curve.name}'
        return None
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return None
    return f'Unsupported public key type: {type(public_key).__name__}'


def verify_signature(public_key, nonce: bytes, signature: bytes) -> bool:
    """Verify a challenge signature, dispatching on key type.

    Each supported key type pairs with a fixed signature scheme:
      - RSA          -> RSASSA-PKCS1v1_5 + SHA-256
      - EC (P-256)   -> ECDSA + SHA-256
      - Ed25519      -> Ed25519 (no separate hash)

    All schemes sign AUTH_DOMAIN + nonce (see AUTH_DOMAIN comment).
    """
    payload = AUTH_DOMAIN + nonce
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, payload)
        else:
            return False
        return True
    except Exception:
        return False


VERSION = '0.1.0'

HOST = '0.0.0.0'
HTML_PORT = int(os.environ.get('PORT', '8081'))

# SWSP protocol versioning. PROTOCOL_VERSION is what this server supports.
# MINIMUM_PROTOCOL_VERSION is the oldest version accepted from devices.
# Devices below the minimum receive a 'protocol_too_old' error with no retry.
PROTOCOL_VERSION = 2
MINIMUM_PROTOCOL_VERSION = 2


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

        # Capacity gate on concurrent TURN allocations. 0 disables the gate.
        # When the gate is active and len(self.turn_clients) >= the cap, new
        # clients receive STUN-only ICE plus an advisory `turn_unavailable`
        # flag in the offer envelope. The TTL-based end-of-session warning
        # uses COTURN_TTL above; the client parses the credential username
        # (an epoch expiry) to compute its own warning/end triggers.
        self.turn_max_active = int(os.environ.get('TURN_MAX_ACTIVE', '0'))
        self.turn_clients = set()           # client_ids currently granted TURN
        self.client_turn_creds = {}         # client_id -> cached creds (generated once at request time, reused at offer time)

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
                'active_turn_clients': len(self.turn_clients),
                'turn_max_active': self.turn_max_active,
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

        # Parse the key. The DER SubjectPublicKeyInfo encoding self-describes
        # the algorithm, so we don't need a separate wire field — the parsed
        # object's type tells us which signature scheme to use.
        try:
            public_key = serialization.load_der_public_key(public_bytes, backend=default_backend())
        except Exception:
            await self._send_error(ws, 'Invalid public_key format')
            return None

        # Reject unsupported key types / undersized RSA before issuing a challenge.
        err = validate_public_key(public_key)
        if err:
            log.warning(f"Device {uid}: rejected key — {err}")
            await self._send_error(ws, err)
            return None

        # Issue challenge
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

            # Preempt any existing connection with this UID. The new
            # connection has proven key ownership, so it takes precedence
            # (typically a device restart racing with its own stale ws).
            if uid in self.devices:
                old_ws = self.devices[uid]
                log.warning(f"Device {uid}: Preempting existing connection")
                try:
                    await old_ws.send(json.dumps({'type': 'error', 'message': 'preempted'}))
                except Exception:
                    pass
                try:
                    await old_ws.close(1000)
                except Exception:
                    pass

                # Boot any clients connected to the old device. Their existing
                # WebRTC peer connections were negotiated with the previous
                # device instance and won't carry over. Forcing a reconnect
                # makes them re-issue 'request' and receive a fresh offer.
                # Snapshot the list because client cleanup mutates self.clients.
                stale = [(cid, cws) for cid, cws in self.clients.items()
                         if cid.startswith(f"{uid}_")]
                for cid, cws in stale:
                    try:
                        await cws.send(json.dumps({'type': 'error', 'message': 'device_preempted'}))
                    except Exception:
                        pass
                    try:
                        await cws.close(1000)
                    except Exception:
                        pass
                    log.info(f"Booted client {cid} (device preempted)")

            # Register device. The old handler's finally block will see that
            # self.devices[uid] != its own ws (we're about to overwrite) and
            # leave the registry alone.
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
                        ice_servers, turn_unavailable, _ = \
                            self._ice_servers_for_client(uid, client_id)
                        forward_msg = {
                            'type': 'offer',
                            'sdp': msg['sdp'],
                            'client_id': client_id,
                            'streams': msg.get('streams', {}),
                            'ice_servers': ice_servers,
                        }
                        if turn_unavailable:
                            forward_msg['turn_unavailable'] = True
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
                self.turn_clients.discard(client_id)
                self.client_turn_creds.pop(client_id, None)
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
                # Decide capacity gating once, at request time. The decision
                # is captured in self.turn_clients and reused at offer-forward
                # time so device and client receive consistent ice_servers.
                self._maybe_grant_turn(client_id, target_uid)
                ice_servers, turn_unavailable, _ = \
                    self._ice_servers_for_client(target_uid, client_id)
                if ice_servers:
                    msg['ice_servers'] = ice_servers
                if await self._forward_to_device(target_uid, msg):
                    if turn_unavailable:
                        turn_status = "STUN only (at capacity)"
                    elif client_id in self.turn_clients:
                        turn_status = "with TURN"
                    elif target_uid in self.device_ice_servers:
                        turn_status = "with device-supplied ICE"
                    else:
                        turn_status = "direct only (no TURN credentials)"
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
        API calls needed. Credentials are short-lived (set via COTURN_TTL).
        Username is the expiry epoch as a string.
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

    def _maybe_grant_turn(self, client_id, target_uid):
        """Capacity decision. Adds client_id to turn_clients iff under cap and
        we'd otherwise be issuing our own coturn credentials. Idempotent."""
        if target_uid in self.device_ice_servers:
            return  # Device override path: no gating, not our bandwidth.
        if not (self.coturn_host and self.coturn_secret):
            return  # No coturn configured.
        if client_id in self.turn_clients:
            return  # Already granted (request was repeated).
        if self.turn_max_active and len(self.turn_clients) >= self.turn_max_active:
            return  # At capacity.
        self.turn_clients.add(client_id)

    def _ice_servers_for_client(self, target_uid, client_id):
        """Returns (ice_servers, turn_unavailable, our_turn).

        - our_turn=True iff the returned ice_servers came from OUR coturn
          (so the time/data budget metadata applies). False for device
          overrides, no-coturn, or capacity-gated STUN-only cases.
        - turn_unavailable=True iff coturn IS configured but this client
          was gated out by capacity. Surfaces to the client as the
          "Server at capacity" banner.

        Credentials are generated once per client and cached, so the
        request-to-device and offer-to-client paths see identical creds."""
        if target_uid in self.device_ice_servers:
            return self.device_ice_servers[target_uid], False, False
        if not (self.coturn_host and self.coturn_secret):
            return [], False, False
        if client_id in self.turn_clients:
            creds = self.client_turn_creds.get(client_id)
            if creds is None:
                creds = self._generate_coturn_credentials()
                self.client_turn_creds[client_id] = creds
            return creds, False, True
        # Coturn configured but client wasn't granted TURN — STUN-only.
        return [{"urls": f"stun:{self.coturn_host}:3478"}], True, False

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
