/**
 * BitBang Bootstrap Client
 *
 * Manages WebRTC connection to device, bridges service worker to data channel,
 * and wires up media streams to the iframe.
 */

console.log('[Bootstrap] script evaluated', performance.now().toFixed(1));

const STATUS = {
    CONNECTING: "Connecting to server...",
    WAITING_OFFER: "Waiting for device...",
    CONNECTING_WEBRTC: "Establishing peer connection...",
    NEGOTIATING: "Negotiating connection...",
    CONNECTED: "Connected"
};

// Per-phase delay before the TURN-withhold fallback fires. The browser
// first tries to connect with host + srflx candidates only (server
// withholds TURN). After MESSAGE_TIMEOUT_MS, if still not connected, we
// show the user a "Negotiating connection..." banner and start the
// second timer. After another MESSAGE_TIMEOUT_MS (so 2 × the timeout
// since the answer was sent), if still not connected, the browser asks
// the server for TURN credentials and adds them via setConfiguration +
// restartIce.
//
// Override via ?msg_timeout=N (seconds, float-OK). Defaults to 3 seconds
// → 6 seconds total before a fallback. Direct paths almost always
// resolve within phase 1; this just biases ICE toward direct.
const MESSAGE_TIMEOUT_MS = (() => {
    const p = new URLSearchParams(window.location.search);
    const n = parseFloat(p.get('msg_timeout'));
    return isFinite(n) && n > 0 ? n * 1000 : 3000;
})();

// SWSP (Simple WebRTC Streaming Protocol) constants
const FLAG_SYN = 0x0001;
const FLAG_FIN = 0x0004;
const FLAG_DAT = 0x0000;
const FLAG_MORE = 0x0002;  // non-final fragment of a chunked WS message
const SWSP_CHUNK_SIZE = 16384;  // max payload bytes per data-channel frame

// --- Bidirectional verify helpers ----------------------------------------
//
// The browser is the connecting party. Before opening WebRTC, it asks the
// signaling server for the device's pubkey, verifies hash(pubkey) === UID
// locally, then rides an encrypted {fingerprint, nonce, code} payload on
// the answer (code is the access code from the URL fragment; omitted only
// when the URL has no #code, in which case the device rejects the
// connection). The device decrypts, confirms the fingerprint matches the
// SDP and the code matches its own, and proves possession of the private
// key by sending sha256(nonce) back as the first stream-0 frame after the
// data channel opens. A rogue signaling server cannot mount a relay
// attack: it can rewrite SDPs all it wants, but without the device's
// private key it can't decrypt the payload or produce a matching nonce
// hash, and the browser will reject the channel.

function bytesToBase64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
}

function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function bytesToHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
        s += bytes[i].toString(16).padStart(2, '0');
    }
    return s;
}

// bytesToBase64Url returns base64url without padding (alphabet [A-Za-z0-9_-]).
// btoa() produces standard base64 with + / =; we swap to URL-safe chars and
// strip padding. Matches Python's base64.urlsafe_b64encode(...).rstrip(b'=')
// and Go's base64.RawURLEncoding.
function bytesToBase64Url(bytes) {
    return bytesToBase64(bytes)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// uidFromPubkeyDer mirrors identity.UIDFromPublicKeyBytes in the server and
// device: first 128 bits of sha256(public_key_DER), base64url-encoded with no
// padding (22 chars). The companion 64-bit access code travels in the URL
// fragment (never sent to the server) and is verified inside the
// encrypted_request payload. Used to verify the pubkey the signaling
// server hands us actually belongs to the UID we're trying to reach —
// without this check, a rogue server could swap pubkeys and the browser
// would happily encrypt to the attacker's key.
async function uidFromPubkeyDer(derBytes) {
    const hash = await crypto.subtle.digest('SHA-256', derBytes);
    return bytesToBase64Url(new Uint8Array(hash).slice(0, 16));
}

// extractDTLSFingerprint pulls "a=fingerprint:sha-256 AA:BB:..." out of an
// SDP and normalizes to uppercase. The device runs the same parse on its end
// (peer/verify.go) so the strings compare directly.
function extractDTLSFingerprint(sdp) {
    const lines = (sdp || '').split('\n');
    for (const raw of lines) {
        const line = raw.replace(/\r$/, '');
        const m = /^a=fingerprint:sha-256\s+([0-9A-Fa-f:]+)\s*$/.exec(line);
        if (m) return m[1].toUpperCase();
    }
    return '';
}

// importDevicePubkey turns a base64 SPKI DER public key into a CryptoKey
// usable for RSA-OAEP/SHA-256 encryption. The DER bytes are also returned so
// the caller can hash them for the UID check without round-tripping through
// the import.
async function importDevicePubkey(b64) {
    const der = base64ToBytes(b64);
    const key = await crypto.subtle.importKey(
        'spki',
        der,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
    );
    return { key, der };
}

// encryptVerifyPayload RSA-OAEP encrypts the bidirectional-verify JSON
// ({fingerprint, nonce, code?}) to the device's public key. The code field
// is the 64-bit access code from the URL fragment (11 base64url chars) —
// omitted when the user browsed to the bare UID without a #code, in
// which case the device will reject the connection unless it was started
// without a code. The matching decrypt lives in identity.Decrypt on the
// device side.
async function encryptVerifyPayload(pubkey, fingerprint, nonceBytes, code) {
    const obj = {
        fingerprint,
        nonce: bytesToBase64(nonceBytes),
    };
    if (code) {
        obj.code = code;
    }
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        pubkey,
        new TextEncoder().encode(JSON.stringify(obj))
    );
    return bytesToBase64(new Uint8Array(ciphertext));
}

// sha256Base64 returns base64(sha256(bytes)) — matches the format the device
// emits in the verify_nonce_hash control frame.
async function sha256Base64(bytes) {
    const hash = await crypto.subtle.digest('SHA-256', bytes);
    return bytesToBase64(new Uint8Array(hash));
}

class BitBangConnection {
    constructor(uid, devicePath, code) {
        this.uid = uid;
        this.devicePath = devicePath || '/';
        this.code = code || '';
        this.pc = null;
        this.dataChannel = null;
        this.ws = null;
        this.streamNameMap = {};      // from offer: { "0": "webcam", ... }
        this.resolvedStreams = {};    // name -> MediaStream
        this.pendingRequests = new Map();  // streamId -> request state
        this.connectResolve = null;   // resolved when device sends 'ready'
        this.nextStreamId = 1;        // streamId 0 is reserved for control
        this.wsStreams = new Map();    // streamId -> { iframe } for WebSocket bridging
        this.sessionId = Array.from(crypto.getRandomValues(new Uint8Array(4)), b => b.toString(16).padStart(2, '0')).join(''); // 8 hex chars
        console.log('[Bootstrap] ctor', this.sessionId);
        this.localCandidateQueue = [];
        this.remoteCandidateQueue = [];
        this.remoteDescriptionSet = false;
        this.progressChannel = new BroadcastChannel('bitbang-progress');

        this.statusEl = document.getElementById('status');
        this.connectionUI = document.getElementById('connection-ui');
        this.debug = new URLSearchParams(window.location.search).has('debug');
        this.noCookieJar = new URLSearchParams(window.location.search).has('nocookiejar');
        this._turnHoldPromise = null;
        this._wasConnected = false;
        this._usingRelay = false;
        this._turnWarnTimer = null;
        this._turnEndTimer = null;
        this._turnExpiryMs = null;
        this._turnUnavailable = false;
        this._turnEnded = false;
    }

    // SWSP frame helpers
    createFrame(streamId, flags, payload) {
        // payload can be string or Uint8Array
        let payloadBytes;
        if (typeof payload === 'string') {
            payloadBytes = new TextEncoder().encode(payload);
        } else if (payload instanceof ArrayBuffer) {
            payloadBytes = new Uint8Array(payload);
        } else {
            payloadBytes = payload;
        }

        const buffer = new ArrayBuffer(8 + payloadBytes.byteLength);
        const view = new DataView(buffer);
        view.setUint32(0, streamId, true);  // little-endian
        view.setUint16(4, flags, true);
        view.setUint16(6, payloadBytes.byteLength, true);
        new Uint8Array(buffer).set(payloadBytes, 8);
        return buffer;
    }

    parseFrame(buffer) {
        const view = new DataView(buffer);
        const streamId = view.getUint32(0, true);
        const flags = view.getUint16(4, true);
        const length = view.getUint16(6, true);
        const payload = buffer.slice(8, 8 + length);
        return { streamId, flags, payload };
    }

    // Append one line to the connection log — a plain append-only terminal:
    // one element, one font. Never replaces or clears a message.
    _print(msg) {
        document.title = msg;
        if (!this.statusEl) return;
        const line = document.createElement('div');
        line.textContent = msg;
        this.statusEl.appendChild(line);
    }

    // Same, but only with ?debug — the extra play-by-play detail.
    _printDebug(msg) {
        if (this.debug) this._print(msg);
    }

    async connect() {
        try {
            await this.registerServiceWorker();
            this._printDebug(STATUS.CONNECTING);
            await this.connectWebSocket();
        } catch (error) {
            console.error('Connection failed:', error);
            this._print(this.userErrorMessage(error.message));
            if (this.statusEl) this.statusEl.classList.add('error');
        }
    }

    userErrorMessage(msg) {
        if (msg === 'Device not found') return 'Device not found';
        if (msg === 'WebSocket connection failed') return 'Could not reach server';
        if (msg === 'Service Worker not supported') return 'This browser is not supported';
        if (msg === 'offer_timeout') return 'Device not responding';
        return 'Connection failed';
    }

    async registerServiceWorker() {
        if (!('serviceWorker' in navigator)) {
            throw new Error('Service Worker not supported');
        }

        const reg = await navigator.serviceWorker.register('/__bitbang__/sw.js', {
            scope: '/',
            updateViaCache: 'none',
        });
        // Force check for SW update on every page load
        reg.update();

        // Handle proxy requests from SW
        navigator.serviceWorker.addEventListener('message', (event) => {
            if (event.data?.type === 'request') {
                this.handleProxyRequest(event.data, event.ports[0]);
            }
        });

        // Drop our session entry when this window goes away (refresh or close)
        // so the SW doesn't carry stale records into the next page load.
        window.addEventListener('pagehide', () => {
            navigator.serviceWorker.controller?.postMessage({
                type: 'unsetBootstrap',
                sessionId: this.sessionId,
            });
        });

        await navigator.serviceWorker.ready;
    }

    handleProxyRequest(data, responsePort) {
        const { method, url, headers, hasBody, contentLength } = data;
        if (this.debug) console.log(`[Bootstrap] Received proxy request: ${method} ${new URL(url).pathname}, DC state: ${this.dataChannel?.readyState}`);

        if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
            console.warn('[Bootstrap] Data channel not open, rejecting request');
            responsePort.postMessage({ type: 'error', message: 'Data channel not open' });
            return;
        }

        // Strip /__device__ prefix, keep query string
        const parsed = new URL(url);
        let pathname = parsed.pathname;
        if (pathname.startsWith('/__device__')) {
            pathname = pathname.slice('/__device__'.length) || '/';
        }
        const fullPath = pathname + parsed.search;

        // Use incrementing stream ID for SWSP
        const streamId = this.nextStreamId++;

        // Initial 30s timeout to catch "device not responding". Cleared once
        // response headers arrive (SYN). After that we rely on FIN / data
        // channel close to signal end -- inactivity is normal during streaming
        // when the consumer (e.g. video player) backpressures the channel.
        let timeout;
        const resetTimeout = () => {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                this.pendingRequests.delete(streamId);
                responsePort.postMessage({ type: 'error', message: 'Request timeout' });
            }, 30000);
        };
        resetTimeout();

        this.pendingRequests.set(streamId, {
            responsePort,
            timeout,
            resetTimeout,
            bytesReceived: 0,
            startTime: Date.now(),
            nextLogMB: 50,
            isUpload: hasBody
        });

        // Build request metadata with all headers. SWSP v3 makes the
        // stream `type` explicit on every SYN; v2 listeners that don't
        // know the field default it to "http" — same effect.
        const requestMeta = { type: 'http', method, pathname: fullPath, headers };
        if (hasBody) {
            requestMeta.contentLength = contentLength;
            // Keep contentType for backward compatibility with older devices
            if (headers['content-type']) {
                requestMeta.contentType = headers['content-type'];
            }
        }

        if (hasBody) {
            // Send SYN frame with metadata, then stream body chunks as they arrive
            const synFrame = this.createFrame(streamId, FLAG_SYN, JSON.stringify(requestMeta));
            try {
                this.dataChannel.send(synFrame);
            } catch (e) {
                responsePort.postMessage({ type: 'error', message: 'Failed to start upload' });
                this.progressChannel.postMessage({ type: 'uploadFailed' });
                return;
            }

            const MAX_CHUNK = 16384;
            let bytesSent = 0;
            let lastProgress = 0;
            let processingChain = Promise.resolve();

            const failUpload = (msg) => {
                this.pendingRequests.delete(streamId);
                responsePort.postMessage({ type: 'error', message: msg });
                this.progressChannel.postMessage({ type: 'uploadFailed' });
            };

            const isOpen = () => this.dataChannel?.readyState === 'open';

            responsePort.onmessage = (event) => {
                processingChain = processingChain.then(async () => {
                    if (!isOpen()) return failUpload('Connection lost');

                    if (event.data.type === 'bodyChunk') {
                        const data = event.data.data;

                        for (let i = 0; i < data.byteLength; i += MAX_CHUNK) {
                            // Backpressure: wait while buffer is full
                            while (isOpen() && this.dataChannel.bufferedAmount > 1024 * 1024) {
                                await new Promise(r => setTimeout(r, 10));
                            }
                            if (!isOpen()) return failUpload('Connection lost');

                            const chunk = data.subarray(i, Math.min(i + MAX_CHUNK, data.byteLength));
                            this.dataChannel.send(this.createFrame(streamId, FLAG_DAT, chunk));
                        }

                        bytesSent += data.byteLength;
                        const now = Date.now();
                        if (now - lastProgress > 100) {
                            lastProgress = now;
                            resetTimeout();
                            this.progressChannel.postMessage({
                                type: 'uploadProgress', loaded: bytesSent, total: contentLength
                            });
                        }

                    } else if (event.data.type === 'bodyEnd') {
                        if (!isOpen()) return failUpload('Connection lost');
                        this.progressChannel.postMessage({ type: 'uploadComplete' });
                        this.dataChannel.send(this.createFrame(streamId, FLAG_FIN, new Uint8Array(0)));
                    }
                });
            };
        } else {
            // No body - send SYN|FIN together
            const frame = this.createFrame(streamId, FLAG_SYN | FLAG_FIN, JSON.stringify(requestMeta));
            this.dataChannel.send(frame);
        }
    }

    connectWebSocket() {
        return new Promise((resolve, reject) => {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            this.ws = new WebSocket(`${protocol}//${window.location.host}/ws/client/${this.uid}`);

            const offerTimeout = setTimeout(() => {
                reject(new Error('offer_timeout'));
            }, 15000);

            // Bidirectional-verify state. devicePubkey + verifyNonce are
            // populated in handleOffer; deviceVerified flips true when the
            // device's first stream-0 frame proves it decrypted the nonce.
            this.devicePubkey = null;
            this.verifyNonce = null;
            this.deviceVerified = false;

            this.ws.onopen = () => {
                // ?relay tells the server to skip TURN withholding and
                // include relay credentials in the initial offer (legacy
                // behavior). ?norelay also disables the fallback (handled
                // in createPeerConnection by dropping iceServers entirely).
                const params = new URLSearchParams(window.location.search);
                const forceRelay = params.has('relay') && !params.has('norelay');
                this.ws.send(JSON.stringify({
                    type: 'request',
                    uid: this.uid,
                    force_relay: forceRelay,
                }));
                this._printDebug(STATUS.WAITING_OFFER);
            };

            this.ws.onmessage = async (event) => {
                const msg = JSON.parse(event.data);
                if (msg.type === 'offer') {
                    // A second offer on an established PC is the device's
                    // ICE-restart re-offer (TURN-withhold fallback): renegotiate
                    // in place so we re-answer and gather relay candidates from
                    // the TURN creds we already added via setConfiguration. The
                    // connect promise resolved on the first offer — leave it be.
                    if (this.pc && this.remoteDescriptionSet) {
                        try {
                            await this.handleRenegotiationOffer(msg);
                        } catch (e) {
                            console.warn('[Bootstrap] ICE-restart renegotiation failed:', e);
                        }
                        return;
                    }
                    clearTimeout(offerTimeout);
                    try {
                        await this.handleOffer(msg);
                    } catch (e) {
                        reject(e);
                        return;
                    }
                    resolve();
                } else if (msg.type === 'candidate') {
                    this.handleRemoteCandidate(msg.candidate);
                } else if (msg.type === 'ice_servers') {
                    await this._handleICEServersPush(msg);
                } else if (msg.type === 'error') {
                    clearTimeout(offerTimeout);
                    if (msg.message === 'device_preempted') {
                        // Server kicked us because a new device instance
                        // registered with the same UID. App state on the old
                        // device is gone -- a reload gives a clean session.
                        this.showReloadScreen('Device reconnected. Reload to continue.');
                    } else {
                        // Other error events. reject() is a no-op once the
                        // connect promise has resolved, but harmless then.
                        reject(new Error(msg.message));
                    }
                }
            };

            this.ws.onerror = () => {
                clearTimeout(offerTimeout);
                reject(new Error('WebSocket connection failed'));
            };
        });
    }

    // Handle the device's ICE-restart re-offer (TURN-withhold fallback).
    // Reuse the existing PC — it already has the TURN servers added by
    // _handleICEServersPush, so creating the answer re-gathers ICE and this
    // time produces relay candidates, which trickle to the device via the
    // existing onicecandidate handler. No re-verify: an ICE restart leaves
    // DTLS (and the verified fingerprint) unchanged, so we skip the encrypted
    // payload and flag the answer so the device applies it without verifying.
    async handleRenegotiationOffer(msg) {
        if (this.debug) console.log('[Bootstrap] ICE-restart re-offer — renegotiating to add relay');
        await this.pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
        const answer = await this.pc.createAnswer();
        await this.pc.setLocalDescription(answer);
        this.ws.send(JSON.stringify({
            type: 'answer',
            uid: this.uid,
            sdp: this.pc.localDescription.sdp,
            ice_restart: true,
        }));
    }

    async handleOffer(msg) {
        // Bidirectional verify, part 1: the offer carries the device's
        // pubkey alongside the SDP. Verify hash(pubkey) === uid locally
        // before doing any WebRTC work — a rogue server can't substitute
        // a key for a UID it doesn't own without breaking this check.
        if (!msg.device_pubkey) {
            throw new Error('offer missing device_pubkey — server too old or misbehaving');
        }
        const { key, der } = await importDevicePubkey(msg.device_pubkey);
        const computedUid = await uidFromPubkeyDer(der);
        if (computedUid !== this.uid) {
            throw new Error(`pubkey/UID mismatch (server gave key for ${computedUid}, expected ${this.uid})`);
        }
        this.devicePubkey = key;

        this._printDebug(STATUS.CONNECTING_WEBRTC);
        this.streamNameMap = msg.streams || {};
        this.deviceName = msg.device_name || null;
        this._turnUnavailable = !!msg.turn_unavailable;
        // Surface "at capacity" immediately on receipt, not after connect:
        // with ?relay + capacity gating the connection may never establish
        // (no TURN server in iceServers + relay-only policy = no candidates),
        // so _onFirstConnected won't ever fire and the user would otherwise
        // get no feedback at all.
        if (this._turnUnavailable) {
            this._print('Relay server (TURN) is at capacity. Connection may fail — please try again later.');
        }
        // Coturn REST-API username format: "<expiry-epoch>[:<user_name>]".
        // The expiry is set via COTURN_TTL in signaling/.env; the optional
        // user_name suffix is the BitBang uid (used for per-uid quota in
        // coturn). Match the leading integer up to either a colon or
        // end-of-string. If multiple TURN entries are present, they share
        // the same username.
        this._turnExpiryMs = null;
        if (Array.isArray(msg.ice_servers)) {
            for (const s of msg.ice_servers) {
                const m = s && s.username && /^(\d+)(:|$)/.exec(s.username);
                if (m) {
                    this._turnExpiryMs = parseInt(m[1], 10) * 1000;
                    break;
                }
            }
        }
        this.iceServers = Array.isArray(msg.ice_servers) ? msg.ice_servers : [];
        this.pc = this.createPeerConnection(msg.ice_servers);

        if (this.debug) {
            const lines = (msg.sdp || '').split('\n').filter(l => l.startsWith('a=candidate:'));
            for (const line of lines) {
                const m = line.match(/typ (\S+)/);
                console.log(`[Bootstrap] offer candidate: ${m ? m[1] : '?'} ${line.trim()}`);
            }
        }

        await this.pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
        this.remoteDescriptionSet = true;

        // Flush buffered remote candidates
        for (const candidate of this.remoteCandidateQueue) {
            await this.pc.addIceCandidate(candidate).catch(() => {});
        }
        this.remoteCandidateQueue = [];

        // Create the answer; setLocalDescription populates the SDP with our
        // DTLS fingerprint, which we then commit to via the encrypted
        // payload below. The device decrypts the payload and checks it
        // against the SDP — a rogue relay rewriting the SDP would mismatch.
        const answer = await this.pc.createAnswer();
        await this.pc.setLocalDescription(answer);

        const localFingerprint = extractDTLSFingerprint(this.pc.localDescription.sdp);
        if (!localFingerprint) {
            throw new Error('local SDP has no sha-256 fingerprint');
        }
        const nonce = crypto.getRandomValues(new Uint8Array(16));
        this.verifyNonce = nonce;
        const encryptedRequest = await encryptVerifyPayload(
            this.devicePubkey, localFingerprint, nonce, this.code);

        this.ws.send(JSON.stringify({
            type: 'answer',
            uid: this.uid,
            sdp: this.pc.localDescription.sdp,
            encrypted_request: encryptedRequest,
        }));

        // Flush buffered local candidates
        for (const msg of this.localCandidateQueue) {
            this.ws.send(JSON.stringify(msg));
        }
        this.localCandidateQueue = [];

        // Start the TURN-withhold fallback timers. After MESSAGE_TIMEOUT_MS,
        // if the connection still isn't up, show the user a friendly
        // "Negotiating connection..." banner. After another MESSAGE_TIMEOUT_MS,
        // silently ask the server for TURN credentials.
        //
        // ?norelay: skip the fallback entirely — connection either works
        // direct or fails. ?relay: server already attached TURN to the offer
        // and the connection should converge quickly; still arm the
        // reassurance timer in case it doesn't.
        const params = new URLSearchParams(window.location.search);
        const noRelay = params.has('norelay');
        this._reassureTimer = setTimeout(() => this._reassureUser(), MESSAGE_TIMEOUT_MS);
        if (!noRelay) {
            // Phase 2 timer is armed inside _reassureUser so it always
            // follows phase 1.5. Nothing to do here.
        }
    }

    createPeerConnection(iceServers) {
        const config = { sdpSemantics: 'unified-plan' };
        // Diagnostic flags:
        //   ?norelay drops STUN/TURN servers entirely so ICE only has host
        //     candidates ("is host-to-host actually broken, or is it just
        //     losing the race to relay?").
        //   ?relay sets iceTransportPolicy:'relay' so the browser only
        //     gathers and uses relay candidates ("force the TURN path so
        //     we can verify the relay-in-use banner / end-of-session UX").
        // The two are mutually exclusive; norelay wins if both are set.
        const params = new URLSearchParams(location.search);
        const noRelay = params.has('norelay');
        const forceRelay = params.has('relay') && !noRelay;
        if (iceServers && iceServers.length > 0 && !noRelay) {
            config.iceServers = iceServers;
        }
        if (forceRelay) {
            config.iceTransportPolicy = 'relay';
        }
        if (noRelay) console.log('[Bootstrap] norelay: forcing host-only ICE');
        if (forceRelay) console.log('[Bootstrap] relay: forcing relay-only ICE');
        const pc = new RTCPeerConnection(config);

        pc.onconnectionstatechange = () => {
            if (this.debug) console.log(`[Bootstrap] connectionState -> ${pc.connectionState}`);
            if (pc.connectionState === 'connected') {
                // Cancel any pending TURN-withhold fallback timers; the
                // connection is up and we no longer need to escalate.
                this._clearFallbackTimers();
                this._printDebug(STATUS.CONNECTED);
                this.pollConnectionType(pc);
                if (!this._wasConnected) {
                    this._wasConnected = true;
                    this._onFirstConnected(pc);
                }
            } else if (pc.connectionState === 'failed') {
                this._clearFallbackTimers();
                if (this._wasConnected) {
                    this._handlePostHandshakeFailure();
                } else {
                    this.showErrorScreen('Peer connection failed');
                }
            }
        };

        // _prevICEState tracks the last-seen iceConnectionState on this PC so
        // we can detect transitions INTO 'connected' (including post-
        // restartIce re-establishments — those go connected → checking →
        // connected within the same PC) and fire one connection_path
        // telemetry message per established or failed event.
        this._prevICEState = null;

        pc.oniceconnectionstatechange = () => {
            if (this.debug) console.log(`[Bootstrap] iceConnectionState -> ${pc.iceConnectionState}`);
            const now = pc.iceConnectionState;
            const prev = this._prevICEState;
            this._prevICEState = now;

            // Telemetry: each transition INTO connected gets one
            // connection_path report with the actual selected path. Each
            // transition INTO failed gets one "failed" report. Fire-and-
            // forget — never block the connection state machine on it.
            if (now === 'connected' && prev !== 'connected') {
                this._detectConnectionPath(pc)
                    .then((path) => this._sendConnectionPath(path))
                    .catch(() => {});
            } else if (now === 'failed' && prev !== 'failed') {
                this._sendConnectionPath('failed', 'ice_failed');
            }

            if (this._wasConnected && this._usingRelay
                && (pc.iceConnectionState === 'failed' || pc.iceConnectionState === 'disconnected')) {
                this._handlePostHandshakeFailure();
            }
        };

        pc.onicecandidate = (event) => {
            if (event.candidate) {
                if (this.debug) {
                    const c = event.candidate.candidate || '';
                    // SDP candidate line: candidate:foundation comp proto prio addr port typ <type> ...
                    const m = c.match(/typ (\S+)/);
                    console.log(`[Bootstrap] local candidate: ${m ? m[1] : '?'} ${c}`);
                }
                const msg = { type: 'candidate', uid: this.uid, candidate: event.candidate };
                if (this.ws?.readyState === WebSocket.OPEN && this.remoteDescriptionSet) {
                    this.ws.send(JSON.stringify(msg));
                } else {
                    this.localCandidateQueue.push(msg);
                }
            } else if (this.debug) {
                console.log('[Bootstrap] local candidate gathering complete');
            }
        };

        pc.ontrack = (event) => {
            const mid = event.transceiver.mid;
            const name = this.streamNameMap[mid] || mid || 'default';
            this.resolvedStreams[name] = event.streams[0];
        };

        pc.ondatachannel = (event) => {
            this.dataChannel = event.channel;
            this.dataChannel.binaryType = 'arraybuffer';  // SWSP uses binary frames
            this.dataChannel.onopen = () => {
                console.log('DataChannel opened');
                // Bidirectional verify: do not send "connect" yet. The
                // device's first stream-0 frame must be verify_nonce_hash
                // and must match sha256(this.verifyNonce). Only then can we
                // trust that the channel really terminates at the device
                // (not a rogue relay), and onDataChannelReady will be called
                // from handleControlMessage on successful verify.
            };
            this.dataChannel.onclose = () => console.log('DataChannel closed');
            this.dataChannel.onerror = (e) => console.error('DataChannel error:', e);
            this.dataChannel.onmessage = (e) => this.handleDataChannelMessage(e);
        };

        return pc;
    }

    handleRemoteCandidate(candidate) {
        if (this.debug) {
            const c = candidate?.candidate || '';
            const m = c.match(/typ (\S+)/);
            console.log(`[Bootstrap] remote candidate: ${m ? m[1] : '?'} ${c}`);
        }
        if (this.remoteDescriptionSet && this.pc) {
            this.pc.addIceCandidate(candidate).catch(() => {});
        } else {
            this.remoteCandidateQueue.push(candidate);
        }
    }

    // Poll every 2s and log when an ICE pair changes for any transport.
    // OctoPrint has multiple transports (video + data channel) which ICE
    // routes independently, so logging only the first hides cases where
    // one transport is on direct and another is on relay.
    pollConnectionType(pc) {
        if (!this.debug) return;
        const lastByTransport = new Map();
        const tick = async () => {
            if (pc.connectionState !== 'connected') return;
            try {
                const stats = await pc.getStats();
                for (const [, report] of stats) {
                    if (report.type !== 'transport' || !report.selectedCandidatePairId) continue;
                    const transportId = report.id;
                    const selectedId = report.selectedCandidatePairId;
                    if (lastByTransport.get(transportId) === selectedId) continue;
                    lastByTransport.set(transportId, selectedId);
                    const pair = stats.get(selectedId);
                    const local = pair && stats.get(pair.localCandidateId);
                    const remote = pair && stats.get(pair.remoteCandidateId);
                    const localDesc = local ? `${local.candidateType} ${local.address}:${local.port}` : 'unknown';
                    const remoteDesc = remote ? `${remote.candidateType} ${remote.address}:${remote.port}` : 'unknown';
                    const isRelay = local?.candidateType === 'relay' || remote?.candidateType === 'relay';
                    const dtlsState = report.dtlsState || '';
                    console.log(`[Bootstrap] ICE pair (transport ${transportId}, dtls=${dtlsState}): ${isRelay ? 'TURN relay' : 'direct'} - local ${localDesc}, remote ${remoteDesc}`);
                }
            } catch (e) {}
            setTimeout(tick, 2000);
        };
        tick();
    }

    // Returns true if any transport's selected ICE candidate pair has a
    // TURN relay on either end.
    async _isUsingRelay(pc) {
        try {
            const stats = await pc.getStats();
            for (const [, report] of stats) {
                if (report.type !== 'transport' || !report.selectedCandidatePairId) continue;
                const pair = stats.get(report.selectedCandidatePairId);
                if (!pair) continue;
                const local = stats.get(pair.localCandidateId);
                const remote = stats.get(pair.remoteCandidateId);
                if (local?.candidateType === 'relay' || remote?.candidateType === 'relay') {
                    return true;
                }
            }
        } catch (e) {}
        return false;
    }

    // Classify the established path for telemetry. Returns "direct",
    // "relay", or "tcp-relay". Looks at every transport's selected pair
    // and picks the "worst" (relay > tcp-relay > direct) so a mixed
    // session — e.g. data direct but video relay — reports relay rather
    // than under-counting it as direct.
    //
    // tcp-relay distinction: when a candidate is type "relay", the
    // relayProtocol field (if exposed) tells us whether the allocation
    // was made over UDP or TCP. We fall back to the candidate's
    // transport protocol if relayProtocol isn't present.
    async _detectConnectionPath(pc) {
        let path = 'direct';
        try {
            const stats = await pc.getStats();
            for (const [, report] of stats) {
                if (report.type !== 'transport' || !report.selectedCandidatePairId) continue;
                const pair = stats.get(report.selectedCandidatePairId);
                if (!pair) continue;
                const local = stats.get(pair.localCandidateId);
                const remote = stats.get(pair.remoteCandidateId);
                const relayCand =
                    local?.candidateType === 'relay' ? local
                  : remote?.candidateType === 'relay' ? remote
                  : null;
                if (!relayCand) continue;
                const proto = (relayCand.relayProtocol || relayCand.protocol || 'udp').toLowerCase();
                // "relay" wins outright over "direct"; "tcp-relay" is a
                // worse outcome than "relay" only in cost/latency terms,
                // not strictly worse, so we treat them as distinct but
                // either takes precedence over direct.
                path = proto === 'tcp' ? 'tcp-relay' : 'relay';
                // Don't break — keep scanning in case a later transport
                // has a worse classification (tcp-relay > relay).
                if (path === 'tcp-relay') break;
            }
        } catch (e) {
            // Telemetry must never break user flow. Best-effort classify
            // as direct and move on.
        }
        return path;
    }

    // Fire-and-forget telemetry. Sends one connection_path message to
    // the signaling server. Tolerant of a closed/closing WS — telemetry
    // failure must never affect the user's session.
    _sendConnectionPath(path, reason) {
        if (this.ws?.readyState !== WebSocket.OPEN) return;
        const msg = { type: 'connection_path', path };
        if (reason) msg.reason = reason;
        try {
            this.ws.send(JSON.stringify(msg));
            if (this.debug) console.log(`[Bootstrap] reported connection_path: ${path}${reason ? ' (' + reason + ')' : ''}`);
        } catch (e) {
            // swallow — see above
        }
    }

    _clearFallbackTimers() {
        if (this._reassureTimer) {
            clearTimeout(this._reassureTimer);
            this._reassureTimer = null;
        }
        if (this._turnFallbackTimer) {
            clearTimeout(this._turnFallbackTimer);
            this._turnFallbackTimer = null;
        }
    }

    // Phase 1.5 of TURN-withhold fallback. Direct ICE hasn't connected yet.
    // Show the user a "Negotiating connection..." banner so they know the
    // page hasn't stalled, and arm phase 2 (request TURN credentials).
    _reassureUser() {
        this._reassureTimer = null;
        if (this.pc && this.pc.connectionState === 'connected') return;
        this._print(STATUS.NEGOTIATING);

        // ?norelay disables phase 2 entirely; only show the banner.
        const params = new URLSearchParams(window.location.search);
        if (params.has('norelay')) return;

        this._turnFallbackTimer = setTimeout(() => this._requestTURNFallback(), MESSAGE_TIMEOUT_MS);
    }

    // Phase 2. Direct ICE still hasn't connected after the second timeout
    // window. Ask the signaling server for TURN credentials; it will reply
    // with an "ice_servers" message that triggers _handleICEServersPush.
    // No banner change — keep "Negotiating connection..." until either
    // direct or TURN actually connects. _onFirstConnected handles the
    // standard "Using temporary relay (TURN)..." banner if TURN wins.
    _requestTURNFallback() {
        this._turnFallbackTimer = null;
        if (this.pc && this.pc.connectionState === 'connected') return;
        if (this.debug) console.log('[Bootstrap] direct ICE timeout, requesting TURN');
        try {
            this.ws.send(JSON.stringify({ type: 'request_ice' }));
        } catch (e) {
            console.warn('[Bootstrap] request_ice failed:', e);
        }
    }

    // Server pushed TURN credentials in response to a request_ice we sent
    // (or in response to a ?relay query path). Inject them into the
    // existing RTCPeerConnection and restart ICE so the relay candidates
    // get gathered and tried alongside the still-running direct attempts.
    async _handleICEServersPush(msg) {
        if (this.debug) console.log('[Bootstrap] received ice_servers push, unavailable=' + !!msg.turn_unavailable);
        if (msg.turn_unavailable) {
            this._print('Relay server (TURN) is at capacity — connection may fail.');
            return;
        }
        if (!this.pc) return;
        const servers = Array.isArray(msg.ice_servers) ? msg.ice_servers : [];
        if (servers.length === 0) return;
        // Parse the TURN credential's epoch expiry from the username so the
        // end-of-session warn/reload timers can arm. Same coturn REST-API
        // format as handleOffer. Without this, _armTurnEndTimers' guard
        // (_usingRelay && _turnExpiryMs) silently falls through and the
        // session runs past its intended TTL.
        for (const s of servers) {
            const m = s && s.username && /^(\d+)(:|$)/.exec(s.username);
            if (m) {
                this._turnExpiryMs = parseInt(m[1], 10) * 1000;
                break;
            }
        }
        // Make the relay creds available to the video PC too: it's negotiated
        // after the data channel and reads this.iceServers when answering the
        // device's video offer. Without this it gathers host-only, so a
        // relay-required path ends up with working data but no video.
        this.iceServers = (this.iceServers || []).concat(servers);
        const config = this.pc.getConfiguration();
        config.iceServers = (config.iceServers || []).concat(servers);
        try {
            this.pc.setConfiguration(config);
            // The device drives the actual ICE restart: the server forwards an
            // ice_restart trigger, the device re-offers, and handleRenegotiationOffer
            // re-answers — gathering relay candidates from the creds just added.
            // A browser-side restartIce() here is inert: we're the answerer, so
            // it would only take effect on a createOffer() we never call.
        } catch (e) {
            console.warn('[Bootstrap] failed to apply TURN credentials:', e);
        }
        // If _onFirstConnected already fired before this push arrived
        // (e.g., the page briefly reached 'connected' on a direct candidate
        // pair before falling back to relay), its arming branch was skipped
        // because _turnExpiryMs was still null. Arm the end timers now that
        // we have an expiry. Idempotent — _clearTurnEndTimers first.
        if (this._wasConnected && this._usingRelay && this._turnExpiryMs) {
            this._clearTurnEndTimers();
            this._armTurnEndTimers();
        }
    }

    // Fired once per session, the first time pc.connectionState reaches
    // 'connected'. DTLS is up by then; candidate-pair byte counters are
    // populated. We use this to:
    //   (a) show the "TURN relay in use" banner if a relay pair has any
    //       byte traffic (or if turn_unavailable was advertised);
    //   (b) arm the 2-second loading-page hold so the banner is readable;
    //   (c) start the data-budget / time-budget poll loop (Part 2).
    async _onFirstConnected(pc) {
        this._usingRelay = await this._isUsingRelay(pc);
        if (this._usingRelay) {
            this._print('Using temporary relay (TURN) — direct peer-to-peer was not possible.');
            this._turnHoldPromise = new Promise(r => setTimeout(r, 2000));
        } else if (this._turnUnavailable) {
            // Banner was already set in handleOffer; just arm the hold so
            // the visible message survives iframe handoff for ~2 s.
            this._turnHoldPromise = new Promise(r => setTimeout(r, 2000));
        }
        // Arm the TTL-based end triggers if we're on a relay path and we
        // know when the credential expires. Direct paths skip both.
        if (this._usingRelay && this._turnExpiryMs) {
            this._armTurnEndTimers();
        }
    }

    // Schedule the title-change warning at expiry-60s and the reload screen
    // at expiry. Both use absolute deltas from now, derived from the epoch
    // expiry the server embedded in the TURN credential username.
    _armTurnEndTimers() {
        const now = Date.now();
        const warnAt = this._turnExpiryMs - 60_000 - now;
        const endAt = this._turnExpiryMs - now;
        if (warnAt > 0) {
            this._turnWarnTimer = setTimeout(() => {
                if (!this._turnEnded) {
                    document.title = '⚠ Relay ending soon — bitba.ng';
                }
            }, warnAt);
        }
        if (endAt > 0) {
            this._turnEndTimer = setTimeout(() => {
                if (this._turnEnded) return;
                this._turnEnded = true;
                this.showReloadScreen(this._endedMessage());
            }, endAt);
        } else {
            // Already past expiry by the time we got here — fire immediately.
            this._turnEnded = true;
            this.showReloadScreen(this._endedMessage());
        }
    }

    _endedMessage() {
        return 'Relay session ended. Reload to continue.';
    }

    _clearTurnEndTimers() {
        if (this._turnWarnTimer) {
            clearTimeout(this._turnWarnTimer);
            this._turnWarnTimer = null;
        }
        if (this._turnEndTimer) {
            clearTimeout(this._turnEndTimer);
            this._turnEndTimer = null;
        }
    }

    // Idempotent. Called from either onconnectionstatechange === 'failed' or
    // oniceconnectionstatechange transitions to failed/disconnected after we
    // were once connected. Message text varies based on whether the session
    // was actually using a TURN relay.
    _handlePostHandshakeFailure() {
        if (this._turnEnded) return;
        this._turnEnded = true;
        this._clearTurnEndTimers();
        const msg = this._usingRelay
            ? 'Connection lost — relay may have expired.'
            : 'Connection lost. Reload to continue.';
        this.showReloadScreen(msg);
    }

    handleDataChannelMessage(event) {
        // SWSP: expect binary frames
        if (!(event.data instanceof ArrayBuffer)) {
            console.error('Received non-binary message on http channel (unexpected)');
            return;
        }

        try {
            const frame = this.parseFrame(event.data);

            // StreamId 0 is reserved for control messages (connect/ready/auth)
            if (frame.streamId === 0) {
                this.handleControlMessage(frame);
                return;
            }

            // WebSocket stream -- forward to iframe
            const ws = this.wsStreams.get(frame.streamId);
            if (ws) {
                this.handleWSFrame(frame, ws);
                return;
            }

            const req = this.pendingRequests.get(frame.streamId);

            if (!req) {
                console.log('Received frame for unknown stream:', frame.streamId);
                return;
            }

            if (frame.flags & FLAG_SYN) {
                // Metadata frame - send headers to SW, it will create the stream
                const text = new TextDecoder().decode(frame.payload);
                const metadata = JSON.parse(text);
                const status = metadata.status || 200;
                if (this.debug) console.log(`[Bootstrap] Response for stream ${frame.streamId}: ${status}`);

                // Clear timeout once response starts. After this, inactivity
                // between chunks is normal (consumer backpressure for streams)
                // and shouldn't kill the request.
                clearTimeout(req.timeout);

                req.responsePort.postMessage({
                    type: 'headers',
                    status: status,
                    headers: metadata.headers || {}
                });

                // Broadcast upload result for iframe UI
                if (req.isUpload) {
                    this.progressChannel.postMessage({
                        type: status >= 200 && status < 300 ? 'uploadSuccess' : 'uploadFailed',
                        status: status
                    });
                }
            }

            if (frame.flags & FLAG_FIN) {
                // End of stream
                if (frame.payload.byteLength > 0 && !(frame.flags & FLAG_SYN)) {
                    req.bytesReceived += frame.payload.byteLength;
                    const data = new Uint8Array(frame.payload);
                    req.responsePort.postMessage({ type: 'chunk', data }, [data.buffer]);
                }

                // Log completion for large transfers
                if (req.bytesReceived > 1024 * 1024) {
                    const elapsed = (Date.now() - req.startTime) / 1000;
                    const sizeMB = req.bytesReceived / (1024 * 1024);
                    const speed = elapsed > 0 ? (sizeMB / elapsed).toFixed(1) : '0';
                    console.log(`Download complete: ${sizeMB.toFixed(0)} MB in ${elapsed.toFixed(1)}s (${speed} MB/s)`);
                }

                req.responsePort.postMessage({ type: 'done' });
                this.pendingRequests.delete(frame.streamId);
            } else if (!(frame.flags & FLAG_SYN) && frame.payload.byteLength > 0) {
                // Data chunk - use transferable to avoid copy
                req.bytesReceived += frame.payload.byteLength;
                const data = new Uint8Array(frame.payload);
                req.responsePort.postMessage({ type: 'chunk', data }, [data.buffer]);

                // Log progress at each 50MB milestone
                const currentMB = req.bytesReceived / (1024 * 1024);
                if (currentMB >= req.nextLogMB) {
                    const elapsed = (Date.now() - req.startTime) / 1000;
                    const speed = elapsed > 0 ? (currentMB / elapsed).toFixed(1) : '0';
                    console.log(`Download: ${currentMB.toFixed(0)} MB (${speed} MB/s)`);
                    req.nextLogMB += 50;
                }
            }
        } catch (e) {
            console.error('Error parsing SWSP frame:', e);
        }
    }

    async handleControlMessage(frame) {
        if (!(frame.flags & FLAG_SYN)) return;

        const text = new TextDecoder().decode(frame.payload);
        const msg = JSON.parse(text);

        // verify_nonce_hash must be the very first control message we see
        // on a freshly-opened data channel. Until it lands and matches
        // sha256(this.verifyNonce), the channel is treated as untrusted and
        // we won't send connect/auth or accept any other control message.
        if (msg.type === 'verify_nonce_hash') {
            if (this.deviceVerified) {
                console.warn('[Bootstrap] duplicate verify_nonce_hash, ignoring');
                return;
            }
            const expected = await sha256Base64(this.verifyNonce);
            if (msg.hash !== expected) {
                console.error('[Bootstrap] nonce hash mismatch — device did not prove possession of the private key. Closing.');
                this.showErrorScreen('Connection rejected: device identity could not be verified.');
                try { this.dataChannel.close(); } catch (e) {}
                try { this.pc.close(); } catch (e) {}
                return;
            }
            this.deviceVerified = true;
            console.log('[Bootstrap] bidirectional verify OK');
            this.onDataChannelReady();
            return;
        }

        if (!this.deviceVerified) {
            // Any non-verify control message before verify is a protocol
            // violation. Treat as if the device failed to authenticate.
            console.error('[Bootstrap] control message %o received before verify_nonce_hash — closing', msg.type);
            this.showErrorScreen('Connection rejected: device identity could not be verified.');
            try { this.dataChannel.close(); } catch (e) {}
            try { this.pc.close(); } catch (e) {}
            return;
        }

        if (msg.type === 'ready') {
            // `server_version` tells us which SWSP version the listener
            // is speaking. v2 listeners send just {type:'ready'} —
            // serverVersion defaults to 2.
            this.serverVersion = msg.server_version || 2;
            if (this.debug) {
                console.log('[Bootstrap] Device ready (server v' + this.serverVersion + ')');
            } else {
                console.log('[Bootstrap] Device ready');
            }
            if (this.connectResolve) {
                this.connectResolve();
                this.connectResolve = null;
            }
        } else if (msg.type === 'auth_required') {
            console.log('[Bootstrap] Device requires authentication');
            // Auto-submit cached PIN from a previous successful auth
            const cachedPIN = sessionStorage.getItem('__bb_pin_' + this.uid);
            if (cachedPIN && !this._authRetry) {
                this._lastPIN = cachedPIN;
                this._authRetry = true;
                const authMsg = JSON.stringify({ type: 'auth', pin: cachedPIN });
                this.dataChannel.send(this.createFrame(0, FLAG_SYN, authMsg));
            } else {
                this._authRetry = false;
                this.showPINPrompt();
            }
        } else if (msg.type === 'auth_result') {
            const handleResult = () => {
                if (msg.success) {
                    this._authRetry = false;
                    if (this._lastPIN) {
                        sessionStorage.setItem('__bb_pin_' + this.uid, this._lastPIN);
                    }
                    if (this.connectResolve) {
                        this.connectResolve();
                        this.connectResolve = null;
                    }
                } else {
                    sessionStorage.removeItem('__bb_pin_' + this.uid);
                    this._authRetry = false;
                    this.showPINPrompt();
                }
            };

            if (this._authRetry) {
                handleResult();
            } else {
                const delay = msg.success ? 2000 : 3000;
                setTimeout(handleResult, delay);
            }
        } else if (msg.type === 'video_offer') {
            // Secondary "video" PeerConnection: the device relays an external
            // media helper's offer over the (verified) data channel. We answer
            // over the data channel too — not via bitba.ng signaling.
            this.handleVideoOffer(msg.sdp);
        } else if (msg.type === 'video_candidate') {
            if (this.videoPc && msg.candidate) {
                this.videoPc.addIceCandidate(msg.candidate).catch(() => {});
            }
        } else if (msg.type === 'error') {
            console.error('[Bootstrap] Device error:', msg.message);
            this.showErrorScreen(msg.message || 'Connection refused');
        }
    }

    // handleVideoOffer answers a video offer that arrived over the data
    // channel, creating a second PeerConnection whose track lands in
    // resolvedStreams (same registry the iframe binds via data-bitbang-stream).
    // Answer + ICE travel back over stream 0 (FLAG_SYN control frames).
    async handleVideoOffer(sdp) {
        try {
            if (this.videoPc) { try { this.videoPc.close(); } catch (e) {} }
            const config = { sdpSemantics: 'unified-plan' };
            if (this.iceServers && this.iceServers.length) config.iceServers = this.iceServers;
            const pc = new RTCPeerConnection(config);
            this.videoPc = pc;

            pc.ontrack = (event) => {
                const stream = event.streams[0];
                this.resolvedStreams['camera'] = stream;
                if (this.debug) console.log('[Bootstrap] video track received');
                const iframe = document.getElementById('device-frame');
                if (iframe) this.wireStreams(iframe);
            };
            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    this.dataChannel.send(this.createFrame(0, FLAG_SYN, JSON.stringify({
                        type: 'video_candidate', candidate: event.candidate.toJSON(),
                    })));
                }
            };
            pc.onconnectionstatechange = () => {
                if (this.debug) console.log('[Bootstrap] video PC -> ' + pc.connectionState);
            };

            await pc.setRemoteDescription({ type: 'offer', sdp });
            await pc.setLocalDescription(await pc.createAnswer());
            this.dataChannel.send(this.createFrame(0, FLAG_SYN, JSON.stringify({
                type: 'video_answer', sdp: pc.localDescription.sdp,
            })));
            if (this.debug) console.log('[Bootstrap] sent video answer');
        } catch (e) {
            console.error('[Bootstrap] video offer handling failed:', e);
        }
    }

    showReloadScreen(message) {
        const iframe = document.getElementById('device-frame');
        if (iframe) iframe.style.display = 'none';
        if (this.connectionUI) {
            this.connectionUI.className = '';
            this.connectionUI.innerHTML = `
                <div style="font-size: 14px; margin-bottom: 12px;">${message}</div>
                <button id="bb-reload-btn"
                        style="padding: 6px 14px; font-size: 14px; border: 1px solid #ccc;
                               border-radius: 3px; background: #fff; cursor: pointer;">Reload</button>
            `;
            this.connectionUI.style.display = '';
            document.getElementById('bb-reload-btn').onclick = () => location.reload();
        }
    }

    showErrorScreen(message) {
        if (this.connectionUI) {
            this._print(message);
            if (this.statusEl) this.statusEl.classList.add('error');
            this.connectionUI.style.display = '';
        }
    }

    showPINPrompt(errorMessage, remaining) {
        const iframe = document.getElementById('device-frame');
        if (iframe) iframe.style.display = 'none';
        if (this.connectionUI) {
            this.connectionUI.className = '';
            const error = errorMessage
                ? `<div style="color: #c00; margin-bottom: 8px;">${errorMessage}</div>`
                : '';
            this.connectionUI.innerHTML = `
                <div style="font-size: 14px; margin-bottom: 8px;">PIN Required</div>
                ${error}
                <div style="display: flex; gap: 6px; align-items: center;">
                    <input type="password" id="pin-input" placeholder="PIN"
                           style="padding: 4px 8px; font-size: 14px; border: 1px solid #ccc;
                                  border-radius: 3px; width: 120px; outline: none;"
                           onkeydown="if(event.key==='Enter')document.getElementById('pin-submit').click()"
                           autofocus>
                    <button id="pin-submit"
                            style="padding: 4px 12px; font-size: 14px; border: 1px solid #ccc;
                                   border-radius: 3px; background: #fff; cursor: pointer;"
                            >OK</button>
                </div>
            `;
            this.connectionUI.style.display = '';

            document.getElementById('pin-submit').onclick = () => {
                const pin = document.getElementById('pin-input').value;
                if (!pin) return;
                this._lastPIN = pin;
                const authMsg = JSON.stringify({ type: 'auth', pin });
                this.dataChannel.send(this.createFrame(0, FLAG_SYN, authMsg));
            };

            // Focus the input after DOM update
            setTimeout(() => document.getElementById('pin-input')?.focus(), 50);
        }
    }

    handleWSFrame(frame, ws) {
        // Generic /__bitbang/<type> streams use raw bytes for DAT and
        // pass the FIN payload through untouched. Per-cap framing
        // (tag bytes, JSON status payloads, etc.) lives in the
        // iframe; bootstrap.js stays a transport.
        if (ws.kind === 'bitbang') {
            this.handleBitbangFrame(frame, ws);
            return;
        }

        if (frame.flags & FLAG_SYN) {
            // Device acknowledged the WebSocket open
            if (this.debug) console.log(`[Bootstrap] ws SYN ack from device, streamId=${frame.streamId}`);
            ws.iframe.postMessage({ type: 'ws-opened', streamId: frame.streamId }, '*');
        }

        if (frame.flags & FLAG_FIN) {
            // Device closed the WebSocket. Parse the JSON close-info payload
            // (added in adapter.py) for the actual close code + reason from
            // the upstream WS. Fall back to 1006 if missing or malformed --
            // we always want SockJS-style clients to retry (code 1000 would
            // be treated as terminal).
            let code = 1006;
            let reason = '';
            if (frame.payload && frame.payload.byteLength > 0) {
                try {
                    const info = JSON.parse(new TextDecoder().decode(frame.payload));
                    if (typeof info.code === 'number') code = info.code;
                    if (typeof info.reason === 'string') reason = info.reason;
                } catch (e) {}
            }
            if (this.debug) console.log(`[Bootstrap] ws FIN from device, streamId=${frame.streamId} code=${code} reason=${JSON.stringify(reason)}`);
            this.wsStreams.delete(frame.streamId);
            ws.iframe.postMessage({
                type: 'ws-closed',
                streamId: frame.streamId,
                code,
                reason
            }, '*');
            return;
        }

        if (frame.payload.byteLength > 0 && !(frame.flags & FLAG_SYN)) {
            // DAT frame(s): a large WS message is split into <=SWSP_CHUNK_SIZE
            // chunks, with FLAG_MORE on every non-final chunk. Buffer until the
            // final chunk, then deliver the reassembled message -- preserving the
            // WS message boundary. The type byte (0=text, 1=binary) rides in the
            // first chunk.
            const part = new Uint8Array(frame.payload);
            if (frame.flags & FLAG_MORE) {
                (ws._rx || (ws._rx = [])).push(part);
                return;
            }
            let full;
            if (ws._rx) {
                ws._rx.push(part);
                const total = ws._rx.reduce((n, a) => n + a.byteLength, 0);
                full = new Uint8Array(total);
                let o = 0;
                for (const a of ws._rx) { full.set(a, o); o += a.byteLength; }
                ws._rx = null;
            } else {
                full = part;
            }

            const isText = full[0] === 0;
            const messageBytes = full.slice(1);

            let data;
            if (isText) {
                data = new TextDecoder().decode(messageBytes);
            } else {
                data = messageBytes.buffer;
            }

            ws.iframe.postMessage({
                type: 'ws-message',
                streamId: frame.streamId,
                data
            }, '*');
        }
    }

    // handleBitbangFrame is the generic transport for streams opened
    // through the magic /__bitbang/<type> path. It does NO per-cap
    // interpretation — the iframe-served code handles tag bytes,
    // JSON FIN payloads, status decoding, etc. Bootstrap.js is just
    // shuttling raw bytes between the SWSP data channel and the
    // iframe's WebSocket shim.
    handleBitbangFrame(frame, ws) {
        if (frame.flags & FLAG_SYN) {
            // A mid-stream SYN from the device is the listener's
            // chosen way to deliver an early-error payload (or any
            // other one-shot metadata). Deliver as a text WS message
            // so the iframe can decide what to do with it. Most caps
            // will UTF-8-decode + JSON.parse and look for `error`.
            const text = frame.payload && frame.payload.byteLength > 0
                ? new TextDecoder().decode(frame.payload) : '';
            ws.iframe.postMessage({
                type: 'ws-message', streamId: frame.streamId, data: text,
            }, '*');
            return;
        }

        if (frame.flags & FLAG_FIN) {
            // FIN — close the iframe-side WebSocket. The FIN payload
            // (if any) becomes the `reason` field on the close event.
            // The iframe parses it however its cap requires (e.g.
            // shell parses {exit_code, signal}; file ops parse
            // {status, error}).
            let reason = '';
            if (frame.payload && frame.payload.byteLength > 0) {
                reason = new TextDecoder().decode(frame.payload);
            }
            this.wsStreams.delete(frame.streamId);
            ws.iframe.postMessage({
                type: 'ws-closed', streamId: frame.streamId, code: 1000, reason,
            }, '*');
            return;
        }

        // DAT — raw bytes through. Send as a binary ws-message; the
        // iframe is responsible for whatever tag-byte or framing
        // scheme its cap uses.
        if (!frame.payload || frame.payload.byteLength === 0) return;
        const view = new Uint8Array(frame.payload);
        const ab = view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
        ws.iframe.postMessage({
            type: 'ws-message', streamId: frame.streamId, data: ab,
        }, '*');
    }

    async onDataChannelReady() {
        // Register this tab's session with the SW
        const pathParts = this.devicePath.split('/').filter(Boolean);
        const target = pathParts[0] || 'device';
        const reg = await navigator.serviceWorker.ready;
        reg.active.postMessage({
            type: 'setBootstrap',
            sessionId: this.sessionId,
            uid: this.uid,
            target: target,
            debug: this.debug,
            noCookieJar: this.noCookieJar,
        });

        // Brief delay for any pending tracks to arrive
        await new Promise(resolve => setTimeout(resolve, 100));

        // Send connect handshake with path (streamId 0). `version` is
        // the SWSP version we're speaking; older v2 listeners ignore
        // it. No `caps` field — bootstrap.js is a pure transport and
        // doesn't claim knowledge of specific stream types. The iframe
        // decides what to open via /__bitbang/<type>.
        const connectMsg = JSON.stringify({
            type: 'connect',
            path: this.devicePath,
            version: 3,
        });
        this.dataChannel.send(this.createFrame(0, FLAG_SYN, connectMsg));

        // Wait for 'ready' response from device, AND for the optional 2 s
        // TURN banner hold. The hold timer is armed in _onFirstConnected
        // (which runs at DTLS-up, before this point), so the wait is
        // concurrent with device app boot. On non-relay paths the hold is
        // null and Promise.all skips immediately.
        const connectPromise = new Promise(resolve => { this.connectResolve = resolve; });
        await Promise.all([connectPromise, this._turnHoldPromise || Promise.resolve()]);

        // Listen for messages from the iframe (WebSocket shim + navigation
        // + open-cap launcher requests).
        window.addEventListener('message', (event) => {
            const iframe = document.getElementById('device-frame');
            if (!iframe || event.source !== iframe.contentWindow) return;
            if (event.data?.type === 'bb-navigate') {
                this.handleNavigateRequest(event.data.path);
            } else if (event.data?.type === 'bb-open-cap') {
                // The iframe asks us to land on /<uid><path>#<code>.
                // The code lives in our fragment (never sent to the
                // iframe), and the iframe sandbox forbids top-frame
                // navigation, so both URL composition and navigation
                // happen here in the top frame.
                //
                // newTab: true (default) → window.open (cap-bar
                // hamburger items, intentional multi-tab launch).
                // newTab: false → navigate this same tab (proxy form's
                // Go button — the proxy tab becomes the target tab).
                const path = event.data.path || '/';
                const url = '/' + this.uid + path + '#' + this.code;
                if (event.data.newTab === false) {
                    window.location.href = url;
                } else {
                    window.open(url, '_blank', 'noopener');
                }
            } else {
                this.handleWSShimMessage(event);
            }
        });

        this.createIframe();
    }

    handleNavigateRequest(path) {
        // Iframe requested navigation to a path that may need PIN auth.
        // Send a new connect message on stream 0. The device will respond
        // with 'ready' (no PIN needed) or 'auth_required'.
        console.log('[Bootstrap] Navigate request:', path);

        const iframe = document.getElementById('device-frame');
        this.devicePath = path;

        // Set up a resolve callback for the auth flow
        const navigateAfterAuth = () => {
            if (iframe) {
                iframe.src = `/__device__/${this.sessionId}${this.devicePath}`;
                iframe.style.display = '';
            }
            if (this.connectionUI) this.connectionUI.style.display = 'none';
        };
        this.connectResolve = navigateAfterAuth;

        // Send connect with the new path. Matches the initial-connect
        // payload — no caps advertisement.
        const connectMsg = JSON.stringify({
            type: 'connect',
            path,
            version: 3,
        });
        this.dataChannel.send(this.createFrame(0, FLAG_SYN, connectMsg));
    }

    handleWSShimMessage(event) {
        const iframe = document.getElementById('device-frame');
        if (!iframe || event.source !== iframe.contentWindow) return;
        if (!this.dataChannel || this.dataChannel.readyState !== 'open') return;

        const msg = event.data;
        if (!msg || !msg.type?.startsWith('ws-')) return;

        if (msg.type === 'ws-open') {
            const streamId = this.nextStreamId++;
            if (this.debug) console.log(`[Bootstrap] ws-open ${msg.pathname}, streamId=${streamId}, cookies.len=${(msg.cookies || '').length}`);

            // Magic path: /__bitbang/<type>?<params> opens a SWSP
            // stream of the named type. bootstrap.js is a generic
            // transport here — it builds the SYN from path+query but
            // shuttles raw bytes for DAT/FIN. Each iframe-served cap
            // (shell, serial, forward, …) handles its own per-stream
            // framing (tag bytes, JSON FIN payloads, etc.). Adding a
            // new cap therefore doesn't require any bootstrap.js
            // changes — just a new device-side handler and an iframe
            // page that opens the right magic URL.
            const bitbangPrefix = '/__bitbang/';
            if (msg.pathname && msg.pathname.indexOf(bitbangPrefix) === 0) {
                const u = new URL(msg.pathname, 'http://device');
                // Pathname after /__bitbang/ is the stream type. Strip
                // the leading slash that URL.pathname keeps and pull
                // out the first segment.
                const tail = u.pathname.substring(bitbangPrefix.length);
                const type = tail.split('/')[0];
                if (!type) {
                    iframe.contentWindow.postMessage({
                        type: 'ws-closed', streamId, code: 1008,
                        reason: 'bitbang: empty type in magic path',
                    }, '*');
                    return;
                }

                // Build the SYN payload from the query string. Each
                // value is JSON-parsed where possible (so "true" → bool,
                // "80" → number, "[\"bash\"]" → array), otherwise kept
                // as a literal string. The result is a typed JSON
                // object the listener can unmarshal cleanly.
                const syn = { type };
                for (const [k, v] of u.searchParams) {
                    try { syn[k] = JSON.parse(v); }
                    catch (e) { syn[k] = v; }
                }

                this.wsStreams.set(streamId, { iframe: iframe.contentWindow, kind: 'bitbang' });
                iframe.contentWindow.postMessage({
                    type: 'ws-assign', pathname: msg.pathname, streamId,
                }, '*');
                this.dataChannel.send(this.createFrame(streamId, FLAG_SYN, JSON.stringify(syn)));
                // Tell the iframe the WS is open now. Listener handlers
                // typically don't send a SYN ack on the success path —
                // the first DAT is the natural signal that things are
                // working. Iframe code can start sending immediately.
                iframe.contentWindow.postMessage({ type: 'ws-opened', streamId }, '*');
                return;
            }

            // Regular WebSocket proxy path (unchanged).
            this.wsStreams.set(streamId, { iframe: iframe.contentWindow, kind: 'websocket' });
            iframe.contentWindow.postMessage({
                type: 'ws-assign',
                pathname: msg.pathname,
                streamId
            }, '*');
            const synPayload = JSON.stringify({
                type: 'websocket',
                pathname: msg.pathname,
                cookies: msg.cookies || '',
            });
            this.dataChannel.send(this.createFrame(streamId, FLAG_SYN, synPayload));
            if (this.debug) console.log(`[Bootstrap] ws SYN sent to device, streamId=${streamId}`);

        } else if (msg.type === 'ws-send') {
            const ws = this.wsStreams.get(msg.streamId);
            if (!ws) return;

            if (ws.kind === 'bitbang') {
                // Generic shuttle: raw bytes go through unchanged. Text
                // frames are UTF-8 encoded; the iframe is responsible
                // for keeping the cap-specific framing it expects.
                let payload;
                if (msg.isText) {
                    payload = new TextEncoder().encode(msg.data);
                } else {
                    payload = msg.data instanceof ArrayBuffer
                        ? new Uint8Array(msg.data)
                        : new Uint8Array(msg.data);
                }
                this.dataChannel.send(this.createFrame(msg.streamId, FLAG_DAT, payload));
                return;
            }

            // Regular WebSocket DAT framing: [1B type: 0=text 1=binary][message]
            let payload;
            if (msg.isText) {
                const textBytes = new TextEncoder().encode(msg.data);
                payload = new Uint8Array(1 + textBytes.length);
                payload[0] = 0; // text
                payload.set(textBytes, 1);
            } else {
                const binBytes = msg.data instanceof ArrayBuffer
                    ? new Uint8Array(msg.data)
                    : new Uint8Array(msg.data);
                payload = new Uint8Array(1 + binBytes.length);
                payload[0] = 1; // binary
                payload.set(binBytes, 1);
            }
            // Chunk at SWSP_CHUNK_SIZE (the data-channel message limit). Non-final
            // chunks carry FLAG_MORE so the device reassembles them into one WS
            // message (the type byte rides in the first chunk).
            for (let off = 0; off < payload.length; off += SWSP_CHUNK_SIZE) {
                const end = off + SWSP_CHUNK_SIZE;
                const flags = end >= payload.length ? FLAG_DAT : (FLAG_DAT | FLAG_MORE);
                this.dataChannel.send(this.createFrame(
                    msg.streamId, flags, payload.subarray(off, Math.min(end, payload.length))));
            }

        } else if (msg.type === 'ws-close') {
            const ws = this.wsStreams.get(msg.streamId);
            if (!ws) return;
            this.wsStreams.delete(msg.streamId);
            this.dataChannel.send(this.createFrame(msg.streamId, FLAG_FIN, new Uint8Array(0)));
        }
    }

    createIframe() {
        const iframe = document.createElement('iframe');
        iframe.id = 'device-frame';
        iframe.sandbox = 'allow-scripts allow-forms allow-same-origin allow-popups allow-modals allow-downloads';
        iframe.allow = 'autoplay; fullscreen';
        iframe.scrolling = 'yes';
        iframe.style.cssText = `
            position: fixed; top: 0; left: 0;
            width: 100%; height: 100%;
            border: none; z-index: 1; background: #fff;
        `;

        iframe.onload = () => {
            // Constrain the iframe body to the viewport so modal height
            // calculations use the visible area, not the content height.
            try {
                const doc = iframe.contentDocument;
                const s = doc.createElement('style');
                s.textContent = 'html, body { height: 100% !important; overflow: auto !important; }';
                doc.head.appendChild(s);
            } catch (e) {}

            this.wireStreams(iframe);
            if (this.connectionUI) this.connectionUI.style.display = 'none';

            const iframeTitle = iframe.contentDocument?.title;
            document.title = iframeTitle || this.deviceName || "BitBang";

            // Set device favicon. Helper to update or create the link element.
            const setFavicon = (href) => {
                let link = document.querySelector('link[rel="icon"]');
                if (!link) {
                    link = document.createElement('link');
                    link.rel = 'icon';
                    document.head.appendChild(link);
                }
                link.href = href;
            };

            // Try /favicon.ico -- only set if it exists (don't clear with a 404)
            fetch(`/__device__/${this.sessionId}/favicon.ico`).then(r => {
                if (r.ok) setFavicon(`/__device__/${this.sessionId}/favicon.ico`);
            }).catch(() => {});

            // Also watch for the device setting a favicon dynamically via JS
            // (e.g. NAS sets <link rel="icon"> after page load)
            const iframeDoc = iframe.contentDocument;
            if (iframeDoc) {
                const copyIcon = () => {
                    const icon = iframeDoc.querySelector('link[rel*="icon"]');
                    if (icon) { setFavicon(icon.href); return true; }
                    return false;
                };
                if (!copyIcon()) {
                    const obs = new MutationObserver(() => { if (copyIcon()) obs.disconnect(); });
                    obs.observe(iframeDoc.head || iframeDoc.documentElement, { childList: true, subtree: true });
                    setTimeout(() => obs.disconnect(), 5000);
                }
            }
        };

        iframe.src = `/__device__/${this.sessionId}${this.devicePath}`;
        document.body.appendChild(iframe);
    }

    wireStreams(iframe) {
        const doc = iframe.contentDocument;
        if (!doc) return;

        // Wire elements with data-bitbang-stream attribute
        doc.querySelectorAll('[data-bitbang-stream]').forEach(el => {
            const name = el.getAttribute('data-bitbang-stream');
            const streamName = (name === '' || name === null)
                ? Object.keys(this.resolvedStreams)[0]
                : name;

            if (streamName && this.resolvedStreams[streamName]) {
                el.srcObject = this.resolvedStreams[streamName];
            }
        });

        // Expose __bitbang to iframe
        iframe.contentWindow.__bitbang = {
            streams: this.resolvedStreams,
            getStream: (name) => this.resolvedStreams[name],
            getDefaultStream: () => this.resolvedStreams[Object.keys(this.resolvedStreams)[0]],
            pc: this.pc
        };
    }
}

// Initialize — but only in the top-level window, not inside the device iframe.
// If bootstrap.html accidentally loads inside the iframe (e.g. due to a redirect
// that escapes the /__device__/ scope), skip initialization to avoid a second
// WebRTC connection that would fail with "Device not found".
(async function() {
    console.log('[Bootstrap] IIFE running', window.location.href);
    if (window !== window.top) {
        console.warn('[Bootstrap] Skipping init — running inside iframe, not top-level');
        return;
    }

    const pathParts = window.location.pathname.split('/').filter(Boolean);
    if (pathParts.length === 0) {
        const el = document.getElementById('status');
        el.textContent = 'No device ID specified';
        el.classList.add('error');
        return;
    }

    const uid = pathParts[0];
    let pathFromUrl = '/' + pathParts.slice(1).join('/');
    // Preserve trailing slash from the original pathname. URL parsing
    // above drops it (filter(Boolean) strips the empty segment after
    // the last /), but the listener's mux mounts cap routes WITH the
    // trailing slash ("/proxy/" not "/proxy"). Without this, the iframe
    // load triggers a 301 from the listener whose Location header
    // doesn't include the /__device__/<sessionId> prefix — the iframe
    // ends up navigating to the wrong place.
    if (window.location.pathname.endsWith('/') && pathFromUrl !== '/') {
        pathFromUrl += '/';
    }

    // The 64-bit access code lives in the URL fragment so the signaling
    // server never sees it. Browsers also never send fragments to servers,
    // so even if a user accidentally posts the URL to a server log, the
    // code part is stripped on first send. The browser bundles it inside
    // the RSA-OAEP-encrypted verify payload sent to the device.
    //
    // We also accept a naively-concatenated path inside the fragment as
    // a convenience: a user with the URL `https://srv/<uid>#<code>` who
    // wants the subpath `/foo` can just append `/foo` to get
    // `https://srv/<uid>#<code>/foo`, and we auto-rearrange to the
    // canonical `https://srv/<uid>/foo#<code>`. The access-code alphabet
    // is base64url (`[A-Za-z0-9_-]`) which never contains `/`, so the
    // first `/` in the fragment unambiguously separates code from path.
    //
    // When both a URL path AND a fragment path are present (the user
    // appended onto an already-canonical URL), we concat them: e.g.
    // `https://srv/<uid>/foo#<code>/bar` -> devicePath `/foo/bar`.
    const rawFragment = window.location.hash ? window.location.hash.slice(1) : '';
    const slashAt = rawFragment.indexOf('/');
    let code, pathFromFragment;
    if (slashAt >= 0) {
        code = rawFragment.substring(0, slashAt);
        pathFromFragment = rawFragment.substring(slashAt);  // keeps the leading '/'
    } else {
        code = rawFragment;
        pathFromFragment = '';
    }

    // Concatenate URL path + fragment path. Drop the lone '/' on the
    // URL side so we don't end up with '//foo'.
    const urlPathSeg = (pathFromUrl === '/') ? '' : pathFromUrl;
    const devicePath = (urlPathSeg + pathFromFragment) || '/';

    // Whenever the fragment contributed a path, rewrite the address bar
    // so a reload / copy / share captures the canonical shape.
    if (pathFromFragment) {
        const canonical = '/' + uid + devicePath
            + (window.location.search || '')
            + '#' + code;
        history.replaceState(null, '', canonical);
        console.log('[Bootstrap] Rearranged URL to canonical form:', canonical);
    }

    const connection = new BitBangConnection(uid, devicePath, code);
    window.__bitbangConnection = connection;
    await connection.connect();
})();
