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

// How long to wait, after sending the answer, before showing the user a
// "Negotiating connection..." reassurance banner (the connection usually
// comes up well before this). Single-phase ICE has no fallback step to arm:
// the direct-vs-relay bias now lives on the device (the ICE-controlling
// agent withholds relay nomination), and the connector trickles all
// candidates immediately. See bitbang/CONVENTIONS.md "Favoring direct on
// slow & embedded devices".
//
// Parse Bitbang URL flags from the fragment. Grammar (see CONVENTIONS.md
// "URL and credential terms"):
//
//   fragment  = <code> [ '!' <flag-list> ] [ '/' <device-URL> ]
//   flag-list = <flag> [ ',' <flag> ]*
//   flag      = <name> [ '=' <value> ]
//
// Flags live in the fragment, so the signaling server never sees them.
// Returns { debug, nocookiejar, relay, norelay, msg_timeout } — booleans
// are true when the flag is present, msg_timeout carries the parsed value
// or undefined. Reads window.location.hash every call so callers see the
// current state (URL fragment can change via history.replaceState).
function parseUrlFlags() {
    const frag = window.location.hash ? window.location.hash.slice(1) : '';
    let i = 0;
    while (i < frag.length && /[A-Za-z0-9_-]/.test(frag[i])) i++;
    if (frag[i] !== '!') return {};
    let j = i + 1;
    while (j < frag.length && frag[j] !== '/') j++;
    const out = {};
    for (const tok of frag.slice(i + 1, j).split(',')) {
        if (!tok) continue;
        const eq = tok.indexOf('=');
        if (eq >= 0) out[tok.slice(0, eq)] = tok.slice(eq + 1);
        else out[tok] = true;
    }
    return out;
}

// Read the raw '!<flag-list>' segment from the current URL fragment (with
// leading '!'), or '' if no flag section is present. Used by syncTopURL to
// preserve the flag tail verbatim across in-iframe navigations.
function readUrlFlagString() {
    const frag = window.location.hash ? window.location.hash.slice(1) : '';
    let i = 0;
    while (i < frag.length && /[A-Za-z0-9_-]/.test(frag[i])) i++;
    if (frag[i] !== '!') return '';
    let j = i + 1;
    while (j < frag.length && frag[j] !== '/') j++;
    return frag.slice(i, j);
}

// Override via !msg_timeout=N (seconds, float-OK). Defaults to 3 seconds.
const MESSAGE_TIMEOUT_MS = (() => {
    const n = parseFloat(parseUrlFlags().msg_timeout);
    return isFinite(n) && n > 0 ? n * 1000 : 3000;
})();

// SWSP (Simple WebRTC Streaming Protocol) constants
const FLAG_SYN = 0x0001;
const FLAG_FIN = 0x0004;
const FLAG_DAT = 0x0000;
const FLAG_MORE = 0x0002;  // non-final fragment of a chunked WS message
const SWSP_CHUNK_SIZE = 16384;  // max payload bytes per data-channel frame
const SWSP_VERSION = SWSPFlowControl.VERSION;
const SWSP_BUFFER_LIMIT = 1024 * 1024;

// Soft reconnect: when an established peer connection drops (e.g. a transient
// network blip on a long-lived session), rebuild the transport under the live
// page instead of showing the reload screen. Modeled as a fresh connection
// request — the device needs no ICE-restart support; it just answers a new
// request via its normal HandleRequest path.
//
// Recovery is budgeted by wall-clock time, not attempt count: failures differ
// wildly in cost (a restarting signaling server refuses in milliseconds; a
// device that hasn't re-registered yet answers "not found" just as fast; a
// dead path times out in seconds), and they are all the same condition — the
// way back isn't ready yet. So: retry with capped exponential backoff until
// RECONNECT_WINDOW_MS of effort has elapsed against a reachable network.
// While the browser knows it's offline, attempts are provably pointless;
// park until the 'online' event and start a fresh window. The reload screen
// is the fallback once the window closes.
const RECONNECT_WINDOW_MS = 5 * 60 * 1000;  // give up after this much failed effort
const RECONNECT_MAX_BACKOFF_MS = 10000;     // cap on the delay between attempts
const RECONNECT_TIMEOUT_MS = 20000;  // per attempt: WS + offer + DC verify + ready
const RECONNECT_SETTLE_MS = 2000;    // after offline→online, let the network settle

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

// Buffer ICE candidates that arrive (or are produced) before the remote
// description is set, then drain them in arrival order. Used by both the
// direct (BitBangConnection) and pair (PairingFlow) handshakes — the
// readiness gate lives at the call site because each flow tracks
// remote-description state and ws-open state differently.
class CandidateQueue {
    constructor() { this.local = []; this.remote = []; }
    pushLocal(msg)  { this.local.push(msg); }
    pushRemote(c)   { this.remote.push(c); }
    drainLocal(send) {
        for (const m of this.local) send(m);
        this.local.length = 0;
    }
    drainRemote(add) {
        for (const c of this.remote) add(c);
        this.remote.length = 0;
    }
}

class BitBangConnection {
    constructor(uid, devicePath, code, deviceSearch, deviceHash) {
        this.uid = uid;
        this.devicePath = devicePath || '/';
        // The proxy target (first path segment, e.g. "localhost:8096"), kept
        // separately: SPA apps that navigate with origin-absolute paths
        // (Jellyfin → /web/#/…) drop both the /__device__/<sid> prefix and the
        // target from the iframe URL, so syncTopURL needs it to reconstruct a
        // target-prefixed device path for refresh/bookmark.
        this.target = (devicePath || '/').split('/').filter(Boolean)[0] || '';
        this.deviceSearch = deviceSearch || '';
        this.deviceHash = deviceHash || '';
        this.code = code || '';
        // Snapshot the URL's `!<flags>` section at session start. If the
        // user edits the code or the flag section in the address bar,
        // iframeShowsTopURL notices the mismatch and lets the hashchange
        // handler reload — a code/flag edit is a genuinely different
        // session, not an in-app navigation.
        this.initialFlagStr = readUrlFlagString();
        this.pc = null;
        this.dataChannel = null;
        this.ws = null;
        this.streamNameMap = {};      // from offer: { "0": "webcam", ... }
        this.resolvedStreams = {};    // name -> MediaStream
        this.pendingRequests = new Map();  // streamId -> request state
        this.connectResolve = null;   // resolved when device sends 'ready'
        this.nextStreamId = 1;        // streamId 0 is reserved for control
        this.wsStreams = new Map();    // streamId -> { iframe } for WebSocket bridging
        this.negotiatedVersion = 2;
        this._protocolReady = false;
        this.sendChains = new Map();
        this.flow = new SWSPFlowControl.Controller((msg) => this._sendControl(msg));
        this.sessionId = Array.from(crypto.getRandomValues(new Uint8Array(4)), b => b.toString(16).padStart(2, '0')).join(''); // 8 hex chars
        console.log('[Bootstrap] ctor', this.sessionId);
        this.candidateQueue = new CandidateQueue();
        this.remoteDescriptionSet = false;
        this.progressChannel = new BroadcastChannel('bitbang-progress');

        this.statusEl = document.getElementById('status');
        this.connectionUI = document.getElementById('connection-ui');
        {
            const _flags = parseUrlFlags();
            this.debug = !!_flags.debug;
            this.noCookieJar = !!_flags.nocookiejar;
        }
        this._turnHoldPromise = null;
        this._wasConnected = false;
        this._usingRelay = false;
        this._turnWarnTimer = null;
        this._turnEndTimer = null;
        this._turnExpiryMs = null;
        this._turnUnavailable = false;
        this._turnEnded = false;
        // Soft-reconnect state.
        this._transportReady = false;   // one-time setup (SW reg, iframe) done
        this._reconnecting = false;     // a reconnect loop is in progress
        this._reconnectResolve = null;  // resolves the in-flight attempt on ready
        this._reconnectReject = null;
        this._reconnectTimeout = null;
    }

    // SWSP frame helpers
    createFrame(streamId, flags, payload) {
        return SWSPFlowControl.createFrame(streamId, flags, payload);
    }

    parseFrame(buffer) {
        return SWSPFlowControl.parseFrame(buffer);
    }

    _sendControl(msg) {
        if (!this.dataChannel || this.dataChannel.readyState !== 'open') return false;
        try {
            this.dataChannel.send(this.createFrame(0, FLAG_SYN, JSON.stringify(msg)));
            return true;
        } catch (e) {
            return false;
        }
    }

    _validStreamId(streamId) {
        return Number.isSafeInteger(streamId) && streamId > 0 && streamId <= 0xffffffff;
    }

    _allocateStreamId() {
        const streamId = this.nextStreamId++;
        if (!this._validStreamId(streamId)) throw new Error('SWSP stream IDs exhausted');
        return streamId;
    }

    _openStream(streamId) {
        if (!this._validStreamId(streamId)) throw new Error('invalid SWSP stream ID');
        this.flow.open(streamId);
    }

    _sendStreamSYN(streamId, flags, payload) {
        this._openStream(streamId);
        try {
            this.dataChannel.send(this.createFrame(streamId, flags, payload));
        } catch (e) {
            this.flow.resetStream(streamId, e);
            throw e;
        }
    }

    _applicationBytes(frame) {
        if (frame.streamId === 0 || (frame.flags & FLAG_SYN)) return 0;
        return frame.payload?.byteLength || 0;
    }

    _acceptFrame(frame) {
        if (frame.flags & FLAG_SYN) {
            if (!this.flow.has(frame.streamId)) {
                this._resetStream(frame.streamId, 'protocol_error', 'unexpected inbound stream', true);
                return false;
            }
            if ((frame.flags & FLAG_FIN) && !this.flow.finishReceive(frame.streamId)) {
                this._resetStream(frame.streamId, 'protocol_error', 'frame received after FIN', true);
                return false;
            }
            return true;
        }
        const bytes = this._applicationBytes(frame);
        if (this.flow.receive(frame.streamId, bytes, !!(frame.flags & FLAG_FIN))) return true;
        this._resetStream(frame.streamId, 'flow_control', 'receive window exceeded', true);
        return false;
    }

    _consumeFrame(streamId, byteLength, frames) {
        if (!this.flow.has(streamId)) return false;
        if (this.flow.consume(streamId, byteLength, frames)) return true;
        this._resetStream(streamId, 'protocol_error', 'invalid receive acknowledgement', true);
        return false;
    }

    _registerWSAck(ws, byteLength, frames, onAck) {
        if (!ws._receiveAcks) ws._receiveAcks = new Map();
        let token;
        do {
            const words = crypto.getRandomValues(new Uint32Array(4));
            token = Array.from(words, word => word.toString(16).padStart(8, '0')).join('');
        } while (ws._receiveAcks.has(token));
        ws._receiveAcks.set(token, { byteLength, frames, onAck });
        return token;
    }

    _handleWSAck(streamId, token) {
        const ws = this.wsStreams.get(streamId);
        const ack = ws?._receiveAcks?.get(token);
        if (!ws || !ack) {
            if (ws) this._resetStream(streamId, 'protocol_error', 'invalid WebSocket acknowledgement', true);
            return;
        }
        ws._receiveAcks.delete(token);
        if (ack.frames > 0 && !this._consumeFrame(streamId, ack.byteLength, ack.frames)) return;
        if (ack.onAck) ack.onAck();
    }

    _finishRequest(streamId) {
        const req = this.pendingRequests.get(streamId);
        if (!req || !req.localFinished || !req.responseClosed) return;
        clearTimeout(req.timeout);
        if (req.cleanupTimeout) clearTimeout(req.cleanupTimeout);
        this.pendingRequests.delete(streamId);
        this.flow.resetStream(streamId, new Error('stream complete'));
    }

    async _waitForDataChannel(streamId) {
        while (this.dataChannel?.readyState === 'open'
            && this.dataChannel.bufferedAmount > SWSP_BUFFER_LIMIT) {
            if (!this.flow.has(streamId)) throw new Error('stream closed');
            await new Promise(resolve => setTimeout(resolve, 10));
        }
        if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
            throw new Error('data channel closed');
        }
    }

    _queueStreamFrame(streamId, flags, payload) {
        const byteLength = (flags & FLAG_SYN) ? 0 : (payload?.byteLength || 0);
        let wireFrame;
        try {
            wireFrame = this.createFrame(streamId, flags, payload);
        } catch (e) {
            return Promise.reject(e);
        }
        const previous = this.sendChains.get(streamId) || Promise.resolve();
        const send = previous.catch(() => {}).then(async () => {
            await this.flow.waitToSend(streamId, byteLength);
            await this._waitForDataChannel(streamId);
            if (!this.flow.has(streamId)) throw new Error('stream closed');
            this.dataChannel.send(wireFrame);
        });
        this.sendChains.set(streamId, send);
        const cleanup = () => {
            if (this.sendChains.get(streamId) === send) this.sendChains.delete(streamId);
        };
        send.then(cleanup, cleanup);
        return send;
    }

    _resetStream(streamId, code, message, notifyPeer) {
        const error = new SWSPFlowControl.FlowError(code, message);
        this.flow.resetStream(streamId, error);
        this.sendChains.delete(streamId);

        const req = this.pendingRequests.get(streamId);
        if (req) {
            clearTimeout(req.timeout);
            if (req.cleanupTimeout) clearTimeout(req.cleanupTimeout);
            this.pendingRequests.delete(streamId);
            try { req.responsePort.postMessage({ type: 'error', message }); } catch (e) {}
        }

        const ws = this.wsStreams.get(streamId);
        if (ws) {
            ws._rxParts = null;
            ws._pendingFrames = [];
            ws._receiveAcks?.clear();
            if (ws._closeTimeout) clearTimeout(ws._closeTimeout);
            this.wsStreams.delete(streamId);
            try {
                ws.iframe.postMessage({ type: 'ws-error', streamId, message }, '*');
                ws.iframe.postMessage({
                    type: 'ws-closed', streamId, code: 1006, reason: message,
                }, '*');
            } catch (e) {}
        }

        if (notifyPeer && this.negotiatedVersion >= SWSP_VERSION) {
            this._sendControl({
                type: 'stream_reset', stream_id: streamId, code, message,
            });
        }

        if (notifyPeer && this.negotiatedVersion < SWSP_VERSION
            && this.dataChannel?.readyState === 'open') {
            try {
                this.dataChannel.send(this.createFrame(streamId, FLAG_FIN, new Uint8Array(0)));
            } catch (e) {}
        }
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

    // Same, but only with !debug — the extra play-by-play detail.
    _printDebug(msg) {
        if (this.debug) this._print(msg);
    }

    // Parse the coturn REST-API expiry from a TURN credential's username
    // ("<epoch>[:<user_name>]") and stash it in this._turnExpiryMs. The
    // server stamps the same epoch on every entry it returns, so the
    // first match wins. Called when the offer's ice_servers arrive — single-
    // phase stamps TURN up front, so there is no separate post-stall push.
    _extractTurnExpiry(servers) {
        if (!Array.isArray(servers)) return;
        for (const s of servers) {
            const m = s && s.username && /^(\d+)(:|$)/.exec(s.username);
            if (m) {
                this._turnExpiryMs = parseInt(m[1], 10) * 1000;
                return;
            }
        }
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

        // Capture whether a SW already controlled us BEFORE registering.
        // controllerchange fires on first-install too (controller goes from
        // null to the new SW), but we only want to reload when an *update*
        // takes over — i.e. when a previous controller was already running.
        const hadController = !!navigator.serviceWorker.controller;

        const reg = await navigator.serviceWorker.register('/__bitbang__/sw.js', {
            scope: '/',
            updateViaCache: 'none',
        });
        // Force check for SW update on every page load.
        reg.update();

        // When a new SW takes over an existing controller, show a small
        // banner offering a reload — don't auto-reload, since a mid-session
        // refresh blows away shell scrollback, half-typed proxied-app form
        // input, etc. The new SW already serves fresh sw.js; the banner is
        // just the user's signal to pull in fresh bootstrap.js/.html.
        // skipWaiting() in sw.js's install handler is what makes the
        // takeover happen without prompting.
        navigator.serviceWorker.addEventListener('controllerchange', () => {
            if (!hadController) return;             // first install, not an update
            showUpdateBanner();
        });

        // Long-lived sessions (a shell sitting open for hours) won't navigate
        // and so won't trigger the browser's default update check. Poll every
        // 30 min so a deploy reaches them within the window. A single fetch
        // of sw.js per half hour is negligible bandwidth.
        setInterval(() => reg.update().catch(() => {}), 30 * 60 * 1000);

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

        if (!this.dataChannel || this.dataChannel.readyState !== 'open'
            || !this.deviceVerified || !this._protocolReady) {
            console.warn('[Bootstrap] Data channel not open, rejecting request');
            responsePort.postMessage({ type: 'error', message: 'Connection not ready' });
            // A live page with a dead channel should be recovering, not
            // rejecting forever — kick the reconnect if nothing else did.
            // (No-op while a reconnect is in flight or after a terminal end.)
            if (this._wasConnected) this._handlePostHandshakeFailure();
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
        const streamId = this._allocateStreamId();

        // Initial 30s timeout to catch "device not responding". Cleared once
        // response headers arrive (SYN). After that we rely on FIN / data
        // channel close to signal end -- inactivity is normal during streaming
        // when the consumer (e.g. video player) backpressures the channel.
        let timeout;
        const resetTimeout = () => {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                this._resetStream(streamId, 'timeout', 'Request timeout', true);
            }, 30000);
            const req = this.pendingRequests.get(streamId);
            if (req) req.timeout = timeout;
        };
        resetTimeout();

        this.pendingRequests.set(streamId, {
            responsePort,
            timeout,
            bytesReceived: 0,
            startTime: Date.now(),
            nextLogMB: 50,
            isUpload: hasBody,
            localFinished: !hasBody,
            remoteFinished: false,
            responseClosed: false,
            headersReceived: false,
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
            try {
                this._sendStreamSYN(streamId, FLAG_SYN, JSON.stringify(requestMeta));
            } catch (e) {
                this._resetStream(streamId, 'send_error', 'Failed to start upload', false);
                this.progressChannel.postMessage({ type: 'uploadFailed' });
                return;
            }

            const MAX_CHUNK = 16384;
            let bytesSent = 0;
            let lastProgress = 0;
            let processingChain = Promise.resolve();

            const failUpload = (msg) => {
                if (this.pendingRequests.has(streamId)) {
                    this._resetStream(streamId, 'upload_error', msg, isOpen());
                }
                this.progressChannel.postMessage({ type: 'uploadFailed' });
            };

            const isOpen = () => this.dataChannel?.readyState === 'open';

            responsePort.onmessage = (event) => {
                if (event.data.type === 'responseConsumed') {
                    this._consumeFrame(streamId, event.data.bytes || 0, event.data.frames || 1);
                    return;
                }
                if (event.data.type === 'responseClosed') {
                    const req = this.pendingRequests.get(streamId);
                    if (req?.cleanupTimeout) clearTimeout(req.cleanupTimeout);
                    if (req) req.responseClosed = true;
                    this._finishRequest(streamId);
                    return;
                }
                if (event.data.type === 'cancel') {
                    this._resetStream(streamId, 'cancelled', event.data.message || 'request cancelled', true);
                    return;
                }
                processingChain = processingChain.then(async () => {
                    if (!isOpen()) return failUpload('Connection lost');

                    if (event.data.type === 'bodyChunk') {
                        const data = event.data.data;

                        for (let i = 0; i < data.byteLength; i += MAX_CHUNK) {
                            const chunk = data.subarray(i, Math.min(i + MAX_CHUNK, data.byteLength));
                            try {
                                await this._queueStreamFrame(streamId, FLAG_DAT, chunk);
                            } catch (e) {
                                return failUpload(e.message || 'Connection lost');
                            }
                        }

                        // The service worker does not read the next request-body
                        // chunk until this one has passed both stream credit and
                        // the data-channel aggregate buffer.
                        responsePort.postMessage({ type: 'bodyAck', seq: event.data.seq });

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
                        try {
                            await this._queueStreamFrame(streamId, FLAG_FIN, new Uint8Array(0));
                            const req = this.pendingRequests.get(streamId);
                            if (req) {
                                req.localFinished = true;
                                this._finishRequest(streamId);
                            }
                        } catch (e) {
                            return failUpload(e.message || 'Connection lost');
                        }
                    }
                });
            };
        } else {
            // No body - send SYN|FIN together
            try {
                this._sendStreamSYN(streamId, FLAG_SYN | FLAG_FIN, JSON.stringify(requestMeta));
            } catch (e) {
                this._resetStream(streamId, 'send_error', 'Failed to start request', false);
                return;
            }
            responsePort.onmessage = (event) => {
                if (event.data.type === 'responseConsumed') {
                    this._consumeFrame(streamId, event.data.bytes || 0, event.data.frames || 1);
                } else if (event.data.type === 'responseClosed') {
                    const req = this.pendingRequests.get(streamId);
                    if (req?.cleanupTimeout) clearTimeout(req.cleanupTimeout);
                    if (req) req.responseClosed = true;
                    this._finishRequest(streamId);
                } else if (event.data.type === 'cancel') {
                    this._resetStream(streamId, 'cancelled', event.data.message || 'request cancelled', true);
                }
            };
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
                // !relay tells the server to skip TURN withholding and
                // include relay credentials in the initial offer (legacy
                // behavior). !norelay also disables the fallback (handled
                // in createPeerConnection by dropping iceServers entirely).
                const flags = parseUrlFlags();
                const forceRelay = !!flags.relay && !flags.norelay;
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
                    // Single-phase ICE: the device sends exactly one offer per
                    // session (TURN creds are stamped on it up front, no ICE
                    // restart). A second offer is unexpected — ignore it.
                    if (this.pc && this.remoteDescriptionSet) {
                        console.warn('[Bootstrap] unexpected second offer on an established PC — ignoring');
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

            this.ws.onclose = () => {
                // A clean close (e.g. the signaling server restarting) fires
                // no 'error' event — without this, a setup in progress would
                // ride out its full timeout instead of failing fast. Once
                // setup has resolved, reject is a no-op: the signaling WS is
                // setup-only by design, the session runs P2P, and recovery
                // redials on demand — so a post-setup close is expected and
                // harmless (it also fires on our own teardown's close()).
                clearTimeout(offerTimeout);
                if (this.debug) console.log('[Bootstrap] signaling WS closed');
                reject(new Error('WebSocket closed'));
            };
        });
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
        // with !relay + capacity gating the connection may never establish
        // (no TURN server in iceServers + relay-only policy = no candidates),
        // so _onFirstConnected won't ever fire and the user would otherwise
        // get no feedback at all.
        if (this._turnUnavailable) {
            this._print('Relay server (TURN) is at capacity. Connection may fail — please try again later.');
        }
        this._turnExpiryMs = null;
        this._extractTurnExpiry(msg.ice_servers);
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
        this.candidateQueue.drainRemote(c => this.pc.addIceCandidate(c).catch(() => {}));

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
        this.candidateQueue.drainLocal(m => this.ws.send(JSON.stringify(m)));

        // Reassurance banner: if the connection still isn't up after
        // MESSAGE_TIMEOUT_MS, show "Negotiating connection..." so the user
        // knows the page hasn't stalled. Under single-phase ICE the relay
        // candidate trickles on its own after the same delay, so there is no
        // separate escalation step to arm.
        this._reassureTimer = setTimeout(() => this._reassureUser(), MESSAGE_TIMEOUT_MS);
    }

    createPeerConnection(iceServers) {
        const config = { sdpSemantics: 'unified-plan' };
        // Diagnostic flags:
        //   !norelay drops STUN/TURN servers entirely so ICE only has host
        //     candidates ("is host-to-host actually broken, or is it just
        //     losing the race to relay?").
        //   !relay sets iceTransportPolicy:'relay' so the browser only
        //     gathers and uses relay candidates ("force the TURN path so
        //     we can verify the relay-in-use banner / end-of-session UX").
        // The two are mutually exclusive; norelay wins if both are set.
        const flags = parseUrlFlags();
        const noRelay = !!flags.norelay;
        const forceRelay = !!flags.relay && !noRelay;
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
                // Connection is up — cancel the "negotiating" reassurance banner.
                this._clearReassureTimer();
                this._printDebug(STATUS.CONNECTED);
                this.pollConnectionType(pc);
                if (!this._wasConnected) {
                    this._wasConnected = true;
                    this._onFirstConnected(pc);
                }
            } else if (pc.connectionState === 'failed') {
                this._clearReassureTimer();
                if (this._wasConnected) {
                    this._handlePostHandshakeFailure();
                } else if (this._reconnecting) {
                    // A reconnect attempt's fresh PC failed before connecting.
                    // Let the reconnect loop's timeout drive the retry rather
                    // than surfacing a terminal error screen.
                    this._settleReconnect(false, new Error('pc_failed'));
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
                const cand = event.candidate.candidate || '';
                if (this.debug) {
                    // SDP candidate line: candidate:foundation comp proto prio addr port typ <type> ...
                    const m = cand.match(/typ (\S+)/);
                    console.log(`[Bootstrap] local candidate: ${m ? m[1] : '?'} ${cand}`);
                }
                // Trickle every candidate immediately, relay included. The
                // direct-vs-relay bias lives on the device (it withholds
                // relay-pair nomination), so the connector no longer delays
                // its relay candidate. See bitbang/CONVENTIONS.md "Favoring
                // direct on slow & embedded devices".
                const msg = { type: 'candidate', uid: this.uid, candidate: event.candidate };
                if (this.ws?.readyState === WebSocket.OPEN && this.remoteDescriptionSet) {
                    this.ws.send(JSON.stringify(msg));
                } else {
                    this.candidateQueue.pushLocal(msg);
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
            this.dataChannel.onclose = () => {
                console.log('DataChannel closed');
                // The channel can die without the PC ever reporting 'failed'
                // (e.g. the device closes its end). Route through the same
                // recovery path; its guards skip intentional teardown
                // (_reconnecting) and terminal ends (_turnEnded).
                if (this._wasConnected) this._handlePostHandshakeFailure();
            };
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
            this.candidateQueue.pushRemote(candidate);
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

    _clearReassureTimer() {
        if (this._reassureTimer) {
            clearTimeout(this._reassureTimer);
            this._reassureTimer = null;
        }
    }

    // Direct ICE hasn't connected within the first timeout window. Show the
    // user a "Negotiating connection..." banner so they know the page hasn't
    // stalled. Under single-phase ICE the relay candidate has already been
    // trickled (or is about to be), so there is nothing to escalate here —
    // this is purely reassurance UX.
    _reassureUser() {
        this._reassureTimer = null;
        if (this.pc && this.pc.connectionState === 'connected') return;
        this._print(STATUS.NEGOTIATING);
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

    // Called from onconnectionstatechange === 'failed' or the ICE handler
    // after we were once connected. Instead of giving up, attempt a soft
    // reconnect: rebuild the transport under the live page. Only falls back to
    // the reload screen once reconnect attempts are exhausted.
    _handlePostHandshakeFailure() {
        if (this._turnEnded) return;      // intentional end (e.g. relay expiry)
        if (this._reconnecting) return;   // a reconnect loop already owns this
        this._reconnectLoop();
    }

    // Rebuild the transport with a fresh connection request, retrying with
    // linear backoff. Each attempt tears down the dead PC/WS and re-runs the
    // normal signaling flow (request → offer → answer → data channel → ready);
    // the device answers via its ordinary HandleRequest path. Preserves the
    // sessionId, iframe, and app state throughout.
    async _reconnectLoop() {
        this._reconnecting = true;
        this._clearTurnEndTimers();
        this._clearReassureTimer();
        this._showReconnecting();

        // deadline is (re)armed whenever attempting becomes newly possible:
        // at entry, and again when connectivity returns after an offline
        // park. Between those points it only counts down.
        let deadline = Date.now() + RECONNECT_WINDOW_MS;
        let backoff = 1000;
        let attempt = 0;
        // A terminal screen (e.g. device_preempted, relay expiry) may fire at
        // any await point — _turnEnded ends the loop wherever it's checked.
        while (!this._turnEnded) {
            if (!navigator.onLine) {
                console.log('[Bootstrap] offline — waiting for connectivity before reconnecting');
                await this._waitForOnline();
                if (this._turnEnded) break;
                await new Promise(r => setTimeout(r, RECONNECT_SETTLE_MS));
                deadline = Date.now() + RECONNECT_WINDOW_MS;
                backoff = 1000;
                continue;
            }
            attempt++;
            this._teardownTransport();
            try {
                await this._reconnectOnce();
                console.log(`[Bootstrap] reconnected on attempt ${attempt}`);
                this._reconnecting = false;
                this._hideReconnecting();
                return;
            } catch (e) {
                console.warn(`[Bootstrap] reconnect attempt ${attempt} failed:`, e?.message || e);
                if (Date.now() + backoff >= deadline) break;
                await new Promise(r => setTimeout(r, backoff));
                backoff = Math.min(backoff * 2, RECONNECT_MAX_BACKOFF_MS);
            }
        }

        // Window closed (or a terminal screen owns the page) — fall back.
        this._reconnecting = false;
        this._hideReconnecting();
        if (this._turnEnded) return;
        this._turnEnded = true;
        const msg = this._usingRelay
            ? 'Connection lost — relay may have expired.'
            : 'Connection lost. Reload to continue.';
        this.showReloadScreen(msg);
    }

    // One reconnect attempt: kick off signaling and resolve once the rebuilt
    // data channel is verified and the device replies 'ready' (via
    // _onReconnected), or reject on timeout / signaling error.
    _reconnectOnce() {
        return new Promise((resolve, reject) => {
            this._reconnectResolve = resolve;
            this._reconnectReject = reject;
            this._reconnectTimeout = setTimeout(() => this._settleReconnect(false, new Error('reconnect_timeout')), RECONNECT_TIMEOUT_MS);
            // connectWebSocket resolves when the offer is handled; the ready
            // signal comes later via _onReconnected. A WS/offer error here
            // fails this attempt.
            this.connectWebSocket().catch(e => this._settleReconnect(false, e));
        });
    }

    // Resolve/reject the in-flight reconnect attempt exactly once.
    _settleReconnect(ok, err) {
        if (this._reconnectTimeout) { clearTimeout(this._reconnectTimeout); this._reconnectTimeout = null; }
        const resolve = this._reconnectResolve, reject = this._reconnectReject;
        this._reconnectResolve = null;
        this._reconnectReject = null;
        if (ok && resolve) resolve();
        else if (!ok && reject) reject(err || new Error('reconnect_failed'));
    }

    // Called from onDataChannelReady when the rebuilt transport reaches 'ready'.
    _onReconnected() {
        this._settleReconnect(true);
    }

    // Resolve once navigator.onLine is true. The 'online' event is the
    // primary signal; a 5s poll backstops it and lets the reconnect loop
    // notice _turnEnded while parked here.
    async _waitForOnline() {
        while (!navigator.onLine && !this._turnEnded) {
            await new Promise((resolve) => {
                const done = () => {
                    window.removeEventListener('online', done);
                    clearTimeout(timer);
                    resolve();
                };
                const timer = setTimeout(done, 5000);
                window.addEventListener('online', done);
            });
        }
    }

    // Tear down the dead transport and reset per-connection state so the next
    // attempt re-runs _onFirstConnected (re-detects relay, re-arms TURN
    // timers). The sessionId, iframe, SW registration, and window listener are
    // deliberately left intact — they survive the transport swap.
    _teardownTransport() {
        this._clearTurnEndTimers();
        this._clearReassureTimer();
        try { if (this.dataChannel) this.dataChannel.close(); } catch (e) {}
        try { if (this.pc) this.pc.close(); } catch (e) {}
        try { if (this.ws) this.ws.close(); } catch (e) {}
        this.dataChannel = null;
        this.pc = null;
        this.ws = null;
        this.remoteDescriptionSet = false;
        this.deviceVerified = false;
        this.connectResolve = null;
        for (const streamId of Array.from(this.pendingRequests.keys())) {
            this._resetStream(streamId, 'session_closed', 'connection lost', false);
        }
        for (const streamId of Array.from(this.wsStreams.keys())) {
            this._resetStream(streamId, 'session_closed', 'connection lost', false);
        }
        this.flow.reset(false);
        this.sendChains.clear();
        this.negotiatedVersion = 2;
        this._protocolReady = false;
        this.candidateQueue = new CandidateQueue();
        this._wasConnected = false;
        this._usingRelay = false;
        this._turnHoldPromise = null;
        this._turnExpiryMs = null;
    }

    _showReconnecting() {
        let el = document.getElementById('bb-reconnect-banner');
        if (!el) {
            this._prevTitle = document.title;   // restored in _hideReconnecting
            document.title = 'Reconnecting… — bitba.ng';
            el = document.createElement('div');
            el.id = 'bb-reconnect-banner';
            el.textContent = 'Reconnecting…';
            el.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;' +
                'background:#333;color:#fff;font:13px/1.6 sans-serif;text-align:center;' +
                'padding:4px;opacity:0.92;';
            document.body.appendChild(el);
        }
    }

    _hideReconnecting() {
        const el = document.getElementById('bb-reconnect-banner');
        if (el) el.remove();
        if (this._prevTitle != null) {
            document.title = this._prevTitle;
            this._prevTitle = null;
        }
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
                this.handleControlMessage(frame).catch((error) => {
                    const text = new TextDecoder().decode(frame.payload);
                    const type = /"type"\s*:\s*"(window_update|stream_reset)"/.exec(text)?.[1];
                    const rawId = /"stream_id"\s*:\s*(\d+)/.exec(text)?.[1];
                    const streamId = rawId === undefined ? NaN : Number(rawId);
                    if (type && this._validStreamId(streamId) && this.flow.has(streamId)) {
                        this._resetStream(
                            streamId, 'protocol_error', 'malformed stream control', true);
                    } else {
                        console.error('Error parsing SWSP control frame:', error);
                    }
                });
                return;
            }

            if (!this._acceptFrame(frame)) return;

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
                if (req.headersReceived) {
                    this._resetStream(frame.streamId, 'protocol_error', 'duplicate response SYN', true);
                    return;
                }
                req.headersReceived = true;
                // Metadata frame - send headers to SW, it will create the stream
                const text = new TextDecoder().decode(frame.payload);
                let metadata;
                try {
                    metadata = JSON.parse(text);
                } catch (e) {
                    this._resetStream(
                        frame.streamId, 'protocol_error', 'invalid HTTP response metadata', true);
                    return;
                }
                if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
                    this._resetStream(
                        frame.streamId, 'protocol_error', 'invalid HTTP response metadata', true);
                    return;
                }
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
                    req.responsePort.postMessage({
                        type: 'chunk', data, wireBytes: frame.payload.byteLength,
                    }, [data.buffer]);
                } else if (!(frame.flags & FLAG_SYN)) {
                    this._consumeFrame(frame.streamId, 0);
                }

                // Log completion for large transfers
                if (req.bytesReceived > 1024 * 1024) {
                    const elapsed = (Date.now() - req.startTime) / 1000;
                    const sizeMB = req.bytesReceived / (1024 * 1024);
                    const speed = elapsed > 0 ? (sizeMB / elapsed).toFixed(1) : '0';
                    console.log(`Download complete: ${sizeMB.toFixed(0)} MB in ${elapsed.toFixed(1)}s (${speed} MB/s)`);
                }

                req.responsePort.postMessage({ type: 'done' });
                req.remoteFinished = true;
                req.cleanupTimeout = setTimeout(() => {
                    const current = this.pendingRequests.get(frame.streamId);
                    if (!current) return;
                    if (current.localFinished) {
                        this.pendingRequests.delete(frame.streamId);
                        this.flow.resetStream(frame.streamId, new Error('stream complete'));
                    } else {
                        this._resetStream(
                            frame.streamId, 'timeout', 'request body did not finish', true);
                    }
                }, 30000);
            } else if (!(frame.flags & FLAG_SYN) && frame.payload.byteLength > 0) {
                // Data chunk - use transferable to avoid copy
                req.bytesReceived += frame.payload.byteLength;
                const data = new Uint8Array(frame.payload);
                req.responsePort.postMessage({
                    type: 'chunk', data, wireBytes: frame.payload.byteLength,
                }, [data.buffer]);

                // Log progress at each 50MB milestone
                const currentMB = req.bytesReceived / (1024 * 1024);
                if (currentMB >= req.nextLogMB) {
                    const elapsed = (Date.now() - req.startTime) / 1000;
                    const speed = elapsed > 0 ? (currentMB / elapsed).toFixed(1) : '0';
                    console.log(`Download: ${currentMB.toFixed(0)} MB (${speed} MB/s)`);
                    req.nextLogMB += 50;
                }
            } else if (!(frame.flags & FLAG_SYN)) {
                // Empty DAT still occupies a receive-frame slot. It carries no
                // application data, so consume it immediately.
                this._consumeFrame(frame.streamId, 0);
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
            if (!this._protocolReady) {
                let versions;
                try {
                    versions = SWSPFlowControl.negotiateVersion(
                        msg.server_version, msg.negotiated_version);
                } catch (e) {
                    this.showErrorScreen('Connection rejected: invalid protocol negotiation.');
                    try { this.dataChannel.close(); } catch (e) {}
                    return;
                }
                this.serverVersion = versions.serverVersion;
                this.negotiatedVersion = versions.negotiatedVersion;
                this.flow.reset(this.negotiatedVersion >= SWSP_VERSION);
                this._protocolReady = true;
            }
            // routing tells us how to interpret the first segment of the
            // URL fragment's device path. "target-prefix" (bitbangproxy)
            // means the first segment is a LAN target that isolates
            // cookies between hosts reached through this UID.
            // "direct" (bitbang-python WSGI/ASGI, or missing = safe
            // default) means the whole path belongs to the app -- no
            // target segment; all paths under this UID share cookies.
            this.routing = msg.routing || 'direct';
            if (this.routing === 'target-prefix') {
                this.target = (this.devicePath || '/').split('/').filter(Boolean)[0] || '';
            } else {
                this.target = '';
            }
            if (this.debug) {
                console.log('[Bootstrap] Device ready (server v' + this.serverVersion + ', routing=' + this.routing + ', target=' + JSON.stringify(this.target) + ')');
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
                    // The following ready frame completes version
                    // negotiation and resolves the connect wait.
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
        } else if (msg.type === 'window_update') {
            if (this.negotiatedVersion < SWSP_VERSION) return;
            if (!this._validStreamId(msg.stream_id)) return;
            if (this.flow.has(msg.stream_id)
                && !this.flow.updateWindow(msg.stream_id, msg.max_bytes)) {
                this._resetStream(msg.stream_id, 'protocol_error', 'invalid window update', true);
            }
        } else if (msg.type === 'stream_reset') {
            if (this.negotiatedVersion < SWSP_VERSION || !this._validStreamId(msg.stream_id)) return;
            this._resetStream(
                msg.stream_id,
                typeof msg.code === 'string' ? msg.code : 'stream_reset',
                typeof msg.message === 'string' ? msg.message : 'stream reset',
                false
            );
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
        // This is terminal — cancel any in-flight soft reconnect and mark the
        // session ended so a reconnect loop mid-backoff bails out.
        this._turnEnded = true;
        if (this._reconnecting) {
            this._reconnecting = false;
            this._settleReconnect(false, new Error('terminal'));
        }
        this._hideReconnecting();
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

    _newWSState(iframe, kind) {
        return {
            iframe,
            kind,
            localClosing: false,
            localFinished: false,
            remoteFinished: false,
            remoteStarted: false,
            _deliveryPending: false,
            _pendingFrames: [],
            _receiveAcks: new Map(),
        };
    }

    _finishWSStream(streamId, ws) {
        if (!ws.localFinished || !ws.remoteFinished
            || this.wsStreams.get(streamId) !== ws) return;
        if (ws._closeTimeout) clearTimeout(ws._closeTimeout);
        ws._receiveAcks.clear();
        ws._pendingFrames.length = 0;
        this.wsStreams.delete(streamId);
        this.flow.resetStream(streamId, new Error('WebSocket closed'));
    }

    _closeWSOutbound(streamId, ws) {
        if (ws.localClosing || ws.localFinished
            || this.wsStreams.get(streamId) !== ws) return;
        ws.localClosing = true;
        this._queueStreamFrame(streamId, FLAG_FIN, new Uint8Array(0)).then(() => {
            if (this.wsStreams.get(streamId) !== ws) return;
            ws.localClosing = false;
            ws.localFinished = true;
            this._finishWSStream(streamId, ws);
            if (!ws.remoteFinished) {
                ws._closeTimeout = setTimeout(() => {
                    this._resetStream(streamId, 'timeout', 'WebSocket close timeout', true);
                }, 30000);
            }
        }).catch((e) => {
            if (this.wsStreams.get(streamId) === ws) {
                this._resetStream(streamId, 'send_error', e.message || 'WebSocket close failed', true);
            }
        });
    }

    _drainWSFrames(streamId, ws) {
        while (!ws._deliveryPending && ws._pendingFrames.length > 0
            && this.wsStreams.get(streamId) === ws) {
            const frame = ws._pendingFrames.shift();
            this.handleWSFrame(frame, ws);
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
            if (ws.remoteStarted || ws._deliveryPending) {
                this._resetStream(frame.streamId, 'protocol_error', 'duplicate WebSocket SYN', true);
                return;
            }
            ws.remoteStarted = true;
            // Device acknowledged the WebSocket open
            if (this.debug) console.log(`[Bootstrap] ws SYN ack from device, streamId=${frame.streamId}`);
            ws.iframe.postMessage({ type: 'ws-opened', streamId: frame.streamId }, '*');
        }

        // A native WebSocket message may be arbitrarily large, so its
        // fragments are streamed into one Blob assembly. Once complete, hold
        // subsequent frames inside the negotiated receive window until the
        // iframe has synchronously dispatched that message. SYN is validated
        // above because it is credit-exempt and must never enter this queue.
        if (ws._deliveryPending) {
            ws._pendingFrames.push(frame);
            return;
        }

        if (frame.flags & FLAG_FIN) {
            if (ws._rxParts) {
                this._resetStream(frame.streamId, 'protocol_error', 'WebSocket closed mid-message', true);
                return;
            }
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
            if (!(frame.flags & FLAG_SYN)) {
                this._consumeFrame(frame.streamId, frame.payload?.byteLength || 0);
            }
            if (this.debug) console.log(`[Bootstrap] ws FIN from device, streamId=${frame.streamId} code=${code} reason=${JSON.stringify(reason)}`);
            const close = () => {
                if (this.wsStreams.get(frame.streamId) !== ws) return;
                ws.remoteFinished = true;
                ws.iframe.postMessage({
                    type: 'ws-closed', streamId: frame.streamId, code, reason,
                }, '*');
                this._closeWSOutbound(frame.streamId, ws);
                this._finishWSStream(frame.streamId, ws);
            };
            if (ws._delivery) ws._delivery.then(close, close);
            else close();
            return;
        }

        if (!(frame.flags & FLAG_SYN)
            && (frame.payload.byteLength > 0 || ws._rxParts)) {
            // Keep fragments as Blob parts so large messages incur one final
            // materialization rather than repeated whole-buffer copies. Credit
            // is returned as each fragment enters this application-owned
            // assembly; the WebSocket API itself still delivers one message.
            const part = new Uint8Array(frame.payload);
            if (!ws._rxParts) {
                if (part.byteLength < 1) {
                    this._resetStream(frame.streamId, 'protocol_error', 'WebSocket message missing type', true);
                    return;
                }
                if (part[0] !== 0 && part[0] !== 1) {
                    this._resetStream(frame.streamId, 'protocol_error', 'invalid WebSocket message type', true);
                    return;
                }
                ws._rxText = part[0] === 0;
                ws._rxParts = [part.subarray(1)];
            } else {
                ws._rxParts.push(part);
            }
            this._consumeFrame(frame.streamId, frame.payload.byteLength);
            if (frame.flags & FLAG_MORE) return;

            const parts = ws._rxParts;
            const isText = ws._rxText;
            ws._rxParts = null;
            ws._rxText = false;
            ws._deliveryPending = true;
            const delivery = (ws._delivery || Promise.resolve()).then(async () => {
                const blob = new Blob(parts);
                const data = isText ? await blob.text() : await blob.arrayBuffer();
                if (this.wsStreams.get(frame.streamId) !== ws) return;
                const ackToken = this._registerWSAck(ws, 0, 0, () => {
                    if (this.wsStreams.get(frame.streamId) !== ws) return;
                    ws._deliveryPending = false;
                    this._drainWSFrames(frame.streamId, ws);
                });
                ws.iframe.postMessage({
                    type: 'ws-message', streamId: frame.streamId, data, ackToken,
                }, '*');
            });
            ws._delivery = delivery.catch((e) => {
                this._resetStream(frame.streamId, 'receive_error', e.message || 'message delivery failed', true);
            });
            return;
        }
        if (!(frame.flags & (FLAG_SYN | FLAG_FIN))) {
            this._resetStream(frame.streamId, 'protocol_error', 'WebSocket message missing type', true);
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
            if (ws.remoteStarted) {
                this._resetStream(frame.streamId, 'protocol_error', 'duplicate stream SYN', true);
                return;
            }
            ws.remoteStarted = true;
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
            if (!(frame.flags & FLAG_FIN)) return;
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
            if (!(frame.flags & FLAG_SYN)) {
                this._consumeFrame(frame.streamId, frame.payload?.byteLength || 0);
            }
            ws.remoteFinished = true;
            ws.iframe.postMessage({
                type: 'ws-closed', streamId: frame.streamId, code: 1000, reason,
            }, '*');
            this._closeWSOutbound(frame.streamId, ws);
            this._finishWSStream(frame.streamId, ws);
            return;
        }

        // DAT — raw bytes through. Send as a binary ws-message; the
        // iframe is responsible for whatever tag-byte or framing
        // scheme its cap uses.
        if (!frame.payload || frame.payload.byteLength === 0) {
            this._consumeFrame(frame.streamId, 0);
            return;
        }
        const view = new Uint8Array(frame.payload);
        const ab = view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
        const ackToken = this._registerWSAck(ws, frame.payload.byteLength, 1);
        ws.iframe.postMessage({
            type: 'ws-message', streamId: frame.streamId, data: ab,
            ackToken,
        }, '*');
    }

    // Send the connect handshake and wait for the device's 'ready' (plus the
    // optional 2 s TURN banner hold). Shared by the initial connect and by a
    // soft reconnect — everything here is safe to run on a rebuilt transport.
    async _sendConnectAndAwaitReady() {
        // Send connect handshake with path (streamId 0). `version` is
        // the SWSP version we're speaking; older v2 listeners ignore
        // it. No `caps` field — bootstrap.js is a pure transport and
        // doesn't claim knowledge of specific stream types. The iframe
        // decides what to open via /__bitbang/<type>.
        const connectMsg = JSON.stringify({
            type: 'connect',
            path: this.devicePath,
            version: SWSP_VERSION,
        });
        this.dataChannel.send(this.createFrame(0, FLAG_SYN, connectMsg));

        // The hold timer is armed in _onFirstConnected (which runs at DTLS-up,
        // before this point), so the wait is concurrent with device app boot.
        // On non-relay paths the hold is null and Promise.all skips immediately.
        const connectPromise = new Promise(resolve => { this.connectResolve = resolve; });
        await Promise.all([connectPromise, this._turnHoldPromise || Promise.resolve()]);
    }

    async onDataChannelReady() {
        // Brief delay for any pending tracks to arrive
        await new Promise(resolve => setTimeout(resolve, 100));

        await this._sendConnectAndAwaitReady();

        // Reconnect path: the transport was rebuilt under a live page. The
        // iframe, SW registration, and window message listener all persist
        // across the swap, so skip the one-time setup below — just resolve
        // the in-flight attempt and let the proxied app retry over the new
        // channel.
        if (this._transportReady) {
            this._onReconnected();
            return;
        }
        this._transportReady = true;

        // Register this tab's session with the SW. Deferred until here so
        // the device's routing declaration (received on 'ready') has been
        // processed — this.target is now the routing-corrected value
        // (empty for direct devices, LAN host for proxy devices). Empty
        // becomes the 'device' sentinel on the SW side (see sw.js), which
        // is what the cookie jar keys and popup redirects use.
        const reg = await navigator.serviceWorker.ready;
        // Registration must complete before createIframe(): the iframe's
        // first navigation races this postMessage into the SW, and if the
        // fetch wins, proxyToDevice finds no session and 503s ("BitBang:
        // no connection"). Send a reply port and wait for the SW's ack,
        // with a timeout fallback so a wedged SW can't hang the page.
        const ackChannel = new MessageChannel();
        const ack = new Promise((resolve) => {
            const timer = setTimeout(() => {
                console.warn('[Bootstrap] setBootstrap ack timed out — proceeding');
                resolve();
            }, 2000);
            ackChannel.port1.onmessage = () => { clearTimeout(timer); resolve(); };
        });
        reg.active.postMessage({
            type: 'setBootstrap',
            sessionId: this.sessionId,
            uid: this.uid,
            target: this.target || 'device',
            // The access code is a URL-fragment secret the SW can't see
            // by itself (fragments never reach the SW). Passing it here
            // lets the SW construct correct redirect URLs for popups from
            // proxied apps — see redirectViaActiveSession in sw.js.
            code: this.code,
            debug: this.debug,
            noCookieJar: this.noCookieJar,
        }, [ackChannel.port2]);
        await ack;

        // Listen for messages from the iframe (WebSocket shim + navigation
        // + open-cap launcher requests).
        window.addEventListener('message', (event) => {
            const iframe = document.getElementById('device-frame');
            if (!iframe || event.source !== iframe.contentWindow) return;
            if (event.data?.type === 'bb-navigate') {
                this.handleNavigateRequest(event.data.path);
            } else if (event.data?.type === 'bb-open-cap') {
                // The iframe asks us to land on /<uid>#<code><path>.
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
                const url = '/' + this.uid + '#' + this.code + path;
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
            version: SWSP_VERSION,
        });
        this.dataChannel.send(this.createFrame(0, FLAG_SYN, connectMsg));
    }

    handleWSShimMessage(event) {
        const iframe = document.getElementById('device-frame');
        if (!iframe || event.source !== iframe.contentWindow) return;
        const msg = event.data;
        if (!msg || !msg.type?.startsWith('ws-')) return;
        if (!this.dataChannel || this.dataChannel.readyState !== 'open'
            || !this.deviceVerified || !this._protocolReady) {
            if (msg.type === 'ws-open') {
                iframe.contentWindow.postMessage({
                    type: 'ws-rejected', requestId: msg.requestId,
                    message: 'Connection not ready',
                }, '*');
            }
            return;
        }

        if (msg.type === 'ws-open') {
            const streamId = this._allocateStreamId();
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
                        type: 'ws-rejected', requestId: msg.requestId,
                        message: 'bitbang: empty type in magic path',
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

                this.wsStreams.set(streamId, this._newWSState(iframe.contentWindow, 'bitbang'));
                iframe.contentWindow.postMessage({
                    type: 'ws-assign', requestId: msg.requestId,
                    pathname: msg.pathname, streamId,
                }, '*');
                try {
                    this._sendStreamSYN(streamId, FLAG_SYN, JSON.stringify(syn));
                } catch (e) {
                    this._resetStream(streamId, 'send_error', 'Failed to open stream', false);
                    return;
                }
                // Tell the iframe the WS is open now. Listener handlers
                // typically don't send a SYN ack on the success path —
                // the first DAT is the natural signal that things are
                // working. Iframe code can start sending immediately.
                iframe.contentWindow.postMessage({ type: 'ws-opened', streamId }, '*');
                return;
            }

            // Regular WebSocket proxy path (unchanged).
            this.wsStreams.set(streamId, this._newWSState(iframe.contentWindow, 'websocket'));
            iframe.contentWindow.postMessage({
                type: 'ws-assign',
                requestId: msg.requestId,
                pathname: msg.pathname,
                streamId
            }, '*');
            const synPayload = JSON.stringify({
                type: 'websocket',
                pathname: msg.pathname,
                cookies: msg.cookies || '',
            });
            try {
                this._sendStreamSYN(streamId, FLAG_SYN, synPayload);
            } catch (e) {
                this._resetStream(streamId, 'send_error', 'Failed to open WebSocket', false);
                return;
            }
            if (this.debug) console.log(`[Bootstrap] ws SYN sent to device, streamId=${streamId}`);

        } else if (msg.type === 'ws-send') {
            const ws = this.wsStreams.get(msg.streamId);
            if (!ws || ws.localClosing || ws.localFinished) return;
            (async () => {
                let raw;
                if (msg.isText) {
                    raw = new TextEncoder().encode(msg.data);
                } else if (msg.data instanceof Blob) {
                    raw = new Uint8Array(await msg.data.arrayBuffer());
                } else {
                    raw = SWSPFlowControl.asBytes(msg.data);
                }

                let payload = raw;
                if (ws.kind === 'websocket') {
                    // Regular WebSocket framing: [1B type][message].
                    payload = new Uint8Array(1 + raw.length);
                    payload[0] = msg.isText ? 0 : 1;
                    payload.set(raw, 1);
                }

                for (let off = 0; off < payload.length; off += SWSP_CHUNK_SIZE) {
                    const end = Math.min(off + SWSP_CHUNK_SIZE, payload.length);
                    const flags = ws.kind === 'websocket' && end < payload.length
                        ? (FLAG_DAT | FLAG_MORE) : FLAG_DAT;
                    await this._queueStreamFrame(
                        msg.streamId, flags, payload.subarray(off, end));
                }
                if (payload.length === 0) {
                    await this._queueStreamFrame(msg.streamId, FLAG_DAT, payload);
                }
                ws.iframe.postMessage({
                    type: 'ws-send-ack', streamId: msg.streamId,
                    bytes: msg.bufferedBytes || raw.byteLength,
                }, '*');
            })().catch((e) => {
                this._resetStream(msg.streamId, 'send_error', e.message || 'send failed', true);
            });

        } else if (msg.type === 'ws-close') {
            const ws = this.wsStreams.get(msg.streamId);
            if (!ws) return;
            this._closeWSOutbound(msg.streamId, ws);
        } else if (msg.type === 'ws-consumed') {
            this._handleWSAck(msg.streamId, msg.ackToken);
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

            // Favicon forwarding. Watches the iframe's <link rel="icon">
            // (and friends) and mirrors it into the top document, rewriting
            // hrefs into /__device__/<sid>/… so the SW proxies favicon
            // fetches to the device rather than to bitba.ng's own origin.
            //
            //   applyDeviceFavicon  updates/creates <link rel="icon"> on
            //                       the top document with a proxied path.
            //                       No-ops for cross-origin hrefs (rare
            //                       but possible for icons on a CDN).
            //
            //   findBestIcon        picks a <link>: rel="icon" beats
            //                       "shortcut icon" beats apple-touch-icon;
            //                       larger declared size wins ties. Guards
            //                       against `apple-touch-icon` clobbering
            //                       the tab icon on apps that ship both.
            //
            // The MutationObserver has NO timeout — apps that init their
            // favicon late (SPA bootstraps that run seconds after
            // iframe.onload) still get picked up. Attribute mutations on
            // href/rel/sizes also trigger it, covering apps that swap the
            // href in place. Observer is re-attached per iframe.onload,
            // so it doesn't accumulate across full navigations.
            // Favicon diagnostics. These fire on every DOM mutation in the
            // proxied app, so they are gated behind the debug flag rather
            // than left on -- silent in normal operation, recoverable with
            // the !debug URL flag when the favicon misbehaves.
            const dbg = this.debug
                ? (...args) => console.log('[favicon]', ...args)
                : () => {};

            const applyDeviceFavicon = (rawHref) => {
                if (!rawHref) return;
                let finalHref;
                // Canvas-generated favicons (data:/blob:) are inline or
                // same-origin-scoped — apply as-is, no proxy rewrite.
                if (rawHref.startsWith('data:') || rawHref.startsWith('blob:')) {
                    finalHref = rawHref;
                } else {
                    let u;
                    try { u = new URL(rawHref, iframe.contentWindow.location.href); }
                    catch { return; }
                    if (u.origin !== window.location.origin) return;
                    let path = u.pathname + u.search;
                    if (!path.startsWith(`/__device__/${this.sessionId}/`)) {
                        path = `/__device__/${this.sessionId}${path.startsWith('/') ? path : '/' + path}`;
                    }
                    finalHref = path;
                }
                let link = document.querySelector('link[rel="icon"]');
                if (!link) {
                    link = document.createElement('link');
                    link.rel = 'icon';
                    document.head.appendChild(link);
                }
                if (link.getAttribute('href') !== finalHref) link.href = finalHref;
            };

            const findBestIcon = (doc) => {
                if (!doc) return null;
                const rank = (rel) => {
                    rel = (rel || '').toLowerCase();
                    if (rel === 'icon') return 3;
                    if (rel === 'shortcut icon') return 2;
                    if (rel.includes('apple-touch-icon')) return 1;
                    return 0;
                };
                const sizeArea = (link) => {
                    const s = link.getAttribute('sizes');
                    if (!s || s.toLowerCase() === 'any') return 0;
                    const [w] = s.split(/[x ]/i);
                    return parseInt(w, 10) || 0;
                };
                const all = [...doc.querySelectorAll('link[rel]')];
                const candidates = all.filter(l => rank(l.rel) > 0 && l.getAttribute('href'));
                candidates.sort((a, b) => rank(b.rel) - rank(a.rel) || sizeArea(b) - sizeArea(a));
                const winner = candidates[0]?.getAttribute('href') || null;
                dbg('scan:', all.length, 'links,', candidates.length, 'candidates, winner:', winner);
                return winner;
            };

            try {
                const doc = iframe.contentDocument;
                if (doc) {
                    dbg('initial scan;', iframe.contentWindow.location.href);
                    applyDeviceFavicon(findBestIcon(doc));
                    new MutationObserver(() => {
                        applyDeviceFavicon(findBestIcon(doc));
                    }).observe(doc.head || doc.documentElement, {
                        childList: true, subtree: true,
                        attributes: true, attributeFilter: ['href', 'rel', 'sizes'],
                    });
                } else {
                    dbg('no iframe.contentDocument');
                }
            } catch (e) {
                dbg('initial scan threw:', String(e));
            }

            // Fallback: /favicon.ico static probe, applied only if no
            // dynamic icon has been detected by the time the fetch
            // resolves. Prevents clobbering a valid dynamic icon.
            const initialHref = document.querySelector('link[rel="icon"]')?.href;
            fetch(`/__device__/${this.sessionId}/favicon.ico`).then(r => {
                if (!r.ok) return;
                const current = document.querySelector('link[rel="icon"]')?.href;
                if (current === initialHref) {
                    dbg('static probe applied');
                    applyDeviceFavicon(`/__device__/${this.sessionId}/favicon.ico`);
                } else {
                    dbg('static probe skipped (dynamic icon already set)');
                }
            }).catch((e) => dbg('static probe error:', String(e)));

            // Mirror the iframe's location into the address bar after every
            // navigation so refresh/bookmark land back on the same page. The
            // iframe is same-origin (/__device__/… on this origin), so we can
            // read its location and hook its navigation. Re-attach per load: a
            // full navigation gives the iframe a fresh window/history.
            //
            // hashchange/popstate cover real hash writes and back/forward.
            // But SPA routers (Jellyfin's React-Router hash history, etc.)
            // navigate via history.pushState — which fires NEITHER event even
            // when it changes the hash — so we also wrap pushState/replaceState
            // to catch forward in-app navigation.
            // Swallow errors: this runs inside the iframe's own pushState, so
            // a throw here (e.g. the browser's replaceState rate limit) must
            // not break the app's routing.
            const sync = (src) => {
                if (this.debug) { try { console.log('[Bootstrap] iframe nav', src, '->', iframe.contentWindow.location.href); } catch (e) {} }
                try { this.syncTopURL(); } catch (e) {}
            };
            try {
                const win = iframe.contentWindow;
                win.addEventListener('hashchange', () => sync('hashchange'));
                win.addEventListener('popstate', () => sync('popstate'));
                for (const m of ['pushState', 'replaceState']) {
                    const orig = win.history[m];
                    win.history[m] = function (...args) {
                        const r = orig.apply(this, args);
                        sync(m);
                        return r;
                    };
                }
            } catch (e) {}

            // Active-session hint for popup routing.
            //
            // A proxied app can pop a new tab at bare bitba.ng (root-
            // relative window.open, target=_blank anchor). That popup
            // lands in the SW's fetch handler, and the SW needs to know
            // which session it belongs to. Referer often doesn't carry
            // /__device__/<sid> (absolute-path apps like OctoPrint leave
            // the proxy prefix), and Cookie / Referer headers are stripped
            // from popup navigations before they reach the SW's fetch
            // event (browser attaches them at the network layer, after
            // the SW). postMessage races the popup's fetch (different
            // async queues, no ordering guarantee).
            //
            // Cache API works: focus and visibilitychange fire seconds
            // before any click, so the async write settles well before
            // the popup opens. sw.js reads /_/active from the same cache
            // in redirectViaActiveSession.
            const markActive = () => {
                caches.open('bitbang-active-session')
                    .then(c => c.put('/_/active',
                        new Response(this.sessionId, {
                            headers: { 'Content-Type': 'text/plain' },
                        })))
                    .catch(() => {});
            };
            markActive();
            window.addEventListener('focus', markActive);
            document.addEventListener('visibilitychange', () => {
                if (document.visibilityState === 'visible') markActive();
            });

            sync('load');
        };

        iframe.src = `/__device__/${this.sessionId}${this.devicePath}${this.deviceSearch}${this.deviceHash}`;
        document.body.appendChild(iframe);
    }

    // Note: popup handling (target=_blank links, window.open() from
    // proxied apps' click handlers, root-relative URLs like Synology's
    // `/?launchApp=…`) is now done entirely in the SW. It intercepts
    // bare-origin navigations that don't match any legitimate bitbang
    // shape and 302s them into the most-recently-active session's URL
    // space, using the (uid, code, target) it learned via setBootstrap.
    // See sw.js's redirectViaActiveSession + isLikelyAppPopup. The old
    // saveOpenHint / interceptNewTabLinks pair used to do this from the
    // page; the SW-only approach avoids the async-cache race and covers
    // programmatic window.open, not just <a target=_blank>.

    // Normalise the device-frame iframe's current location into
    // {devicePath, deviceSearch, deviceHash}, matching parseDeviceURL's output.
    //
    // The iframe may sit at the prefixed proxy URL
    // (/__device__/<sid>/<target>/path) OR — for apps that navigate with
    // origin-absolute paths (Jellyfin: /web/#/movies) — at a bare /path with
    // neither the prefix nor the target. Either way we reconstruct a
    // target-prefixed device path. Returns null if the iframe isn't readable.
    iframeDeviceURL() {
        const iframe = document.getElementById('device-frame');
        if (!iframe) return null;
        let loc;
        try { loc = iframe.contentWindow.location; } catch (e) { return null; }

        const pfx = `/__device__/${this.sessionId}`;
        let p = loc.pathname;
        if (p === pfx) p = '/';
        else if (p.startsWith(pfx + '/')) p = p.slice(pfx.length);
        const tseg = this.target ? '/' + this.target : '';
        if (tseg && p !== tseg && !p.startsWith(tseg + '/')) {
            p = tseg + (p === '/' ? '/' : p);
        }
        p = p || '/';
        if (/^\/[^/]+:\d+$/.test(p)) p += '/';   // bare host:port → trailing slash (matches parseDeviceURL)
        return { devicePath: p, deviceSearch: loc.search, deviceHash: loc.hash };
    }

    // True when the iframe is already displaying what the top-level address bar
    // says. Used to tell back/forward (which restores BOTH the iframe and the
    // top fragment, so they already agree) apart from a manual address-bar edit
    // (where only the top fragment changed). Order-independent: reads the
    // iframe's live, already-restored location rather than relying on the
    // popstate-vs-hashchange firing order.
    iframeShowsTopURL() {
        const n = this.iframeDeviceURL();
        if (!n) return false;
        const p = parseDeviceURL();
        // A manual edit to the code or the !<flags> section is a
        // different session, not an in-app navigation — force reload.
        if (p.code !== this.code) return false;
        if (readUrlFlagString() !== this.initialFlagStr) return false;
        return n.devicePath === p.devicePath
            && n.deviceSearch === p.deviceSearch
            && n.deviceHash === p.deviceHash;
    }

    // Mirror the iframe's current location into the top-level address bar so
    // refresh/bookmark land back on the same page. The device URL
    // (path?query#hash) rides in the fragment after the access code, so nothing
    // here reaches the signaling server. replaceState (not pushState) keeps a
    // single history entry and does not fire `hashchange`, so this never trips
    // the reload-on-edit handler.
    syncTopURL() {
        const n = this.iframeDeviceURL();
        if (!n) return;
        this.devicePath = n.devicePath;
        this.deviceSearch = n.deviceSearch;
        this.deviceHash = n.deviceHash;
        const tail = (n.devicePath === '/' && !n.deviceSearch && !n.deviceHash)
            ? '' : n.devicePath + n.deviceSearch + n.deviceHash;
        // Flags ride the fragment right after the code, before the device
        // URL. Preserve whatever flag section the current URL carries.
        const flagStr = readUrlFlagString();
        const top = '/' + this.uid + '#' + this.code + flagStr + tail;
        if (this.debug) console.log('[Bootstrap] syncTopURL ->', top);
        history.replaceState(null, '', top);
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

// ============================================================================
// Pairing (code exchange) — the browser connector side.
//
// A 6-digit URL path (bitba.ng/482731) means the user is pairing rather than
// opening a device URL. The browser is the *answerer* (the device offers, same
// as the direct flow), runs a commit→challenge→reveal so the short SAS can't be
// ground by a malicious server, computes the 6-digit SAS, displays it to read
// aloud, and reads {uid, public_key, access_code} off the (now SAS-verified)
// data channel. On success it navigates to /<uid>#<code> — re-running the
// standard direct flow with full pubkey verify for the actual session.
//
// All commit/challenge/reveal/credentials messages ride the WebRTC data channel
// (the signaling server never sees them). Must match internal/pairing/commit.go
// byte-for-byte: SAS = sha256(rc ‖ rd ‖ sort(upper(fp)).join('|'))[:4] read
// big-endian, mod 1_000_000, zero-padded to 6 digits.
// ============================================================================

const PAIR_CODE_RE = /^\d{6}$/;
const PAIR_NONCE_LEN = 32;

function pairNonce() { return crypto.getRandomValues(new Uint8Array(PAIR_NONCE_LEN)); }

// base64(SHA-256(nonce)) — the connector's hiding+binding commitment.
async function pairCommitment(nonce) {
    const h = await crypto.subtle.digest('SHA-256', nonce);
    return bytesToBase64(new Uint8Array(h));
}

// The 6-digit SAS. rc/rd are Uint8Array(32); localFp/remoteFp are the SDP
// fingerprint strings.
async function pairComputeSAS(rc, rd, localFp, remoteFp) {
    const fps = [(localFp || '').toUpperCase(), (remoteFp || '').toUpperCase()].sort();
    const fpBytes = new TextEncoder().encode(fps[0] + '|' + fps[1]);
    const data = new Uint8Array(rc.length + rd.length + fpBytes.length);
    data.set(rc, 0);
    data.set(rd, rc.length);
    data.set(fpBytes, rc.length + rd.length);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const n = new DataView(hash).getUint32(0); // big-endian
    return String(n % 1000000).padStart(6, '0');
}

// Parse a data-channel message (ArrayBuffer from a binary send, or a string)
// into a JS object, or null.
function pairDecodeMessage(data) {
    let text;
    if (typeof data === 'string') text = data;
    else text = new TextDecoder().decode(data);
    try { return JSON.parse(text); } catch (e) { return null; }
}

function pairEscapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
}

function pairErrorText(serverMsg) {
    if (serverMsg === 'unknown_code') {
        return "That code isn't valid or has expired. Pairing codes last 5 minutes — ask for a fresh one.";
    }
    return 'Could not start pairing: ' + (serverMsg || 'unknown error') + '.';
}

function pairRejectText(reason) {
    switch (reason) {
        case 'sas_mismatch':
            return "The codes didn't match, so the connection was refused to keep you safe. Try pairing again.";
        case 'user_declined':
            return 'The device owner declined the connection.';
        case 'timeout':
            return "The device owner didn't confirm in time. Ask them to accept and try again.";
        default:
            return 'Pairing was rejected (' + (reason || 'unknown') + ').';
    }
}

// Minimal pairing UI rendered into #connection-ui.
const pairUI = {
    el: null,
    _injectStyle() {
        if (document.getElementById('pair-style')) return;
        const s = document.createElement('style');
        s.id = 'pair-style';
        s.textContent = `
            .pair-box{max-width:420px;margin:48px auto;padding:0 20px;text-align:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}
            .pair-box h2{font-size:18px;font-weight:600;margin-bottom:12px;color:#111;}
            .pair-box p{font-size:14px;color:#555;line-height:1.5;margin:8px 0;}
            .pair-sas{font-size:44px;font-weight:700;letter-spacing:.12em;color:#111;margin:18px 0;font-variant-numeric:tabular-nums;}
            .pair-wait{color:#888;font-size:13px;margin-top:18px;}
            .pair-err{color:#c00;}
            .pair-spinner{display:inline-block;width:22px;height:22px;border:3px solid #ddd;border-top-color:#555;border-radius:50%;animation:pairspin .8s linear infinite;}
            .pair-spinner.small{width:13px;height:13px;border-width:2px;vertical-align:-2px;margin-right:6px;}
            @keyframes pairspin{to{transform:rotate(360deg)}}
            .pair-input{font-size:28px;letter-spacing:.25em;text-align:center;width:200px;padding:10px;border:2px solid #ccc;border-radius:8px;font-variant-numeric:tabular-nums;}
            .pair-btn{display:inline-block;margin-top:14px;padding:10px 18px;font-size:14px;border:none;border-radius:8px;background:#111;color:#fff;cursor:pointer;}
            .pair-btn:disabled{background:#bbb;cursor:not-allowed;}
            .pair-link{color:#06c;cursor:pointer;text-decoration:underline;background:none;border:none;font-size:14px;}
            .pair-modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;z-index:99999;}
            .pair-modal{background:#fff;max-width:420px;width:90%;padding:24px;border-radius:14px;box-shadow:0 10px 40px rgba(0,0,0,.25);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}
            .pair-modal h3{font-size:17px;margin-bottom:10px;}
            .pair-modal p{font-size:13px;color:#555;margin:8px 0;}
            .pair-url{font-family:"SF Mono",Menlo,monospace;font-size:12px;background:#f4f4f4;border:1px solid #e0e0e0;border-radius:8px;padding:10px;word-break:break-all;user-select:all;margin:10px 0;}
            .pair-modal .pair-priv{font-size:12px;}
            .pair-row{display:flex;gap:10px;align-items:center;margin-top:14px;}
        `;
        document.head.appendChild(s);
    },
    init() {
        this._injectStyle();
        const root = document.getElementById('connection-ui') || document.body;
        root.innerHTML = '';
        this.el = document.createElement('div');
        this.el.className = 'pair-box';
        root.appendChild(this.el);
    },
    connecting(text) {
        this.el.innerHTML = `<div class="pair-spinner"></div><p>${pairEscapeHtml(text || 'Connecting…')}</p>`;
    },
    showSAS(sas) {
        if (!this.el) this.init();
        const grouped = sas.slice(0, 3) + ' ' + sas.slice(3);
        this.el.innerHTML =
            `<h2>Read this code aloud</h2>` +
            `<div class="pair-sas">${pairEscapeHtml(grouped)}</div>` +
            `<p>Say these 6 digits to the device owner. They'll type them on their device to confirm it's really you.</p>` +
            `<p class="pair-wait"><span class="pair-spinner small"></span>Waiting for the device owner to confirm…</p>`;
    },
    error(text) {
        if (!this.el) this.init();
        this.el.innerHTML =
            `<h2>Pairing failed</h2>` +
            `<p class="pair-err">${pairEscapeHtml(text)}</p>` +
            `<p><a class="pair-link" href="/">Try again</a></p>`;
    },
};

// PairingFlow drives the browser connector half of code exchange. State
// (pc, dc, remoteSet, aborted, the DC inbox + pending waiter) lives on
// the instance instead of the closures of a single async function — it
// makes the WS message handler and the offer/handshake methods easier to
// follow, and lets us share CandidateQueue with the direct flow.
class PairingFlow {
    constructor(code) {
        this.code = code;
        const flags = parseUrlFlags();
        this.forceRelay = !!flags.relay && !flags.norelay;
        this.ws = null;
        this.pc = null;
        this.dc = null;
        this.remoteSet = false;
        this.aborted = false;
        this.candidateQueue = new CandidateQueue();
        // Promise-based reader over data-channel pairing messages: at most
        // one outstanding waiter; inbox holds messages that arrived before
        // anyone was waiting.
        this._dcInbox = [];
        this._dcWaiter = null;
    }

    run() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        this.ws = new WebSocket(`${proto}//${location.host}/ws/pair`);
        this.ws.onopen = () => this.ws.send(JSON.stringify({
            type: 'pair_init', code: this.code, force_relay: this.forceRelay,
        }));
        this.ws.onerror = () => this.fail('Connection error. Please try again.');
        this.ws.onmessage = (ev) => this._onWsMessage(ev);
    }

    fail(text) {
        if (this.aborted) return;
        this.aborted = true;
        pairUI.error(text);
        try { this.ws?.close(); } catch (e) {}
        try { this.pc?.close(); } catch (e) {}
        if (this._dcWaiter) { const w = this._dcWaiter; this._dcWaiter = null; w(null); }
    }

    _dcDeliver(obj) {
        if (this._dcWaiter) { const w = this._dcWaiter; this._dcWaiter = null; w(obj); }
        else this._dcInbox.push(obj);
    }

    _dcRecv(timeoutMs) {
        return new Promise((resolve) => {
            if (this._dcInbox.length) { resolve(this._dcInbox.shift()); return; }
            const t = setTimeout(() => { this._dcWaiter = null; resolve(null); }, timeoutMs);
            this._dcWaiter = (obj) => { clearTimeout(t); resolve(obj); };
        });
    }

    async _onWsMessage(ev) {
        let msg; try { msg = JSON.parse(ev.data); } catch (e) { return; }
        switch (msg.type) {
            case 'pair_routed': break;
            case 'error': this.fail(pairErrorText(msg.message)); break;
            case 'offer': await this._handleOffer(msg); break;
            case 'candidate':
                if (this.remoteSet && this.pc) this.pc.addIceCandidate(msg.candidate).catch(() => {});
                else this.candidateQueue.pushRemote(msg.candidate);
                break;
            case 'pair_approved': break; // bare ack — credentials arrive over the DC
            case 'pair_rejected': this.fail(pairRejectText(msg.reason)); break;
        }
    }

    async _handleOffer(msg) {
      try {
        const config = {};
        if (Array.isArray(msg.ice_servers) && msg.ice_servers.length) config.iceServers = msg.ice_servers;
        if (this.forceRelay) config.iceTransportPolicy = 'relay';
        this.pc = new RTCPeerConnection(config);

        this.pc.onicecandidate = (e) => {
            if (!e.candidate) return;
            const m = { type: 'candidate', candidate: e.candidate };
            if (this.ws.readyState === WebSocket.OPEN && this.remoteSet) this.ws.send(JSON.stringify(m));
            else this.candidateQueue.pushLocal(m);
        };
        this.pc.onconnectionstatechange = () => {
            if (this.pc.connectionState === 'failed') {
                this.fail('Could not connect to the device. Try again, or ask the owner to check their network.');
            }
        };
        this.pc.ondatachannel = (e) => {
            this.dc = e.channel;
            this.dc.binaryType = 'arraybuffer';
            this.dc.onmessage = (me) => { const o = pairDecodeMessage(me.data); if (o) this._dcDeliver(o); };
            this.dc.onopen = () => { this._runHandshake(); };
        };

        await this.pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
        this.remoteSet = true;
        const answer = await this.pc.createAnswer();
        await this.pc.setLocalDescription(answer);
        this.ws.send(JSON.stringify({ type: 'answer', sdp: this.pc.localDescription.sdp }));
        this.candidateQueue.drainLocal(m => this.ws.send(JSON.stringify(m)));
        this.candidateQueue.drainRemote(c => this.pc.addIceCandidate(c).catch(() => {}));
      } catch (e) {
        this.fail('Could not set up the connection: ' + (e && e.message ? e.message : e));
      }
    }

    async _runHandshake() {
        try {
            // 1. Commit our nonce (hidden) before the device reveals its challenge.
            const rc = pairNonce();
            this.dc.send(JSON.stringify({ type: 'pair_commit', commit: await pairCommitment(rc) }));

            // 2. Receive the device's challenge nonce.
            const challenge = await this._dcRecv(30000);
            if (this.aborted) return;
            if (!challenge || challenge.type !== 'pair_challenge') { this.fail('Pairing timed out.'); return; }
            const rd = base64ToBytes(challenge.nonce_d || '');
            if (rd.length !== PAIR_NONCE_LEN) { this.fail('Pairing failed (bad challenge).'); return; }

            // 3. Reveal.
            this.dc.send(JSON.stringify({ type: 'pair_reveal', nonce_c: bytesToBase64(rc) }));

            // 4. Compute and show the SAS to read aloud.
            const localFp = extractDTLSFingerprint(this.pc.localDescription.sdp);
            const remoteFp = extractDTLSFingerprint(this.pc.remoteDescription.sdp);
            const sas = await pairComputeSAS(rc, rd, localFp, remoteFp);
            pairUI.showSAS(sas);

            // 5. Wait for credentials over the data channel (approval) — or a
            //    pair_rejected over signaling (handled by ws.onmessage → fail).
            const creds = await this._dcRecv(120000);
            if (this.aborted) return;
            if (!creds || creds.type !== 'pair_credentials' || !creds.uid || !creds.access_code) {
                this.fail("The device owner didn't confirm in time.");
                return;
            }

            // 6. Navigate into the direct flow; drop the spent pairing URL from
            //    history, and flag the bookmark prompt for the destination load.
            sessionStorage.setItem('bitbang_just_paired', '1');
            location.replace('/' + creds.uid + '#' + creds.access_code);
        } catch (e) {
            this.fail('Pairing failed: ' + (e && e.message ? e.message : e));
        }
    }
}

// showPairingInput is the bitba.ng/ landing page: a numeric pairing-code
// input. Renders into an operator-supplied `#bb-pair-input` div (from a
// FRONT_PAGE snippet) when present; otherwise takes over #connection-ui
// via pairUI so the page is still usable when no snippet is configured.
function showPairingInput() {
    const slot = document.getElementById('bb-pair-input');
    let root;
    if (slot) {
        // Operator-supplied front page provides framing; we just fill the
        // mount point. The surrounding snippet (headline, install hint,
        // links) stays untouched. Apply .pair-box so the form picks up
        // the same centering/sizing it gets in the no-snippet path.
        pairUI._injectStyle();
        slot.className = 'pair-box';
        slot.innerHTML = '';
        root = slot;
    } else {
        // No snippet — pairUI owns #connection-ui as before.
        pairUI.init();
        root = pairUI.el;
    }
    root.innerHTML =
        `<h2>Enter pairing code</h2>` +
        `<p>Type the 6-digit code the device owner gave you.</p>` +
        `<input class="pair-input" id="pair-code-in" inputmode="numeric" pattern="\\d*" maxlength="6" autofocus>` +
        `<div><button class="pair-btn" id="pair-go" disabled>Connect</button></div>`;
    const input = document.getElementById('pair-code-in');
    const button = document.getElementById('pair-go');
    const sync = () => {
        input.value = input.value.replace(/\D/g, '').slice(0, 6);
        button.disabled = !PAIR_CODE_RE.test(input.value);
    };
    const go = () => {
        const v = (input.value || '').replace(/\D/g, '').slice(0, 6);
        if (PAIR_CODE_RE.test(v)) location.href = '/' + v;
        else input.focus();
    };
    input.addEventListener('input', sync);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    button.addEventListener('click', go);
}

// showUpdateBanner renders a small fixed-position banner at the top of
// the viewport announcing that a new bootstrap version is available.
// Triggered from the SW controllerchange handler when a deploy lands
// mid-session. The user clicks Reload to refresh into the new code, or
// dismisses to keep their current session state (shell scrollback,
// half-typed proxied-app input, in-progress downloads, etc.).
//
// Idempotent — if the banner is already showing (a second deploy
// arrives before the user has acted on the first), the call is a no-op.
function showUpdateBanner() {
    if (document.getElementById('bb-update-banner')) return;

    const bar = document.createElement('div');
    bar.id = 'bb-update-banner';
    bar.style.cssText = [
        'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:9999',
        'background:#f4f4f4', 'border-bottom:1px solid #ddd',
        'padding:8px 14px',
        'font-family:-apple-system,"Segoe UI",Roboto,sans-serif',
        'font-size:13px', 'color:#333',
        'display:flex', 'align-items:center', 'gap:12px',
        'box-shadow:0 1px 3px rgba(0,0,0,0.08)',
    ].join(';');

    const text = document.createElement('span');
    text.textContent = 'A new version is available.';
    text.style.flex = '1';

    const reloadBtn = document.createElement('button');
    reloadBtn.textContent = 'Reload';
    reloadBtn.style.cssText = [
        'border:none', 'background:#111', 'color:#fff',
        'font-size:13px', 'padding:4px 12px', 'border-radius:4px',
        'cursor:pointer',
    ].join(';');
    reloadBtn.addEventListener('click', () => window.location.reload());

    const dismissBtn = document.createElement('button');
    dismissBtn.textContent = '×';
    dismissBtn.setAttribute('aria-label', 'Dismiss');
    dismissBtn.style.cssText = [
        'border:none', 'background:none', 'font-size:18px',
        'color:#888', 'cursor:pointer', 'line-height:1', 'padding:0 4px',
    ].join(';');
    dismissBtn.addEventListener('click', () => bar.remove());

    bar.appendChild(text);
    bar.appendChild(reloadBtn);
    bar.appendChild(dismissBtn);
    document.body.appendChild(bar);
}

// showBookmarkModal is shown once, on the post-pairing load, nudging the user
// to save the device URL (the browser's only "remember"). Non-blocking overlay.
function showBookmarkModal() {
    pairUI._injectStyle();
    const url = location.href;
    const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '');
    const shortcut = isMac ? '⌘D' : 'Ctrl+D';

    const bg = document.createElement('div');
    bg.className = 'pair-modal-bg';
    const modal = document.createElement('div');
    modal.className = 'pair-modal';
    modal.innerHTML =
        `<h3>Paired</h3>` +
        `<p>Save this link to reconnect instantly — no code needed next time:</p>` +
        `<div class="pair-url" id="pair-url"></div>` +
        `<div class="pair-row"><button class="pair-btn" id="pair-copy">Copy link</button>` +
        `<span style="font-size:12px;color:#888">or press ${shortcut} to bookmark</span></div>` +
        `<p class="pair-priv">This link connects straight to the device — keep it private.</p>` +
        `<div class="pair-row" style="justify-content:flex-end"><button class="pair-btn" id="pair-done">Done</button></div>`;
    bg.appendChild(modal);
    document.body.appendChild(bg);
    document.getElementById('pair-url').textContent = url;
    const copyBtn = document.getElementById('pair-copy');
    copyBtn.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(url); copyBtn.textContent = 'Copied'; }
        catch (e) { copyBtn.textContent = 'Copy failed — select the link above'; }
    });
    const close = () => { try { document.body.removeChild(bg); } catch (e) {} };
    document.getElementById('pair-done').addEventListener('click', close);
    bg.addEventListener('click', (e) => { if (e.target === bg) close(); });
}

// parseDeviceURL parses window.location into the pieces the direct flow
// needs:
//
//   uid          — the 22-char base64url device id (path[0])
//   code         — the access code (start of the URL fragment)
//   devicePath   — the device URL path the iframe loads (default `/`)
//   deviceSearch — the device URL's own query string (leading `?`, or '')
//   deviceHash   — the device URL's fragment / SPA route (leading `#`, or '')
//
// The whole device URL lives in the fragment, after the code:
//
//   /<uid>#<code>/localhost:8096/web/#/livetv?collectionType=livetv
//          └code┘└──────────── device URL ───────────────────────┘
//
// The fragment after the code is, verbatim, the device's own URL
// (`/path?query#hash`). The access-code alphabet is base64url
// (`[A-Za-z0-9_-]`, no `/ ? #`), so the first such character ends the
// code and begins the device URL. Consequences:
//
//   - Nothing of the path/query/route reaches the signaling server: the
//     fragment is never transmitted in an HTTP request, even on refresh.
//   - There is no shorthand to rearrange — the typed URL is already
//     canonical, so no reorder/redirect step is needed.
//   - A bare `host:port` target still gets a trailing slash so the
//     proxied app's relative URLs resolve from its root.
//
// Bitbang flags (!debug, !relay, …) live in the fragment right after the
// code and before the device URL — `#<code>[!flag,flag=value][/device-URL]`
// — and are read separately via `parseUrlFlags()`. The boundary between
// flag section and device URL is exactly one character: everything after
// the first `/` in the fragment (after the code) is device content and
// gets forwarded verbatim. Assumes a direct-flow URL — caller does the
// pair-code/empty-path routing first.
function parseDeviceURL() {
    const uid = window.location.pathname.split('/').filter(Boolean)[0];

    const frag = window.location.hash ? window.location.hash.slice(1) : '';
    let i = 0;
    while (i < frag.length && /[A-Za-z0-9_-]/.test(frag[i])) i++;
    const code = frag.slice(0, i);
    // Skip the optional !<flag-list> — it ends at the first '/' (which
    // starts the device URL) or at end-of-fragment.
    if (frag[i] === '!') {
        while (i < frag.length && frag[i] !== '/') i++;
    }
    const rest = frag.slice(i);            // '' or `/path?query#hash`

    let devicePath = '/', deviceSearch = '', deviceHash = '';
    if (rest) {
        const h = rest.indexOf('#');
        deviceHash = h >= 0 ? rest.slice(h) : '';
        const beforeHash = h >= 0 ? rest.slice(0, h) : rest;
        const q = beforeHash.indexOf('?');
        deviceSearch = q >= 0 ? beforeHash.slice(q) : '';
        devicePath = (q >= 0 ? beforeHash.slice(0, q) : beforeHash) || '/';
    }
    devicePath = stripDeviceScheme(devicePath);
    if (/^\/[^/]+:\d+$/.test(devicePath)) devicePath += '/';

    return { uid, code, devicePath, deviceSearch, deviceHash };
}

// Strip an explicit http/https scheme from the device path.
//
// The target is a host:port, never a URL -- but users reasonably type
// "https://nas.local:8971", and the scheme then rides along in the fragment.
// Left in place, the first path segment is "https:", which every downstream
// consumer treats as the hostname: this.target becomes "https:", the iframe
// is built against it, and syncTopURL mirrors "#<code>/https:/login" into the
// address bar -- a URL that is neither representative nor refreshable.
//
// Normalising here (rather than at each consumer) means target derivation,
// the iframe URL, and the address-bar mirror all see a clean path. The device
// side strips schemes too, so this is belt-and-braces rather than the only
// guard.
//
// Tolerates "//" collapsed to "/", case variation, and percent-encoding,
// since this string crosses several URL normalisers before it gets here.
// Order matters in the alternation: the longer separators must precede
// their own prefixes or "://" would match as ":/" and leave a stray slash.
function stripDeviceScheme(p) {
    return p.replace(
        /^\/(?:https?)(?::\/\/|%3A%2F%2F|:\/|%3A%2F)/i,
        '/'
    );
}

// The pathname is always `/<uid>`, so a top-frame nav that changes only the
// device URL fires `hashchange` without reloading. The cause is told apart by
// whether the iframe is ALREADY showing the new URL:
//   - Manual address-bar edit → iframe NOT yet there → reload (a fresh
//     bootstrap re-parses the device URL and rebuilds the iframe).
//   - Back/forward that restored a top-frame fragment entry → the browser also
//     restored the iframe, so it already matches → do nothing.
//   - In-iframe nav → mirrored to the bar via replaceState, which does not fire
//     `hashchange`, so it never reaches here. (Normal in-app back/forward is
//     iframe-driven and likewise never reaches this handler.)
//
// `iframeShowsTopURL` (reads the iframe's live location) is the discriminator —
// NOT the event type: a manual address-bar edit fires `popstate` as well as
// `hashchange`, so popstate cannot be used to detect a traversal. The decision
// is deferred to a microtask only so it runs once after the paired events.
window.addEventListener('hashchange', () => {
    queueMicrotask(() => {
        const conn = window.__bitbangConnection;
        if (conn && conn.iframeShowsTopURL()) return;   // back/forward restored it; nothing to do
        // Manual address-bar edit (or back/forward to a top entry the iframe
        // isn't showing): reload. A fresh bootstrap re-parses the device URL and
        // rebuilds the iframe with an intact /__device__/ referer chain. We
        // deliberately do NOT re-point the iframe in place — navigating it to
        // the prefixed URL makes the SPA redirect to a bare origin path the SW
        // can't re-route (→ bootstrap.html loads inside the iframe → blank
        // hang). Reload is heavier but robust; manual edits are rare.
        if (conn && conn.debug) console.log('[Bootstrap] address-bar edit → reload');
        location.reload();
    });
});

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

    // Post-pairing bookmark nudge: shown once on the direct-flow load we just
    // navigated to after a successful pairing (non-blocking overlay).
    if (sessionStorage.getItem('bitbang_just_paired')) {
        sessionStorage.removeItem('bitbang_just_paired');
        try { showBookmarkModal(); } catch (e) {}
    }

    // The bb-front-page slot is only meaningful on `/` (the entry page).
    // Pair-flow and direct-flow take over #connection-ui; the snippet area
    // would otherwise sit above them as visual leftover. Hide for any
    // non-entry route.
    const frontPageDiv = document.getElementById('bb-front-page');
    const connectionUIDiv = document.getElementById('connection-ui');

    // Routing: a bare 6-digit path is a pairing code → run code exchange; an
    // empty path shows the pairing-code input; anything else is a device URL
    // handled by the direct flow below.
    if (pathParts.length === 1 && PAIR_CODE_RE.test(pathParts[0])) {
        if (frontPageDiv) frontPageDiv.style.display = 'none';
        new PairingFlow(pathParts[0]).run();
        return;
    }
    if (pathParts.length === 0) {
        // Entry page. Nothing here connects to a device, so the title is
        // never overwritten by _print() or by the iframe title the way
        // the device flow overwrites it — set it explicitly, or the tab
        // and any bookmark keep the bare static fallback.
        document.title = 'BitBang';
        // If the operator's snippet provided a #bb-pair-input slot, the
        // form renders there and #connection-ui is unused — hide it so
        // the placeholder doesn't sit below the snippet. If no slot,
        // showPairingInput falls back to #connection-ui itself.
        if (document.getElementById('bb-pair-input') && connectionUIDiv) {
            connectionUIDiv.style.display = 'none';
        }
        showPairingInput();
        return;
    }
    // Direct flow (device URL): snippet area is leftover chrome, hide it.
    if (frontPageDiv) frontPageDiv.style.display = 'none';

    const { uid, devicePath, deviceSearch, deviceHash, code } = parseDeviceURL();
    const connection = new BitBangConnection(uid, devicePath, code, deviceSearch, deviceHash);
    window.__bitbangConnection = connection;
    await connection.connect();
})();
