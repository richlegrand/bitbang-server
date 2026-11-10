/**
 * BitBang Bootstrap: bitba.ng's own page
 *
 * The page at bitba.ng/<uid>#<code>[!flags][/path]. It keeps the access code
 * and never gives it out. The device connection lives one frame down, in the
 * device's own origin, https://<label>.<host>/__bb/start (connection.js),
 * which frames the device's pages in turn. See bitbang-docs/device-origins.md.
 *
 * This page:
 *   - computes the label, from a secret kept in this origin's storage;
 *   - frames the connection frame, and answers it -- only it, by source and
 *     origin -- with proofs for its connections (prove), the PIN, and in-place
 *     navigation;
 *   - shows the address bar, title and icon the content frame reports;
 *   - runs pairing (a 6-digit path) and the entry page, which need no device
 *     origin.
 *
 * Whatever the connection frame asks, it could be device script asking: the
 * two share an origin. So it gets nothing it could use once the tab closes --
 * a proof is good for the connection it was asked for, and the code itself
 * never leaves this page.
 */

// BUILD is spliced in by the server as this file is served (see
// handler.buildStamp).
const BUILD = '__BB_BUILD__';

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
// leading '!'), or '' if no flag section is present. Used to preserve the flag
// tail verbatim in the address bar, and to hand it to the connection frame.
function readUrlFlagString() {
    const frag = window.location.hash ? window.location.hash.slice(1) : '';
    let i = 0;
    while (i < frag.length && /[A-Za-z0-9_-]/.test(frag[i])) i++;
    if (frag[i] !== '!') return '';
    let j = i + 1;
    while (j < frag.length && frag[j] !== '/') j++;
    return frag.slice(i, j);
}

// --- Bidirectional verify helpers ----------------------------------------
//
// The browser is the connecting party. The device's offer carries its pubkey;
// this page verifies hash(pubkey) === UID, then makes the encrypted payload
// that rides on the answer (code is the access code from the URL fragment;
// omitted only when the URL has no #code, in which case the device rejects
// the connection). The device decrypts, confirms the fingerprint matches the
// SDP and the code matches its own, and proves possession of the private key
// by sending sha256(nonce) back as the first stream-0 frame after the data
// channel opens. A rogue signaling server cannot mount a relay attack: it can
// rewrite SDPs all it wants, but without the device's private key it can't
// decrypt the payload or produce a matching nonce hash, and the connection
// frame rejects the channel.
//
// The offer and answer travel through the connection frame (connection.js);
// only the payload is made here (answerProve), and pairing (PairingFlow) runs
// its own handshake on this page.

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

// A SHA-256 DTLS fingerprint as SDP writes it, "AB:CD:...", 32 pairs.
const FINGERPRINT_RE = /^[0-9A-F]{2}(:[0-9A-F]{2}){31}$/;

// fingerprintBytes turns "AB:CD:..." into its 32 bytes.
function fingerprintBytes(fp) {
    return new Uint8Array(fp.split(':').map(h => parseInt(h, 16)));
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

// encryptVerifyPayload RSA-OAEP encrypts the bidirectional-verify JSON to the
// device's public key. The code field is the 64-bit access code from the URL
// fragment (11 base64url chars) -- omitted when the user browsed to the bare
// UID without a #code, in which case the device will reject the connection
// unless it was started without a code. The matching decrypt lives in
// identity.Decrypt on the device side.
//
// Two formats (device-origins.md, "The device challenge"):
//
//   {fp, nonce, code, challenge}  when the offer carried a challenge. fp is
//       the fingerprint's 32 bytes in base64, not SDP's 95 characters of
//       colon-separated hex: RSA-2048 OAEP/SHA-256 takes at most 190 bytes,
//       and the old spelling plus a challenge is 208. This is 148.
//   {fingerprint, nonce, code}    for a device that sent none (an installed
//       CLI). Replayable, as it always was.
async function encryptVerifyPayload(pubkey, fingerprint, nonceBytes, code, challenge) {
    let obj;
    if (challenge) {
        obj = {
            fp: bytesToBase64(fingerprintBytes(fingerprint)),
            nonce: bytesToBase64(nonceBytes),
        };
        if (code) obj.code = code;
        obj.challenge = challenge;
    } else {
        obj = {
            fingerprint,
            nonce: bytesToBase64(nonceBytes),
        };
        if (code) obj.code = code;
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
// description is set, then drain them in arrival order. Used by the pair
// (PairingFlow) handshake here; connection.js has its own copy for the direct
// one. The readiness gate lives at the call site.
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

function pairErrorText(msg) {
    if (msg.code === 'unknown_code') {
        return "That code isn't valid or has expired. Pairing codes last 5 minutes — ask for a fresh one.";
    }
    return 'Could not start pairing: ' + (msg.message || 'unknown error') + '.';
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
            case 'error': this.fail(pairErrorText(msg)); break;
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

// ============================================================================
// The device flow: framing the connection frame, and answering it.
// ============================================================================

// What the connection frame may use, and so what the device's pages may: a
// cross-origin frame gets only what its allow= lists, and a frame inside it
// only what it had. connection.js lists the same for the content frame.
const FRAME_ALLOW = 'autoplay; fullscreen; clipboard-read; clipboard-write; picture-in-picture; camera; microphone';

// No allow-top-navigation, so a device page that tries to bust out of its
// frame can't take the tab. allow-same-origin keeps the frame in its own
// origin -- the label's, not this page's -- which is what lets it register
// its worker and keep the device's cookies; it gains nothing over this page.
const FRAME_SANDBOX = 'allow-scripts allow-forms allow-same-origin allow-popups allow-modals allow-downloads';

// localStorage: this browser's label secret, and what each device has said
// about its routing. sessionStorage: a PIN that worked, per device, per tab.
const LABEL_SECRET_KEY = 'bb-label-secret';
const ROUTING_KEY_PREFIX = 'bb-routing:';
const PIN_KEY_PREFIX = '__bb_pin_';

// A challenge as devices send it: 16 bytes, standard base64.
const CHALLENGE_RE = /^[A-Za-z0-9+/]{22}==$/;

// base32Lower is RFC 4648 base32 in lowercase (a-z, 2-7), unpadded: what a DNS
// label can hold, and what label.go's labelRE accepts.
function base32Lower(bytes) {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
    let out = '', bits = 0, value = 0;
    for (const b of bytes) {
        value = (value << 8) | b;
        bits += 8;
        while (bits >= 5) {
            out += alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
    return out;
}

// labelKey returns this browser's label secret as an HMAC key, made on first
// use. Kept in this origin's storage and never sent anywhere: it is what makes
// a label say nothing about the device to anyone watching the network.
//
// Storage can be unavailable (some private modes). Then the secret lasts for
// this page only, so every visit gets new labels and the device's cookies
// don't survive -- a fresh session each time, which is what private mode
// asks for anyway.
async function labelKey() {
    let b64 = null;
    try { b64 = localStorage.getItem(LABEL_SECRET_KEY); } catch { /* unavailable */ }
    if (!b64) {
        b64 = bytesToBase64(crypto.getRandomValues(new Uint8Array(32)));
        try { localStorage.setItem(LABEL_SECRET_KEY, b64); } catch {
            console.warn('[Bootstrap] no localStorage; labels will not persist');
        }
    }
    return crypto.subtle.importKey('raw', base64ToBytes(b64),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

// computeLabel is the device origin's name for this link in this browser:
//
//     base32(HMAC-SHA256(secret, uid + "/" + target + "/" + code))[:16]
//
// The code is in it so a user link and an admin link to the same device get
// different origins; the target, so each proxied LAN app gets its own.
async function computeLabel(uid, target, code) {
    const key = await labelKey();
    const mac = await crypto.subtle.sign('HMAC', key,
        new TextEncoder().encode(uid + '/' + target + '/' + code));
    return base32Lower(new Uint8Array(mac).slice(0, 10));
}

// rememberedRouting is what a device last said about its routing, in this
// browser: 'direct', 'target-prefix', or null if it hasn't been asked.
function rememberedRouting(uid) {
    try { return localStorage.getItem(ROUTING_KEY_PREFIX + uid); } catch { return null; }
}

// targetFor is the LAN target a device path names, or ''. A device that says
// it routes the whole path itself ('direct') has none. Otherwise -- the CLI,
// or a device not yet heard from -- the CLI's own rule decides
// (parseTargetFromPath in bitbangproxy's streamtype/http.go): a first segment
// with a colon or a dot in it, or "localhost". A guess about a device not yet
// heard from is checked when it connects (onRouting).
function targetFor(uid, devicePath) {
    if (rememberedRouting(uid) === 'direct') return '';
    const seg = (devicePath || '/').split('/').filter(Boolean)[0] || '';
    if (seg.includes(':') || seg.includes('.') || seg === 'localhost') return seg;
    return '';
}

// DeviceTab is this page's half of a device session: the connection frame,
// and every message to and from it.
class DeviceTab {
    constructor({ uid, code, devicePath, deviceSearch, deviceHash }) {
        this.uid = uid;
        this.code = code || '';
        this.flagStr = readUrlFlagString();
        this.debug = !!parseUrlFlags().debug;
        this.target = targetFor(uid, devicePath);
        // The content frame's path is the device path without the target:
        // the label origin belongs to that target alone.
        const tp = this.target ? '/' + this.target : '';
        this.framePath = (devicePath || '/').slice(tp.length) || '/';
        this.deviceSearch = deviceSearch || '';
        this.deviceHash = deviceHash || '';
        // What the address bar last said, as the content frame reported it.
        // A hashchange to anything else is the person editing the address.
        this.shown = { path: devicePath || '/', search: this.deviceSearch, hash: this.deviceHash };
        this.frame = null;
        this.labelOrigin = '';
        this.pinOverlay = null;
        this.typedPIN = null;
        this.pubkeys = new Map();       // device_pubkey string -> CryptoKey, uid-checked
    }

    async start() {
        const label = await computeLabel(this.uid, this.target, this.code);
        this.labelOrigin = location.protocol + '//' + label + '.' + location.host;
        if (this.debug) console.log('[Bootstrap] device origin', this.labelOrigin, 'target', JSON.stringify(this.target));

        window.addEventListener('message', (event) => this.onMessage(event));
        window.addEventListener('hashchange', () => this.onHashChange());

        const frame = document.createElement('iframe');
        frame.id = 'bb-connection';
        frame.sandbox = FRAME_SANDBOX;
        frame.allow = FRAME_ALLOW;
        frame.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;'
            + 'border:none;z-index:1;background:#fff;';
        // The frame's own URL says what it needs to start, none of it secret:
        // see parseStartURL in connection.js.
        const at = this.target ? '@' + encodeURIComponent(this.target) : '';
        frame.src = this.labelOrigin + '/__bb/start#' + this.uid + at + this.flagStr
            + this.framePath + this.deviceSearch + this.deviceHash;
        this.frame = frame;
        document.body.appendChild(frame);
    }

    // Every message this page acts on comes from its own connection frame:
    // that window, at that origin. Anything else -- another site, a frame the
    // content frame opened -- is ignored.
    onMessage(event) {
        if (!this.frame || event.source !== this.frame.contentWindow) return;
        if (event.origin !== this.labelOrigin) return;
        const msg = event.data;
        if (!msg || typeof msg.type !== 'string') return;
        switch (msg.type) {
            case 'prove': this.answerProve(msg); break;
            case 'title': this.onTitle(msg); break;
            case 'icon': this.onIcon(msg); break;
            case 'location': this.onLocation(msg); break;
            case 'pin_needed': this.onPINNeeded(msg); break;
            case 'pin_ok': this.onPINOK(); break;
            case 'open': this.onOpen(msg); break;
            case 'routing': this.onRouting(msg); break;
            case 'reload': location.reload(); break;
        }
    }

    toFrame(msg) {
        this.frame?.contentWindow?.postMessage(msg, this.labelOrigin);
    }

    // The proof for one connection: the payload encrypted to the device's
    // key, and sha256(nonce), which the device's first frame must equal.
    //
    // The key is checked against the uid here, whatever the frame says it
    // checked. The fingerprint and challenge are taken as given -- the frame
    // is the only one that can see them -- but only in the shapes devices
    // send, so nothing else rides into the payload.
    async answerProve(msg) {
        const fail = (message) => {
            console.error('[Bootstrap] proof refused:', message);
            this.toFrame({ type: 'proof_error', id: msg.id, message });
        };
        try {
            if (typeof msg.device_pubkey !== 'string') return fail('no device key');
            if (typeof msg.fingerprint !== 'string' || !FINGERPRINT_RE.test(msg.fingerprint)) {
                return fail('bad fingerprint');
            }
            const challenge = msg.challenge == null ? null : msg.challenge;
            if (challenge !== null && (typeof challenge !== 'string' || !CHALLENGE_RE.test(challenge))) {
                return fail('bad challenge');
            }
            let key = this.pubkeys.get(msg.device_pubkey);
            if (!key) {
                const imported = await importDevicePubkey(msg.device_pubkey);
                const computedUid = await uidFromPubkeyDer(imported.der);
                if (computedUid !== this.uid) {
                    return fail(`pubkey/UID mismatch (server gave key for ${computedUid}, expected ${this.uid})`);
                }
                key = imported.key;
                this.pubkeys.set(msg.device_pubkey, key);
            }
            if (!challenge) {
                // An installed CLI, which predates the challenge. Its payload
                // can be replayed by whoever captures it, as always.
                console.warn('[Bootstrap] device sent no challenge; payload is replayable');
            }
            const nonce = crypto.getRandomValues(new Uint8Array(16));
            const encrypted = await encryptVerifyPayload(key, msg.fingerprint, nonce, this.code, challenge);
            this.toFrame({
                type: 'proof',
                id: msg.id,
                encrypted_request: encrypted,
                nonce_hash: await sha256Base64(nonce),
            });
        } catch (e) {
            fail(String(e && e.message || e));
        }
    }

    onTitle(msg) {
        if (typeof msg.title !== 'string') return;
        document.title = msg.title.slice(0, 300);
    }

    // A data: URL, made by the connection frame from the device's icon; this
    // page can't fetch from the label origin itself.
    onIcon(msg) {
        if (typeof msg.href !== 'string' || !msg.href.startsWith('data:image/')) return;
        if (msg.href.length > 256 * 1024) return;
        let link = document.querySelector('link[rel="icon"]');
        if (!link) {
            link = document.createElement('link');
            link.rel = 'icon';
            document.head.appendChild(link);
        }
        if (link.getAttribute('href') !== msg.href) link.href = msg.href;
    }

    // The content frame moved: put its address after the code and flags, so
    // refresh and bookmarks come back to it. replaceState, so this adds no
    // history entry (the frame's navigation did) and fires no hashchange.
    onLocation(msg) {
        if (typeof msg.path !== 'string' || !msg.path.startsWith('/')) return;
        const search = typeof msg.search === 'string' ? msg.search : '';
        const hash = typeof msg.hash === 'string' ? msg.hash : '';
        this.shown = { path: msg.path, search, hash };
        const tail = (msg.path === '/' && !search && !hash) ? '' : msg.path + search + hash;
        const url = '/' + this.uid + '#' + this.code + this.flagStr + tail;
        if (this.debug) console.log('[Bootstrap] address ->', url);
        try { history.replaceState(null, '', url); } catch (e) { /* rate-limited */ }
    }

    // The address changed under the page: the person edited it, or a link
    // here pointed at it. A different code or flag section is a different
    // session, and so is another target (another origin): reload. Otherwise
    // the content frame moves, and the connection stays.
    onHashChange() {
        const p = parseDeviceURL();
        if (p.code !== this.code || readUrlFlagString() !== this.flagStr) {
            location.reload();
            return;
        }
        if (p.devicePath === this.shown.path && p.deviceSearch === this.shown.search
            && p.deviceHash === this.shown.hash) {
            return;
        }
        if (targetFor(this.uid, p.devicePath) !== this.target) {
            location.reload();
            return;
        }
        this.shown = { path: p.devicePath, search: p.deviceSearch, hash: p.deviceHash };
        this.toFrame({ type: 'navigate', path: p.devicePath, search: p.deviceSearch, hash: p.deviceHash });
    }

    // The device wants its PIN. One this tab already used comes back at once,
    // unless it just failed.
    onPINNeeded(msg) {
        const key = PIN_KEY_PREFIX + this.uid;
        if (msg.failed) {
            try { sessionStorage.removeItem(key); } catch { /* unavailable */ }
            this.typedPIN = null;
            this.showPINPrompt('Incorrect PIN');
            return;
        }
        let cached = null;
        try { cached = sessionStorage.getItem(key); } catch { /* unavailable */ }
        if (cached) {
            this.typedPIN = cached;
            this.toFrame({ type: 'pin', pin: cached, cached: true });
            return;
        }
        this.showPINPrompt();
    }

    onPINOK() {
        if (this.typedPIN) {
            try { sessionStorage.setItem(PIN_KEY_PREFIX + this.uid, this.typedPIN); } catch { /* unavailable */ }
        }
        this.hidePINPrompt();
    }

    // Over the connection frame, drawn by this page: the PIN is typed here.
    // It goes down to the frame to send, which is acceptable -- it is a second
    // factor, useless without the code (device-origins.md, "Connecting").
    showPINPrompt(errorMessage) {
        this.hidePINPrompt();
        const el = document.createElement('div');
        el.style.cssText = 'position:fixed;inset:0;z-index:2;background:#fff;'
            + 'padding:12px 16px;font:13px/1.6 "SF Mono",Menlo,Monaco,Consolas,monospace;color:#333;';
        el.innerHTML = `
            <div style="font-size: 14px; margin-bottom: 8px;">PIN Required</div>
            <div id="pin-error" style="color: #c00; margin-bottom: 8px;"></div>
            <div style="display: flex; gap: 6px; align-items: center;">
                <input type="password" id="pin-input" placeholder="PIN"
                       style="padding: 4px 8px; font-size: 14px; border: 1px solid #ccc;
                              border-radius: 3px; width: 120px; outline: none;">
                <button id="pin-submit"
                        style="padding: 4px 12px; font-size: 14px; border: 1px solid #ccc;
                               border-radius: 3px; background: #fff; cursor: pointer;">OK</button>
            </div>`;
        document.body.appendChild(el);
        this.pinOverlay = el;
        const err = el.querySelector('#pin-error');
        if (errorMessage) err.textContent = errorMessage; else err.remove();
        const input = el.querySelector('#pin-input');
        const submit = () => {
            const pin = input.value;
            if (!pin) return;
            this.typedPIN = pin;
            this.toFrame({ type: 'pin', pin, cached: false });
        };
        el.querySelector('#pin-submit').onclick = submit;
        input.onkeydown = (e) => { if (e.key === 'Enter') submit(); };
        setTimeout(() => input.focus(), 50);
    }

    hidePINPrompt() {
        this.pinOverlay?.remove();
        this.pinOverlay = null;
    }

    // Open /<uid>#<code><path>: in a new tab (the CLI's cap bar, and every
    // popup a device page makes), or in this one (the CLI's proxy form). The
    // new tab is an ordinary bitba.ng page with its own connection.
    onOpen(msg) {
        if (typeof msg.path !== 'string' || !msg.path.startsWith('/')) return;
        const url = '/' + this.uid + '#' + this.code + msg.path;
        if (msg.newTab === false) {
            location.href = url;          // same pathname: a hashchange, see above
        } else {
            window.open(url, '_blank', 'noopener');
        }
    }

    // What the device said about its routing, remembered for the next visit.
    // A device that routes the whole path itself, framed in an origin named
    // for a target, is in the wrong origin: reload into the right one. Once:
    // the next load finds the routing remembered.
    onRouting(msg) {
        if (msg.routing !== 'direct' && msg.routing !== 'target-prefix') return;
        const before = rememberedRouting(this.uid);
        try { localStorage.setItem(ROUTING_KEY_PREFIX + this.uid, msg.routing); } catch { /* unavailable */ }
        if (msg.routing === 'direct' && this.target) {
            // Remembered already and still wrong, or not rememberable at all:
            // a reload would come back the same. Stay, in the wrong origin --
            // the device still works, only its cookies sit apart.
            if (before === 'direct' || rememberedRouting(this.uid) !== 'direct') {
                console.error('[Bootstrap] device is direct, still framed for target', this.target);
                return;
            }
            console.log('[Bootstrap] device routes the whole path; reloading into its own origin');
            location.reload();
        }
    }
}


// retireOldWorker removes what the old runtime left in this origin: its
// service worker, which carried every device's requests from here, and the
// storage it kept -- every device's access code among it, and one cookie jar
// for all devices. Unregistering leaves storage behind, so the caches go by
// name. sw.js does the same when a browser fetches it; this covers a browser
// that hasn't yet. Not awaited: nothing on this page needs a worker, and this
// page has none of its own to keep.
function retireOldWorker() {
    navigator.serviceWorker?.getRegistrations?.()
        .then((regs) => {
            for (const r of regs) {
                r.unregister().then((gone) => {
                    if (gone) console.log('[Bootstrap] unregistered the old service worker');
                }).catch(() => {});
            }
        })
        .catch(() => {});
    if (typeof caches !== 'undefined') {
        for (const name of ['bitbang-sessions', 'bitbang-cookies', 'bitbang-active-session']) {
            caches.delete(name).catch(() => {});
        }
    }
}

// Initialize. Only top-level: bitba.ng's page is never framed. (Nothing frames
// it now that device pages live in their own origins; the check stays because
// a framed copy would answer nobody's connection frame and connect nothing.)
(async function() {
    console.log('[Bootstrap] running', BUILD, window.location.href.split('#')[0]);
    if (window !== window.top) {
        console.warn('[Bootstrap] Skipping init — running inside a frame, not top-level');
        return;
    }

    retireOldWorker();

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

    const tab = new DeviceTab(parseDeviceURL());
    window.__bitbangTab = tab;
    try {
        await tab.start();
    } catch (e) {
        // computeLabel needs WebCrypto, which needs a secure context.
        console.error('[Bootstrap] could not start:', e);
        const status = document.getElementById('status');
        if (status) {
            status.textContent = 'This browser is not supported';
            status.classList.add('error');
        }
    }
})();
