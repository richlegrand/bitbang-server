/**
 * BitBang connection frame
 *
 * Runs in a device origin, https://<label>.<host>/__bb/start, framed by
 * bitba.ng's page (bootstrap.js). See bitbang-docs/device-origins.md.
 *
 * Holds the WebRTC connection to the device, answers the label worker's
 * requests over the data channel, and frames the device's pages (the content
 * frame), which are same-origin with it -- so their video elements take this
 * frame's MediaStreams directly.
 *
 * What it never has is the access code. For each connection it sends
 * bitba.ng's page the device's key, its own DTLS fingerprint and the device's
 * challenge, and gets back the encrypted payload to send and the hash the
 * device must answer with (askProof). Everything that touches the address bar,
 * the tab's title and icon, the PIN, or a reload of the whole tab goes to that
 * page the same way (toTop).
 *
 * Its own URL carries what it needs to start, none of it secret:
 *
 *     /__bb/start#<uid>[@<target>][!<flags>][/<device path>]
 *
 * -- bitba.ng's fragment grammar with the uid where the code would be, plus
 * the proxied app's LAN target (parseStartURL).
 */

// BUILD is spliced in by the server as this file is served (see
// handler.buildStamp). label-sw.js carries the same value for a given deploy,
// so if the active worker reports a different one, this page is stale.
const BUILD = '__BB_BUILD__';

console.log('[Connection] script evaluated', BUILD, performance.now().toFixed(1));

// The origin of bitba.ng's page: this host without the label. Every message
// to it is addressed to this origin, and only messages from it, from the
// parent window, are heard.
const TOP_ORIGIN = (() => {
    const host = location.host.slice(location.host.indexOf('.') + 1);
    return location.protocol + '//' + host;
})();

// toTop sends bitba.ng's page a message. Never anything it could not hand to
// any script in this origin: every script here can read what this frame
// sends and forge what it says.
function toTop(msg) {
    window.parent.postMessage(msg, TOP_ORIGIN);
}

// fromTop calls fn for each message from bitba.ng's page.
function fromTop(fn) {
    window.addEventListener('message', (event) => {
        if (event.source !== window.parent || event.origin !== TOP_ORIGIN) return;
        if (event.data && typeof event.data.type === 'string') fn(event.data);
    });
}

// The tab's title belongs to bitba.ng's page. Kept here too, so code that
// saves a title to restore later can read back what it last set.
let topTitle = '';
function setTopTitle(title) {
    topTitle = title;
    toTop({ type: 'title', title });
}

// reloadTab reloads the whole tab: bitba.ng's page as well as this frame,
// which a stale build needs (both halves of the runtime are behind) and
// which a device restart is simplest served by.
function reloadTab() {
    toTop({ type: 'reload' });
}

// askProof asks bitba.ng's page for this connection's proof: the payload
// encrypted to the device's key, and the hash the device must answer with.
// The page checks the key against the uid itself, so a key this frame was
// handed by a rogue server is caught there.
let proofSeq = 0;
const proofWaiters = new Map();
function askProof(devicePubkey, fingerprint, challenge) {
    const id = ++proofSeq;
    return new Promise((resolve, reject) => {
        proofWaiters.set(id, { resolve, reject });
        toTop({ type: 'prove', id, device_pubkey: devicePubkey, fingerprint, challenge: challenge || null });
    });
}
fromTop((msg) => {
    if (msg.type !== 'proof' && msg.type !== 'proof_error') return;
    const w = proofWaiters.get(msg.id);
    if (!w) return;
    proofWaiters.delete(msg.id);
    if (msg.type === 'proof') w.resolve(msg);
    else w.reject(new Error(msg.message || 'proof refused'));
});

// askServiceWorkerBuild returns the build stamp of the worker that would
// serve this page, or null if nothing answers. Uses a MessageChannel so
// it works before the worker controls us.
function askServiceWorkerBuild(worker) {
    if (!worker) return Promise.resolve(null);
    return new Promise((resolve) => {
        const ch = new MessageChannel();
        const timer = setTimeout(() => resolve(null), 2000);
        ch.port1.onmessage = (e) => {
            clearTimeout(timer);
            resolve(e.data?.build ?? null);
        };
        try {
            worker.postMessage({ type: 'get_build' }, [ch.port2]);
        } catch {
            clearTimeout(timer);
            resolve(null);
        }
    });
}

// -- Banners -------------------------------------------------------------------
//
// A strip across the top of the page, over the device's UI. Everything that
// takes that place goes through banner(), so they share one look, and the
// level is what decides both the color and which strip is on top when two are
// up. That order used to be two z-index literals in two functions, related
// only by a comment in one of them.
//
// Nothing may hide a session in trouble, which is the whole reason there is an
// order.
const BANNER_LEVELS = {
    trouble: { z: 2147483647, background: '#333' },     // reconnecting, device reset
    news:    { z: 2147483646, background: '#1f4e79' },  // a new browser runtime
};

// Strips asked for before the body existed, by id, latest request winning.
const pendingBanners = new Map();

// banner shows the strip `id`, or changes the words of the one already up.
// `action`, if given, is a button: { label, onClick }.
function banner(spec) {
    const { id, text, level, action } = spec;
    /* Callers can run before the body exists -- the stale-build check can
       finish first -- and nobody awaits them, so a throw would just mean the
       strip never appears. Wait for the body instead, and let removeBanner
       cancel the wait. */
    if (!document.body) {
        if (!pendingBanners.has(id)) {
            document.addEventListener('DOMContentLoaded', () => {
                const latest = pendingBanners.get(id);
                pendingBanners.delete(id);
                if (latest) banner(latest);
            }, { once: true });
        }
        pendingBanners.set(id, spec);
        return;
    }
    const existing = document.getElementById(id);
    if (existing) {
        existing.querySelector('span').textContent = text;
        return;
    }
    const { z, background } = BANNER_LEVELS[level];
    const el = document.createElement('div');
    el.id = id;
    el.style.cssText = `position:fixed;top:0;left:0;right:0;z-index:${z};` +
        `background:${background};color:#fff;font:13px/1.6 sans-serif;` +
        'text-align:center;padding:5px;opacity:0.95;';
    const words = document.createElement('span');
    words.textContent = text;
    el.appendChild(words);
    if (action) {
        const b = document.createElement('button');
        b.textContent = action.label;
        b.style.cssText = 'font:inherit;color:inherit;background:none;' +
            'border:1px solid currentColor;border-radius:3px;padding:0 .6em;' +
            'margin-left:.6em;cursor:pointer;';
        b.onclick = action.onClick;
        el.appendChild(b);
    }
    document.body.appendChild(el);
}

function removeBanner(id) {
    pendingBanners.delete(id);
    document.getElementById(id)?.remove();
}

// offerReload puts a bar across the top of the page saying a new browser
// runtime is available, with a button that reloads.
//
// It used to reload on its own, with no warning, on the reasoning that a
// second of lost state beats running two halves of the same release. The
// trade was fair; the presentation was not. A page that reloads itself
// while you are reading it is indistinguishable from a crash, and a page
// that does it in the middle of a shell command has thrown away work to
// explain nothing. Saying so instead makes the same event feedback rather
// than a glitch, and leaves the choice of moment with the person who
// knows what they were doing.
//
// What that costs is honest: a page which declines stays mismatched with
// its worker for as long as it likes. That is survivable because the two
// halves only disagree about code, not about a protocol -- for now. The
// day the worker's framing changes is the day this needs a second stamp
// beside BUILD, one that moves only when the contract between them does,
// so a breaking mismatch can insist where a cosmetic one asks.
function offerReload(theirs) {
    banner({
        id: 'bb-update-banner',
        level: 'news',
        /* "Browser runtime" rather than "version": what changed is the code
           this page runs, not the device's firmware or the app behind it, and
           on a page that is showing a device "new version" reads as news
           about the device. */
        text: 'New browser runtime available',
        action: {
            label: 'Reload',
            onClick: () => {
                /* Remembered before reloading, not after: if a deploy left the
                   two files disagreeing for good, the page comes back still
                   stale and would be offered the same reload forever. One
                   click per stamp. */
                try { sessionStorage.setItem('bb-reloaded-for', theirs); } catch { /* private mode */ }
                reloadTab();
            },
        },
    });
}

// offerReloadIfStale compares our build stamp against the worker's and
// offers a reload when they differ.
async function offerReloadIfStale(worker) {
    offerReloadFor(await askServiceWorkerBuild(worker));
}

// offerReloadFor offers a reload when `theirs` -- a build stamp learned from
// the service worker, or pushed by the server as a build_stamp -- is not the
// one this page was loaded with. Both routes end here so the guard is written
// once.
//
// Offered at most once per stamp per tab: a page that has already come back
// once for this build and still disagrees is in a broken deploy, and asking
// again would mean clicking forever. A worker that predates the stamp reports
// null and is left alone.
function offerReloadFor(theirs) {
    if (!theirs || theirs === BUILD) return;
    try {
        if (sessionStorage.getItem('bb-reloaded-for') === theirs) {
            console.warn('[Connection] build still', BUILD, 'after reloading for', theirs);
            return;
        }
    } catch { /* private mode: offer it */ }
    console.log('[Connection] stale page', BUILD, '-> offering reload for', theirs);
    offerReload(theirs);
}

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

// parseStartURL reads this frame's own URL, which bitba.ng's page built:
//
//     /__bb/start#<uid>[@<target>][!flags][/path]
//
// The path is the content frame's: for a proxied app, without its target,
// which this frame puts back on every request (ProxyRequests.start). The
// grammar and its parser, parseFragment, are runtime-common.js's, as are
// parseUrlFlags, extractDTLSFingerprint, CandidateQueue and UPLOAD_CREDIT;
// label-start.html loads it first.
function parseStartURL() {
    const f = parseFragment(window.location.hash);
    return {
        uid: f.head, target: f.target,
        devicePath: f.devicePath, deviceSearch: f.deviceSearch, deviceHash: f.deviceHash,
    };
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

// The SWSP version offered in `connect`. v4 is per-stream flow control
// (~/bitbang/swsp.md section 6): each stream may have 1 MiB in flight in
// each direction, and the receiver raises that with window_update as it
// consumes. A listener that speaks less negotiates down, and the session
// runs exactly as v3 did. The window and threshold are the Go side's
// (internal/protocol/swsp.go) and are protocol constants, not tuning.
const SWSP_VERSION = 4;
const STREAM_WINDOW = 1 << 20;
const STREAM_WINDOW_UPDATE_AT = STREAM_WINDOW / 2;

// Stream chunk header, little-endian:
//
//    0  u32  frame id      monotonic per stream, never reused
//    4  u16  chunk index
//    6  u16  chunk count
//    8  u16  flags         bit 0 = keyframe
//   10  u16  reserved
//   12  u32  pts_ms        capture time, milliseconds since the device booted
//
// pts and the keyframe flag are carried before anything reads them. Audio has
// to share a timebase with video to be synchronized, and H.264 cannot be
// decoded without knowing which frames are independent. See
// av-streaming-api.md in the design notes.
const VIDEO_CHUNK_HEADER = 16;
const VIDEO_FLAG_KEYFRAME = 0x0001;

// A stream channel announces itself with this in RTCDataChannel.protocol,
// followed by the codec: bitbang-stream/mjpeg, .../h264, .../opus, .../fmp4.
// The label carries <presentation>/<component> -- cam/video, cam/audio -- so
// the label names the stream and the protocol names its type. Both are needed:
// a decoder has to be chosen before the first frame, and one element binds to
// a presentation rather than to a component.
const STREAM_PROTOCOL_PREFIX = 'bitbang-stream/';

// How long to wait after ICE first reports 'connected' before classifying the
// path for telemetry, when 'completed' has not arrived. Long enough for the
// relay-to-direct migration that the device's nomination policy produces,
// short enough that a brief session still reports.
const PATH_SETTLE_MS = 5000;
// How many frames may be part-assembled at once. Chunks of consecutive frames
// interleave on an unordered channel, so this needs to be more than one -- but
// only just, since a frame that is still short by the time two newer ones have
// arrived is missing a chunk that is never coming.
const VIDEO_FRAME_SLOTS = 3;
const SWSP_CHUNK_SIZE = 16384;  // max payload bytes per data-channel frame

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

// A relayed session on a visible page renews its TURN credential this long
// before it expires, through the same soft reconnect: a fresh request, so a
// fresh credential through the server's capacity check. Ahead of the expiry
// rather than at it, because the relay ends the allocation when the
// credential runs out, and renewing then means renewing a dropped connection.
const TURN_RENEW_LEAD_MS = 30_000;
// How often a hidden page that is due to renew looks again, until expiry.
const TURN_RENEW_RECHECK_MS = 5000;

// How often to tell the service worker it is busy while a proxied request is
// open (ProxyRequests.keepWorkerAlive). label-sw.js holds itself for KEEPALIVE_HOLD_MS (25s) per
// keepalive, so this has to come round well inside that.
const SW_KEEPALIVE_MS = 10000;

// What the top strip says when the device has reset and the page is reloading
// because of it. Shown before the reload and again on the reloaded page until
// it has a connection, so it is one message that stays up across the reload
// rather than two -- and it has to be the same words both times.
const DEVICE_RESET_TEXT = 'Device reset, reloading...';
// Carries that across the reload. Read and cleared by the page that arrives.
const DEVICE_RESET_KEY = 'bb-device-reset';

// How often this frame tells the worker it is alive, which keeps the device's
// session cookies (sweepSessionCookies in label-sw.js; its SESSION_GAP_MS is
// several of these).
const ALIVE_EVERY_MS = 60 * 1000;

// Redialing the signaling socket after it drops under a live session. The
// first attempt waits a second, because the usual cause is the server
// restarting and that takes a moment; after that it backs off, since each
// attempt against a device that is not back yet costs the server's slow
// refusal. Reset by hearing a build stamp, which only a socket the server let
// in receives.
const SIGNAL_REDIAL_MIN_MS = 1000;
const SIGNAL_REDIAL_MAX_MS = 30000;

// --- Bidirectional verify -------------------------------------------------
//
// The browser is the connecting party. The offer carries the device's
// pubkey; the answer carries a payload encrypted to it, which proves the
// browser has the access code, and the device answers with sha256(nonce) as
// its first stream-0 frame, which proves it holds the private key. A rogue
// signaling server can rewrite SDPs all it wants, but without the device's
// private key it can't decrypt the payload or produce a matching nonce hash,
// and this frame rejects the channel.
//
// All of the payload is made by bitba.ng's page (askProof), which checks the
// key against the uid first. This frame only reads its own fingerprint
// (extractDTLSFingerprint, in runtime-common.js).

// One stream's SWSP v4 credit, both directions. Cumulative counts, as on the
// wire: a window_update names the total the peer may send, so a duplicate or
// late one is a no-op rather than extra credit. The Go connector's stream
// (internal/client/session.go) keeps the same numbers.
class StreamCredit {
    constructor() {
        this.sendLimit = STREAM_WINDOW;  // the SYN opens both directions
        this.sent = 0;
        this.receiveLimit = STREAM_WINDOW;
        this.received = 0;
        this.consumed = 0;
        this.lastUpdate = 0;
        this.overrun = false;            // logged once, see arrived()
        this.closed = false;
        this.waiters = [];               // senders waiting for credit
    }

    // Resolves true once `bytes` may be sent, false if the stream ended first.
    // Free frames (SYN, empty FIN) never wait.
    async reserve(bytes) {
        while (!this.closed && this.sent + bytes > this.sendLimit) {
            await new Promise(r => this.waiters.push(r));
        }
        if (this.closed) return false;
        this.sent += bytes;
        return true;
    }

    raiseSendLimit(max) {
        if (max <= this.sendLimit) return;
        this.sendLimit = max;
        this._wake();
    }

    close() {
        this.closed = true;
        this._wake();
    }

    _wake() {
        const w = this.waiters;
        this.waiters = [];
        for (const r of w) r();
    }

    // Bytes arrived. A peer sending past what it was granted is a protocol
    // violation, and the Go side resets the stream for it; here it is logged
    // and the data kept, since dropping it would corrupt the stream and every
    // peer that implements v4 stays inside the window anyway.
    arrived(bytes, streamId) {
        this.received += bytes;
        if (this.received > this.receiveLimit && !this.overrun) {
            this.overrun = true;
            console.warn(`[Connection] stream ${streamId}: peer sent past its window ` +
                `(${this.received} > ${this.receiveLimit})`);
        }
    }

    // Bytes consumed. Returns the new receive limit to announce, or 0 when
    // the last announcement still has half a window to run.
    consume(bytes) {
        this.consumed += bytes;
        if (this.consumed - this.lastUpdate < STREAM_WINDOW_UPDATE_AT) return 0;
        this.lastUpdate = this.consumed;
        this.receiveLimit = this.consumed + STREAM_WINDOW;
        return this.receiveLimit;
    }
}

// The SWSP side of the data channel: the frame format, stream ids, the
// version a session runs, and v4's per-stream credit (~/bitbang/swsp.md).
// Knows nothing of what a stream carries -- requests, sockets and the bench
// are BitBangConnection's -- and nothing of the page.
//
// One for the life of the frame. A soft reconnect detaches the channel it
// was on and attaches the new one; stream ids carry on across that, so a
// late frame from an old stream can never be taken for a new one.
//
// -- SWSP v4 flow control
//
// Before v4 nothing told the device to slow down for a browser: every frame
// was handed on the moment it arrived, so whatever the final reader could
// not keep up with piled up in this tab -- a whole file, for the download
// that prompted this. In a v4 session every stream has credit in each
// direction (StreamCredit), granted back as the bytes are consumed, so a
// slow reader slows the device instead.
//
// Gated on the session, not on the stream type: a listener that negotiated
// v4 enforces its receive window on every stream and resets one that
// overruns it, so every send after the SYN has to go through sendOnStream. A
// v2/v3 session -- Python, ESP32, Go before 0.5.0 -- skips all of this.
class SwspChannel {
    constructor() {
        this.dc = null;
        this.version = 0;          // what this transport runs, from 'ready'
        this.credit = new Map();   // streamId -> StreamCredit, v4 sessions only
        this.nextStreamId = 1;     // 0 is control
    }

    // The frame header, little-endian: u32 stream id, u16 flags, u16 payload
    // length, then the payload. A payload is a string, an ArrayBuffer or a
    // Uint8Array.
    static createFrame(streamId, flags, payload) {
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
        view.setUint32(0, streamId, true);
        view.setUint16(4, flags, true);
        view.setUint16(6, payloadBytes.byteLength, true);
        new Uint8Array(buffer).set(payloadBytes, 8);
        return buffer;
    }

    static parseFrame(buffer) {
        const view = new DataView(buffer);
        const streamId = view.getUint32(0, true);
        const flags = view.getUint16(4, true);
        const length = view.getUint16(6, true);
        const payload = buffer.slice(8, 8 + length);
        return { streamId, flags, payload };
    }

    attach(dc) {
        this.dc = dc;
        dc.binaryType = 'arraybuffer';
    }

    // The transport is gone. Credit belongs to the channel it was granted
    // on: senders still waiting for some are released, and see their
    // stream as ended. The next transport negotiates its version afresh.
    detach() {
        this.close();
        this.dc = null;
        for (const [, credit] of this.credit) credit.close();
        this.credit.clear();
        this.version = 0;
    }

    // Close the channel, telling the device, and leave the rest to detach.
    close() {
        try { this.dc?.close(); } catch (e) { /* already gone */ }
    }

    get open() { return this.dc?.readyState === 'open'; }
    get state() { return this.dc ? this.dc.readyState : 'missing'; }
    get bufferedAmount() { return this.dc ? this.dc.bufferedAmount : 0; }
    get flowControl() { return this.version >= 4; }

    newStreamId() { return this.nextStreamId++; }

    // A frame as it is, outside the credit: a SYN, which opens a stream and
    // costs nothing. Throws, as RTCDataChannel.send does, if the channel is
    // not open.
    send(streamId, flags, payload) {
        this.dc.send(SwspChannel.createFrame(streamId, flags, payload));
    }

    // A message on stream 0. Every control message goes through here.
    // Returns whether it went: false when there is no open channel.
    sendControl(msg) {
        if (!this.open) return false;
        this.send(0, FLAG_SYN, JSON.stringify(msg));
        return true;
    }

    // Start a stream's credit. Called as its SYN goes out: the SYN is what
    // opens the initial window in both directions.
    openCredit(streamId) {
        if (this.flowControl) this.credit.set(streamId, new StreamCredit());
    }

    // Send a frame once the stream's credit allows it. Resolves false if the
    // stream or the channel ended first, so a caller knows to stop.
    async sendOnStream(streamId, flags, payload) {
        if (this.flowControl) {
            const credit = this.credit.get(streamId);
            if (!credit) return false;
            const bytes = (flags & FLAG_SYN) ? 0 : payload.byteLength;
            if (bytes > 0 && !(await credit.reserve(bytes))) return false;
        }
        if (!this.open) return false;
        this.send(streamId, flags, payload);
        return true;
    }

    // Send frames on a WebSocket-style stream, behind whatever it is already
    // sending. ws.send() returns at once, so in a v4 session one send can be
    // waiting for credit while the page sends the next; the chain, kept on
    // the stream's own record, keeps them in order, and a close behind the
    // data before it. What waits here is what a real WebSocket would count
    // in bufferedAmount.
    queueOnStream(stream, streamId, frames) {
        stream.sendChain = (stream.sendChain || Promise.resolve()).then(async () => {
            for (const [flags, payload] of frames) {
                if (!(await this.sendOnStream(streamId, flags, payload))) return;
            }
        });
        return stream.sendChain;
    }

    // A frame arrived. consumedNow says whether delivering it was consuming
    // it: true for a stream whose reader cannot be slowed (a WebSocket's
    // onmessage), false for an http response, whose bytes count only once
    // the worker reports the reader took them (onConsumed).
    onArrived(frame, consumedNow) {
        if (frame.flags & FLAG_SYN) return;
        const credit = this.credit.get(frame.streamId);
        if (!credit) return;
        credit.arrived(frame.payload.byteLength, frame.streamId);
        if (consumedNow) this.onConsumed(frame.streamId, frame.payload.byteLength);
    }

    onConsumed(streamId, bytes) {
        const credit = this.credit.get(streamId);
        if (!credit || credit.closed || bytes <= 0) return;
        const max = credit.consume(bytes);
        if (max) this.sendControl({ type: 'window_update', stream_id: streamId, max_bytes: max });
    }

    // The device's window_update: it may be sent up to `max` on the stream.
    raiseSendLimit(streamId, max) {
        if (this.flowControl && max > 0) this.credit.get(streamId)?.raiseSendLimit(max);
    }

    // Forget a stream's credit, releasing anything waiting on it.
    dropCredit(streamId) {
        const credit = this.credit.get(streamId);
        if (!credit) return;
        credit.close();
        this.credit.delete(streamId);
    }

    // End a stream in both directions, for when its reader has gone: a
    // cancelled download, a request that timed out. Without it the device
    // would keep sending a stream nobody reads until its credit ran out, and
    // hold it open after. v2/v3 have no way to say this.
    resetStream(streamId, code, message) {
        if (!this.flowControl) return;
        this.dropCredit(streamId);
        this.sendControl({ type: 'stream_reset', stream_id: streamId, code, message });
    }
}

// What the reload screen says when a relayed session's credential runs out.
const RELAY_ENDED_TEXT = 'Relay session ended. Reload to continue.';

// Whether the session is on a TURN relay, kept current for the life of the
// connection, and what happens as a relay's credential runs out: the title
// warns, a visible page renews, a hidden one ends at the expiry and hands its
// relay slot back.
//
// It acts on the connection only through `hooks`:
//   pc()            the peer connection now in use, or null
//   ended()         the session has ended for good (nothing to renew or end)
//   reconnecting()  a reconnect is in flight (it renews by itself)
//   renew()         renew the credential: a soft reconnect
//   end(text)       end the session with the reload screen
class RelayMonitor {
    constructor(hooks, debug) {
        this.hooks = hooks;
        this.debug = debug;
        this.usingRelay = false;
        this.expiryMs = null;      // the credential's, from the offer's TURN username
        this.monitorTimer = null;
        this.warnTimer = null;
        this.endTimer = null;
        this.prevTitle = null;     // the tab title the warning replaced
    }

    // The relay credential of a new offer. The coturn REST-API username is
    // "<epoch>[:<user_name>]"; the server stamps the same epoch on every
    // entry, so the first match wins. Single-phase ICE stamps TURN up front,
    // so there is no separate post-stall push.
    setCredential(servers) {
        this.expiryMs = null;
        if (!Array.isArray(servers)) return;
        for (const s of servers) {
            const m = s && s.username && /^(\d+)(:|$)/.exec(s.username);
            if (m) {
                this.expiryMs = parseInt(m[1], 10) * 1000;
                return;
            }
        }
    }

    // Whether the session is *currently* carried over a TURN relay.
    //
    // Two conditions, and both matter. The pair has to be the one selected
    // right now -- ICE migrates, and a relay pair usually wins the first race
    // because a TURN allocation is a deterministic round trip while a direct
    // pair still has to hole-punch. And the pair has to be carrying traffic:
    // with video and data on separate transports, an idle or superseded
    // transport should not decide what the whole session is doing.
    static async isUsingRelay(pc) {
        if (!pc) return false;
        try {
            const stats = await pc.getStats();
            for (const [, report] of stats) {
                if (report.type !== 'transport' || !report.selectedCandidatePairId) continue;
                const pair = stats.get(report.selectedCandidatePairId);
                if (!pair) continue;
                if (((pair.bytesSent || 0) + (pair.bytesReceived || 0)) === 0) continue;
                const local = stats.get(pair.localCandidateId);
                const remote = stats.get(pair.remoteCandidateId);
                if (local?.candidateType === 'relay' || remote?.candidateType === 'relay') {
                    return true;
                }
            }
        } catch (e) {}
        return false;
    }

    // What isUsingRelay is actually looking at, in a form a person can read.
    // Kept beside it so the two cannot drift: if this says every pair is host
    // and the session still ended on relay expiry, the fault is in the caller
    // rather than in the stats.
    static async describeSelectedPairs(pc) {
        const out = [];
        try {
            const stats = await pc.getStats();
            for (const [, report] of stats) {
                if (report.type !== 'transport' || !report.selectedCandidatePairId) continue;
                const pair = stats.get(report.selectedCandidatePairId);
                if (!pair) { out.push('transport with no pair'); continue; }
                const local = stats.get(pair.localCandidateId);
                const remote = stats.get(pair.remoteCandidateId);
                out.push({
                    local: local?.candidateType,
                    remote: remote?.candidateType,
                    state: pair.state,
                    nominated: pair.nominated,
                    bytes: (pair.bytesSent || 0) + (pair.bytesReceived || 0),
                });
            }
        } catch (e) {
            out.push('getStats failed: ' + e);
        }
        return out;
    }

    // Debug only: poll every 2s and log when an ICE pair changes for any
    // transport. OctoPrint has multiple transports (video + data channel)
    // which ICE routes independently, so logging only the first hides cases
    // where one transport is on direct and another is on relay.
    static logPairChanges(pc) {
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
                    console.log(`[Connection] ICE pair (transport ${transportId}, dtls=${dtlsState}): ${isRelay ? 'TURN relay' : 'direct'} - local ${localDesc}, remote ${remoteDesc}`);
                }
            } catch (e) {}
            setTimeout(tick, 2000);
        };
        tick();
    }

    // Sample the path now, and remember the verdict.
    async check(pc) {
        this.usingRelay = await RelayMonitor.isUsingRelay(pc);
        return this.usingRelay;
    }

    // Keep usingRelay honest for the life of the connection.
    //
    // The verdict used to be sampled once, at the first 'connected' event,
    // which is the earliest and least representative moment: the relay pair
    // typically succeeds first and the device (the controlling agent) then
    // nominates a direct pair, by design. A session that spent two seconds on
    // a relay and the next ten minutes direct was still shown the relay
    // banner, and was still killed by the relay's expiry timer.
    watch(pc) {
        this.stopWatching();
        const tick = async () => {
            // Only a replaced or discarded connection ends the monitor. A
            // transient 'disconnected' must not: the state flaps on any blip
            // and recovers, and returning here without rescheduling left the
            // monitor dead for the rest of the session -- with usingRelay
            // frozen at whatever it was, which is usually true, because the
            // relay pair wins first and the direct pair is nominated after.
            if (this.hooks.pc() !== pc) return;
            if (pc.connectionState !== 'connected') {
                this.monitorTimer = setTimeout(tick, 2000);
                return;
            }
            const now = await RelayMonitor.isUsingRelay(pc);
            if (now !== this.usingRelay) {
                this.usingRelay = now;
                if (this.debug) {
                    console.log(`[Connection] path changed: now ${now ? 'relayed' : 'direct'}`);
                }
                if (now) {
                    if (!this.hooks.ended()) this.armEndTimers();
                } else {
                    // Off the relay: nothing here expires any more.
                    this.clearEndTimers();
                    this.restoreTitle();
                }
            }
            this.monitorTimer = setTimeout(tick, 2000);
        };
        tick();
    }

    stopWatching() {
        clearTimeout(this.monitorTimer);
        this.monitorTimer = null;
    }

    // The transport is gone: forget its path and its credential.
    reset() {
        this.stopWatching();
        this.clearEndTimers();
        this.usingRelay = false;
        this.expiryMs = null;
    }

    restoreTitle() {
        if (!this.prevTitle) return;
        setTopTitle(this.prevTitle);
        this.prevTitle = null;
    }

    // Schedule what happens as the credential runs out. TURN_RENEW_LEAD_MS
    // before the expiry, a visible page renews: a soft reconnect, which
    // brings a fresh credential and arms this again. A hidden page keeps
    // looking until the expiry and renews if someone comes back; otherwise it
    // ends as it always has -- the title warns from expiry-60s, the reload
    // screen comes at expiry -- so a tab nobody is looking at hands its relay
    // slot back. Nothing to do without a credential.
    //
    // A credential that arrives with less than the lead left ends as before
    // too, rather than renewing straight away: a server whose TTL is shorter
    // than the lead would otherwise renew in a loop.
    //
    // Cleared first because this can run twice on a relayed connection, and
    // in practice does: the monitor's first tick and the first-connected
    // check race to see the path turn relayed, and each arms. Only the second
    // pair of handles was kept, so the first pair could not be cancelled --
    // not by a soft reconnect, not by the path going direct -- and ended the
    // session at the expiry of the credential it was armed from, however
    // many fresh ones had arrived since.
    armEndTimers() {
        if (!this.expiryMs) return;
        this.clearEndTimers();
        const now = Date.now();
        const warnAt = this.expiryMs - 60_000 - now;
        const renewAt = this.expiryMs - TURN_RENEW_LEAD_MS - now;
        const endAt = this.expiryMs - now;
        const warn = () => {
            if (!this.prevTitle) this.prevTitle = topTitle;
            setTopTitle('⚠ Relay ending soon — bitba.ng');
        };
        if (warnAt > 0) {
            this.warnTimer = setTimeout(() => {
                // A visible page renews before anything ends; no warning.
                if (this.hooks.ended() || !this.usingRelay || !document.hidden) return;
                warn();
            }, warnAt);
        }
        // Re-check the live path before tearing the page down. The monitor
        // should have caught a migration to direct already, but this timer is
        // what actually ends the session, so it verifies rather than trusting
        // a verdict that may be minutes old.
        const endNow = async () => {
            if (this.hooks.ended()) return;
            const pc = this.hooks.pc();
            if (!(await RelayMonitor.isUsingRelay(pc))) {
                this.usingRelay = false;
                this.clearEndTimers();
                return;
            }
            // Ended before the stats are read, so nothing else acts on the
            // session while they are.
            this.hooks.end(RELAY_ENDED_TEXT);
            // Not behind the debug flag. This fires at most once per session
            // and only while tearing the page down, which is exactly the
            // moment evidence is worth having -- "it said relay and I was not
            // on a relay" is otherwise unfalsifiable after the fact.
            console.warn('[Connection] ended session on relay expiry;',
                         'selected pairs:', await RelayMonitor.describeSelectedPairs(pc));
        };
        // The same check before renewing: a session that went direct has
        // nothing to renew.
        const renewOrEnd = async () => {
            if (this.hooks.ended() || this.hooks.reconnecting()) return;
            if (!(await RelayMonitor.isUsingRelay(this.hooks.pc()))) {
                this.usingRelay = false;
                this.clearEndTimers();
                return;
            }
            if (this.hooks.ended() || this.hooks.reconnecting()) return;
            if (!document.hidden) {
                this.restoreTitle();
                this.hooks.renew();
                return;
            }
            // Hidden after the warning was due, the page has not warned yet.
            warn();
            const left = this.expiryMs - Date.now();
            this.endTimer = left > TURN_RENEW_RECHECK_MS
                ? setTimeout(renewOrEnd, TURN_RENEW_RECHECK_MS)
                : setTimeout(endNow, Math.max(0, left));
        };
        if (renewAt > 0) {
            this.endTimer = setTimeout(renewOrEnd, renewAt);
        } else if (endAt > 0) {
            this.endTimer = setTimeout(endNow, endAt);
        } else {
            // Already past expiry by the time we got here -- check and fire.
            endNow();
        }
    }

    clearEndTimers() {
        clearTimeout(this.warnTimer);
        clearTimeout(this.endTimer);
        this.warnTimer = null;
        this.endTimer = null;
    }
}

// The connection_path telemetry: one message to the signaling server per ICE
// establishment, saying whether it ended up direct, relayed or relayed over
// TCP, and one when ICE fails. Fire-and-forget: it never affects the session.
//
// Sample once ICE has settled, not the moment it first works. 'connected'
// means some pair succeeded; 'completed' means checking is done and the
// nomination is final. A relay pair usually wins the first race -- a TURN
// allocation is one deterministic round trip, a direct pair still has to
// hole-punch -- and the device then nominates direct, by design. Sampling at
// 'connected' therefore counted relay for sessions that spent their whole
// life direct.
//
// 'completed' is not guaranteed to arrive, and a short session may end before
// it does, so a settle timer bounds the wait. First one wins; `reported`
// keeps it to one report per establishment.
//
// hooks: pc() as RelayMonitor's, and send(msg) to the signaling socket.
class PathReporter {
    constructor(hooks, debug) {
        this.hooks = hooks;
        this.debug = debug;
        this.reported = false;
        this.settleTimer = null;
        this.prevState = null;     // the last iceConnectionState seen
    }

    // A new peer connection: a new establishment to report.
    reset() {
        this.prevState = null;
        this.reported = false;
        this.clearSettleTimer();
    }

    // Each transition INTO connected gets one report with the actual
    // selected path, and each transition INTO failed gets one "failed".
    onIceState(pc) {
        const now = pc.iceConnectionState;
        const prev = this.prevState;
        this.prevState = now;
        if ((now === 'connected' || now === 'completed') && !this.reported) {
            if (now === 'completed') {
                this.report(pc);
            } else if (!this.settleTimer) {
                this.settleTimer = setTimeout(() => this.report(pc), PATH_SETTLE_MS);
            }
        } else if (now === 'failed' && prev !== 'failed') {
            this.clearSettleTimer();
            if (!this.reported) {
                this.reported = true;
                this.send('failed', 'ice_failed');
            }
        } else if (now === 'checking' && prev && prev !== 'checking') {
            // A restartIce re-establishment (connected -> checking ->
            // connected on the same PC) is a new establishment and earns its
            // own report.
            this.clearSettleTimer();
            this.reported = false;
        }
    }

    // One report per establishment, whichever trigger fires first.
    report(pc) {
        this.clearSettleTimer();
        if (this.reported || this.hooks.pc() !== pc) return;
        this.reported = true;
        PathReporter.classify(pc)
            .then((path) => this.send(path))
            .catch(() => {});
    }

    clearSettleTimer() {
        clearTimeout(this.settleTimer);
        this.settleTimer = null;
    }

    // Classify the established path. Returns "direct", "relay", or
    // "tcp-relay". Looks at every transport's selected pair and picks the
    // "worst" (tcp-relay > relay > direct) so a mixed session -- e.g. data
    // direct but video relay -- reports relay rather than under-counting it
    // as direct.
    //
    // tcp-relay distinction: when a candidate is type "relay", the
    // relayProtocol field (if exposed) tells us whether the allocation was
    // made over UDP or TCP. We fall back to the candidate's transport
    // protocol if relayProtocol isn't present.
    static async classify(pc) {
        let path = 'direct';
        try {
            const stats = await pc.getStats();
            for (const [, report] of stats) {
                if (report.type !== 'transport' || !report.selectedCandidatePairId) continue;
                const pair = stats.get(report.selectedCandidatePairId);
                if (!pair) continue;
                // An idle or superseded transport should not classify the
                // session; same rule as RelayMonitor.isUsingRelay.
                if (((pair.bytesSent || 0) + (pair.bytesReceived || 0)) === 0) continue;
                const local = stats.get(pair.localCandidateId);
                const remote = stats.get(pair.remoteCandidateId);
                const relayCand =
                    local?.candidateType === 'relay' ? local
                  : remote?.candidateType === 'relay' ? remote
                  : null;
                if (!relayCand) continue;
                const proto = (relayCand.relayProtocol || relayCand.protocol || 'udp').toLowerCase();
                path = proto === 'tcp' ? 'tcp-relay' : 'relay';
                // Keep scanning in case a later transport has a worse
                // classification (tcp-relay > relay).
                if (path === 'tcp-relay') break;
            }
        } catch (e) {
            // Telemetry must never break user flow. Best-effort classify
            // as direct and move on.
        }
        return path;
    }

    send(path, reason) {
        const msg = { type: 'connection_path', path };
        if (reason) msg.reason = reason;
        if (this.hooks.send(msg) && this.debug) {
            console.log(`[Connection] reported connection_path: ${path}${reason ? ' (' + reason + ')' : ''}`);
        }
    }
}

// The soft reconnect: when an established peer connection drops, rebuild the
// transport under the live page with fresh connection requests, until one
// works or RECONNECT_WINDOW_MS of trying is used up (see the constants).
// Also how a relay credential is renewed, ahead of its expiry.
//
// It acts on the connection only through `hooks`:
//   ended()     the session has ended for good: stop
//   begin()     a loop is starting: quiet the timers, show the strip
//   attempt()   tear down what is left and send a fresh request; a promise
//               that rejects if signaling fails. Success is reported later,
//               by succeeded(), when the new transport reaches 'ready'.
//   finish()    the loop is over, either way: take the strip down
//   giveUp()    the window closed without a connection: end the session
class Reconnector {
    constructor(hooks) {
        this.hooks = hooks;
        this.active = false;       // a loop is running
        this.renewing = false;     // ...and it is renewing a relay credential
        this.resolve = null;       // the attempt in flight
        this.reject = null;
        this.timeout = null;
        this.wake = null;          // cuts a backoff short, see sleep
    }

    // The established connection failed. Nothing to do if the session has
    // ended on purpose or a loop already owns the recovery.
    start() {
        if (this.hooks.ended() || this.active) return;
        this.loop();
    }

    // Renew the relay credential: the same loop, flagged so the offer handler
    // can tell a renewal that finds the relay full from a reconnect that
    // should keep trying.
    renew() {
        this.renewing = true;
        this.loop();
    }

    // Rebuild with capped exponential backoff. Each attempt re-runs the
    // normal signaling flow (request, offer, answer, data channel, ready);
    // the device answers via its ordinary HandleRequest path. The iframe and
    // the page's state are untouched throughout.
    async loop() {
        this.active = true;
        this.hooks.begin();

        // deadline is (re)armed whenever attempting becomes newly possible:
        // at entry, and again when connectivity returns after an offline
        // park. Between those points it only counts down.
        let deadline = Date.now() + RECONNECT_WINDOW_MS;
        let backoff = 1000;
        let attempt = 0;
        // A terminal screen (the device ending the session, relay expiry)
        // may land at any await point; ended() stops the loop wherever it is
        // checked.
        while (!this.hooks.ended()) {
            if (!navigator.onLine) {
                console.log('[Connection] offline — waiting for connectivity before reconnecting');
                await this.waitForOnline();
                if (this.hooks.ended()) break;
                await new Promise(r => setTimeout(r, RECONNECT_SETTLE_MS));
                deadline = Date.now() + RECONNECT_WINDOW_MS;
                backoff = 1000;
                continue;
            }
            attempt++;
            try {
                await this.once();
                console.log(`[Connection] reconnected on attempt ${attempt}`);
                this.active = false;
                this.renewing = false;
                this.hooks.finish();
                return;
            } catch (e) {
                console.warn(`[Connection] reconnect attempt ${attempt} failed:`, e?.message || e);
                if (Date.now() + backoff >= deadline) break;
                await this.sleep(backoff);
                backoff = Math.min(backoff * 2, RECONNECT_MAX_BACKOFF_MS);
            }
        }

        // Window closed (or a terminal screen owns the page) -- fall back.
        this.active = false;
        this.renewing = false;
        this.hooks.finish();
        if (this.hooks.ended()) return;
        this.hooks.giveUp();
    }

    // One attempt: resolves once the rebuilt data channel is verified and the
    // device replies 'ready' (succeeded), or rejects on timeout or a
    // signaling error.
    once() {
        return new Promise((resolve, reject) => {
            this.resolve = resolve;
            this.reject = reject;
            this.timeout = setTimeout(() => this.fail(new Error('reconnect_timeout')), RECONNECT_TIMEOUT_MS);
            this.hooks.attempt().catch(e => this.fail(e));
        });
    }

    // The attempt in flight worked: the new transport reached 'ready'. A
    // no-op when nothing is waiting.
    succeeded() { this.settle(true); }

    // The attempt in flight failed (a fresh peer connection that never
    // connected, say). The loop's backoff decides what next.
    fail(err) { this.settle(false, err); }

    // A terminal screen took the page: stop, and fail what is in flight.
    cancel() {
        if (!this.active) return;
        this.active = false;
        this.fail(new Error('terminal'));
    }

    // Resolve or reject the attempt in flight, exactly once.
    settle(ok, err) {
        clearTimeout(this.timeout);
        this.timeout = null;
        const resolve = this.resolve, reject = this.reject;
        this.resolve = null;
        this.reject = null;
        if (ok && resolve) resolve();
        else if (!ok && reject) reject(err || new Error('reconnect_failed'));
    }

    // Resolve once navigator.onLine is true. The 'online' event is the
    // primary signal; a 5s poll backstops it and lets the loop notice the
    // session ending while parked here.
    async waitForOnline() {
        while (!navigator.onLine && !this.hooks.ended()) {
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

    // A sleep the device coming back can cut short (wakeUp).
    //
    // The backoff reaches ten seconds, and a device that has finished
    // rebooting should not be waited out for the rest of it -- the moment it
    // registers is the one moment an attempt is certain to find something.
    // Resolving early is all this does; the loop re-decides everything else
    // for itself.
    sleep(ms) {
        return new Promise((resolve) => {
            let t = null;
            const done = () => { clearTimeout(t); this.wake = null; resolve(); };
            t = setTimeout(done, ms);
            this.wake = done;
        });
    }

    wakeUp() { this.wake?.(); }
}

// The HTTP requests the label worker hands this frame (proxy_request), each
// on a stream of its own: the request out, with its body if it has one, and
// the response back to the worker's port as it arrives.
//
// hooks:
//   targetPrefix()  '/<target>' for a proxied app, put back on every path
//   channelDead()   a request found no open channel: start recovering
class ProxyRequests {
    constructor(swsp, hooks, debug) {
        this.swsp = swsp;
        this.hooks = hooks;
        this.debug = debug;
        this.pending = new Map();      // streamId -> request state
        this.keptAliveAt = 0;          // last keepalive sent (keepWorkerAlive)
        // Upload progress, for whichever device page started the upload
        // (ota.html, the CLI's file browser). The whole vocabulary:
        // uploadProgress { loaded, total }, uploadComplete (all bytes
        // sent), then uploadSuccess or uploadFailed once the device answers.
        //
        // camelCase, unlike the rest of the browser's messages, because
        // device pages hear these and we don't ship all of them: the CLI's
        // file browser listens for these names, and a CLI already installed
        // has to keep working against a new server. Never rename them.
        this.progress = new BroadcastChannel('bitbang-progress');
        // Backstop for keepWorkerAlive, which otherwise runs on arriving
        // frames: an upload sends and receives nothing until it finishes, and
        // a stalled response receives nothing either.
        setInterval(() => this.keepWorkerAlive(), SW_KEEPALIVE_MS);
    }

    has(streamId) { return this.pending.has(streamId); }

    // Tell the label worker it is still busy, at most every SW_KEEPALIVE_MS
    // and only while a proxied request is open.
    //
    // The worker streams every proxied response, but its bytes come from here
    // over a MessagePort, and the browser does not count port traffic as the
    // worker doing anything. Firefox stopped one inside 45s of quiet, and the
    // response did not fail -- it ended short, as if complete. Chromium kept
    // it alive through 330s (measured 2026-10-18), but nothing promises that.
    // A posted message is an event, which is the one thing that counts.
    //
    // Called on every arriving frame rather than only from a timer, because a
    // download usually runs in a tab nobody is looking at, and a hidden tab's
    // timers can be held to one wake-up a minute; frames are not throttled.
    // The constructor's interval covers a request with no frames arriving.
    keepWorkerAlive() {
        if (this.pending.size === 0) return;
        const now = Date.now();
        if (now - this.keptAliveAt < SW_KEEPALIVE_MS) return;
        this.keptAliveAt = now;
        // The registration's worker rather than .controller, which Chrome can
        // drop from a page that is still very much alive (see proxyToDevice).
        navigator.serviceWorker.ready
            .then((reg) => reg.active?.postMessage({ type: 'keepalive' }))
            .catch(() => {});
    }

    start(data, responsePort) {
        const { method, url, headers, hasBody, contentLength } = data;
        if (this.debug) console.log(`[Connection] Received proxy request: ${method} ${new URL(url).pathname}, DC state: ${this.swsp.state}`);

        if (!this.swsp.open) {
            console.warn('[Connection] Data channel not open, rejecting request');
            responsePort.postMessage({ type: 'proxy_error', message: 'Data channel not open' });
            // A live page with a dead channel should be recovering, not
            // rejecting forever -- kick the reconnect if nothing else did.
            this.hooks.channelDead();
            return;
        }

        // The path as the device expects it. A proxied app's origin belongs to
        // one LAN target, which its pages never see in their paths; the
        // listener routes on it, so it goes back on here.
        const parsed = new URL(url);
        const fullPath = this.hooks.targetPrefix() + parsed.pathname + parsed.search;

        const streamId = this.swsp.newStreamId();

        // Initial 30s timeout to catch "device not responding". Cleared once
        // response headers arrive (SYN). After that we rely on FIN / data
        // channel close to signal end -- inactivity is normal during streaming
        // when the consumer (e.g. video player) backpressures the channel,
        // which in a v4 session it really does.
        let timeout;
        const resetTimeout = () => {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                this.pending.delete(streamId);
                this.swsp.resetStream(streamId, 'timeout', 'no response within 30s');
                responsePort.postMessage({ type: 'proxy_error', message: 'Request timeout' });
            }, 30000);
            /* Kept on the entry too, which is the one other code clears: it
               held the first timer's id for good, so after a reset, clearing
               req.timeout cleared a timer that had already been replaced. */
            const req = this.pending.get(streamId);
            if (req) req.timeout = timeout;
        };
        resetTimeout();

        this.pending.set(streamId, {
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
        // know the field default it to "http" -- same effect.
        const requestMeta = { type: 'http', method, pathname: fullPath, headers };
        if (hasBody) {
            requestMeta.contentLength = contentLength;
            // Keep contentType for backward compatibility with older devices
            if (headers['content-type']) {
                requestMeta.contentType = headers['content-type'];
            }
        }

        // Besides the upload, the worker's end of this request's port says
        // how much of the response its reader has taken (proxy_consumed),
        // which is the credit a v4 session grants back, and that the reader
        // has gone (proxy_cancel).
        let onUpload = null;  // set below for a request with a body
        responsePort.onmessage = (event) => {
            const msg = event.data;
            if (msg.type === 'proxy_consumed') {
                this.swsp.onConsumed(streamId, msg.bytes);
            } else if (msg.type === 'proxy_cancel') {
                this.cancel(streamId);
            } else if (onUpload) {
                onUpload(msg);
            }
        };

        this.swsp.openCredit(streamId);

        if (!hasBody) {
            // No body: SYN and FIN together.
            this.swsp.send(streamId, FLAG_SYN | FLAG_FIN, JSON.stringify(requestMeta));
            return;
        }

        // A body: the SYN with the metadata, then the body's chunks as the
        // worker hands them over.
        try {
            this.swsp.send(streamId, FLAG_SYN, JSON.stringify(requestMeta));
        } catch (e) {
            this.swsp.dropCredit(streamId);
            responsePort.postMessage({ type: 'proxy_error', message: 'Failed to start upload' });
            this.progress.postMessage({ type: 'uploadFailed' });
            return;
        }

        let bytesSent = 0;
        let lastProgress = 0;
        let processingChain = Promise.resolve();
        let failed = false;

        // Once: the chunks queued behind the one that failed would each
        // say so again.
        const failUpload = (msg) => {
            if (failed) return;
            failed = true;
            this.pending.delete(streamId);
            responsePort.postMessage({ type: 'proxy_error', message: msg });
            this.progress.postMessage({ type: 'uploadFailed' });
        };

        const isOpen = () => this.swsp.open;

        onUpload = (msg) => {
            processingChain = processingChain.then(async () => {
                if (failed) return;
                if (!isOpen()) return failUpload('Connection lost');

                if (msg.type === 'upload_chunk') {
                    const data = msg.data;

                    for (let i = 0; i < data.byteLength; i += SWSP_CHUNK_SIZE) {
                        // Backpressure: wait while buffer is full
                        while (isOpen() && this.swsp.bufferedAmount > 1024 * 1024) {
                            await new Promise(r => setTimeout(r, 10));
                        }
                        if (!isOpen()) return failUpload('Connection lost');

                        // And in a v4 session for the device's credit,
                        // which is what a slow target looks like from
                        // here. False means the stream ended meanwhile:
                        // the device reset it, or the channel went.
                        const chunk = data.subarray(i, Math.min(i + SWSP_CHUNK_SIZE, data.byteLength));
                        if (!(await this.swsp.sendOnStream(streamId, FLAG_DAT, chunk))) {
                            return failUpload(isOpen() ? 'Upload stopped by device' : 'Connection lost');
                        }
                    }

                    bytesSent += data.byteLength;
                    // Let the worker hand over more. Without this it read
                    // the whole body as fast as it could and every chunk
                    // queued here, so an upload over a slow link sat in
                    // the tab's memory -- for every listener, v4 or not.
                    responsePort.postMessage({ type: 'upload_credit', max: bytesSent + UPLOAD_CREDIT });

                    const now = Date.now();
                    if (now - lastProgress > 100) {
                        lastProgress = now;
                        resetTimeout();
                        this.progress.postMessage({
                            type: 'uploadProgress', loaded: bytesSent, total: contentLength
                        });
                    }

                } else if (msg.type === 'upload_end') {
                    if (!isOpen()) return failUpload('Connection lost');
                    this.progress.postMessage({ type: 'uploadComplete' });
                    await this.swsp.sendOnStream(streamId, FLAG_FIN, new Uint8Array(0));
                }
            });
        };
    }

    // A frame on one of the requests' streams: the response's headers (SYN),
    // its body, its end (FIN). Handed to the worker as it comes.
    onFrame(frame) {
        const req = this.pending.get(frame.streamId);
        if (!req) return;
        this.keepWorkerAlive();
        // Not consumed yet: the worker reports that as its reader takes
        // the bytes (proxy_consumed).
        this.swsp.onArrived(frame, false);

        // Cancelled in a v2/v3 session, which cannot stop the device: the
        // rest goes nowhere.
        if (req.cancelled) {
            if (frame.flags & FLAG_FIN) this.pending.delete(frame.streamId);
            return;
        }

        if (frame.flags & FLAG_SYN) {
            // Metadata frame - send headers to SW, it will create the stream
            const text = new TextDecoder().decode(frame.payload);
            const metadata = JSON.parse(text);
            const status = metadata.status || 200;
            if (this.debug) console.log(`[Connection] Response for stream ${frame.streamId}: ${status}`);

            // Clear timeout once response starts. After this, inactivity
            // between chunks is normal (consumer backpressure for streams)
            // and shouldn't kill the request.
            clearTimeout(req.timeout);

            req.responsePort.postMessage({
                type: 'proxy_headers',
                status: status,
                headers: metadata.headers || {}
            });

            // Broadcast upload result for iframe UI
            if (req.isUpload) {
                this.progress.postMessage({
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
                req.responsePort.postMessage({ type: 'proxy_chunk', data }, [data.buffer]);
            }

            // Log completion for large transfers
            if (req.bytesReceived > 1024 * 1024) {
                const elapsed = (Date.now() - req.startTime) / 1000;
                const sizeMB = req.bytesReceived / (1024 * 1024);
                const speed = elapsed > 0 ? (sizeMB / elapsed).toFixed(1) : '0';
                console.log(`Download complete: ${sizeMB.toFixed(0)} MB in ${elapsed.toFixed(1)}s (${speed} MB/s)`);
            }

            req.responsePort.postMessage({ type: 'proxy_end' });
            this.pending.delete(frame.streamId);
            this.swsp.dropCredit(frame.streamId);
        } else if (!(frame.flags & FLAG_SYN) && frame.payload.byteLength > 0) {
            // Data chunk - use transferable to avoid copy
            req.bytesReceived += frame.payload.byteLength;
            const data = new Uint8Array(frame.payload);
            req.responsePort.postMessage({ type: 'proxy_chunk', data }, [data.buffer]);

            // Log progress at each 50MB milestone
            const currentMB = req.bytesReceived / (1024 * 1024);
            if (currentMB >= req.nextLogMB) {
                const elapsed = (Date.now() - req.startTime) / 1000;
                const speed = elapsed > 0 ? (currentMB / elapsed).toFixed(1) : '0';
                console.log(`Download: ${currentMB.toFixed(0)} MB (${speed} MB/s)`);
                req.nextLogMB += 50;
            }
        }
    }

    // The response's reader went away: a download cancelled in the browser,
    // a media element that has what it needs. A v4 session tells the device,
    // which stops reading its target; v2/v3 cannot, so the rest of the
    // response is dropped as it arrives instead of being handed to nobody.
    cancel(streamId) {
        const req = this.pending.get(streamId);
        if (!req) return;
        clearTimeout(req.timeout);
        if (this.swsp.flowControl) {
            this.pending.delete(streamId);
            this.swsp.resetStream(streamId, 'cancelled', 'the reader went away');
        } else {
            req.cancelled = true;
        }
    }

    // The device reset one request's stream.
    onReset(streamId, why) {
        const req = this.pending.get(streamId);
        if (!req) return;
        clearTimeout(req.timeout);
        this.pending.delete(streamId);
        req.responsePort.postMessage({ type: 'proxy_error', message: why });
        if (req.isUpload) this.progress.postMessage({ type: 'uploadFailed' });
    }

    // The channel every request was on has gone. One sent on it can never be
    // answered, and used to wait out its own 30 s timeout instead. A
    // settings poll sent as Wi-Fi's Apply took the device off the network
    // held the panel's polling that long, since the panel waits for its
    // outstanding poll before sending another: the page had reconnected, and
    // still showed the device busy for 14 s more (2026-10-10). Ended here,
    // the caller hears at once and its next request goes out on the new
    // channel.
    failAll(message) {
        for (const [, req] of this.pending) {
            clearTimeout(req.timeout);
            try { req.responsePort.postMessage({ type: 'proxy_error', message }); } catch (e) {}
            // An upload says so on its own channel as well, as failUpload does.
            if (req.isUpload) this.progress.postMessage({ type: 'uploadFailed' });
        }
        this.pending.clear();
    }
}

// The device page's WebSockets, each a stream on the data channel. ws-shim.js
// in the page posts ws_open, ws_send and ws_close (its vocabulary is listed at
// the top of that file); this sends them on, and answers with ws_assign,
// ws_opened, ws_message and ws_closed.
//
// Two kinds of stream:
//   websocket  a proxied app's WebSocket. Each message carries a type byte
//              (0 text, 1 binary) and is split at SWSP_CHUNK_SIZE, with
//              FLAG_MORE on every piece but the last; the FIN carries the
//              close code and reason.
//   bitbang    the magic path, /__bitbang/<type>?<params>: a stream of the
//              named type, raw bytes both ways. Each cap's page does its own
//              framing (tag bytes, JSON FIN payloads), so a new cap needs a
//              device handler and a page, and nothing here.
//
// hooks: targetPrefix(), as ProxyRequests'.
const MAGIC_PREFIX = '/__bitbang/';

class SocketBridge {
    constructor(swsp, hooks, debug) {
        this.swsp = swsp;
        this.hooks = hooks;
        this.debug = debug;
        // streamId -> { page, kind, sendChain (SwspChannel.queueOnStream),
        // rx (a websocket message's pieces so far) }
        this.streams = new Map();
    }

    has(streamId) { return this.streams.has(streamId); }

    // To the page, which is this origin's: a frame that has navigated
    // somewhere else doesn't get a socket's traffic.
    static post(page, msg) { page.postMessage(msg, location.origin); }

    // A message from ws-shim.js in the content frame (`page`, its window).
    onPageMessage(msg, page) {
        if (!msg || !msg.type?.startsWith('ws_')) return;
        if (msg.type === 'ws_open') this.open(msg, page);
        else if (!this.swsp.open) return;
        else if (msg.type === 'ws_send') this.send(msg);
        else if (msg.type === 'ws_close') this.close(msg);
    }

    open(msg, page) {
        const streamId = this.swsp.newStreamId();
        // The shim matches a socket still waiting by openId, and everything
        // after by streamId, so the id goes back first, whatever follows.
        const assign = () => SocketBridge.post(page, { type: 'ws_assign', openId: msg.openId, streamId });
        const refuse = (code, reason) => {
            assign();
            SocketBridge.post(page, { type: 'ws_closed', streamId, code, reason });
        };

        // No transport, so an open fails rather than being dropped. Dropped,
        // the socket waited in CONNECTING for an answer that never came, and
        // a page retrying across a reconnect -- the console panel -- retried
        // once and then hung.
        if (!this.swsp.open) return refuse(1006, '');

        if (this.debug) console.log(`[Connection] ws_open ${msg.pathname}, streamId=${streamId}, cookies.len=${(msg.cookies || '').length}`);
        let kind, syn;
        if (msg.pathname && msg.pathname.startsWith(MAGIC_PREFIX)) {
            kind = 'bitbang';
            syn = SocketBridge.magicSyn(msg.pathname);
            if (!syn) return refuse(1008, 'bitbang: empty type in magic path');
        } else {
            kind = 'websocket';
            syn = {
                type: 'websocket',
                // The device's path: a proxied app's target goes back on, as
                // for HTTP (ProxyRequests.start).
                pathname: this.hooks.targetPrefix() + msg.pathname,
                cookies: msg.cookies || '',
            };
        }
        this.streams.set(streamId, { page, kind });
        assign();
        this.swsp.openCredit(streamId);
        this.swsp.send(streamId, FLAG_SYN, JSON.stringify(syn));
        if (kind === 'bitbang') {
            // Open now. Listener handlers typically don't send a SYN ack on
            // the success path -- the first DAT is the natural signal that
            // things are working -- so the page can start sending at once.
            SocketBridge.post(page, { type: 'ws_opened', streamId });
        } else if (this.debug) {
            console.log(`[Connection] ws SYN sent to device, streamId=${streamId}`);
        }
    }

    // The SYN for a magic path, or null if it names no type. The type is the
    // first segment after /__bitbang/; each query value is JSON-parsed where
    // possible ("true" a bool, "80" a number, '["bash"]' an array) and kept
    // as a string otherwise, so the listener unmarshals a typed object.
    static magicSyn(pathname) {
        const u = new URL(pathname, 'http://device');
        const type = u.pathname.substring(MAGIC_PREFIX.length).split('/')[0];
        if (!type) return null;
        const syn = { type };
        for (const [k, v] of u.searchParams) {
            try { syn[k] = JSON.parse(v); }
            catch (e) { syn[k] = v; }
        }
        return syn;
    }

    send(msg) {
        const s = this.streams.get(msg.streamId);
        if (!s) return;
        const bytes = msg.isText ? new TextEncoder().encode(msg.data) : new Uint8Array(msg.data);

        if (s.kind === 'bitbang') {
            // Raw bytes through unchanged, text UTF-8 encoded; the page keeps
            // whatever framing its cap expects.
            this.swsp.queueOnStream(s, msg.streamId, [[FLAG_DAT, bytes]]);
            return;
        }

        // [1 byte type: 0 text, 1 binary][message], in pieces of at most
        // SWSP_CHUNK_SIZE (the data-channel message limit). Every piece but
        // the last carries FLAG_MORE, so the device reassembles one message;
        // the type byte rides in the first.
        const payload = new Uint8Array(1 + bytes.length);
        payload[0] = msg.isText ? 0 : 1;
        payload.set(bytes, 1);
        const frames = [];
        for (let off = 0; off < payload.length; off += SWSP_CHUNK_SIZE) {
            const end = off + SWSP_CHUNK_SIZE;
            const flags = end >= payload.length ? FLAG_DAT : (FLAG_DAT | FLAG_MORE);
            frames.push([flags, payload.subarray(off, Math.min(end, payload.length))]);
        }
        this.swsp.queueOnStream(s, msg.streamId, frames);
    }

    close(msg) {
        const s = this.streams.get(msg.streamId);
        if (!s) return;
        this.streams.delete(msg.streamId);
        // Behind whatever the page sent before closing, then the stream's
        // credit is done with.
        const streamId = msg.streamId;
        this.swsp.queueOnStream(s, streamId, [[FLAG_FIN, new Uint8Array(0)]])
            .then(() => this.swsp.dropCredit(streamId));
        // The stream is forgotten, so whatever the device answers is
        // dropped. The app's close event comes from here, carrying the code
        // it asked to close with; without it the socket sat in CLOSING and
        // onclose never ran.
        SocketBridge.post(s.page, {
            type: 'ws_closed', streamId,
            code: msg.code || 1000, reason: msg.reason || '',
        });
    }

    // A frame on one of the sockets' streams. A WebSocket's reader cannot be
    // slowed, so handing a frame on is consuming it; a piece counts as it
    // joins reassembly, or a message larger than the window could never
    // complete.
    onFrame(frame) {
        const s = this.streams.get(frame.streamId);
        if (!s) return;
        this.swsp.onArrived(frame, true);
        if (frame.flags & FLAG_FIN) this.swsp.dropCredit(frame.streamId);
        if (s.kind === 'bitbang') this.onBitbangFrame(frame, s);
        else this.onWebSocketFrame(frame, s);
    }

    onWebSocketFrame(frame, s) {
        const streamId = frame.streamId;
        if (frame.flags & FLAG_SYN) {
            // Device acknowledged the WebSocket open
            if (this.debug) console.log(`[Connection] ws SYN ack from device, streamId=${streamId}`);
            SocketBridge.post(s.page, { type: 'ws_opened', streamId });
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
            if (this.debug) console.log(`[Connection] ws FIN from device, streamId=${streamId} code=${code} reason=${JSON.stringify(reason)}`);
            this.streams.delete(streamId);
            SocketBridge.post(s.page, { type: 'ws_closed', streamId, code, reason });
            return;
        }

        if (frame.payload.byteLength === 0 || (frame.flags & FLAG_SYN)) return;
        // A piece of a message; FLAG_MORE on all but the last. Buffered
        // until the last, then delivered whole, keeping the WS message
        // boundary.
        const part = new Uint8Array(frame.payload);
        if (frame.flags & FLAG_MORE) {
            (s.rx || (s.rx = [])).push(part);
            return;
        }
        let full = part;
        if (s.rx) {
            s.rx.push(part);
            full = new Uint8Array(s.rx.reduce((n, a) => n + a.byteLength, 0));
            let o = 0;
            for (const a of s.rx) { full.set(a, o); o += a.byteLength; }
            s.rx = null;
        }
        const messageBytes = full.slice(1);
        const data = full[0] === 0 ? new TextDecoder().decode(messageBytes) : messageBytes.buffer;
        SocketBridge.post(s.page, { type: 'ws_message', streamId, data });
    }

    // No interpretation at all: the page's code handles tag bytes, JSON FIN
    // payloads and status decoding.
    onBitbangFrame(frame, s) {
        const streamId = frame.streamId;
        const text = () => (frame.payload && frame.payload.byteLength > 0)
            ? new TextDecoder().decode(frame.payload) : '';

        if (frame.flags & FLAG_SYN) {
            // A mid-stream SYN is the listener's way to deliver an
            // early-error payload (or other one-shot metadata), as a text
            // message; most caps decode it and look for `error`.
            SocketBridge.post(s.page, { type: 'ws_message', streamId, data: text() });
            return;
        }

        if (frame.flags & FLAG_FIN) {
            // The FIN payload, if any, is the close event's reason, parsed
            // however the cap requires (shell: {exit_code, signal}; file
            // ops: {status, error}).
            this.streams.delete(streamId);
            SocketBridge.post(s.page, { type: 'ws_closed', streamId, code: 1000, reason: text() });
            return;
        }

        // DAT: the bytes, as a binary message.
        if (!frame.payload || frame.payload.byteLength === 0) return;
        const view = new Uint8Array(frame.payload);
        const data = view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
        SocketBridge.post(s.page, { type: 'ws_message', streamId, data });
    }

    // The device reset one socket's stream.
    onReset(streamId, why) {
        const s = this.streams.get(streamId);
        if (!s) return;
        this.streams.delete(streamId);
        SocketBridge.post(s.page, { type: 'ws_closed', streamId, code: 1011, reason: why });
    }

    // Every socket was on a data channel that has gone, and none of them will
    // be carried over: a new peer connection is a new set of streams on the
    // device too. Closed here, as a device FIN would, so each socket's close
    // handler runs and the page can open it again. Left alone, a socket
    // stayed OPEN with nothing ever arriving on it -- the console panel sat at
    // "connected" and silent after a soft reconnect, and only a reload
    // brought it back (2026-10-01).
    closeAll() {
        for (const [streamId, s] of this.streams) {
            SocketBridge.post(s.page, { type: 'ws_closed', streamId, code: 1006, reason: '' });
        }
        this.streams.clear();
    }
}

class BitBangConnection {
    constructor({ uid, target, devicePath, deviceSearch, deviceHash }) {
        this.uid = uid;
        // The content frame's path. For a proxied app (routing
        // "target-prefix") it never carries the target: this origin belongs
        // to one target, which ProxyRequests.start puts back on every request
        // and reportLocation on every address the top page shows.
        this.devicePath = devicePath || '/';
        this.target = target || '';
        this.deviceSearch = deviceSearch || '';
        this.deviceHash = deviceHash || '';
        // Streams this page has asked the device for. Cleared when the data
        // channel opens, since the device knows nothing of a previous one.
        this.subscribedStreams = new Set();
        this.pc = null;
        this.swsp = new SwspChannel();   // the data channel, framed
        this.ws = null;
        this.streamNameMap = {};      // from offer: { "0": "webcam", ... }
        this.resolvedStreams = {};    // name -> MediaStream
        this.connectResolve = null;   // resolved when device sends 'ready'
        this.benchStreams = new Map(); // streamId -> stats, for the transport benchmark
        this.sessionId = Array.from(crypto.getRandomValues(new Uint8Array(4)), b => b.toString(16).padStart(2, '0')).join(''); // 8 hex chars
        console.log('[Connection] ctor', this.sessionId);
        this.candidateQueue = new CandidateQueue();
        this.remoteDescriptionSet = false;
        this.answerSent = false;          // local candidates wait for it
        // Frames arriving on a stream channel, forwarded to whatever page the
        // device served. The page owns the canvas; this only carries bytes.
        //
        // A MessagePort rather than a BroadcastChannel, because postMessage
        // takes a transfer list and BroadcastChannel does not: a frame is
        // handed over rather than structured-cloned on its way to the page.
        // Created in wireStreams, where there is finally a page to hand it to.
        this.streamPort = null;
        // The same frames on a BroadcastChannel, for debug sessions only --
        // it is what audio-harness.html taps to run against a real device.
        // Opened on first use because debug is not parsed until below, and it
        // costs a copy of every frame, so it stays shut otherwise.
        this.videoFrameChannel = null;
        // Stream channels by "presentation/component": cam/video, cam/audio.
        // One entry per component, each with its own reassembly state, because
        // each numbers its frames independently. See attachStreamChannel.
        this.streams = new Map();

        this.statusEl = document.getElementById('status');
        this.connectionUI = document.getElementById('connection-ui');
        {
            const _flags = parseUrlFlags();
            this.debug = !!_flags.debug;
            this.noCookieJar = !!_flags.nocookiejar;
        }
        this._turnHoldPromise = null;
        this._wasConnected = false;
        // The relay verdict and its credential's expiry, and the path
        // telemetry. Both act on this only through the hooks given here.
        // The worker's HTTP requests and the device page's WebSockets, each
        // a stream on this.swsp.
        this.requests = new ProxyRequests(this.swsp, {
            targetPrefix: () => this.targetPrefix(),
            channelDead: () => { if (this._wasConnected) this.reconnector.start(); },
        }, this.debug);
        this.sockets = new SocketBridge(this.swsp, {
            targetPrefix: () => this.targetPrefix(),
        }, this.debug);
        this.relay = new RelayMonitor({
            pc: () => this.pc,
            ended: () => this._sessionEnded,
            reconnecting: () => this.reconnector.active,
            renew: () => {
                console.log('[Connection] renewing the relay credential before it expires');
                this.reconnector.renew();
            },
            end: (text) => this.showReloadScreen(text),
        }, this.debug);
        this.path = new PathReporter({
            pc: () => this.pc,
            send: (msg) => this._sendSignaling(msg),
        }, this.debug);
        this._turnUnavailable = false;
        // The session has ended for good: relay expiry, the device ending it,
        // or the reconnect window closing. Nothing retries after this.
        this._sessionEnded = false;
        this._transportReady = false;   // one-time setup (SW reg, iframe) done
        this.reconnector = new Reconnector({
            ended: () => this._sessionEnded,
            begin: () => {
                this.relay.clearEndTimers();
                this._clearReassureTimer();
                this._showReconnecting();
            },
            attempt: () => {
                this._teardownTransport();
                return this.connectWebSocket();
            },
            finish: () => this._hideReconnecting(),
            giveUp: () => this.showReloadScreen(this.relay.usingRelay
                ? 'Connection lost — relay may have expired.'
                : 'Connection lost. Reload to continue.'),
        });

        // What the server has told us about the device, as opposed to what
        // our own transport has worked out. The two are independent: a device
        // can leave the server with the peer connection still up, and the peer
        // connection can fail with the device still registered. Keeping them
        // apart is what lets a page say which one happened.
        // Which run of the device's firmware we have been talking to, or null
        // before we have been told. In memory on purpose: a reloaded page
        // learns the current identity fresh, so a reload loop is impossible
        // rather than guarded against.
        this._deviceBoot = null;

        // Keeping the signaling socket up after the session is established.
        // See _keepSignaling.
        this._signalBackoff = SIGNAL_REDIAL_MIN_MS;
        this._signalTimer = null;
    }

    // A channel carrying frames rather than SWSP. Each message is one chunk of
    // one frame; see VIDEO_CHUNK_HEADER on the device for why frames are split.
    //
    // One of these per component, and the reassembly state belongs to the
    // component rather than to the connection: a presentation is cam/video plus
    // cam/audio, each numbering its own frames from zero. Held in one set of
    // fields, the second channel to open would reset the first one's frame map
    // and newest id, and the two streams' frame ids would collide in it --
    // video would break the moment a device declared audio, before a sample was
    // sent. See av-streaming-api.md.
    attachStreamChannel(ch) {
        // cam/video -> presentation "cam", component "video".
        const slash = ch.label.indexOf('/');
        const presentation = slash > 0 ? ch.label.slice(0, slash) : ch.label;
        const component = slash > 0 ? ch.label.slice(slash + 1) : 'video';
        // bitbang-stream/ulaw, or bitbang-stream/ulaw;rate=8000. The parameter
        // is optional and nothing sends one yet; a renderer that needs a rate
        // supplies its own default. Parsed here so declaring one later is a
        // firmware change rather than a change on both sides.
        const proto = ch.protocol && ch.protocol.startsWith(STREAM_PROTOCOL_PREFIX)
            ? ch.protocol.slice(STREAM_PROTOCOL_PREFIX.length)
            : 'mjpeg';
        const semi = proto.indexOf(';');
        const codec = semi > 0 ? proto.slice(0, semi) : proto;
        const rateMatch = /;\s*rate=(\d+)/.exec(proto);
        const rate = rateMatch ? parseInt(rateMatch[1], 10) : undefined;
        const key = `${presentation}/${component}`;
        console.log(`[Connection] stream channel open: ${key}, codec ${codec}`);

        ch.binaryType = 'arraybuffer';
        const s = {
            presentation, component, codec, rate, ch,
            frames: new Map(),   // frame id -> partial frame
            newest: -1,          // newest frame id already forwarded
            stats: { drawn: 0, dropped: 0, since: performance.now() },
        };
        this.streams.set(key, s);
        // The page cannot bind an element to a component it has not heard of,
        // and it cannot hear of one any other way: nothing arrives on the
        // channel until something subscribes, and subscribing is what binding
        // decides. So the list is pushed, not polled.
        this.announceStreams();

        ch.onmessage = (e) => {
            if (this.benchVideo) {
                this.countBenchMessage(e.data);
                return;
            }
            this.handleStreamChunk(s, e.data);
        };
        ch.onclose = () => {
            console.log(`[Connection] stream channel closed: ${key}`);
            // Only if this is still the channel under that key. A reconnect can
            // attach a new one before the old one's close fires, and deleting
            // unconditionally would drop the live stream.
            if (this.streams.get(key) === s) this.streams.delete(key);
            this.announceStreams();
        };
    }

    // What the device is offering, for the page's shim to bind elements to.
    // Codec and rate ride along because a renderer has to be chosen before the
    // first frame arrives, and neither the label nor the payload can say which
    // one -- the label names the stream, not its type.
    announceStreams() {
        if (!this.streamPort) return;
        this.streamPort.postMessage({
            type: 'streams',
            streams: [...this.streams.values()].map(s => ({
                key: `${s.presentation}/${s.component}`,
                presentation: s.presentation,
                component: s.component,
                codec: s.codec,
                rate: s.rate,
            })),
        });
    }

    // The stream a caller means when it does not say. Bench and teardown want
    // "the video channel" from when there could only be one.
    firstStream() {
        for (const s of this.streams.values()) {
            if (s.component === 'video') return s;
        }
        return this.streams.values().next().value;
    }

    // Reassemble one frame from its chunks.
    //
    // The channel is unordered and lifetime-limited, so chunks arrive in any
    // order, chunks of different frames interleave, and some never arrive at
    // all. A frame is drawn only once every chunk is in hand; one that is still
    // short when newer frames are completing is missing a chunk that is not
    // coming, and waiting for it would only add latency to everything behind
    // it.
    handleStreamChunk(s, buf) {
        if (buf.byteLength < VIDEO_CHUNK_HEADER) return;
        const dv = new DataView(buf);
        const frameId = dv.getUint32(0, true);
        const index = dv.getUint16(4, true);
        const count = dv.getUint16(6, true);
        const flags = dv.getUint16(8, true);
        const ptsMs = dv.getUint32(12, true);
        if (count === 0 || index >= count) return;

        // A device that restarts begins numbering at zero again.
        if (frameId + 1000 < s.newest) {
            s.frames.clear();
            s.newest = -1;
        }
        // Already drawn, or older than what has been drawn.
        if (frameId <= s.newest) return;

        let f = s.frames.get(frameId);
        if (f === undefined) {
            f = { count, got: 0, bytes: 0, parts: new Array(count),
                  ptsMs, keyframe: (flags & VIDEO_FLAG_KEYFRAME) !== 0 };
            s.frames.set(frameId, f);
            if (s.frames.size > VIDEO_FRAME_SLOTS) {
                let oldest = Infinity;
                for (const id of s.frames.keys()) {
                    if (id < oldest) oldest = id;
                }
                s.frames.delete(oldest);
                s.stats.dropped++;
                // The chunk that just arrived belongs to the frame that was
                // evicted: it is behind everything else in flight.
                if (oldest === frameId) return;
            }
        }
        if (f.parts[index] !== undefined) return;   // duplicate

        const part = new Uint8Array(buf, VIDEO_CHUNK_HEADER);
        f.parts[index] = part;
        f.bytes += part.byteLength;
        if (++f.got !== f.count) return;

        const frame = new Uint8Array(f.bytes);
        let off = 0;
        for (const p of f.parts) {
            frame.set(p, off);
            off += p.byteLength;
        }
        s.frames.delete(frameId);
        s.newest = frameId;
        // Anything still pending is older than what is about to be drawn.
        for (const id of [...s.frames.keys()]) {
            if (id < frameId) {
                s.frames.delete(id);
                s.stats.dropped++;
            }
        }

        if (f.bytes === 0) return;   // nothing to draw

        s.stats.drawn++;
        const secs = (performance.now() - s.stats.since) / 1000;
        if (secs >= 5) {
            const st = s.stats;
            // Debug only: this is the counter that says whether reassembly is
            // keeping up, which matters while something is wrong and is noise
            // the rest of the time.
            if (this.debug) {
                console.log(`[${s.presentation}/${s.component}] ` +
                            `${(st.drawn / secs).toFixed(1)} fps, ` +
                            `${st.drawn} drawn, ${st.dropped} incomplete`);
            }
            st.drawn = 0; st.dropped = 0; st.since = performance.now();
        }

        // The renderer lives in the page, so this hands over bytes and stops.
        // Nothing here knows what a JPEG is, and nothing on the other side
        // knows what a chunk is.
        //
        // pts is relative to the device's boot, so it is only meaningful
        // against other frames from the same device. The consumer takes the
        // first one it sees as the origin -- which also means a device restart
        // is just a new origin rather than a discontinuity to handle.
        //
        // A tap for the harness, which is a page of its own and not the one the
        // device served, so it cannot be on the other end of the port. Costs a
        // copy of every frame, which is why it only runs under debug.
        //
        // Taken before the transfer below, not after: transferring detaches
        // the buffer, and reading a detached one gives zero bytes rather than
        // an error. A harness quietly receiving empty frames is a worse
        // failure than the copy is a cost.
        if (this.debug) {
            if (!this.videoFrameChannel) {
                this.videoFrameChannel = new BroadcastChannel('bitbang-video');
            }
            this.videoFrameChannel.postMessage(
                { type: 'frame', data: frame.slice().buffer,
                  ptsMs: f.ptsMs, keyframe: f.keyframe,
                  stream: s.presentation, component: s.component, codec: s.codec });
        }

        // Transferred, not copied: ownership moves and the bytes do not. This
        // has to be the last use of the buffer here, which it is.
        if (this.streamPort) {
            this.streamPort.postMessage(
                { type: 'frame', key: `${s.presentation}/${s.component}`,
                  data: frame.buffer, ptsMs: f.ptsMs, keyframe: f.keyframe },
                [frame.buffer]);
        }
    }

    // Benchmark accounting for messages arriving on the video channel. The
    // run is still started and finished over SWSP, so only the payload moved.
    countBenchMessage(buf) {
        const st = this.benchVideo;
        const len = buf.byteLength;
        if (len < 4) return;
        const p = new Uint8Array(buf);
        const seq = (p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24)) >>> 0;

        st.seen++;
        if (seq > st.maxSeq) st.maxSeq = seq;
        if (seq < st.lastSeq) st.reordered++;
        st.lastSeq = seq;

        let b = st.bySize.get(len);
        if (!b) {
            b = { bytes: 0, count: 0, first: performance.now(), last: 0, minSeq: seq, maxSeq: seq };
            st.bySize.set(len, b);
        }
        b.bytes += len;
        b.count++;
        b.last = performance.now();
        if (seq < b.minSeq) b.minSeq = seq;
        if (seq > b.maxSeq) b.maxSeq = seq;
    }

    // -- Transport benchmark --
    //
    // Run from the console: __bitbangConnection.startBench(). The device sweeps
    // message sizes and sends flat out; we count what arrives.
    //
    // Both halves are needed. The device reports what it offered to the
    // transport, which on an unreliable channel is not what gets delivered --
    // the difference is the number the ordered/unordered comparison is about.
    startBench() {
        if (!this.swsp.open) {
            console.error('[bench] data channel is not open');
            return;
        }
        if (!this.firstStream()) {
            console.error('[bench] the video channel is not open');
            return;
        }
        const streamId = this.swsp.newStreamId();
        // Started and finished over SWSP, counted on the video channel.
        this.benchVideo = {
            bySize: new Map(),   // payload length -> bucket
            maxSeq: -1,
            lastSeq: -1,
            reordered: 0,
            seen: 0,
        };
        this.benchStreams.set(streamId, this.benchVideo);
        this.swsp.openCredit(streamId);
        this.swsp.send(streamId, FLAG_SYN, JSON.stringify({ bench: true }));
        console.log(`[bench] run started on stream ${streamId}`);
        this.pollIceDuringBench(streamId);
    }

    // Whether the peer's connectivity checks are actually leaving this browser.
    //
    // The device sees roughly one check in four go missing while a transfer is
    // running. From its end there is no way to tell a check that was never sent
    // from one lost on the air. Chrome knows: requestsSent counts what it put
    // on the wire, responsesReceived what came back.
    pollIceDuringBench(streamId) {
        let prev = null;
        const tick = async () => {
            if (!this.benchStreams.has(streamId)) return;   // run finished
            try {
                const stats = await this.pc.getStats();
                const now = { req: 0, res: 0, consent: 0, recv: 0,
                              tbytes: 0, dcmsgs: 0, dcbytes: 0, pairs: 0 };
                for (const [, r] of stats) {
                    if (r.type === 'candidate-pair' && r.nominated) {
                        now.pairs++;
                        now.req += r.requestsSent || 0;
                        now.res += r.responsesReceived || 0;
                        now.consent += r.consentRequestsSent || 0;
                        now.recv += r.packetsReceived || 0;
                    } else if (r.type === 'transport') {
                        // Counted below DTLS, so it moves even when the
                        // candidate-pair counter does not.
                        now.tbytes += r.bytesReceived || 0;
                    } else if (r.type === 'data-channel' && r.label === 'video') {
                        // What Chrome actually handed up as complete messages.
                        now.dcmsgs += r.messagesReceived || 0;
                        now.dcbytes += r.bytesReceived || 0;
                    }
                }
                if (prev) {
                    const kb = (n) => Math.round(n / 1024);
                    console.log(`[bench/ice] +${now.req - prev.req} requests sent, ` +
                                `+${now.res - prev.res} responses back, ` +
                                `+${now.consent - prev.consent} consent, ` +
                                `+${now.recv - prev.recv} packets in ` +
                                `(${now.pairs} pair) | transport +${kb(now.tbytes - prev.tbytes)} KB ` +
                                `| video dc +${now.dcmsgs - prev.dcmsgs} msgs ` +
                                `+${kb(now.dcbytes - prev.dcbytes)} KB`);
                }
                prev = now;
            } catch (e) { /* getStats can throw during teardown */ }
            setTimeout(tick, 5000);
        };
        setTimeout(tick, 5000);
    }

    handleBenchFrame(frame, st) {
        if (frame.flags & FLAG_FIN) {
            this.benchVideo = null;
            // The device names its own configuration in the closing frame, so
            // a printed result always says what produced it.
            let mode = null;
            if (frame.payload.byteLength > 0) {
                try { mode = JSON.parse(new TextDecoder().decode(frame.payload)); } catch (e) { /* older device */ }
            }
            this.reportBench(frame.streamId, st, mode);
            this.benchStreams.delete(frame.streamId);
            return;
        }

        const len = frame.payload.byteLength;
        if (len < 4) return;
        const p = new Uint8Array(frame.payload);
        const seq = (p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24)) >>> 0;

        st.seen++;
        if (seq > st.maxSeq) st.maxSeq = seq;
        // Arriving behind the previous frame is expected on an unordered
        // channel and should never happen on an ordered one.
        if (seq < st.lastSeq) st.reordered++;
        st.lastSeq = seq;

        let b = st.bySize.get(len);
        if (!b) {
            b = { bytes: 0, count: 0, first: performance.now(), last: 0, minSeq: seq, maxSeq: seq };
            st.bySize.set(len, b);
        }
        b.bytes += len;
        b.count++;
        b.last = performance.now();
        if (seq < b.minSeq) b.minSeq = seq;
        if (seq > b.maxSeq) b.maxSeq = seq;
    }

    reportBench(streamId, st, mode) {
        const how = mode
            ? `${mode.ordered ? 'ordered' : 'unordered'}, ` +
              (mode.lifetime_ms ? `lifetime ${mode.lifetime_ms}ms` : 'reliable')
            : 'mode not reported';
        console.log(`[bench] stream ${streamId} complete -- ${how}`);
        for (const [size, b] of [...st.bySize.entries()].sort((a, c) => a[0] - c[0])) {
            const secs = (b.last - b.first) / 1000;
            const rate = secs > 0 ? (b.bytes / 1024 / secs) : 0;
            // The device numbers each message, so the span between the first
            // and last sequence seen at this size says how many it sent, and
            // the shortfall is what did not arrive.
            const sent = b.maxSeq - b.minSeq + 1;
            const lost = sent - b.count;
            const lossPct = sent > 0 ? (100 * lost / sent) : 0;
            console.log(
                `[bench] ${String(size).padStart(6)} B  ` +
                `${String(b.count).padStart(5)} msgs  ` +
                `${rate.toFixed(0).padStart(6)} KB/s  ` +
                `lost ${lost} (${lossPct.toFixed(1)}%)`);
        }
        console.log(`[bench] totals: ${st.seen} received, ${st.maxSeq + 1} sent, ` +
                    `${st.maxSeq + 1 - st.seen} lost, ${st.reordered} out of order`);
    }

    // Append one line to the connection log — a plain append-only terminal:
    // one element, one font. Never replaces or clears a message.
    _print(msg) {
        setTopTitle(msg);
        if (!this.statusEl) return;
        const line = document.createElement('div');
        line.textContent = msg;
        this.statusEl.appendChild(line);
    }

    // Same, but only with !debug — the extra play-by-play detail.
    _printDebug(msg) {
        if (this.debug) this._print(msg);
    }

    // Same, marked as an error, with the status area made visible. Was
    // showErrorScreen, beside showReloadScreen -- which does replace the page.
    // This only writes a line.
    _printError(msg) {
        if (this.connectionUI) {
            this._print(msg);
            if (this.statusEl) this.statusEl.classList.add('error');
            this.connectionUI.style.display = '';
        }
    }


    async connect() {
        try {
            await this.registerServiceWorker();
            this._printDebug(STATUS.CONNECTING);
            await this.connectWebSocket();
        } catch (error) {
            console.error('Connection failed:', error);
            this._print(this.userErrorMessage(error.code || error.message));
            if (this.statusEl) this.statusEl.classList.add('error');
        }
    }

    // The wording for a failure, by its code: a server error's `code`, a
    // device's refusal, or one of the failures this file raises itself. The
    // wording is ours; an unrecognized code gets the generic one, so nothing
    // outside this file decides what goes on the screen.
    userErrorMessage(code) {
        switch (code) {
            case 'device_not_found': return 'Device not found';
            case 'WebSocket connection failed': return 'Could not reach server';
            case 'Service Worker not supported': return 'This browser is not supported';
            case 'offer_timeout': return 'Device not responding';
            // The device answered and refused: every session slot is taken.
            // Worth its own wording because it is the one failure here the
            // person can actually do something about, and because it used to
            // arrive as "Device not responding" after a 30 second wait.
            case 'device_busy': return 'Device is busy: too many viewers connected';
            default: return 'Connection failed';
        }
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

        // The label worker: this origin's, serving this one device. Its
        // script is the one thing in this origin page script cannot alter --
        // the browser fetches it from the network, and only our server serves
        // it here (label.go).
        const reg = await navigator.serviceWorker.register('/__bitbang__/label-sw.js', {
            scope: '/',
            updateViaCache: 'none',
        });
        // Force check for SW update on every page load.
        reg.update();

        // When a new SW takes over an existing controller, offer a reload if
        // the build stamps disagree. skipWaiting() in label-sw.js's install handler
        // is what makes the takeover happen without prompting, which is also
        // what creates the window this closes: the new worker claims the page
        // immediately, while the page itself may still be running the previous
        // deploy's connection.js.
        navigator.serviceWorker.addEventListener('controllerchange', () => {
            if (!hadController) return;             // first install, not an update
            // Only a page that is actually behind is asked. The common case
            // after a deploy is a fresh navigation that already has the new
            // connection.js and merely watched the worker turn over underneath
            // it -- nothing to say there.
            offerReloadIfStale(navigator.serviceWorker.controller);
        });

        // Covers the tab that was already open and never saw a
        // controllerchange, e.g. a deploy that reached the worker before
        // this listener was attached.
        offerReloadIfStale(reg.active || navigator.serviceWorker.controller);

        // The fallback. An open tab normally hears about a deploy from the
        // server, as a build_stamp on its signaling socket, which is kept up
        // and redialed when the server restarts; the server sends the stamp on
        // every connect and again whenever it moves. This covers what that
        // misses -- a tab that couldn't get a socket back, or a server too old
        // to send one. A fetch of label-sw.js per half hour.
        setInterval(() => reg.update().catch(() => {}), 30 * 60 * 1000);

        // Handle proxy requests from the worker. The vocabulary of this
        // channel is listed beside the worker's own message listener in
        // label-sw.js. The worker finds this frame among its clients; nothing
        // has to be registered with it. It asks whether this frame is
        // connected before choosing it (connection_state), so a frame that is
        // reconnecting or waiting on a PIN is passed over when another tab's
        // is up.
        navigator.serviceWorker.addEventListener('message', (event) => {
            if (event.data?.type === 'proxy_request') {
                this.requests.start(event.data, event.ports[0]);
            } else if (event.data?.type === 'connection_state' && event.ports[0]) {
                event.ports[0].postMessage({
                    type: 'connection_state',
                    connected: !!(this.swsp.open && this.deviceVerified && this._transportReady),
                });
            }
        });

        window.addEventListener('pagehide', (event) => {
            // Tell the device we are going, by closing rather than just
            // walking away.
            //
            // Without this the device only learns the browser is gone when ICE
            // consent stops being answered, which takes about 24 seconds. A
            // refresh brings the new session up well inside that window, so the
            // device is holding two: the cap is two, its thread stacks have to
            // come out of internal RAM, and the new connection can fail to get
            // one while the dead session still holds its own. The result is a
            // page that connects to nothing for half a minute.
            //
            // Not on a bfcache hide -- there the page can still come back, and
            // closing would strand it. A page holding an open RTCPeerConnection
            // is usually not eligible anyway, so this is close to always taken.
            if (event.persisted) return;
            this.swsp.close();
            for (const s of this.streams.values()) {
                try { s.ch.close(); } catch (e) { /* already gone */ }
            }
            try { if (this.pc) this.pc.close(); } catch (e) { /* already gone */ }
        });

        await navigator.serviceWorker.ready;
    }

    // The device ended one stream -- its target went away, or this side
    // broke the stream's rules. Everything else on the session continues.
    onStreamReset(msg) {
        const streamId = msg.stream_id;
        const why = msg.message || msg.code || 'stream reset by device';
        console.warn(`[Connection] stream ${streamId} reset by device: ${why}`);
        this.swsp.dropCredit(streamId);
        this.requests.onReset(streamId, why);
        this.sockets.onReset(streamId, why);
        this.benchStreams.delete(streamId);
    }

    // The signaling socket's URL, for the session and for the control socket
    // alike. Signaling is bitba.ng's, not this origin's: a label host serves
    // nothing but its own files (label.go) and answers anything else with the
    // start page, so a socket opened here never opens.
    signalingURL() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        return `${proto}//${new URL(TOP_ORIGIN).host}/ws/client/${this.uid}`;
    }

    connectWebSocket() {
        return new Promise((resolve, reject) => {
            const ws = new WebSocket(this.signalingURL());
            this.ws = ws;

            const offerTimeout = setTimeout(() => {
                reject(new Error('offer_timeout'));
            }, 15000);

            // Bidirectional-verify state. verifyNonceHash is set in
            // handleOffer; deviceVerified flips true when the device's first
            // stream-0 frame proves it decrypted the nonce.
            this.verifyNonceHash = null;
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
                        console.warn('[Connection] unexpected second offer on an established PC — ignoring');
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
                } else if (msg.type === 'device_up') {
                    this._onDeviceBoot(msg.boot);
                } else if (msg.type === 'build_stamp') {
                    this._onBuildStamp(msg.build);
                } else if (msg.type === 'error') {
                    clearTimeout(offerTimeout);
                    // reject() is a no-op once the connect promise has
                    // resolved, but harmless then. The code rides along for
                    // userErrorMessage; a device refusing (device_busy) sends
                    // a message only.
                    const err = new Error(msg.message);
                    err.code = msg.code || msg.message;
                    reject(err);
                }
            };

            this.ws.onerror = () => {
                clearTimeout(offerTimeout);
                reject(new Error('WebSocket connection failed'));
            };

            this.ws.onclose = () => {
                // A clean close (e.g. the signaling server restarting) fires
                // no 'error' event -- without this, a setup in progress would
                // ride out its full timeout instead of failing fast. Once
                // setup has resolved, reject is a no-op.
                clearTimeout(offerTimeout);
                if (this.debug) console.log('[Connection] signaling WS closed');
                reject(new Error('WebSocket closed'));

                // After setup this socket used to be let go, on the grounds
                // that the session runs peer to peer and nothing needs it. Two
                // things do now: it is where a new build is announced, and
                // where a returning device is. And the usual reason it closes
                // is the server restarting for a deploy -- the moment the page
                // most needs to hear from it.
                //
                // Only if this is still the current socket. Our own teardown
                // clears this.ws before its close lands, and a reconnect
                // replaces it; either way that close is not news.
                if (ws === this.ws) {
                    this.ws = null;
                    this._keepSignaling();
                }
            };
        });
    }

    async handleOffer(msg) {
        // Bidirectional verify, part 1: the offer carries the device's
        // pubkey alongside the SDP. bitba.ng's page checks hash(pubkey) ===
        // uid before it proves anything (askProof) -- a rogue server can't
        // substitute a key for a UID it doesn't own without breaking that.
        if (!msg.device_pubkey) {
            throw new Error('offer missing device_pubkey — server too old or misbehaving');
        }

        // Checked before any WebRTC work: if the device restarted, this
        // session is about to be built on a page that cannot use it, and the
        // sooner that is settled the less there is to throw away.
        this._onDeviceBoot(msg.device_boot);
        if (this._sessionEnded) return;      // reloading; do not negotiate

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
        // A renewal is a reconnect the session did not need yet. Relay-only
        // with the relay full, this attempt cannot connect and neither can
        // the next few minutes of retries, so end now with the message the
        // expiry would have shown.
        if (this.reconnector.renewing && this._turnUnavailable) {
            const flags = parseUrlFlags();
            if (flags.relay && !flags.norelay) {
                console.warn('[Connection] relay full at renewal; ending session');
                this.showReloadScreen(RELAY_ENDED_TEXT);
                return;
            }
        }
        this.relay.setCredential(msg.ice_servers);
        this.iceServers = Array.isArray(msg.ice_servers) ? msg.ice_servers : [];
        this.pc = this.createPeerConnection(msg.ice_servers);

        if (this.debug) {
            const lines = (msg.sdp || '').split('\n').filter(l => l.startsWith('a=candidate:'));
            for (const line of lines) {
                const m = line.match(/typ (\S+)/);
                console.log(`[Connection] offer candidate: ${m ? m[1] : '?'} ${line.trim()}`);
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
        // The payload is made by bitba.ng's page, which holds the code. It
        // picks the nonce too, and hands down only its hash: the device's
        // first frame must match it (handleControlMessage). The challenge, if
        // the device sent one, makes the payload good for this connection
        // only (device-origins.md, "The device challenge").
        const proof = await askProof(msg.device_pubkey, localFingerprint, msg.challenge);
        this.verifyNonceHash = proof.nonce_hash;
        const encryptedRequest = proof.encrypted_request;
        // The socket may have gone while bitba.ng's page worked.
        if (!this.ws) throw new Error('WebSocket closed');

        this.ws.send(JSON.stringify({
            type: 'answer',
            uid: this.uid,
            sdp: this.pc.localDescription.sdp,
            encrypted_request: encryptedRequest,
        }));
        this.answerSent = true;

        // Flush buffered local candidates, now that they follow the answer.
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
        if (noRelay) console.log('[Connection] norelay: forcing host-only ICE');
        if (forceRelay) console.log('[Connection] relay: forcing relay-only ICE');
        const pc = new RTCPeerConnection(config);

        pc.onconnectionstatechange = () => {
            if (this.debug) console.log(`[Connection] connectionState -> ${pc.connectionState}`);
            if (pc.connectionState === 'connected') {
                // Connection is up — cancel the "negotiating" reassurance banner.
                this._clearReassureTimer();
                this._printDebug(STATUS.CONNECTED);
                if (this.debug) RelayMonitor.logPairChanges(pc);
                this.relay.watch(pc);
                if (!this._wasConnected) {
                    this._wasConnected = true;
                    this._onFirstConnected(pc);
                }
            } else if (pc.connectionState === 'failed') {
                this._clearReassureTimer();
                if (this._wasConnected) {
                    this.reconnector.start();
                } else if (this.reconnector.active) {
                    // A reconnect attempt's fresh PC failed before connecting.
                    // Let the reconnect loop's backoff drive the retry rather
                    // than surfacing a terminal error screen.
                    this.reconnector.fail(new Error('pc_failed'));
                } else {
                    this._printError('Peer connection failed');
                }
            }
        };

        // A new peer connection is a new establishment to report.
        this.path.reset();

        pc.oniceconnectionstatechange = () => {
            if (this.debug) console.log(`[Connection] iceConnectionState -> ${pc.iceConnectionState}`);
            this.path.onIceState(pc);

            if (this._wasConnected && this.relay.usingRelay
                && (pc.iceConnectionState === 'failed' || pc.iceConnectionState === 'disconnected')) {
                this.reconnector.start();
            }
        };

        pc.onicecandidate = (event) => {
            // Firefox ends gathering with a candidate whose string is empty,
            // as well as the null event. Nothing to trickle, and bitbang-python
            // (aiortc's candidate_from_sdp) fails on it, which costs the device
            // its signaling socket for a few seconds.
            if (event.candidate && event.candidate.candidate) {
                const cand = event.candidate.candidate;
                if (this.debug) {
                    // SDP candidate line: candidate:foundation comp proto prio addr port typ <type> ...
                    const m = cand.match(/typ (\S+)/);
                    console.log(`[Connection] local candidate: ${m ? m[1] : '?'} ${cand}`);
                }
                // Trickle every candidate immediately, relay included. The
                // direct-vs-relay bias lives on the device (it withholds
                // relay-pair nomination), so the connector no longer delays
                // its relay candidate. See bitbang/CONVENTIONS.md "Favoring
                // direct on slow & embedded devices".
                const msg = { type: 'candidate', uid: this.uid, candidate: event.candidate };
                // Not on a control socket (see _redialSignaling). A candidate
                // belongs to the session's client id, and a control socket has
                // a different one, so the device would get it for a client it
                // has never heard of. Queued instead, which for a session whose
                // own socket is gone means dropped at the next teardown -- the
                // only honest thing to do with it.
                //
                // And not before the answer. The answer waits on bitba.ng's
                // page for its proof, and a browser that gathers quickly
                // (Firefox) has candidates before that round trip is done.
                // Sent first, they reach a device that has no answer to put
                // them on; pion shrugs, aiortc fails the session.
                if (this.ws?.readyState === WebSocket.OPEN && !this.ws.bbControl
                        && this.answerSent) {
                    this.ws.send(JSON.stringify(msg));
                } else {
                    this.candidateQueue.pushLocal(msg);
                }
            } else if (this.debug) {
                console.log('[Connection] local candidate gathering complete');
            }
        };

        pc.ontrack = (event) => {
            const mid = event.transceiver.mid;
            const name = this.streamNameMap[mid] || mid || 'default';
            this.resolvedStreams[name] = event.streams[0];
        };

        pc.ondatachannel = (event) => {
            // Dispatch by label. A device may open more than one channel, and
            // attaching the SWSP parser to a channel carrying anything else
            // reads its payload as frame headers -- and attaching it to
            // this.swsp would send SWSP out on the wrong one.
            // Dispatch on the protocol. The label alone cannot classify a
            // channel -- "cam/video" names one stream among possibly several,
            // and says nothing about how to decode it.
            const proto = event.channel.protocol || '';
            if (proto.startsWith(STREAM_PROTOCOL_PREFIX)) {
                this.attachStreamChannel(event.channel);
                return;
            }

            const dc = event.channel;
            this.swsp.attach(dc);
            dc.onopen = () => {
                this.subscribedStreams.clear();
                console.log('DataChannel opened');
                // Bidirectional verify: do not send "connect" yet. The
                // device's first stream-0 frame must be verify_nonce_hash
                // and must match this.verifyNonceHash. Only then can we
                // trust that the channel really terminates at the device
                // (not a rogue relay), and onDataChannelReady will be called
                // from handleControlMessage on successful verify.
            };
            dc.onclose = () => {
                console.log('DataChannel closed');
                // The channel can die without the PC ever reporting 'failed'
                // (e.g. the device closes its end). Route through the same
                // recovery path; start() skips a loop already running and a
                // session that has ended.
                if (this._wasConnected) this.reconnector.start();
            };
            dc.onerror = (e) => console.error('DataChannel error:', e);
            dc.onmessage = (e) => this.handleDataChannelMessage(e);
        };

        return pc;
    }

    handleRemoteCandidate(candidate) {
        if (this.debug) {
            const c = candidate?.candidate || '';
            const m = c.match(/typ (\S+)/);
            console.log(`[Connection] remote candidate: ${m ? m[1] : '?'} ${c}`);
        }
        if (this.remoteDescriptionSet && this.pc) {
            this.pc.addIceCandidate(candidate).catch(() => {});
        } else {
            this.candidateQueue.pushRemote(candidate);
        }
    }

    // A message to the signaling server, if its socket is open. Returns
    // whether it went; a socket that has closed is not an error here.
    _sendSignaling(msg) {
        if (this.ws?.readyState !== WebSocket.OPEN) return false;
        try {
            this.ws.send(JSON.stringify(msg));
            return true;
        } catch (e) {
            return false;
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
        const relayed = await this.relay.check(pc);
        if (relayed) {
            this._print('Using temporary relay (TURN) — direct peer-to-peer was not possible.');
            this._turnHoldPromise = new Promise(r => setTimeout(r, 2000));
        } else if (this._turnUnavailable) {
            // Banner was already set in handleOffer; just arm the hold so
            // the visible message survives iframe handoff for ~2 s.
            this._turnHoldPromise = new Promise(r => setTimeout(r, 2000));
        }
        // Arm the TTL-based end triggers if we're on a relay path (and the
        // credential says when it expires). Direct paths skip both.
        if (relayed) this.relay.armEndTimers();
    }

    // A device registered for our UID, and this is which run of its firmware.
    //
    // The whole decision is one comparison, and it is here rather than on the
    // server because the server would have to remember which boot each client
    // had been talking to, and the client already knows.
    //
    // Nothing to compare against means this is the first identity we have
    // seen: store it and carry on, which is every fresh page load.
    //
    // The same identity means the device never stopped -- its signaling
    // reconnected, or this server redeployed -- so the iframe, the worker's
    // session table, the bound stream elements and the settings table are all
    // still describing something real. Nothing to do; if the transport
    // happens to be down the reconnect loop is already working on it, and
    // waking it is the only thing worth doing here.
    //
    // A different identity means the device restarted, and nothing the page
    // is holding survives that. Not a renegotiation -- a reload. The page is
    // showing an app served by firmware that no longer exists, and if the
    // firmware changed, every assumption in it is worse rather than better.
    _onDeviceBoot(boot) {
        if (!boot) {
            // Firmware too old to say. Treat it as unknown rather than as
            // unchanged: a device that cannot be identified is one whose
            // freshness cannot be vouched for.
            console.warn('[Connection] device sent no boot identity');
            return;
        }
        if (this._deviceBoot === null) {
            this._deviceBoot = boot;
            return;
        }
        if (this._deviceBoot === boot) {
            this.reconnector.wakeUp();    // shortens a backoff, nothing more
            return;
        }

        console.log('[Connection] device restarted:', this._deviceBoot, '->', boot);
        this._deviceBoot = boot;
        this._reloadForRestart();
    }

    // Automatic, and said while it happens.
    //
    // A reload is the only correct answer to a restart, and it used to wait
    // for a click -- which for someone watching a device on another continent
    // meant a dead page until they came back to it.
    //
    // One message, kept up across the reload. There used to be a second one,
    // different words in a different color on the page after the reload, and
    // in use it was just another strip appearing unexplained a moment after
    // the first -- the thing it existed to prevent. So now it is the same strip
    // with the same words on both sides of the reload.
    _reloadForRestart() {
        this._sessionEnded = true;           // stop the reconnect loop competing
        this._showReconnecting(DEVICE_RESET_TEXT);
        // Not a delay: the reload is not held for the message. The page that
        // comes back puts the same strip up again and takes it down once it
        // is connected, so it stays up for as long as it is true instead of
        // for the hundred milliseconds this page has left.
        // The whole tab, not just this frame: bitba.ng's page holds the
        // address the device page was last at, and this frame's own URL only
        // the one it started with. The key survives in this origin's
        // sessionStorage, which belongs to the tab.
        try { sessionStorage.setItem(DEVICE_RESET_KEY, '1'); } catch { /* private mode */ }
        reloadTab();
    }

    // The server says which build it is serving. Different from ours means this
    // page is running code the server no longer serves, so offer a reload --
    // the same offer a worker turning over produces, with the same guard.
    _onBuildStamp(build) {
        // Heard from a live server, so whatever redial got us here worked.
        this._signalBackoff = SIGNAL_REDIAL_MIN_MS;
        if (!build || build === BUILD) return;
        // Fetch the new worker now, so it is installed by the time anyone
        // clicks. The reload would fetch it anyway; this gets it out of the way
        // while the person is still reading the banner.
        navigator.serviceWorker?.getRegistration('/')
            .then(r => r?.update()).catch(() => {});
        offerReloadFor(build);
    }

    // Keep a signaling socket up for as long as the session is.
    //
    // Only while the session is established and nothing else is managing the
    // socket: before setup the connect path owns it, and during a reconnect the
    // loop opens and closes its own. And only when there is no socket already --
    // which is what stops a redial scheduled earlier from opening a second one
    // after the reconnect loop has put its own in place.
    _shouldHoldSignaling() {
        return this._transportReady && !this.reconnector.active && !this._sessionEnded
            && !this.ws;
    }

    _keepSignaling() {
        if (!this._shouldHoldSignaling() || this._signalTimer) return;
        const delay = this._signalBackoff;
        this._signalBackoff = Math.min(this._signalBackoff * 2, SIGNAL_REDIAL_MAX_MS);
        this._signalTimer = setTimeout(() => {
            this._signalTimer = null;
            this._redialSignaling();
        }, delay);
    }

    // A control socket, not a session. It never sends `request`, so the device
    // is not asked for an offer and nothing about the running session changes.
    // It is there to be told things: a new build, a device coming back.
    //
    // A refusal needs no case of its own. While the device is still coming back,
    // the server answers "Device not found" after its deliberate delay and
    // closes, and the close schedules the next attempt with a longer wait. The
    // backoff only resets on a build stamp, which the server sends after it has
    // let the socket in -- so a refused socket, which also opens before it is
    // refused, cannot reset it and turn the backoff into a retry every few
    // seconds.
    _redialSignaling() {
        if (!this._shouldHoldSignaling()) return;
        const ws = new WebSocket(this.signalingURL());
        ws.bbControl = true;                  // carries no session; see the trickle
        this.ws = ws;
        if (this.debug) console.log('[Connection] redialing signaling');

        ws.onmessage = (event) => {
            let msg;
            try { msg = JSON.parse(event.data); } catch { return; }
            if (msg.type === 'device_up') this._onDeviceBoot(msg.boot);
            else if (msg.type === 'build_stamp') this._onBuildStamp(msg.build);
        };
        ws.onclose = () => {
            if (ws !== this.ws) return;       // torn down or replaced
            this.ws = null;
            this._keepSignaling();
        };
    }

    // Tear down the dead transport and reset per-connection state so the next
    // attempt re-runs _onFirstConnected (re-detects relay, re-arms TURN
    // timers). The sessionId, iframe, SW registration, and window listener are
    // deliberately left intact — they survive the transport swap.
    _teardownTransport() {
        // A redial waiting to fire would open a socket the reconnect loop does
        // not know about. The loop owns the socket from here.
        clearTimeout(this._signalTimer);
        this._signalTimer = null;
        this._clearReassureTimer();
        // The channel, its credit and its version go with it (detach), and
        // the relay verdict and credential with the peer connection.
        this.relay.reset();
        this.swsp.detach();
        try { if (this.pc) this.pc.close(); } catch (e) {}
        try { if (this.ws) this.ws.close(); } catch (e) {}
        this.pc = null;
        this.ws = null;
        this.remoteDescriptionSet = false;
        this.answerSent = false;
        this.deviceVerified = false;
        this.connectResolve = null;
        this.candidateQueue = new CandidateQueue();
        this._wasConnected = false;
        this._turnHoldPromise = null;

        // Every stream the page has open was on the channel just closed; the
        // sockets are closed and the requests failed, so the page can try
        // again on the next one (closeAll and failAll say why).
        this.sockets.closeAll();
        this.requests.failAll('Connection lost');
    }

    // The text is a parameter because this strip says two things: that the
    // connection is being worked on, and that the device reset and the page is
    // reloading. They follow each other -- the second usually replaces the first
    // -- so one strip that changes its words beats two competing for the same
    // place at the top of the page.
    _showReconnecting(text = 'Reconnecting…') {
        if (this._prevTitle == null) this._prevTitle = topTitle;   // restored in _hideReconnecting
        banner({ id: 'bb-reconnect-banner', level: 'trouble', text });
        setTopTitle(text + ' - bitba.ng');
    }

    _hideReconnecting() {
        removeBanner('bb-reconnect-banner');
        if (this._prevTitle != null) {
            setTopTitle(this._prevTitle);
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
            const frame = SwspChannel.parseFrame(event.data);

            // StreamId 0 is reserved for control messages (connect/ready/auth)
            if (frame.streamId === 0) {
                this.handleControlMessage(frame);
                return;
            }

            if (this.sockets.has(frame.streamId)) {
                this.sockets.onFrame(frame);
                return;
            }

            // Transport benchmark -- see startBench()
            const bench = this.benchStreams.get(frame.streamId);
            if (bench) {
                this.swsp.onArrived(frame, true);
                if (frame.flags & FLAG_FIN) this.swsp.dropCredit(frame.streamId);
                this.handleBenchFrame(frame, bench);
                return;
            }

            if (this.requests.has(frame.streamId)) {
                this.requests.onFrame(frame);
                return;
            }
            console.log('Received frame for unknown stream:', frame.streamId);
        } catch (e) {
            console.error('Error parsing SWSP frame:', e);
        }
    }

    // The device did not prove it holds its key, or broke the order that
    // proof comes in. Nothing more is said on this connection.
    rejectUnverified(why) {
        console.error('[Connection] ' + why + '. Closing.');
        this._printError('Connection rejected: device identity could not be verified.');
        this.swsp.close();
        try { this.pc.close(); } catch (e) {}
    }

    async handleControlMessage(frame) {
        if (!(frame.flags & FLAG_SYN)) return;

        const text = new TextDecoder().decode(frame.payload);
        const msg = JSON.parse(text);

        // verify_nonce_hash must be the very first control message we see
        // on a freshly-opened data channel. Until it lands and matches the
        // hash bitba.ng's page sent with the proof, the channel is treated as
        // untrusted and we won't send connect/auth or accept any other
        // control message.
        if (msg.type === 'verify_nonce_hash') {
            if (this.deviceVerified) {
                console.warn('[Connection] duplicate verify_nonce_hash, ignoring');
                return;
            }
            if (!this.verifyNonceHash || msg.hash !== this.verifyNonceHash) {
                this.rejectUnverified('nonce hash mismatch -- device did not prove possession of the private key');
                return;
            }
            this.deviceVerified = true;
            console.log('[Connection] bidirectional verify OK');
            this.onDataChannelReady();
            return;
        }

        if (!this.deviceVerified) {
            // Any non-verify control message before verify is a protocol
            // violation. Treat as if the device failed to authenticate.
            this.rejectUnverified(`control message ${JSON.stringify(msg.type)} before verify_nonce_hash`);
            return;
        }

        // v4 flow control. Both arrive often -- a window_update for every
        // half megabyte a stream moves -- so they come first.
        if (msg.type === 'window_update') {
            this.swsp.raiseSendLimit(msg.stream_id, msg.max_bytes);
            return;
        }
        if (msg.type === 'stream_reset') {
            if (this.swsp.flowControl) this.onStreamReset(msg);
            return;
        }

        if (msg.type === 'ready') {
            // `server_version` tells us which SWSP version the listener
            // is speaking. v2 listeners send just {type:'ready'} —
            // serverVersion defaults to 2.
            this.serverVersion = msg.server_version || 2;
            // The version this session runs, which the listener fixed at
            // the first connect. A listener that predates negotiated_version
            // speaks the lower of the two.
            this.swsp.version = msg.negotiated_version
                || Math.min(this.serverVersion, SWSP_VERSION);
            // routing tells us how to interpret the first segment of the
            // URL fragment's device path. "target-prefix" (bitbangproxy)
            // means the first segment is a LAN target that isolates
            // cookies between hosts reached through this UID.
            // "direct" (bitbang-python WSGI/ASGI, or missing = safe
            // default) means the whole path belongs to the app -- no
            // target segment; all paths under this UID share cookies.
            //
            // The target itself came from bitba.ng's page, in this frame's
            // URL; onDataChannelReady checks the two agree.
            this.routing = msg.routing || 'direct';
            if (this.debug) {
                console.log('[Connection] Device ready (server v' + this.serverVersion + ', SWSP v' + this.swsp.version + ', routing=' + this.routing + ', target=' + JSON.stringify(this.target) + ')');
            } else {
                console.log('[Connection] Device ready (SWSP v' + this.swsp.version + ')');
            }
            if (this.connectResolve) {
                this.connectResolve();
                this.connectResolve = null;
            }
        } else if (msg.type === 'auth_required') {
            // bitba.ng's page asks for the PIN, and remembers it for this tab:
            // a PIN it already has comes straight back (pin_needed answers
            // with a pin message either way, see onTopPIN).
            console.log('[Connection] Device requires authentication');
            toTop({ type: 'pin_needed' });
        } else if (msg.type === 'auth_result') {
            const handleResult = () => {
                if (msg.success) {
                    toTop({ type: 'pin_ok' });
                    if (this.connectResolve) {
                        this.connectResolve();
                        this.connectResolve = null;
                    }
                } else {
                    // A remembered PIN that failed is forgotten, and the
                    // person is asked.
                    toTop({ type: 'pin_needed', failed: true });
                }
            };
            // A PIN the person typed gets a moment to read "OK" or the
            // error before the page changes under them; a remembered one
            // doesn't.
            if (this._authCached) {
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
            console.error('[Connection] Device error:', msg.message);
            // Two very different moments produce this. Before the device UI
            // is up (a refused code, a rejected connect path) #connection-ui
            // is what the user is looking at, so print into it as always.
            //
            // Once the iframe exists it is position:fixed, full viewport,
            // opaque, z-index 1 -- it paints straight over #connection-ui, so
            // _printError would say nothing at all. Worse, the device is
            // about to close the channel, and onclose routes into the
            // reconnect loop: the user would be left watching "Reconnecting..."
            // for a session that has intentionally ended, which is the
            // opposite of the truth. showReloadScreen is the existing
            // terminal path (relay expiry uses it): it marks the session
            // ended so nothing retries, hides the iframe, and offers Reload.
            if (document.getElementById('device-frame')) {
                this.showReloadScreen(msg.message || 'The device ended this session');
            } else {
                this._printError(msg.message || 'Connection refused');
            }
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
                if (this.debug) console.log('[Connection] video track received');
                const iframe = document.getElementById('device-frame');
                if (iframe) this.wireStreams(iframe);
            };
            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    this.swsp.sendControl({ type: 'video_candidate', candidate: event.candidate.toJSON() });
                }
            };
            pc.onconnectionstatechange = () => {
                if (this.debug) console.log('[Connection] video PC -> ' + pc.connectionState);
            };

            await pc.setRemoteDescription({ type: 'offer', sdp });
            await pc.setLocalDescription(await pc.createAnswer());
            this.swsp.sendControl({ type: 'video_answer', sdp: pc.localDescription.sdp });
            if (this.debug) console.log('[Connection] sent video answer');
        } catch (e) {
            console.error('[Connection] video offer handling failed:', e);
        }
    }

    showReloadScreen(message) {
        // This is terminal — cancel any in-flight soft reconnect and mark the
        // session ended so a reconnect loop mid-backoff bails out.
        this._sessionEnded = true;
        this.reconnector.cancel();
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
            document.getElementById('bb-reload-btn').onclick = () => reloadTab();
        }
    }

    // A PIN from bitba.ng's page, which prompts for it and remembers it per
    // tab. `cached` says it was remembered rather than just typed, which
    // only changes how quickly the result is acted on.
    onTopPIN(msg) {
        if (typeof msg.pin !== 'string' || !msg.pin) return;
        if (!this.swsp.open) return;
        this._authCached = !!msg.cached;
        this.swsp.sendControl({ type: 'auth', pin: msg.pin });
    }

    // Send the connect handshake and wait for the device's 'ready' (plus the
    // optional 2 s TURN banner hold). Shared by the initial connect and by a
    // soft reconnect — everything here is safe to run on a rebuilt transport.
    // The connect message, for a whole device path (target included). The
    // device answers 'ready', or 'auth_required' for a path behind a PIN.
    //
    // `version` is the SWSP version we're speaking; older v2 listeners
    // ignore it. The listener fixes the version at the first connect and
    // keeps it, which is what lets streams already open keep their
    // flow-control accounting when a navigation connects again. No `caps`
    // field -- this frame is a pure transport and doesn't claim knowledge
    // of specific stream types. The iframe decides what to open via
    // /__bitbang/<type>.
    sendConnect(path) {
        return this.swsp.sendControl({ type: 'connect', path, version: SWSP_VERSION });
    }

    async _sendConnectAndAwaitReady() {
        this.sendConnect(this.targetPrefix() + this.devicePath);

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

        // Two separate questions, which used to be one `if`.
        //
        // Is a reconnect attempt waiting to hear that it worked? Answer it
        // first and unconditionally -- it is a no-op when nothing is waiting.
        // It used to be answered only on the branch where the one-time setup
        // had already been done, and a reconnect loop can start before the
        // first connection ever gets here: anything that fails after DTLS is
        // up but before ready -- a verify that doesn't match, a device
        // resetting mid-handshake -- starts one. Its attempt then succeeded
        // down the first-connection branch, nothing told it, and it waited out
        // RECONNECT_TIMEOUT_MS over a working connection before tearing that
        // connection down to try again. Twenty seconds of "Reconnecting..."
        // and then a real disconnect, with nothing actually wrong.
        this.reconnector.succeeded();

        // Does the one-time setup still need doing? The iframe, SW
        // registration, and window message listener all persist across a
        // transport swap, so a page that has done it once never does it again.
        if (this._transportReady) return;
        this._transportReady = true;

        // The first connection is up, so anything the top strip was saying
        // about getting here -- a device reset carried across the reload, for
        // one -- has stopped being true.
        this._hideReconnecting();

        // The device says on 'ready' whether its first path segment is a LAN
        // target. bitba.ng's page had to decide that before it could pick
        // this origin, since the target is part of the label, and on a first
        // visit it applies the CLI's rule (targetFor in bootstrap.js). A
        // device that routes the whole path itself, given a target, is in the
        // wrong origin: tell the page, which remembers the device's routing
        // and reloads into the right one. Once per device per browser. (The
        // CLI with no target is its own pages, at the CLI's root: right.)
        toTop({ type: 'routing', routing: this.routing });
        if (this.routing !== 'target-prefix' && this.target) {
            console.warn('[Connection] routing', this.routing, 'but target',
                         JSON.stringify(this.target), '-- bitba.ng\'s page will reload');
            return;
        }

        // The worker's settings for this tab. Nothing here identifies the
        // device: the worker serves exactly one, whichever this origin is.
        const reg = await navigator.serviceWorker.ready;
        reg.active?.postMessage({
            type: 'config',
            debug: this.debug,
            noCookieJar: this.noCookieJar,
        });
        // While this tab is open, the device's session cookies are in use:
        // the worker drops them only once no tab has said so for a few
        // minutes (sweepSessionCookies in label-sw.js).
        const alive = () => navigator.serviceWorker.ready
            .then(r => r.active?.postMessage({ type: 'alive' })).catch(() => {});
        alive();
        setInterval(alive, ALIVE_EVERY_MS);

        // Listen for messages from the content frame. Besides the ws_*
        // traffic (SocketBridge.onPageMessage), a device page can post:
        //   bb-navigate  { path }                 move the iframe to a path
        //   bb-open-cap  { path, newTab = true }  open /<uid>#<code><path>
        //
        // Kebab-case, unlike the rest of the browser's messages, because
        // device pages send these and we don't ship all of them: the CLI's
        // cap bar, proxy page and HTTP landing page post these names, and a
        // CLI already installed has to keep working against a new server.
        // Never rename them.
        window.addEventListener('message', (event) => {
            const iframe = document.getElementById('device-frame');
            if (!iframe || event.source !== iframe.contentWindow) return;
            if (event.data?.type === 'bb-navigate') {
                this.handleNavigateRequest(event.data.path);
            } else if (event.data?.type === 'bb-open-cap' || event.data?.type === 'bb-open') {
                // The device page asks to land on /<uid>#<code><path>: in a
                // new tab by default (the cap bar's menu, and every popup the
                // shim catches, as bb-open), or in this one (the proxy
                // form's Go button). The code is bitba.ng's page's, so the
                // page composes the URL and opens it.
                //
                // bb-open-cap's path is a whole device path, target included
                // (the CLI's pages name targets themselves). bb-open is the
                // shim's, for a link or window.open in this origin, whose
                // path is the page's own and so lacks the target.
                let path = typeof event.data.path === 'string' ? event.data.path : '/';
                if (!path.startsWith('/')) path = '/' + path;
                if (event.data.type === 'bb-open') path = this.targetPrefix() + path;
                toTop({ type: 'open', path, newTab: event.data.newTab !== false });
            } else {
                this.sockets.onPageMessage(event.data, iframe.contentWindow);
            }
        });

        // The content frame's first fetch must reach the worker: on the
        // network, a label host answers every path with this page.
        await this.waitForController();

        this.createIframe();
    }

    // The target as a path prefix, '/<target>', or '' for a device that
    // routes the whole path itself.
    targetPrefix() {
        return targetPrefix(this.target);
    }

    // A page loaded with a hard reload (Ctrl+Shift+R) starts uncontrolled --
    // Chrome bypasses the service worker for that navigation. Everything else
    // works: connection.js runs, the peer connection comes up, video frames
    // arrive. Only the iframe fetch goes to the network instead of the SW, and
    // nothing there serves it, so the page is white behind a working data
    // channel. It looks like a video failure and is not one.
    //
    // clients.claim() in label-sw.js's activate handler does claim us, but it can
    // land after the iframe has already navigated, so waiting for it is the
    // fix rather than reloading. Reload only if the claim never arrives.
    async waitForController(timeoutMs = 3000) {
        const key = 'bb-reloaded-uncontrolled';
        if (navigator.serviceWorker.controller) {
            try { sessionStorage.removeItem(key); } catch (e) { /* private mode */ }
            return true;
        }

        const claimed = await new Promise((resolve) => {
            const timer = setTimeout(() => resolve(false), timeoutMs);
            navigator.serviceWorker.addEventListener('controllerchange', () => {
                clearTimeout(timer);
                resolve(true);
            }, { once: true });
        });
        if (claimed) {
            try { sessionStorage.removeItem(key); } catch (e) { /* private mode */ }
            return true;
        }

        // Once per tab, so a service worker that genuinely cannot claim this
        // page produces one wasted reload rather than a loop.
        try {
            if (sessionStorage.getItem(key)) {
                console.error('[Connection] no service worker controller after reloading; '
                            + 'the device page cannot be fetched');
                return false;
            }
            sessionStorage.setItem(key, '1');
        } catch (e) { /* private mode: fall through and reload once */ }

        console.warn('[Connection] no service worker controller (hard reload?); reloading normally');
        window.location.reload();
        return false;
    }

    handleNavigateRequest(path) {
        // Iframe requested navigation to a path that may need PIN auth.
        // Send a new connect message on stream 0. The device will respond
        // with 'ready' (no PIN needed) or 'auth_required'.
        console.log('[Connection] Navigate request:', path);
        if (typeof path !== 'string') return;
        if (!path.startsWith('/')) path = '/' + path;

        // The path is a whole device path, as the device sees it. A path for
        // another LAN target belongs to another origin, so bitba.ng's page
        // takes it, in this tab.
        const tp = this.targetPrefix();
        if (tp && path !== tp && !path.startsWith(tp + '/')) {
            toTop({ type: 'open', path, newTab: false });
            return;
        }
        const framePath = path.slice(tp.length) || '/';

        const iframe = document.getElementById('device-frame');
        this.devicePath = framePath;

        // Set up a resolve callback for the auth flow
        const navigateAfterAuth = () => {
            if (iframe) {
                iframe.src = framePath;
                iframe.style.display = '';
            }
            if (this.connectionUI) this.connectionUI.style.display = 'none';
        };
        this.connectResolve = navigateAfterAuth;
        this.sendConnect(path);
    }

    createIframe() {
        const iframe = document.createElement('iframe');
        iframe.id = 'device-frame';
        // The same sandbox bitba.ng's page puts on this frame, which a nested
        // frame inherits anyway: no top navigation, so a device page that
        // tries to bust out of its frame can't take the tab. Popups are
        // allowed only so the shim's own bb-open path is not the sole way a
        // download or a link in a new tab can work; they are caught and sent
        // to bitba.ng's page where the shim can see them.
        iframe.sandbox = 'allow-scripts allow-forms allow-same-origin allow-popups allow-modals allow-downloads';
        // A cross-origin frame gets only what its parent's allow= lists, and
        // this one only what bitba.ng's page gave this frame (FRAME_ALLOW in
        // bootstrap.js, which must match).
        iframe.allow = 'autoplay; fullscreen; clipboard-read; clipboard-write; picture-in-picture; camera; microphone';
        iframe.scrolling = 'yes';
        iframe.style.cssText = `
            position: fixed; top: 0; left: 0;
            width: 100%; height: 100%;
            border: none; z-index: 1; background: #fff;
        `;

        iframe.onload = () => {
            // Constrain the iframe body to the viewport so modal height
            // calculations use the visible area, not the content height.
            //
            // border-box matters as much as the height does. Without it a page
            // that puts padding on body -- which the settings page does, 2rem
            // top and bottom -- is one viewport tall *plus* that padding, so it
            // overflows by about 4rem and always shows a scrollbar with
            // roughly 90% of itself visible. Only html and body are touched,
            // so a page's own box model below that is its own business.
            try {
                const doc = iframe.contentDocument;
                const s = doc.createElement('style');
                s.textContent = 'html, body { height: 100% !important; '
                              + 'box-sizing: border-box !important; '
                              + 'overflow: auto !important; }';
                doc.head.appendChild(s);
            } catch (e) {}

            this.wireStreams(iframe);
            if (this.connectionUI) this.connectionUI.style.display = 'none';

            let iframeTitle = '';
            try { iframeTitle = iframe.contentDocument?.title || ''; } catch (e) {}
            setTopTitle(iframeTitle || this.deviceName || "BitBang");

            // Favicon forwarding. Watches the iframe's <link rel="icon">
            // (and friends) and sends the icon to bitba.ng's page, which
            // shows it as the tab's. As a data URL: bitba.ng's page can't
            // fetch from this origin -- a request it makes is its own, so
            // this origin's worker never sees it, and the label host would
            // answer with the start page.
            //
            //   applyDeviceFavicon  fetches the icon here, through the
            //                       worker, and sends it up. No-ops for
            //                       cross-origin hrefs (rare but possible
            //                       for icons on a CDN).
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

            // The href last sent up, so a mutation that changes nothing sends
            // nothing. Per frame, not per page load: bitba.ng's page keeps
            // the icon across the content frame's navigations, as a tab does.
            const applyDeviceFavicon = (rawHref) => {
                if (!rawHref || rawHref === this._iconHref) return;
                this._iconHref = rawHref;
                if (rawHref.startsWith('data:')) {
                    sendIcon(rawHref);
                    return;
                }
                let u;
                try { u = new URL(rawHref, iframe.contentWindow.location.href); }
                catch { return; }
                if (u.origin !== window.location.origin && u.protocol !== 'blob:') return;
                // Through this origin's worker, from the device.
                fetch(u.href).then(r => (r.ok ? r.blob() : null)).then((blob) => {
                    if (!blob || rawHref !== this._iconHref) return;
                    const reader = new FileReader();
                    reader.onload = () => sendIcon(reader.result);
                    reader.readAsDataURL(blob);
                }).catch((e) => dbg('icon fetch failed:', String(e)));
            };
            // Larger than any tab icon needs; a device that serves a huge one
            // keeps bitba.ng's.
            const sendIcon = (dataURL) => {
                if (typeof dataURL !== 'string' || dataURL.length > 256 * 1024) return;
                this._iconSet = true;
                toTop({ type: 'icon', href: dataURL });
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

            // Fallback: /favicon.ico, used only if no page has named an icon
            // by the time it arrives, so it never replaces a real one.
            if (!this._iconSet) {
                fetch('/favicon.ico').then(r => (r.ok ? r.blob() : null)).then((blob) => {
                    if (!blob || this._iconSet || !/^image\//.test(blob.type)) return;
                    dbg('static probe applied');
                    const reader = new FileReader();
                    reader.onload = () => { if (!this._iconSet) sendIcon(reader.result); };
                    reader.readAsDataURL(blob);
                }).catch((e) => dbg('static probe error:', String(e)));
            }

            // Report the content frame's location to bitba.ng's page after
            // every navigation, so refresh and bookmarks land back on the
            // same page. Same origin as this frame, so its location is
            // readable and its history hookable. Re-attach per load: a full
            // navigation gives the iframe a fresh window/history.
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
                if (this.debug) { try { console.log('[Connection] iframe nav', src, '->', iframe.contentWindow.location.href); } catch (e) {} }
                try { this.reportLocation(); } catch (e) {}
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

            sync('load');
        };

        // The device's own path: this origin is the device's, so nothing is
        // prefixed and nothing needs stripping. The content frame's address
        // is the address an app would have on the LAN.
        iframe.src = this.devicePath + this.deviceSearch + this.deviceHash;
        document.body.appendChild(iframe);
    }

    // Tell bitba.ng's page where the content frame is, so the address bar
    // follows it and refresh and bookmarks land back on the same page. The
    // path goes up whole, target included, as the address bar shows it;
    // bitba.ng's page puts it after the code and flags.
    //
    // The content frame is this origin's, so its location is just its
    // location: no prefix to strip, no target to guess back.
    reportLocation() {
        const iframe = document.getElementById('device-frame');
        if (!iframe) return;
        let loc;
        try { loc = iframe.contentWindow.location; } catch (e) { return; }
        // A frame that has left this origin (a link to a LAN address the
        // browser can't reach anyway) has no device path to report.
        if (loc.origin !== location.origin) return;
        this.devicePath = loc.pathname || '/';
        this.deviceSearch = loc.search;
        this.deviceHash = loc.hash;
        toTop({
            type: 'location',
            path: this.targetPrefix() + this.devicePath,
            search: loc.search,
            hash: loc.hash,
        });
    }

    // bitba.ng's page asks for a path in this origin: the address bar was
    // edited to one, or it was moved to a meta-page (/*settings). The path is
    // a whole device path, as reportLocation sends them. Answered by moving
    // the content frame, keeping the connection. A path for another target
    // never arrives here: bitba.ng's page reloads into that target's origin.
    navigateTo(msg) {
        const iframe = document.getElementById('device-frame');
        if (!iframe || typeof msg.path !== 'string') return;
        const tp = this.targetPrefix();
        let path = msg.path;
        if (tp) {
            if (path !== tp && !path.startsWith(tp + '/')) return;
            path = path.slice(tp.length) || '/';
        }
        this.devicePath = path;
        this.deviceSearch = typeof msg.search === 'string' ? msg.search : '';
        this.deviceHash = typeof msg.hash === 'string' ? msg.hash : '';
        iframe.src = this.devicePath + this.deviceSearch + this.deviceHash;
        if (this.debug) console.log('[Connection] navigate in place ->', iframe.src);
    }

    // Tell the device whether this page wants a stream.
    //
    // It goes on stream 0, not on the stream's own channel: a media channel is
    // maxRetransmits 0, so a subscribe sent there can vanish and leave the
    // viewer silently blank. Named, so audio uses the same message.
    setStream(name, on) {
        if (!name || !this.swsp.open) {
            // Silently dropping this is indistinguishable, from the device's
            // side, from a page that never asked -- and the page has no way to
            // know it was lost, so it never retries. Worth a line.
            console.warn(`[Connection] ${name} subscribe dropped: channel ` +
                         `${this.swsp.state}`);
            return;
        }
        try {
            if (!this.swsp.sendControl({ type: 'stream', name, on: !!on })) return;
            if (on) this.subscribedStreams.add(name);
            else this.subscribedStreams.delete(name);
        } catch (e) {
            if (this.debug) console.warn('[Connection] setStream failed', e);
        }
    }

    // Whether a name is the presentation half of a stream channel ("cam", when
    // the device has cam/video) rather than a whole one ("cam/video").
    isPresentation(name) {
        if (name.indexOf('/') > 0) return false;
        for (const s of this.streams.values()) {
            if (s.presentation === name) return true;
        }
        return false;
    }

    // Hand the page one end of a port and tell it what the device offers.
    //
    // The other end is stream-shim.js, which the service worker prepended to
    // this response. It renders; this side never learns what a codec is.
    //
    // postMessage into the iframe rather than a property on contentWindow,
    // because a port has to be transferred and a property cannot transfer one.
    // The shim installs its listener while the document is still parsing -- it
    // is the first script in the response -- and this runs on load, so the
    // handshake cannot be missed in that direction.
    attachStreamPort(iframe) {
        if (!iframe.contentWindow) return;
        const chan = new MessageChannel();
        // A previous page's port, if this is a navigation within the device.
        // Closing it drops any frame still queued for a document that is gone.
        if (this.streamPort) this.streamPort.close();
        this.streamPort = chan.port1;
        this.streamPort.onmessage = (e) => {
            const msg = e.data;
            if (!msg || msg.type !== 'subscribe') return;
            // The shim asks for exactly the components it found an element for,
            // which is the rule that keeps a device from sending what nobody is
            // showing.
            this.setStream(msg.name, msg.on !== false);
        };
        // Targeted rather than '*'. The device page is same-origin -- the
        // service worker serves it from this origin, which is how
        // contentDocument is readable at all -- so naming the origin costs
        // nothing and means a frame that navigated somewhere else does not
        // receive a port that can subscribe to a device.
        iframe.contentWindow.postMessage({ type: 'stream_port' },
                                         location.origin, [chan.port2]);
        // Channels usually open well before the page finishes loading, so the
        // shim would otherwise wait for a device to declare something new.
        this.announceStreams();
    }

    wireStreams(iframe) {
        const doc = iframe.contentDocument;
        if (!doc) return;

        // A device declares its stream channels on every session, so without
        // this the device cannot tell a page that renders video from one that
        // merely connected -- and it sends to both, halving the frame rate of
        // the page that actually wanted it. The settings meta-page declares no
        // sinks and so asks for nothing.
        //
        // Scanned once, when the page loads. A page that builds its DOM later
        // calls __bitbang.subscribe() itself; watching the document for
        // changes would be more code, permanently running, for a case a
        // load-time scan could not have served reliably anyway.
        //
        // A name that is the presentation of a stream channel is left to the
        // shim, which subscribes per component once it knows which element can
        // render which codec. Sending "cam" here as well would be a message
        // the device has no stream for -- it ignores unknown names, but there
        // is no reason to make it.
        const wanted = new Set();
        doc.querySelectorAll('[data-bitbang-stream]').forEach(el => {
            const n = el.getAttribute('data-bitbang-stream');
            if (n && !this.isPresentation(n)) wanted.add(n);
        });
        for (const n of wanted) {
            if (!this.subscribedStreams.has(n)) this.setStream(n, true);
        }

        this.attachStreamPort(iframe);

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
            // For a page that renders after load: subscribe when it mounts.
            subscribe: (name) => this.setStream(name, true),
            unsubscribe: (name) => this.setStream(name, false),
            streams: this.resolvedStreams,
            getStream: (name) => this.resolvedStreams[name],
            getDefaultStream: () => this.resolvedStreams[Object.keys(this.resolvedStreams)[0]],
            pc: this.pc
        };
    }
}

// Start. Only as bitba.ng's page's child: anywhere else there is no one to
// ask for a proof, and nothing to connect with. The server already answers a
// top-level load with a page saying so (label.go); this covers a browser that
// doesn't send Sec-Fetch-Dest, and a page that framed this one itself, which
// frame-ancestors stops before it gets here.
(async function () {
    console.log('[Connection] starting', location.href.split('#')[0]);
    if (window.parent === window) {
        document.title = 'Open from your link - BitBang';
        const ui = document.getElementById('connection-ui');
        if (ui) ui.textContent = 'This page only works inside the BitBang tab it came from. '
            + 'Go back to that tab, or open the device again from its link.';
        return;
    }
    // A content frame that reached the network before the worker controlled
    // this origin gets this page for whatever path it asked (label.go). It is
    // not the connection frame -- that one is bitba.ng's page's direct child
    // -- so it starts nothing; the connection frame waits for the worker
    // before it frames anything (waitForController), so this is a hard
    // reload's leftover at most.
    if (window.parent !== window.top) {
        console.warn('[Connection] loaded as a content frame, not starting');
        return;
    }

    let deviceReset = false;
    try {
        deviceReset = sessionStorage.getItem(DEVICE_RESET_KEY) === '1';
        sessionStorage.removeItem(DEVICE_RESET_KEY);
    } catch { /* private mode: nothing was stored */ }

    const connection = new BitBangConnection(parseStartURL());
    window.__bitbangConnection = connection;
    fromTop((msg) => {
        if (msg.type === 'pin') connection.onTopPIN(msg);
        else if (msg.type === 'navigate') connection.navigateTo(msg);
    });
    // Taken down in onDataChannelReady once the first connection is up.
    if (deviceReset) connection._showReconnecting(DEVICE_RESET_TEXT);
    await connection.connect();
})();
