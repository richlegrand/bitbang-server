/**
 * BitBang runtime: what more than one of its pieces needs.
 *
 * Loaded by bitba.ng's page (bootstrap.html, before bootstrap.js), by the
 * connection frame (label-start.html, before connection.js) and by the label
 * worker (importScripts in label-sw.js). A device origin and bitba.ng can't
 * share a module across origins without CORS, so this is a plain script:
 * everything in it is a global, and none of it touches the DOM, so it runs in
 * the worker too.
 *
 * The server serves it from both kinds of host (allowedBitbangAssets in
 * static.go, labelAssets in label.go), and it is a stamp input, so a change
 * here moves BUILD like a change in any file that loads it.
 */

// -- The URL fragment --------------------------------------------------------
//
//   fragment  = <head> [ '@' <target> ] [ '!' <flag-list> ] [ '/' <device-URL> ]
//   flag-list = <flag> [ ',' <flag> ]*
//   flag      = <name> [ '=' <value> ]
//
// The head is the access code in bitba.ng's URL, /<uid>#<code>..., and the uid
// in the connection frame's, /__bb/start#<uid>@<target>... (bitba.ng's page
// builds that one). Only the connection frame's carries a target. Everything
// after the first '/' is the device URL, passed on verbatim.
//
// Flags live in the fragment, so the signaling server never sees them:
// debug, nocookiejar, relay, norelay, msg_timeout=<seconds>, and the rest in
// CONVENTIONS.md. A flag without a value is true.
//
// parseFragment takes the hash as given, with or without its '#', and reads
// nothing else: callers pass location.hash when they want the current one
// (it changes with history.replaceState).
function parseFragment(hash) {
    const frag = (hash || '').replace(/^#/, '');
    let i = 0;
    while (i < frag.length && /[A-Za-z0-9_-]/.test(frag[i])) i++;
    const head = frag.slice(0, i);

    let target = '';
    if (frag[i] === '@') {
        const start = ++i;
        while (i < frag.length && frag[i] !== '!' && frag[i] !== '/') i++;
        const raw = frag.slice(start, i);
        try { target = decodeURIComponent(raw); } catch (e) { target = raw; }
    }

    // With its '!', as it goes back into a URL.
    let flagString = '';
    if (frag[i] === '!') {
        const start = i;
        while (i < frag.length && frag[i] !== '/') i++;
        flagString = frag.slice(start, i);
    }
    const flags = {};
    for (const tok of flagString.slice(1).split(',')) {
        if (!tok) continue;
        const eq = tok.indexOf('=');
        if (eq >= 0) flags[tok.slice(0, eq)] = tok.slice(eq + 1);
        else flags[tok] = true;
    }

    return { head, target, flagString, flags, ...splitDeviceURL(frag.slice(i)) };
}

// The current URL's flags.
function parseUrlFlags() {
    return parseFragment(self.location.hash).flags;
}

// A device URL, '' or '/path?query#hash', in its three parts. The path is
// '/' when there is none.
function splitDeviceURL(rest) {
    if (!rest) return { devicePath: '/', deviceSearch: '', deviceHash: '' };
    const h = rest.indexOf('#');
    const deviceHash = h >= 0 ? rest.slice(h) : '';
    const beforeHash = h >= 0 ? rest.slice(0, h) : rest;
    const q = beforeHash.indexOf('?');
    return {
        devicePath: (q >= 0 ? beforeHash.slice(0, q) : beforeHash) || '/',
        deviceSearch: q >= 0 ? beforeHash.slice(q) : '',
        deviceHash,
    };
}

// A proxied app's LAN target as the path prefix it is to the device,
// '/<target>', or '' for a device that routes the whole path itself.
function targetPrefix(target) {
    return target ? '/' + target : '';
}

// -- WebRTC ------------------------------------------------------------------

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

// Buffer ICE candidates that arrive (or are produced) before the remote
// description is set, then drain them in arrival order. Used by both the
// device connection (connection.js) and pairing (PairingFlow in
// bootstrap.js) -- the readiness gate lives at the call site because each
// flow tracks remote-description state and ws-open state differently.
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

// -- Between the label worker and the connection frame -----------------------

// How much of a request body the worker may hand the connection frame beyond
// what the frame has sent on to the device. Both start with it; the frame
// raises the limit with upload_credit as it sends.
const UPLOAD_CREDIT = 1 << 20;
