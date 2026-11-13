/**
 * BitBang label worker
 *
 * The service worker of one device origin, https://<label>.<host>/. See
 * bitbang-docs/device-origins.md.
 *
 * It serves exactly one device -- whichever this origin is -- so there is no
 * session to find: every request from a device page goes to a connection
 * frame of this origin (connection.js, at /__bb/start), which carries it over
 * the data channel. Paths are the device's own, unprefixed.
 *
 * What it serves itself, it fetches from the network, never from storage
 * (device-origins.md, property 6): every script in this origin can write the
 * Cache API, and anything of ours served from there would be theirs on every
 * later visit. Storage holds data only -- the cookie jar.
 *
 * What it refuses:
 *   - a top-level document: this origin is only ever framed. The network
 *     answers it with a page saying to open the device from its link.
 *   - a navigation it can't attribute to its own frames (attributable): a
 *     page that knows this origin's label could otherwise make the browser
 *     send the device requests over this tab's connection.
 */

// BUILD is spliced in by the server as this file is served (see
// handler.buildStamp). Every asset in a given deploy carries the same
// value, so a page whose copy differs from ours is running older code.
const BUILD = '__BB_BUILD__';

console.log('[label-sw] booted', BUILD);

// What this worker shares with the connection frame (UPLOAD_CREDIT). At the
// top, as importScripts has to be: a worker can only import while it first
// runs.
importScripts('/__bitbang__/runtime-common.js');

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

// bitba.ng's host: this one without the label. The only origin that may frame
// anything here (with this one between).
const PARENT_HOST = self.location.host.slice(self.location.host.indexOf('.') + 1);

// The connection frame's document. Never a device path.
const START_PATH = '/__bb/start';

// -- Persisted maps ----------------------------------------------------------
//
// A Map kept in the Cache API, so SW idle-termination (Chrome ~30s) doesn't
// lose it. Here only the cookie jar uses one; the helper is sw.js's, kept
// whole because its ordering rules are subtle and already right.
//
// Every save writes a FULL snapshot, so two saves landing out of order would
// revert the whole table, not just lose one entry. So the writes are chained,
// each taking its snapshot when its turn comes: the last write is of the
// latest table, never an older one.
//
// The chain starts behind the load. Nothing stops a save while the map is
// still loading -- rememberClientSession doesn't wait, and on a cold start it
// is often first -- and a snapshot taken then would write a table missing
// everything persisted. For the same reason the load doesn't overwrite an
// entry set while it ran: that entry is newer than the persisted one.
//
// revive and forSave are per entry, and return undefined to drop it. Pruning
// stays with the callers: what to evict is a judgment about what entries
// mean, and it differs in kind between the three.
//
// save returns the write, for keepAlive() -- an unawaited cache.put is dropped
// outright if the SW is terminated first.
function persistedMap(cacheName, key, { revive = (v) => v, forSave = (v) => v } = {}) {
    const map = new Map();
    const ready = (async () => {
        try {
            const cache = await caches.open(cacheName);
            const resp = await cache.match(key);
            if (!resp) return;
            const data = await resp.json();
            if (!data || typeof data !== 'object') return;
            for (const [k, v] of Object.entries(data)) {
                if (map.has(k)) continue;
                const entry = revive(v);
                if (entry !== undefined) map.set(k, entry);
            }
        } catch (e) {}
    })();
    function snapshot() {
        const data = {};
        for (const [k, v] of map) {
            const entry = forSave(v);
            if (entry !== undefined) data[k] = entry;
        }
        return JSON.stringify(data);
    }
    let chain = ready;
    function save() {
        chain = chain
            .then(() => caches.open(cacheName))
            .then(cache => cache.put(key, new Response(snapshot(), {
                headers: { 'Content-Type': 'application/json' },
            })))
            .catch(() => {});
        return chain;
    }
    return { map, ready, save };
}

// -- Messages from pages -------------------------------------------------------
//
// The whole vocabulary of the page <-> worker channel. Pages post to the
// worker; replies go back on the MessagePort the page sent, if any. Every
// sender is a page of this origin -- nothing else can reach this worker -- and
// so could be device script; nothing here trusts what it is told beyond this
// one device.
//
//   get_build         page -> worker   reply on port: build { build }
//   config            connection.js    { debug, noCookieJar }
//   alive             connection.js    {}, every minute (sweepSessionCookies)
//   get_cookies       ws-shim.js       { path }; reply on port: { cookies }
//                                      (no type)
//   cookie_write      device-shim.js   { value }
//   keepalive         connection.js    {}, while a proxied request is open
//
// And the other direction, worker -> connection.js: connection_state, asked
// on a port before choosing a connection frame (pickConnection), and for each
// request it proxies (proxyToDevice): proxy_request, then on that request's
// own port upload_chunk / upload_end, proxy_consumed { bytes } and
// proxy_cancel from the worker, and proxy_headers, proxy_chunk, proxy_end,
// proxy_error and upload_credit { max } back from connection.js.

// How long one keepalive holds the worker. connection.js sends one at most
// every 10s while data is moving (SW_KEEPALIVE_MS there), so 25s leaves room
// for a late one -- a hidden tab's timers can run late -- while staying well
// under Chrome's 5-minute cap on any single event.
const KEEPALIVE_HOLD_MS = 25000;

// Settings from the connection frame, for the tab's flags. In memory: a
// worker that restarts forgets them, which costs a debug log or the
// !nocookiejar flag until the next page load, nothing more.
let config = { debug: false, noCookieJar: false };

// The cookie jar's one partition. The jar used to be keyed by uid:target,
// one partition per device, because every device shared bitba.ng's origin;
// this origin is one device's, so the browser does the partitioning. The key
// stays, constant, because the shim's broadcast listener filters on it.
const JAR_KEY = 'device';

self.addEventListener('message', async (event) => {
    const type = event.data?.type;
    // A response this worker streams is fed over a MessagePort, and port
    // traffic is not an event: nothing else tells the browser the worker is
    // busy. Firefox stops it inside 45s of quiet and the response ends short,
    // as if complete (keepWorkerAlive in connection.js has the measurements).
    // Each keepalive holds the worker a little longer than the gap to the
    // next, so the holds overlap. Before any await: waitUntil is only
    // accepted while the event is being dispatched.
    if (type === 'keepalive') {
        event.waitUntil(new Promise(r => setTimeout(r, KEEPALIVE_HOLD_MS)));
        return;
    }
    // Answered on the port the page supplied, so it works before we
    // control the page (a claim may not have landed yet).
    if (type === 'get_build') {
        event.ports[0]?.postMessage({ type: 'build', build: BUILD });
        return;
    }
    if (type === 'config') {
        config = { debug: !!event.data.debug, noCookieJar: !!event.data.noCookieJar };
        return;
    }
    if (type === 'alive') {
        keepAlive(event, noteAlive());
        return;
    }
    if (type === 'get_cookies') {
        // ws-shim asks for the Cookie header for a WebSocket's path. The jar
        // is canonical: document.cookie can be stale, since Set-Cookie is
        // stripped from responses.
        const port = event.ports?.[0];
        if (!port) return;
        await cookieJarReady;
        const path = String(event.data.path || '/').split('?')[0];
        port.postMessage({ cookies: config.noCookieJar ? '' : (getCookieHeader(JAR_KEY, path) || '') });
        return;
    }
    if (type === 'cookie_write') {
        // App code wrote document.cookie. Mirror into the jar so the next
        // outbound request includes it.
        if (typeof event.data.value !== 'string') return;
        await cookieJarReady;
        keepAlive(event, storeCookies(JAR_KEY, event.data.value));
    }
});

// Flow between this worker and connection.js, per proxied request (see
// proxyToDevice).
//
// UPLOAD_CREDIT (runtime-common.js): how much of a request body may be
// handed over beyond what connection.js has sent on. connection.js raises
// the limit with upload_credit.
//
// CONSUMED_REPORT_BYTES: how much of a response the reader takes before it is
// reported back as consumed. connection.js returns credit to the device a
// half window (512 KiB) at a time, so this only has to be well under that.
//
// BUFFERED_BODY_PIECE: the size a body that had to be read whole (no
// Request.body: Firefox) is handed over in.
const CONSUMED_REPORT_BYTES = 64 * 1024;
const BUFFERED_BODY_PIECE = 256 * 1024;

// -- Cookie jar (persisted to Cache API) -------------------------------------

// JAR_KEY -> [cookie], one partition: this origin is one device's. Loaded on
// worker startup; cookieJarReady is awaited before a request is sent, so the
// first one carries its cookies.
//
// Data only, in storage every script here can read and write
// (device-origins.md, "Cookies"): HttpOnly keeps a cookie out of the
// document.cookie mirror, but not out of reach of device script. What reaches
// the page from here goes through jsonForScript.
const {
    map: cookieJar, ready: cookieJarReady, save: saveCookieJar,
} = persistedMap('bitbang-cookies', '/__bitbang__/cookie-jar', {
    revive: reviveCookies,
    forSave: unexpiredCookies,
});

// A bound on the jar. Without one it only ever grew: entries leave when a
// cookie's own expiry passes, and a session cookie (expires === null) has
// none. The oldest go first.
const MAX_JAR_COOKIES = 500;

function pruneCookieJar() {
    const jar = cookieJar.get(JAR_KEY);
    if (!jar || jar.length <= MAX_JAR_COOKIES) return false;
    jar.splice(0, jar.length - MAX_JAR_COOKIES);
    return true;
}

// Discard session cookies when this device no longer has a tab open.
//
// Session cookies are the ones a browser drops at the end of a browsing
// session, and this is the equivalent moment: the last tab on this device is
// gone. Cookies with an explicit expiry survive, exactly as they would in a
// normal browser, so "remember me" still works.
//
// Called when a connection frame starts, finds no other, and none has been
// alive for a while (sweepSessionCookies) -- never on a page going away: a
// refresh is a page going away and a new one starting, and dropping then
// would log people out on every reload.
function dropSessionCookies() {
    let changed = false;
    for (const [key, cookies] of [...cookieJar]) {
        const keep = cookies.filter(c => c.expires !== null);
        if (keep.length === cookies.length) continue;
        changed = true;
        if (keep.length > 0) {
            cookieJar.set(key, keep);
        } else {
            cookieJar.delete(key);
        }
    }
    return changed;
}

// One partition as it comes out of the cache, normalized rather than trusted.
//
// The persisted shape has already changed once (httpOnly was added), and a
// partial or corrupt write is possible. Without this, a non-array value makes
// every later jar.filter/findIndex throw -- inside the response handler,
// where an uncaught throw can leave the request promise unsettled and hang
// the fetch. One bad entry would break cookies permanently until the user
// cleared site data.
function reviveCookies(cookies) {
    if (!Array.isArray(cookies)) return undefined;
    const clean = [];
    for (const c of cookies) {
        if (!c || typeof c.name !== 'string' || typeof c.value !== 'string') continue;
        clean.push({
            name: c.name,
            value: c.value,
            path: typeof c.path === 'string' && c.path ? c.path : '/',
            expires: typeof c.expires === 'number' ? c.expires : null,
            httpOnly: !!c.httpOnly,
        });
    }
    // Expired ones are dropped on the way in as well as on the way out, or
    // the two sides disagree and an expired cookie is resurrected on restart.
    return unexpiredCookies(clean);
}

// One partition without its expired cookies; undefined if that leaves none.
function unexpiredCookies(cookies) {
    const now = Date.now();
    const valid = cookies.filter(c => c.expires === null || c.expires > now);
    return valid.length > 0 ? valid : undefined;
}

// Hold the service worker alive until an async persistence write settles.
// Chrome terminates an idle SW ~30s after the last event; without this a
// cache.put issued while responding can simply never run, silently
// reverting the persisted jar to an older state.
//
// Takes a FetchEvent or an ExtendableMessageEvent.
function keepAlive(event, promise) {
    try {
        if (typeof event?.waitUntil === 'function') event.waitUntil(promise);
    } catch (e) {
        // waitUntil throws if the event is no longer active. The write is
        // already in flight either way; losing the keepalive is not fatal.
    }
    return promise;
}

// Browsers cap cookie lifetime at 400 days (RFC 6265bis; Chrome 104+).
// The jar clamps to the same ceiling so it is never MORE permissive than
// the browser the app would be talking to directly -- a proxy whose cookies
// outlive the origin's own rules is a bug, not a feature.
//
// This also contains a real bug class: servers that put an absolute Unix
// timestamp in Max-Age, which is defined as a relative duration in seconds.
// Frigate does exactly this -- it sends Max-Age=<the JWT's own exp claim>,
// so Date.now() + maxAge*1000 lands ~57 years out. Unclamped, the jar keeps
// replaying a token that actually died 24 hours in and never expires it,
// producing an authenticated-looking session that 401s on every request and
// does not self-heal across reloads.
const MAX_COOKIE_LIFETIME_MS = 400 * 24 * 60 * 60 * 1000;

function parseCookie(setCookieStr) {
    const parts = setCookieStr.split(';').map(p => p.trim());
    const [nameValue, ...attrs] = parts;
    const eqIdx = nameValue.indexOf('=');
    if (eqIdx < 0) return null;

    const cookie = {
        name: nameValue.substring(0, eqIdx),
        value: nameValue.substring(eqIdx + 1),
        // KNOWN DIVERGENCE FROM RFC 6265 §5.1.4 -- deliberate, do not
        // "fix" casually. The spec's default-path is the directory of the
        // request URI (a Set-Cookie with no Path from /app/x defaults to
        // /app); we default to "/" instead, because parseCookie has no
        // access to the request path.
        //
        // Consequences, both currently latent:
        //   - Over-sharing: a cookie scoped to /app/ is sent to every path
        //     of this origin. Contained -- the origin is one device's (one
        //     LAN host's, for the CLI), so it cannot cross hosts or devices,
        //     only paths on one host.
        //   - Dedupe collision: storeCookies keys on (name, path), so two
        //     same-named cookies legitimately scoped to /a/ and /b/ both
        //     land at "/" and clobber each other.
        //
        // Left alone on purpose: correcting it NARROWS cookie scope, which
        // can only break apps that work today, and there is no coverage
        // against real apps to catch that. Reviewed 2026-07-30 -- no
        // observed misbehaviour, so it stays until an actual bug points
        // here. If you do fix it, thread the request path in from
        // storeCookies' caller and expect to retest every proxied app.
        path: '/',
        expires: null,
        // Tracked so the jar can keep HttpOnly cookies out of the
        // document.cookie mirror. See "HttpOnly invariant" below.
        httpOnly: false,
    };

    for (const attr of attrs) {
        // Split on the FIRST '=' only. attr.split('=') would truncate any
        // attribute value that itself contains '=' (e.g. Path=/a=b).
        const eq = attr.indexOf('=');
        const k = (eq < 0 ? attr : attr.slice(0, eq)).trim();
        const v = eq < 0 ? undefined : attr.slice(eq + 1).trim();
        const kl = k.toLowerCase();
        if (kl === 'path') {
            cookie.path = v || '/';
        } else if (kl === 'max-age') {
            const sec = parseInt(v, 10);
            if (!isNaN(sec)) cookie.expires = Date.now() + sec * 1000;
        } else if (kl === 'expires' && cookie.expires === null) {
            const d = new Date(v);
            if (!isNaN(d.getTime())) cookie.expires = d.getTime();
        } else if (kl === 'httponly') {
            cookie.httpOnly = true;
        }
    }

    // Clamp to the browser's 400-day ceiling. Applied after the attribute
    // loop so it covers both Max-Age and Expires.
    if (cookie.expires !== null) {
        const ceiling = Date.now() + MAX_COOKIE_LIFETIME_MS;
        if (cookie.expires > ceiling) cookie.expires = ceiling;
    }
    return cookie;
}

// -- HttpOnly invariant ------------------------------------------------------
//
// HttpOnly cookies live ONLY in the SW jar. They are attached to outbound
// requests (getCookieHeader, and the WebSocket upgrade via the get_cookies
// message) but are never written into document.cookie by any of the three
// mirror paths: the per-response X-BB-Set-Cookie header, the parse-time
// cookieSync injection, and the cross-tab BroadcastChannel.
//
// Rationale: the mirror exists so app code can read values it legitimately
// reads (CSRF tokens and the like). App code by definition never reads an
// HttpOnly cookie, so mirroring one buys nothing -- and costs the protection,
// because the browser ignores the HttpOnly attribute on a document.cookie
// write, turning a protected session token into a JS-readable one. For a
// proxied app that means XSS could exfiltrate a session it could not have
// touched on the origin site.
//
// Note: jars persisted before this flag existed have httpOnly === undefined
// (falsy), so their cookies keep mirroring until the app re-issues them.
function isMirrorable(cookie) {
    return !cookie.httpOnly;
}

// The jar's cookies as device-shim.js writes them into document.cookie:
// unexpired, HttpOnly left out (the invariant above), each a
// "name=value;path=...[;expires=...]" string. Both of the worker's mirror
// sources use it, the preamble's window.__bbCookies and the BroadcastChannel,
// so the shim writes one form whichever told it. The expiry goes with each:
// without it every mirrored cookie would be a session one.
function mirrorStrings(jarKey) {
    const now = Date.now();
    return (cookieJar.get(jarKey) || [])
        .filter(c => (c.expires === null || c.expires > now) && isMirrorable(c))
        .map(c => c.name + '=' + c.value + ';path=' + c.path
            + (c.expires !== null ? ';expires=' + new Date(c.expires).toUTCString() : ''));
}

// Serialize a value for embedding inside an inline <script> element.
//
// JSON.stringify alone is NOT safe here. It produces a valid JS literal but
// does not escape "<", and the HTML parser terminates a script block at the
// first "</script" sequence regardless of JS string context. A cookie whose
// value contains "</script><img src=x onerror=...>" would therefore close
// the shim's script tag and inject arbitrary markup into the device page.
//
// That path is reachable: app code writing document.cookie is mirrored into
// the jar via the cookie_write message, and the jar is replayed into every
// subsequent HTML navigation by cookieSync. So an XSS inside a proxied app
// could otherwise escalate into persistent injection into every later page
// of the app -- and persist across sessions, because the jar lives in the
// Cache API. (Device script can write the jar directly too; it stays within
// its own device's pages either way.)
//
// Escaping "<" closes both "</script" and "<!--". U+2028/U+2029 are escaped
// because they are literal line terminators in JS source.
function jsonForScript(value) {
    return JSON.stringify(value)
        .replace(/</g, '\\u003c')
        .replace(/\u2028/g, '\\u2028')
        .replace(/\u2029/g, '\\u2029');
}

// Returns the persistence promise so callers can keepAlive() it. Always
// returns a promise, including on the no-op path.
function storeCookies(jarKey, setCookieHeaders) {
    if (!setCookieHeaders) return Promise.resolve();
    const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];

    if (!cookieJar.has(jarKey)) cookieJar.set(jarKey, []);
    const jar = cookieJar.get(jarKey);

    for (const h of headers) {
        const cookie = parseCookie(h);
        if (!cookie) continue;

        const idx = jar.findIndex(c => c.name === cookie.name && c.path === cookie.path);
        if (idx !== -1) jar.splice(idx, 1);

        if (cookie.value === '' || cookie.value === '""') continue;
        if (cookie.expires !== null && cookie.expires <= Date.now()) continue;

        jar.push(cookie);
    }

    pruneCookieJar();
    return saveCookieJar();
}

function getCookieHeader(jarKey, requestPath) {
    const jar = cookieJar.get(jarKey);
    if (!jar || jar.length === 0) return null;

    const now = Date.now();
    const valid = jar.filter(c => {
        if (c.expires !== null && c.expires <= now) return false;
        if (!requestPath.startsWith(c.path)) return false;
        if (!c.path.endsWith('/')) {
            const remainder = requestPath.substring(c.path.length);
            if (remainder !== '' && !remainder.startsWith('/')) return false;
        }
        return true;
    });

    let pruned = false;
    for (let i = jar.length - 1; i >= 0; i--) {
        if (jar[i].expires !== null && jar[i].expires <= now) {
            jar.splice(i, 1);
            pruned = true;
        }
    }
    // Persist the prune. Previously this read path mutated the in-memory jar
    // and left the cache untouched, so the two drifted apart.
    if (pruned) saveCookieJar();

    if (valid.length === 0) return null;
    valid.sort((a, b) => b.path.length - a.path.length);
    return valid.map(c => `${c.name}=${c.value}`).join('; ');
}

// -- Fetch handler -----------------------------------------------------------

// Ours, from the network: the start page and the runtime under /__bitbang__/.
// Everything else on this origin is the device's.
function isOurs(pathname) {
    return pathname === START_PATH || pathname.startsWith('/__bitbang__/');
}

// A meta-page: /*settings, /*console, /*ota. The shell is ours; what it shows
// comes from the device, through this worker like any device page's fetches.
const META_PATH = /^\/\*([A-Za-z0-9_-]+)$/;

// The destinations a frame navigation can have.
const FRAME_DESTINATIONS = new Set(['iframe', 'frame', 'object', 'embed']);

self.addEventListener('fetch', (event) => {
    const req = event.request;
    const url = new URL(req.url);
    if (url.origin !== self.location.origin) return;

    // Top level: a link opened in a new tab, a page busting out of its frame,
    // or another site sending someone here. This origin is only ever framed,
    // and has nothing to show on its own. The network's answer says so
    // (label.go), whatever the path.
    if (req.mode === 'navigate' && req.destination === 'document') {
        event.respondWith(fetch(req).catch(() => new Response(
            'Open this device from its BitBang link.', { status: 404 })));
        return;
    }

    if (isOurs(url.pathname)) {
        // A connection frame starting with no other open: the last tab on this
        // device closed since the one before, so its session cookies go, as a
        // browser's do when its last window closes.
        if (url.pathname === START_PATH && req.mode === 'navigate') {
            event.waitUntil(sweepSessionCookies(event));
        }
        // A navigation is answered, from the network, rather than left to
        // fall through: Firefox leaves a page this worker declined to answer
        // uncontrolled, and a connection frame that isn't controlled waits
        // for a controller that never comes, then reloads itself for nothing.
        // Measured Nov 9; Chromium and WebKit control it either way.
        if (req.mode === 'navigate') event.respondWith(fetch(req));
        return;      // a subresource: the network, untouched
    }

    if (req.mode === 'navigate' && FRAME_DESTINATIONS.has(req.destination)) {
        event.respondWith(attributable(event).then((ok) => {
            if (!ok) {
                console.warn('[label-sw] refused a navigation from outside this origin:', url.pathname);
                return new Response('BitBang: this page can only be opened from its own device page.',
                    { status: 403, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
            }
            const meta = url.pathname.match(META_PATH);
            if (meta) return serveMetaPage(meta[1]);
            return proxyToDevice(event);
        }));
        return;
    }

    // A subresource. Its client is a page of this origin, or it would not be
    // ours to handle: a fetch is handled by the requesting page's worker, so
    // another site's request for a URL here never reaches this one.
    event.respondWith(proxyToDevice(event));
});

// attributable says whether a frame navigation came from this origin's own
// pages. Any page that knows the label can make the browser navigate a frame
// here -- an iframe of its own, a form with a target -- and frame-ancestors
// only stops the response from rendering, after the request has gone. So the
// worker decides before anything reaches the device (device-origins.md,
// property 7).
//
// Evidence, strongest first:
//   - clientId: the page that started the navigation, if the browser says
//     (Chromium does; Firefox gives navigations an empty one). A client this
//     worker can see is a page of this origin.
//   - referrer: same-origin. Label responses carry Referrer-Policy:
//     same-origin, and so do device pages (proxyToDevice sets it), so this
//     origin's own navigations name it. Another site's carry that site, or
//     nothing.
//   - neither: a navigation that suppressed its referrer (rel=noreferrer,
//     a no-referrer policy) and has no client. Allowed only as a GET, so
//     nothing is submitted; the response still renders only under the
//     parent (frame-ancestors). A GET that changes state on a device is
//     left as the residual risk, and the label being hard to guess as its
//     mitigation.
async function attributable(event) {
    const req = event.request;
    if (event.clientId) {
        const c = await self.clients.get(event.clientId);
        if (c) return true;
    }
    if (req.referrer) {
        try { return new URL(req.referrer).origin === self.location.origin; } catch { return false; }
    }
    return req.method === 'GET';
}

// Session cookies end with the device's last tab -- but a reload is a tab
// ending and another starting, and must not log anyone out. So "the last tab
// closed" is measured, not inferred: connection frames say they are alive
// every ALIVE_EVERY_MS (connection.js), and the time is kept here. A frame
// starting with no other open, more than SESSION_GAP_MS after the last sign
// of one, is a new session. A reload, or a tab closed and reopened within a
// few minutes, keeps them -- as a browser restoring its session would.
const SESSION_GAP_MS = 5 * 60 * 1000;
const ALIVE_CACHE = 'bitbang-cookies';
const ALIVE_KEY = '/__bitbang__/alive';

function noteAlive() {
    return caches.open(ALIVE_CACHE)
        .then(c => c.put(ALIVE_KEY, new Response(String(Date.now()))))
        .catch(() => {});
}

async function lastAlive() {
    try {
        const r = await (await caches.open(ALIVE_CACHE)).match(ALIVE_KEY);
        return r ? Number(await r.text()) || 0 : 0;
    } catch {
        return 0;
    }
}

async function sweepSessionCookies(event) {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const others = all.filter(c => c.id !== event.resultingClientId
        && new URL(c.url).pathname === START_PATH);
    if (others.length === 0 && Date.now() - await lastAlive() > SESSION_GAP_MS) {
        await cookieJarReady;
        if (dropSessionCookies()) await saveCookieJar();
    }
    await noteAlive();
}

// pickConnection finds the connection frame to carry a request: this origin's
// window clients at /__bb/start, asked whether they are connected. Two tabs on
// one link have two, both the same device at the same access level. A
// connected one is preferred over one reconnecting or waiting on a PIN, then
// the focused one, then a visible one -- most likely the tab the request came
// from, since the worker can't see which frame holds which.
async function pickConnection() {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const frames = all.filter(c => {
        try { return new URL(c.url).pathname === START_PATH; } catch { return false; }
    });
    if (frames.length === 0) return null;
    if (frames.length === 1) return frames[0];
    const states = await Promise.all(frames.map(askConnected));
    const rank = (c, connected) => (connected ? 4 : 0) + (c.focused ? 2 : 0)
        + (c.visibilityState === 'visible' ? 1 : 0);
    let best = null, bestRank = -1;
    frames.forEach((c, i) => {
        const r = rank(c, states[i]);
        if (r > bestRank) { best = c; bestRank = r; }
    });
    return best;
}

// Whether a connection frame says it is connected. A frame that doesn't
// answer -- a content frame that loaded the start page and did not start, or
// one mid-reload -- counts as not.
function askConnected(client) {
    return new Promise((resolve) => {
        const ch = new MessageChannel();
        const timer = setTimeout(() => resolve(false), 300);
        ch.port1.onmessage = (e) => { clearTimeout(timer); resolve(!!e.data?.connected); };
        try {
            client.postMessage({ type: 'connection_state' }, [ch.port2]);
        } catch {
            clearTimeout(timer);
            resolve(false);
        }
    });
}

// The response headers that decide where a device page may be framed. The
// device's own, written for an app at its own address, almost always say "not
// framed by anyone but me" (X-Frame-Options: SAMEORIGIN, frame-ancestors
// 'self'). Here the page is framed by the connection frame and bitba.ng, so
// they would blank it. They are replaced by this origin's own rule, the same
// one label.go sends: the parent, with this origin between. The rest of a
// device's CSP stands.
function reframe(headers) {
    for (const k of Object.keys(headers)) {
        const kl = k.toLowerCase();
        if (kl === 'x-frame-options') {
            delete headers[k];
        } else if (kl === 'content-security-policy' && typeof headers[k] === 'string') {
            const kept = headers[k].split(';').map(d => d.trim())
                .filter(d => d && !/^frame-ancestors\b/i.test(d));
            if (kept.length) headers[k] = kept.join('; ');
            else delete headers[k];
        }
    }
    return [`frame-ancestors 'self' ${PARENT_HOST}`];
}

async function serveMetaPage(name) {
    // A fetch issued from inside a service worker does not re-enter its own
    // fetch handler, so this reaches the network normally.
    const r = await fetch(`/__bitbang__/${name}.html`, { cache: 'no-cache' });
    if (!r.ok) {
        /* The server's body names what it does have, and is passed through
           rather than replaced: guessing a plausible name is how someone finds
           out which pages are real, and this worker is no longer in a position
           to tell them. 404 stays a 404 -- no such page -- while anything else
           is the server failing to hand over a page that exists. */
        const why = await r.text().catch(() => '');
        return new Response(why.trim() || `no meta-page named "${name}"`, {
            status: r.status === 404 ? 404 : 502,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
        });
    }
    // ws-shim, because a service worker cannot see a WebSocket handshake at
    // all -- the shim replaces window.WebSocket with a postMessage bridge to
    // the connection frame, and without it a meta-page opening
    // /__bitbang/<type> would dial this origin itself and reach nothing.
    //
    // fetch() needs no shim: it reaches this worker, which sends everything
    // to the device.
    //
    // No cookie replay: a meta-page is ours and has no app cookies to mirror.
    const preamble = '<!DOCTYPE html>'
        + `<script>window.__bbJarKey=null;window.__bbDebug=${!!config.debug};</script>`
        + '<script src="/__bitbang__/device-shim.js"></script>'
        + '<script src="/__bitbang__/ws-shim.js"></script>';

    const body = preamble + await r.text();
    const headers = new Headers({
        'Content-Type': 'text/html; charset=utf-8',
        'Referrer-Policy': 'same-origin',
    });
    headers.append('Content-Security-Policy', `frame-ancestors 'self' ${PARENT_HOST}`);
    return new Response(body, { status: 200, headers });
}

/**
 * Proxy a request through a connection frame's data channel. The path is the
 * device's own; connection.js puts a proxied app's target back on.
 */
async function proxyToDevice(event) {
    const url = new URL(event.request.url);
    const devicePath = url.pathname;

    // -- Find a connection frame --
    //
    // includeUncontrolled because Chrome may drop worker->client control
    // after idle, with the page still alive and its connection working.
    const connection = await pickConnection();

    if (config.debug) console.log(`[label-sw] ${event.request.method} ${devicePath} -> connection: ${!!connection}`);

    if (!connection) {
        console.warn('[label-sw] no connection frame');
        return new Response('BitBang: no connection', { status: 503 });
    }

    // -- Build request with cookies --
    const jarKey = JAR_KEY;
    const session = config;
    const channel = new MessageChannel();
    const hasBody = event.request.method !== 'GET' && event.request.method !== 'HEAD';

    // Request.body is not available everywhere: Firefox does not support it in
    // any version, Samsung Internet gained it in 20, Chrome in 105. Without a
    // fallback the body was simply never sent -- the request went out empty and
    // the server rejected it, which looked like a login failure rather than a
    // missing body. Buffer it in that case; there is no streaming option there.
    let bufferedBody = null;
    if (hasBody && !event.request.body) {
        try {
            bufferedBody = new Uint8Array(await event.request.arrayBuffer());
        } catch (e) {
            // Nothing readable. Send an empty body rather than hanging: the
            // request still has to be completed or the page waits forever.
            bufferedBody = new Uint8Array(0);
        }
    }

    // Buffering has one upside: the exact size is known, so the listener can
    // send a real Content-Length instead of chunked encoding. The streaming
    // path has to fall back to the header, which browsers do not expose to a
    // service worker -- so it is usually absent and the request goes chunked.
    const contentLength = bufferedBody !== null ? bufferedBody.byteLength : parseInt(
        event.request.headers.get('content-length') ||
        event.request.headers.get('x-file-size') ||
        '0', 10
    );

    const reqHeaders = Object.fromEntries(event.request.headers);
    if (!session.noCookieJar) {
        await cookieJarReady;
        const appCookies = getCookieHeader(jarKey, devicePath);
        if (appCookies) {
            reqHeaders['cookie'] = appCookies;
        } else {
            delete reqHeaders['cookie'];
        }
    } else {
        delete reqHeaders['cookie'];
    }

    connection.postMessage({
        type: 'proxy_request',
        url: url.origin + devicePath + url.search,
        method: event.request.method,
        headers: reqHeaders,
        hasBody,
        contentLength
    }, [channel.port2]);

    // How much of the body this worker may hand over beyond what connection.js
    // has put on the data channel. It starts at UPLOAD_CREDIT and connection.js
    // raises it (upload_credit) as pieces go out. Before, the whole body was
    // read as fast as it could be and queued in the page, so an upload
    // over a slow link sat in the tab's memory.
    const upload = { allowed: UPLOAD_CREDIT, sent: 0, wake: null, stopped: false, reader: null };
    const wakeUpload = () => { const w = upload.wake; upload.wake = null; w?.(); };
    const stopUpload = () => {
        upload.stopped = true;
        wakeUpload();
        upload.reader?.cancel().catch(() => {});
    };

    // -- Stream response back to browser --
    //
    // The handler goes on the port before the body is sent, so an answer the
    // device gives while the upload is still going -- a 413, a reset -- is
    // acted on rather than queued behind a loop that only ends with the body.
    const response = new Promise((resolve) => {
        let streamController;
        let resolved = false;
        let timeout;
        if (!hasBody) {
            timeout = setTimeout(() => {
                if (!resolved) {
                    resolve(new Response('BitBang: request timeout', { status: 504 }));
                }
            }, 30000);
        }

        // The response body is pulled, not pushed. Chunks wait here until the
        // reader asks for one, and each one handed over is reported back as
        // consumed, which is the credit a v4 session returns to the device.
        // So a reader that stops -- a paused download, a slow disk, a page
        // that reads at its own pace -- stops the device instead of filling
        // this worker. Before, every chunk was enqueued the moment it came,
        // and the stream's queue held whatever the reader had not taken.
        const pending = [];      // arrived, not yet taken by the reader
        let ended = false;       // proxy_end arrived
        let waiting = null;      // resolves the reader's outstanding pull
        let unreported = 0;      // consumed bytes not yet reported
        const report = (now) => {
            if (unreported > 0 && (now || unreported >= CONSUMED_REPORT_BYTES)) {
                channel.port1.postMessage({ type: 'proxy_consumed', bytes: unreported });
                unreported = 0;
            }
        };
        // Hand the reader one chunk if there is one, or close if that was
        // all of them. Reported at once when nothing is left behind it, so
        // the last credit before a lull is never held back.
        const give = (controller) => {
            if (pending.length > 0) {
                const chunk = pending.shift();
                controller.enqueue(chunk);
                unreported += chunk.byteLength;
                report(pending.length === 0);
                return true;
            }
            if (ended) {
                try { controller.close(); } catch (e) {}
                return true;
            }
            return false;
        };
        const answerPull = () => {
            if (waiting && streamController && give(streamController)) {
                const w = waiting;
                waiting = null;
                w();
            }
        };

        channel.port1.onmessage = (msg) => {
            const { type, status, headers, data, message } = msg.data;

            if (type === 'upload_credit') {
                if (msg.data.max > upload.allowed) {
                    upload.allowed = msg.data.max;
                    wakeUpload();
                }
                return;
            }

            if (type === 'proxy_headers') {
                if (timeout) clearTimeout(timeout);
                resolved = true;

                // Store response cookies in our jar (skipped when !nocookiejar is set)
                const setCookie = headers?.['Set-Cookie'] || headers?.['set-cookie'];
                if (setCookie && !session.noCookieJar) {
                    // keepAlive: the jar write is async and the SW can be
                    // terminated the moment this response is done streaming.
                    keepAlive(event, storeCookies(jarKey, setCookie));
                    // Surface cookies via a custom header so device-shim can
                    // sync them into document.cookie *synchronously* in the
                    // same Promise/event chain as the response, before app
                    // code's handler runs. JSON-encoded so multiple Set-Cookie
                    // values round-trip through a single header without
                    // ambiguity from comma joins.
                    //
                    // Strip Domain= so the browser scopes the cookie to the
                    // current document origin (this label) instead of
                    // silently refusing the write when the upstream's Domain
                    // attribute (e.g. octoprint.local, 192.168.1.10) doesn't
                    // match -- or, worse, writing it for bitba.ng itself.
                    const stripCookieAttrs = (s) => s.split(';')
                        .map(p => p.trim())
                        .filter(p => !p.toLowerCase().startsWith('domain='))
                        .join('; ');
                    // HttpOnly cookies are withheld from the mirror entirely
                    // (see "HttpOnly invariant"). They are already in the jar,
                    // so outbound requests still carry them.
                    const isHttpOnlyHeader = (s) => s.split(';').slice(1)
                        .some(p => p.trim().toLowerCase() === 'httponly');
                    const list = (Array.isArray(setCookie) ? setCookie : [setCookie])
                        .filter(s => !isHttpOnlyHeader(s))
                        .map(stripCookieAttrs);
                    if (list.length > 0) {
                        headers['X-BB-Set-Cookie'] = JSON.stringify(list);
                    }
                    // Cross-tab fallback: another tab won't see X-BB-Set-Cookie
                    // (different fetch). The broadcast keeps its document.cookie
                    // eventually consistent. A BroadcastChannel is per origin,
                    // so it reaches this device's pages only.
                    //
                    // It reaches the tab that made this request as well, and
                    // carries the whole jar rather than what just changed.
                    // Both are harmless only because the page writes what it
                    // receives straight to the native cookie setter, never
                    // through the one that forwards to this jar -- see the
                    // cookie section of device-shim.js. When it went through that
                    // one, every cookie here came back without its expiry.
                    const bc = new BroadcastChannel('bitbang-cookies');
                    bc.postMessage({ jarKey, cookies: mirrorStrings(jarKey) });
                    bc.close();
                    delete headers['Set-Cookie'];
                    delete headers['set-cookie'];
                }

                // Redirects need nothing: an absolute-path Location (/login/
                // from OctoPrint's forced login) resolves against this origin,
                // which is the device's.

                // Detect HTML navigation responses for shim injection
                const ct = headers?.['Content-Type'] || headers?.['content-type'] || '';
                // A download is a navigation too, so without this a saved
                // .html file would come out with our script tags in front of
                // it. The CLI's file browser hands its downloads to the
                // browser this way, and other devices' apps can do the same.
                const disposition = headers?.['Content-Disposition']
                    || headers?.['content-disposition'] || '';
                const isAttachment = /^\s*attachment\b/i.test(disposition);
                const isNav = !isAttachment && event.request?.mode === 'navigate';

                const stream = new ReadableStream({
                    start(controller) {
                        streamController = controller;

                        // Inject shims + cookie sync into HTML navigation responses
                        if (ct.includes('text/html') && isNav) {
                            // The jar's cookies, for device-shim.js to mirror
                            // into document.cookie as it starts -- not written
                            // here, because where the browser won't keep
                            // cookies in this frame the shim keeps the mirror
                            // itself, and only it knows which.
                            const cookieSync = session?.noCookieJar ? [] : mirrorStrings(jarKey);

                            const eruda = session?.debug
                                ? '<script src="https://cdn.jsdelivr.net/npm/eruda@3.4.3/eruda.js" integrity="sha384-weDBY9jeIj4NqaiZF9f6PMAMMY4lIu+0CAI+TjBIE73RctCQOxDoEHltYnstRszI" crossorigin="anonymous" onload="eruda.init();eruda.position({x:innerWidth-60,y:innerHeight-60})"></script>'
                                : '';
                            const shims = '<!DOCTYPE html>'
                                + `<script>window.__bbJarKey=${jsonForScript(jarKey)};window.__bbDebug=${!!session?.debug};window.__bbCookies=${jsonForScript(cookieSync)};</script>`
                                + eruda
                                + '<script src="/__bitbang__/device-shim.js"></script>'
                                + '<script src="/__bitbang__/ws-shim.js"></script>';
                            // These two and no more, because these two are the
                            // only ones that have to precede the page's own
                            // script: they replace XMLHttpRequest, popups and
                            // window.WebSocket, which page code may call on its
                            // first line.
                            //
                            // stream-shim.js used to be here and is not code of
                            // that kind -- it patches nothing, and a page loads
                            // it with a script tag like any other library. It
                            // was injected because it was built beside these two
                            // and inherited their delivery. What it cost was 15
                            // KB on every device page including the ones with no
                            // stream element at all, and a second story for how
                            // the library gets into a page, when
                            // settings-panel.js already had the first one.
                            controller.enqueue(new TextEncoder().encode(shims));
                        }
                    },
                    // Called when the reader wants a chunk -- with a high-
                    // water mark of 0, only then. Waits for one to arrive if
                    // none is here yet.
                    pull(controller) {
                        if (give(controller)) return;
                        return new Promise((r) => { waiting = r; });
                    },
                    // The reader is gone: a download cancelled in the browser,
                    // a media element done with a range. connection.js stops the
                    // device sending the rest (in a v4 session; v3 cannot).
                    cancel() {
                        pending.length = 0;
                        channel.port1.postMessage({ type: 'proxy_cancel' });
                    },
                }, { highWaterMark: 0 });

                // CORS headers for fonts with crossorigin attributes. Only
                // this origin's own pages ever see a response from here (a
                // request is handled by the requesting page's worker), so
                // this opens nothing to other sites.
                if (!headers['access-control-allow-origin']) {
                    headers['access-control-allow-origin'] = '*';
                }

                // Where this response may be framed: the device's own rule
                // out, this origin's in (reframe).
                const ours = reframe(headers);
                const out = new Headers();
                for (const [k, v] of Object.entries(headers)) {
                    try { out.set(k, Array.isArray(v) ? v.join(', ') : String(v)); } catch (e) { /* forbidden or malformed */ }
                }
                for (const csp of ours) out.append('Content-Security-Policy', csp);
                // A document of this origin names it in the referrer of the
                // navigations it starts, which is how the worker knows them
                // for its own (attributable). A page's own meta tag or
                // rel=noreferrer can still suppress it; that falls back to
                // GET-only.
                if (isNav) out.set('Referrer-Policy', 'same-origin');

                // 204/304 responses must not have a body per spec
                const nullBodyStatus = (status === 204 || status === 304);
                resolve(new Response(nullBodyStatus ? null : stream, { status, headers: out }));
            } else if (type === 'proxy_chunk') {
                pending.push(data);
                answerPull();
            } else if (type === 'proxy_end') {
                ended = true;
                answerPull();
            } else if (type === 'proxy_error') {
                if (timeout) clearTimeout(timeout);
                stopUpload();
                pending.length = 0;
                if (waiting) { const w = waiting; waiting = null; w(); }
                if (!resolved) {
                    resolve(new Response(`BitBang: ${message}`, { status: 500 }));
                } else {
                    try { streamController?.error(new Error(message)); } catch (e) {}
                }
            }
        };
    });

    // -- Stream request body (if any) --
    if (hasBody) {
        // Hand over one piece once the credit allows; false if the upload
        // was stopped (the device refused it, or the channel went) while
        // waiting.
        const post = async (piece) => {
            while (!upload.stopped && upload.sent >= upload.allowed) {
                await new Promise((r) => { upload.wake = r; });
            }
            if (upload.stopped) return false;
            upload.sent += piece.byteLength;
            channel.port1.postMessage({ type: 'upload_chunk', data: piece }, [piece.buffer]);
            return true;
        };
        if (bufferedBody !== null) {
            // Already all in memory (no Request.body here), so slicing it buys
            // nothing in this worker -- but it keeps connection.js to the same
            // credit as a streamed body. Copies, since each is transferred.
            for (let off = 0; off < bufferedBody.byteLength; off += BUFFERED_BODY_PIECE) {
                if (!(await post(bufferedBody.slice(off, off + BUFFERED_BODY_PIECE)))) break;
            }
        } else if (event.request.body) {
            const reader = event.request.body.getReader();
            upload.reader = reader;
            try {
                while (!upload.stopped) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    if (!(await post(value))) break;
                }
            } catch (e) {
                // Cancelled by stopUpload, or the page went away.
            } finally {
                try { reader.releaseLock(); } catch (e) {}
            }
        }
        if (!upload.stopped) channel.port1.postMessage({ type: 'upload_end' });
    }

    return response;
}
