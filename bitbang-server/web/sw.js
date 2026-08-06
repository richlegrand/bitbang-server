/**
 * BitBang Service Worker
 *
 * Routes requests through the WebRTC data channel to the device.
 * Absolute-path requests (e.g. <script src="/app.js">) are resolved
 * to the active session and proxied directly. XHR/fetch absolute paths
 * are rewritten at the source by xhr-shim.js.
 */

importScripts('/__bitbang__/sw-upload.js');

console.log('[SW] booted');

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

// -- Session tracking --------------------------------------------------------

// Map of sessionId -> { clientId, uid, target }.
// Persisted to Cache API so SW idle-termination (Chrome ~30s) doesn't drop
// session records while the bootstrap window is still alive.
const sessions = new Map();
const SESSIONS_CACHE_KEY = '/__bitbang__/sessions';

// -- Client -> session binding (fix 1c) --------------------------------------
//
// Maps clientId -> sessionId. Recorded when the SW proxies a navigation for
// an already-resolved session: FetchEvent.resultingClientId is the id of the
// client that navigation will create, so the frame that lands can later be
// resolved by IDENTITY instead of by parsing a URL.
//
// Why this exists: xhr-shim.js:44 deliberately strips /__device__/<sid> from
// the iframe's own URL (SPA routers read location.pathname and can't match a
// route with the proxy prefix in it). That erases the routing key from BOTH
// signals the concrete strategies read -- the frame's client.url and the
// referrer it sends. So a short-top-path navigation out of a proxied iframe
// (Frigate's post-login `location.href = '/'`) is structurally unresolvable:
// confirmed live 2026-07-30, sessions map populated, no strategy matched.
//
// A clientId binding is immune to that rewriting, and unlike frameType or
// request.destination it names WHICH session -- so it stays exact with
// several tabs open, instead of degrading to a most-recent guess.
//
// Persisted alongside sessions because SW idle-termination (~30s) is easily
// reached while a user types a password; an in-memory-only binding would be
// gone by the time the login POST completes.
const clientSessions = new Map();
const CLIENT_SESSIONS_CACHE_KEY = '/__bitbang__/client-sessions';

async function loadSessions() {
    try {
        const cache = await caches.open('bitbang-sessions');
        const resp = await cache.match(SESSIONS_CACHE_KEY);
        if (resp) {
            const data = await resp.json();
            const entries = Object.entries(data);
            for (const [sid, sess] of entries) {
                sessions.set(sid, sess);
            }
            if (entries.length > 0) {
                console.log(`[SW] Restored ${entries.length} session(s) from cache`);
            }
        }
        const cresp = await cache.match(CLIENT_SESSIONS_CACHE_KEY);
        if (cresp) {
            const cdata = await cresp.json();
            for (const [cid, sid] of Object.entries(cdata)) {
                clientSessions.set(cid, sid);
            }
        }
    } catch (e) {}
}

// Serialized like the cookie jar: full-snapshot writes that land out of
// order would revert the whole binding table, not just lose one entry.
let clientSessionsSaveChain = Promise.resolve();

function saveClientSessions() {
    const data = {};
    for (const [cid, sid] of clientSessions) data[cid] = sid;
    const body = JSON.stringify(data);
    clientSessionsSaveChain = clientSessionsSaveChain
        .then(() => caches.open('bitbang-sessions'))
        .then(cache => cache.put(CLIENT_SESSIONS_CACHE_KEY,
            new Response(body, { headers: { 'Content-Type': 'application/json' } })
        ))
        .catch(() => {});
    return clientSessionsSaveChain;
}

// Drop bindings whose session is gone, then bound the table. Each navigation
// within a session mints a new clientId, so without a cap a long-lived
// session would grow this without limit. Map preserves insertion order, so
// deleting from the front evicts oldest-first.
const MAX_CLIENT_BINDINGS = 200;

function pruneClientSessions() {
    for (const [cid, sid] of clientSessions) {
        if (!sessions.has(sid)) clientSessions.delete(cid);
    }
    while (clientSessions.size > MAX_CLIENT_BINDINGS) {
        clientSessions.delete(clientSessions.keys().next().value);
    }
}

// Record the binding for a navigation the SW is about to proxy. resultingClientId
// is populated only for navigations, which is exactly when a new client appears.
function rememberClientSession(event, sessionId) {
    const rcid = event?.resultingClientId;
    if (!rcid || !sessionId) return;
    if (clientSessions.get(rcid) === sessionId) return;   // no-op, skip the write
    clientSessions.set(rcid, sessionId);
    pruneClientSessions();
    keepAlive(event, saveClientSessions());
}

function saveSessions() {
    const data = {};
    for (const [sid, sess] of sessions) data[sid] = sess;
    caches.open('bitbang-sessions').then(cache => {
        cache.put(SESSIONS_CACHE_KEY,
            new Response(JSON.stringify(data), {
                headers: { 'Content-Type': 'application/json' }
            })
        );
    }).catch(() => {});
}

const sessionsReady = loadSessions();

self.addEventListener('message', async (event) => {
    if (event.data?.type === 'setBootstrap' && event.data.sessionId) {
        const uid = event.data.uid || '';

        await sessionsReady;

        // Remove stale sessions for the same UID whose client is dead
        // (e.g. page refresh). Preserve live sessions (other tabs).
        for (const [oldSid, oldSess] of sessions) {
            if (oldSess.uid === uid && oldSid !== event.data.sessionId) {
                const oldClient = await self.clients.get(oldSess.clientId);
                if (!oldClient) {
                    sessions.delete(oldSid);
                }
            }
        }

        sessions.set(event.data.sessionId, {
            clientId: event.source.id,
            uid: uid,
            target: event.data.target || 'device',
            // code is the URL-fragment access secret; used by
            // redirectViaActiveSession to build correct 302 targets for
            // popups from proxied apps.
            code: event.data.code || '',
            // lastActive lets redirectViaActiveSession pick the most-
            // recently-used session when multiple are open. Bumped on
            // registration and on every proxied fetch.
            lastActive: Date.now(),
            debug: !!event.data.debug,
            noCookieJar: !!event.data.noCookieJar,
        });
        saveSessions();
        console.log('[SW] Bootstrap registered, session:', event.data.sessionId,
            event.data.noCookieJar ? '(nocookiejar)' : '');
        // Ack so the page knows the session is routable before it creates
        // the iframe (whose first fetch races this message handler).
        event.ports?.[0]?.postMessage({ type: 'bootstrapAck' });
    } else if (event.data?.type === 'unsetBootstrap' && event.data.sessionId) {
        // Best-effort cleanup from pagehide. Don't gate on event.source --
        // it may be null when fired during page unload, and even when it's
        // present, postMessage delivery from a closing page to a possibly-
        // idle SW is unreliable. The findSession sweep below is the
        // authoritative cleanup; this is just a fast path when it works.
        await sessionsReady;
        if (sessions.delete(event.data.sessionId)) {
            saveSessions();
            console.log('[SW] Bootstrap unregistered, session:', event.data.sessionId);
        }
    } else if (event.data?.type === 'getCookies') {
        // Iframe (ws-shim) asks for the current Cookie header value for a path.
        // The SW jar is canonical -- reading document.cookie can be stale
        // because Set-Cookie is stripped from responses.
        const port = event.ports?.[0];
        const session = sessions.get(event.data.sessionId);
        if (!session || !port) {
            port?.postMessage({ cookies: '' });
            return;
        }
        await cookieJarReady;
        const jarKey = `${session.uid}:${session.target}`;
        const path = (event.data.path || '/').split('?')[0];
        port.postMessage({ cookies: getCookieHeader(jarKey, path) || '' });
    } else if (event.data?.type === 'cookieWrite') {
        // App code in iframe wrote document.cookie. Mirror into the jar so
        // the next outbound request includes it.
        const session = sessions.get(event.data.sessionId);
        if (!session) return;
        await cookieJarReady;
        const jarKey = `${session.uid}:${session.target}`;
        keepAlive(event, storeCookies(jarKey, event.data.value));
    }
});

/**
 * Find the session ID for a request. Strategies (in order):
 *
 *   1. Referer contains /__device__/<sessionId>
 *   2. Requesting client's URL contains /__device__/<sessionId>
 *   3. Referer path starts with /<uid> for a known session
 *   4. Single-session fallback (excludes top-level UID paths)
 *   5. Most recent session (sub-resources only)
 */
// Session-resolution strategies, applied in order by findSession. Each
// returns a sessionId on a hit or null on a miss.
//
// `evidence` controls how the strategy interacts with pair-entry paths
// (bare `/` and `/<6-digit>`):
//
//   - 'concrete' — the request carries an explicit `/__device__/<sid>`
//     handle (in its referer or its requesting client's URL). Safe for
//     pair-entry paths: an in-session iframe redirected to `/` still
//     has a `/__device__/<sid>` referer, so we proxy correctly.
//
//   - 'fuzzy' — the strategy infers a session from weaker signals
//     (referer-uid match, single-session fallback, most-recent session).
//     SKIPPED for pair-entry paths: a fresh tab to bitba.ng/ would
//     otherwise leak to whatever session another tab has open.
const SESSION_STRATEGIES = [
    {
        name: 'client-binding',  // clientId recorded when this frame was navigated
        evidence: 'concrete',
        // Strongest signal available and the cheapest (a Map lookup, no
        // await), so it runs first. Concrete because the binding was
        // recorded by the SW itself while proxying a navigation for a
        // known session -- it is not inferred from anything the page
        // controls, and it survives xhr-shim.js:44 rewriting the URL.
        async match({ event }) {
            if (!event.clientId) return null;
            const sid = clientSessions.get(event.clientId);
            return sid && sessions.has(sid) ? sid : null;
        },
    },
    {
        name: 'referer-device',  // referer has /__device__/<sid>
        evidence: 'concrete',
        async match({ referer }) {
            const m = referer.match(/\/__device__\/([^/]+)/);
            return m && sessions.has(m[1]) ? m[1] : null;
        },
    },
    {
        name: 'client-device',  // requesting client's URL has /__device__/<sid>
        evidence: 'concrete',
        async match({ event }) {
            if (!event.clientId) return null;
            const client = await self.clients.get(event.clientId);
            if (!client) return null;
            const m = client.url.match(/\/__device__\/([^/]+)/);
            return m && sessions.has(m[1]) ? m[1] : null;
        },
    },
    {
        name: 'referer-uid',  // referer has /<uid>
        evidence: 'fuzzy',
        async match({ referer }) {
            if (!referer) return null;
            try {
                const refPath = new URL(referer).pathname;
                for (const [sid, sess] of sessions) {
                    if (sess.uid && refPath.startsWith('/' + sess.uid)) return sid;
                }
            } catch (e) {}
            return null;
        },
    },
    {
        name: 'single-session',  // exactly one open session
        evidence: 'fuzzy',
        async match({ isUidPath }) {
            // Excludes top-level UID paths (e.g. /bb29bead...) which
            // need the signaling server to load bootstrap.html, even
            // when the only open session happens to share the UID.
            if (sessions.size === 1 && !isUidPath) {
                return Array.from(sessions.keys())[0];
            }
            return null;
        },
    },
    {
        name: 'most-recent',  // any session → most recent
        evidence: 'fuzzy',
        // Final fallback: covers sub-resource fetches (XHR, fetch, img,
        // …) from contexts whose URL doesn't include /__device__/<sid>
        // — bare-origin iframes the proxied app spawns — and form-POST
        // navigations into hidden iframes (Synology DSM uses this for
        // /webman/login.cgi). Top-level UID-path navigations are already
        // excluded by the isUidPath+navigate early return in findSession,
        // so it's safe to include 'navigate' mode here.
        async match() {
            return sessions.size > 0 ? Array.from(sessions.keys()).pop() : null;
        },
    },
];

async function findSession(event) {
    await sessionsReady;

    // Top-level navigations to /<uid>/... are bootstrap-page loads — they
    // must always reach the signaling server (which serves bootstrap.html),
    // never get proxied to the device. Without this, a page reload while
    // the old bootstrap window is still being torn down can match the
    // stale session via the referer-uid strategy and end up routing the
    // reload through the device, which then 404s.
    //
    // The UID is 22 base64url chars (alphabet [A-Za-z0-9_-]), followed by
    // either end-of-path or "/", so we don't accidentally treat
    // /__device__/... or anything else as a UID path.
    const reqUrl = new URL(event.request.url);
    const isUidPath = /^\/[A-Za-z0-9_-]{22}(\/|$)/.test(reqUrl.pathname);
    if (isUidPath && event.request.mode === 'navigate') return null;

    // Short top-level paths — bare `/`, 6-digit pair codes, and any
    // single-segment lowercase path like `/install`, `/status`, `/health`
    // — share the server-owned namespace. They're resolved against active
    // sessions using concrete-evidence strategies only (referer-device,
    // client-device): an iframe inside a session that redirects to such
    // a path is correctly proxied to the device, but a fresh tab to the
    // same URL reaches the server.
    //
    // The syntactic rule means future server-side utility endpoints
    // (`/install.ps1`, `/docs`, anything similar) route correctly with
    // no SW change required. Convention to preserve: server routes are
    // short, lowercase, single-segment; device-tunneled deep paths can
    // be any shape (they're disambiguated by concrete evidence).
    const isShortTopPath = reqUrl.pathname === '/'
        || /^\/\d{6}$/.test(reqUrl.pathname)
        || /^\/[a-z][a-z0-9_-]*\/?$/.test(reqUrl.pathname);

    // Drop sessions whose owning client is gone. Without this, an
    // auto-fetch (e.g. /favicon.ico right after a refresh) can match a
    // stale uid-keyed entry from a previous page and get routed into
    // the rescue path. The pagehide cleanup is best-effort; this sweep
    // is authoritative.
    let swept = false;
    for (const [sid, sess] of sessions) {
        if (!(await self.clients.get(sess.clientId))) {
            sessions.delete(sid);
            swept = true;
        }
    }
    if (swept) {
        saveSessions();
        // Bindings pointing at a swept session must go too, or a recycled
        // clientId could resolve to a dead session.
        pruneClientSessions();
        saveClientSessions();
    }

    const ctx = {
        event,
        isUidPath,
        referer: event.request.referrer || '',
    };
    for (const strat of SESSION_STRATEGIES) {
        if (isShortTopPath && strat.evidence !== 'concrete') break;
        const sid = await strat.match(ctx);
        if (sid) {
            // Confirmation log for fix 1c. A short top path resolving via
            // client-binding is exactly the case that used to fall through
            // to the signaling server and load bootstrap.html into the
            // iframe. Rare by nature, so it is not noisy -- if this never
            // prints on a post-login navigation, the binding is not being
            // recorded and the fix is inert.
            if (isShortTopPath && strat.name === 'client-binding') {
                console.log('[SW] client-binding resolved short top path',
                    reqUrl.pathname, '->', sid);
            }
            return sid;
        }
    }
    return null;
}

// -- Cookie jar (persisted to Cache API) -------------------------------------

const cookieJar = new Map();
const COOKIE_CACHE_KEY = '/__bitbang__/cookie-jar';

async function loadCookieJar() {
    try {
        const cache = await caches.open('bitbang-cookies');
        const resp = await cache.match(COOKIE_CACHE_KEY);
        if (!resp) return;
        const data = await resp.json();
        if (!data || typeof data !== 'object') return;

        const now = Date.now();
        for (const [key, cookies] of Object.entries(data)) {
            // Normalize on the way in rather than trusting the cache.
            //
            // The persisted shape has already changed once (httpOnly was
            // added), and a partial or corrupt write is possible. Without
            // this, a non-array value here makes every later
            // jar.filter/findIndex throw -- inside the response handler,
            // where an uncaught throw can leave the request promise
            // unsettled and hang the fetch. One bad entry would break
            // cookies permanently until the user cleared site data.
            if (!Array.isArray(cookies)) continue;
            const clean = [];
            for (const c of cookies) {
                if (!c || typeof c.name !== 'string' || typeof c.value !== 'string') continue;
                const expires = typeof c.expires === 'number' ? c.expires : null;
                // Filter expired on the way in, mirroring saveCookieJar's
                // filter on the way out. Without this the two sides
                // disagree and expired cookies get resurrected on restart.
                if (expires !== null && expires <= now) continue;
                clean.push({
                    name: c.name,
                    value: c.value,
                    path: typeof c.path === 'string' && c.path ? c.path : '/',
                    expires,
                    httpOnly: !!c.httpOnly,
                });
            }
            if (clean.length > 0) cookieJar.set(key, clean);
        }
    } catch (e) {}
}

// Serializes jar writes. Every save persists a FULL snapshot, so two
// concurrent saves resolving out of order would revert the whole jar to an
// older state, not just lose one cookie. Chaining guarantees the last
// caller's snapshot is the last one written.
let cookieSaveChain = Promise.resolve();

function saveCookieJar() {
    const data = {};
    const now = Date.now();
    for (const [key, cookies] of cookieJar) {
        const valid = cookies.filter(c => c.expires === null || c.expires > now);
        if (valid.length > 0) data[key] = valid;
    }
    // Serialize synchronously so the snapshot is frozen at call time.
    // Deferring JSON.stringify into the .then would stringify whatever the
    // jar looks like when the promise runs, not when the save was requested.
    const body = JSON.stringify(data);

    cookieSaveChain = cookieSaveChain
        .then(() => caches.open('bitbang-cookies'))
        .then(cache => cache.put(COOKIE_CACHE_KEY,
            new Response(body, {
                headers: { 'Content-Type': 'application/json' }
            })
        ))
        .catch(() => {});
    // Returned so callers can hand it to keepAlive() -- an unawaited
    // cache.put is dropped outright if the SW is terminated first.
    return cookieSaveChain;
}

// Hold the service worker alive until an async persistence write settles.
// Chrome terminates an idle SW ~30s after the last event; without this a
// cache.put issued while responding can simply never run, silently
// reverting the persisted jar to an older state.
//
// Accepts either a real FetchEvent/ExtendableMessageEvent (has waitUntil)
// or the synthetic event object proxyAbsolutePath constructs, which carries
// a _waitUntil bound to the originating real event.
function keepAlive(event, promise) {
    try {
        if (typeof event?.waitUntil === 'function') {
            event.waitUntil(promise);
        } else if (typeof event?._waitUntil === 'function') {
            event._waitUntil(promise);
        }
    } catch (e) {
        // waitUntil throws if the event is no longer active. The write is
        // already in flight either way; losing the keepalive is not fatal.
    }
    return promise;
}

// Load persisted cookies on SW startup. The promise is awaited in the
// fetch handler to ensure cookies are available for the first request.
const cookieJarReady = loadCookieJar();

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
        //     under the same jarKey. Contained -- jarKey is uid:target, so
        //     it cannot cross hosts or devices, only paths on one host.
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
// requests (getCookieHeader, and the WebSocket upgrade via the getCookies
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

// Serialize a value for embedding inside an inline <script> element.
//
// JSON.stringify alone is NOT safe here. It produces a valid JS literal but
// does not escape "<", and the HTML parser terminates a script block at the
// first "</script" sequence regardless of JS string context. A cookie whose
// value contains "</script><img src=x onerror=...>" would therefore close
// the shim's script tag and inject arbitrary markup into the bitba.ng page.
//
// That path is reachable: app code writing document.cookie is mirrored into
// the jar via the cookieWrite message, and the jar is replayed into every
// subsequent HTML navigation by cookieSync. So an XSS inside a proxied app
// could otherwise escalate into persistent injection in the proxy wrapper --
// and persist across sessions, because the jar lives in the Cache API.
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

// Signaling-server endpoints — and our own static assets — must reach the
// origin server, not the device tunnel. Without this list, a tail of
// proxyAbsolutePath would route /status (and similar) through whatever
// session happens to be open, returning whatever 404/406 the device app
// thinks of the path. Worst case the user looks at /status in a browser
// that's been used for bitbang, gets a 404 from their own SW, and thinks
// the server is broken.
//
// Keep in sync with the signaling server's route table in
// cmd/signaling/main.go.
function isServerEndpoint(pathname) {
    return pathname === '/status'
        || pathname.startsWith('/ws/')
        || pathname.startsWith('/__bitbang__/');
}

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    if (url.origin !== self.location.origin) return;

    // Popups from proxied apps: an iframe's JS generates a root-relative
    // URL not realizing it lives behind a proxy, then window.open(...) or
    // a top-level nav lands at bare-origin. Catch anything that looks
    // like it belongs to a proxied app and 302 it into the most-recently-
    // active session's URL space. See isLikelyAppPopup for what qualifies.
    // Popup detection: only treat as popup when the request destination
    // is 'document' — a top-level navigation (window.open, target=_blank).
    // Iframe navigations (destination='iframe') MUST fall through to
    // proxyAbsolutePath so form submits and in-app navigations reach the
    // device tunnel and don't get redirected into bootstrap.html-inside-
    // an-iframe. Request.destination is on the Request object itself
    // and visible in the SW; Sec-Fetch-* headers, by contrast, are added
    // at the network layer after the SW's fetch handler runs.
    if (event.request.mode === 'navigate'
        && event.request.destination === 'document'
        && isLikelyAppPopup(url)) {
        event.respondWith(redirectViaActiveSession(event, url));
        return;
    }

    if (isServerEndpoint(url.pathname)) return;

    if (url.pathname.startsWith('/__device__/')) {
        // Bind the client this navigation creates to the session named in
        // the URL. This is the iframe's FIRST load (bootstrap sets
        // src=/__device__/<sid>/…), and it is what makes the binding
        // available later, once xhr-shim has stripped the prefix away.
        const m = url.pathname.match(/^\/__device__\/([^/]+)/);
        if (m && sessions.has(m[1])) rememberClientSession(event, m[1]);
        event.respondWith(proxyToDevice(event));
    } else {
        event.respondWith(proxyAbsolutePath(event, url));
    }
});

// isLikelyAppPopup: does this URL look like a popup from a proxied app
// rather than a legitimate bitba.ng navigation? Excludes only paths that
// we KNOW are always server-owned or session-internal:
//
//   - `isServerEndpoint(p)`  — explicit list: /status, /ws/*, /__bitbang__/*
//   - `/__device__/*`        — the SW's own internal proxy path
//   - `/<22-char UID>`       — canonical device URL
//   - `/<6-digit>`           — pair code path
//   - bare `/` (no query)    — entry page
//
// Everything else — including single-lowercase-segment paths like
// `/reverse_proxy_test/` that proxied apps sometimes generate — is
// treated as a possible popup and handed to `redirectViaActiveSession`.
// That function falls through to the network when no active session
// exists, so cold-start users typing exotic URLs are unaffected: only
// users who have a live session in this browser get redirected.
//
// We do NOT re-use findSession's `isShortTopPath` short-route reservation
// here. That reservation exists so new server-side lowercase routes can
// be added without SW updates, but for the popup-redirect path we'd
// rather catch a real proxied-app popup than preserve the shortcut.
// New server routes must be added to `isServerEndpoint` explicitly.
function isLikelyAppPopup(url) {
    const p = url.pathname;
    if (p === '/') return !!url.search;
    if (/^\/[A-Za-z0-9_-]{22}(\/|$)/.test(p)) return false;
    if (/^\/\d{6}$/.test(p)) return false;
    if (isServerEndpoint(p)) return false;
    if (p.startsWith('/__device__/')) return false;
    return true;
}

// extractRefererSession pulls the /__device__/<sid> segment out of a
// Referer URL, or null if it's absent. Used to identify which session a
// popup came from — a hard signal that beats the lastActive tie-breaker
// when multiple sessions are open in the same browser.
function extractRefererSession(referer) {
    if (!referer) return null;
    const m = referer.match(/\/__device__\/([^/?#]+)/);
    return m ? m[1] : null;
}

// redirectViaActiveSession: 302 the request into the most-recently-used
// session's URL space. Path/search from the request are preserved; the
// session provides uid, target, and code. If no session qualifies (none
// registered, or the ones we have lack a code), falls through to the
// network so the entry page still loads normally for genuinely-fresh
// visitors.
async function redirectViaActiveSession(event, url) {
    await sessionsReady;

    // Sweep dead sessions so we don't redirect into a session whose page
    // has been closed. Cheap here — happens only on the popup-shaped
    // navigation, not on every fetch.
    let swept = false;
    for (const [sid, sess] of sessions) {
        if (!(await self.clients.get(sess.clientId))) {
            sessions.delete(sid);
            swept = true;
        }
    }
    if (swept) saveSessions();

    // Selection priority — most specific signal first.
    //
    // 1. Cache API "active session" — bootstrap writes on iframe load,
    //    window focus, and visibility→visible. Focus fires WAY before
    //    the user can click a link, so the async write is always settled
    //    by popup time. This is the only signal that reliably identifies
    //    the source session when Cookie and Referer are stripped from
    //    the popup navigation by the browser (noreferrer, cross-context).
    //
    // 2. Referer contains /__device__/<sid>. Works for iframes still on
    //    the proxy prefix. Defensive fallback; not usually helpful for
    //    popups since Referer is usually stripped there.
    //
    // 3. Most-recently-active (lastActive). Final fallback for the
    //    single-session case where any answer is right.
    let best = null;

    try {
        const cache = await caches.open('bitbang-active-session');
        const resp = await cache.match('/_/active');
        if (resp) {
            const s = sessions.get(await resp.text());
            if (s && s.uid && s.code) best = s;
        }
    } catch (e) {}

    if (!best) {
        const refererSid = extractRefererSession(event.request.referrer);
        if (refererSid) {
            const s = sessions.get(refererSid);
            if (s && s.uid && s.code) best = s;
        }
    }

    if (!best) {
        for (const sess of sessions.values()) {
            if (!sess.uid || !sess.code) continue;
            if (!best || (sess.lastActive || 0) > (best.lastActive || 0)) {
                best = sess;
            }
        }
    }

    if (!best) return fetch(event.request);

    // Build the canonical URL per CONVENTIONS.md's URL scheme:
    //
    //   /<UID>#<code>[!<flag-list>]<device-URL>
    //
    // Popup redirects do NOT propagate flags (they're per-session
    // diagnostic switches; inheriting them across popups is not the
    // desired behavior). Everything device-specific (target + pathname +
    // search + hash) lives in the fragment after the code and after any
    // flag section. The signaling server never sees any of it — fragments
    // aren't transmitted in HTTP requests.
    //
    //   target === 'device'  is the fixed-target sentinel (no target
    //                        segment). Any other value is a real proxy
    //                        host, prepended as `/host` before the popup's
    //                        own path so relative URLs resolve correctly.
    //   url.pathname         the popup's path (`/`, `/Library`, etc.).
    //   url.search           the popup's query (`?launchApp=…`).
    //   url.hash             not visible to the SW (browsers don't send
    //                        fragments), so lost. Popups rarely carry one.
    const tseg = (best.target && best.target !== 'device') ? '/' + best.target : '';
    const deviceUrl = tseg + url.pathname + url.search;
    const loc = '/' + best.uid + '#' + best.code + deviceUrl;
    return new Response(null, {
        status: 302,
        headers: { Location: loc },
    });
}

/**
 * Proxy an absolute-path request through the device tunnel.
 *
 * Resolves the session, constructs the internal /__device__/ URL, and
 * proxies directly (no 307 redirect). This keeps the browser's view of
 * URLs consistent -- preloaded resources match CSS-referenced resources
 * because both use the original absolute path.
 *
 * If no session is found, the request passes through to the signaling server.
 */
async function proxyAbsolutePath(event, url) {
    const sessionId = await findSession(event);
    if (sessionId) {
        // Keep the chain alive: an in-session navigation to an absolute path
        // mints a new client, which must inherit the binding or the NEXT
        // navigation out of that frame loses it again.
        rememberClientSession(event, sessionId);
        const deviceUrl = `${url.origin}/__device__/${sessionId}${url.pathname}${url.search}`;
        const reqInit = {
            method: event.request.method,
            headers: event.request.headers,
            credentials: event.request.credentials,
            redirect: 'manual',
        };
        // 'navigate' mode can't be set on constructed Requests
        if (event.request.mode !== 'navigate') {
            reqInit.mode = event.request.mode;
        }
        // Requests with a body need the duplex option
        if (event.request.method !== 'GET' && event.request.method !== 'HEAD') {
            reqInit.body = event.request.body;
            reqInit.duplex = 'half';
        }
        const proxyEvent = {
            request: new Request(deviceUrl, reqInit),
            // Bridge to the real FetchEvent so proxyToDevice can keep the SW
            // alive for async jar writes. The synthetic event has no
            // waitUntil of its own.
            _waitUntil: (p) => event.waitUntil(p),
        };
        // Carry the navigate flag so proxyToDevice can inject shims
        if (event.request.mode === 'navigate') {
            proxyEvent._isNavigate = true;
        }
        return proxyToDevice(proxyEvent);
    }
    return fetch(event.request);
}

/**
 * Proxy a /__device__/<sessionId>/path request through the data channel.
 */
async function proxyToDevice(event) {
    const url = new URL(event.request.url);

    // -- Parse session and path from URL --
    const parts = url.pathname.slice('/__device__/'.length).split('/');
    const sessionId = parts[0];
    const devicePath = '/' + parts.slice(1).join('/');

    // -- Find bootstrap client --
    let bootstrap = null;
    await sessionsReady;
    let session = sessions.get(sessionId);
    // A request can still beat setBootstrap here (e.g. an ack-less older
    // page, or a fetch already in flight when the SW restarted). Give
    // registration up to ~1s to land before declaring no connection.
    for (let i = 0; !session && i < 10; i++) {
        await new Promise(r => setTimeout(r, 100));
        session = sessions.get(sessionId);
    }
    if (session) {
        // In-memory only; no saveSessions() per fetch. lastActive is used
        // as a tie-breaker in redirectViaActiveSession — ephemeral is fine.
        session.lastActive = Date.now();
        bootstrap = await self.clients.get(session.clientId);

        // Chrome may drop SW->client control after idle. The page is
        // still alive (WebRTC works) but self.clients.get() returns null.
        // Search all clients including uncontrolled ones.
        if (!bootstrap) {
            const allClients = await self.clients.matchAll({
                type: 'window',
                includeUncontrolled: true,
            });
            console.warn(`[SW] Stored client ${session.clientId} gone. ` +
                `Searching ${allClients.length} window clients: ` +
                allClients.map(c => `${c.id} url=${c.url.substring(0, 60)} vis=${c.visibilityState}`).join(' | '));
            // Use a non-iframe window client to deliver this request, but
            // do NOT rewrite session.clientId. If the matched id equals the
            // stored id (SW-restart-with-same-page case), the rewrite is a
            // no-op; if it differs (refresh case), the rewrite would attach
            // the stale session to the new bootstrap, defeating the
            // dead-clientId cleanup in setBootstrap and leaking entries.
            for (const c of allClients) {
                if (!c.url.includes('/__device__/')) {
                    bootstrap = c;
                    break;
                }
            }
        }
    }

    if (session?.debug) console.log(`[SW] ${event.request.method} ${url.pathname} -> session: ${sessionId}, bootstrap: ${!!bootstrap}`);

    if (!bootstrap) {
        console.warn('[SW] No bootstrap client found');
        return new Response('BitBang: no connection', { status: 503 });
    }

    // -- Build request with cookies --
    const jarKey = `${session.uid}:${session.target}`;
    const channel = new MessageChannel();
    const hasBody = event.request.method !== 'GET' && event.request.method !== 'HEAD';
    const contentLength = parseInt(
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

    const cleanUrl = url.origin + '/__device__' + devicePath + url.search;
    bootstrap.postMessage({
        type: 'request',
        url: cleanUrl,
        method: event.request.method,
        headers: reqHeaders,
        hasBody,
        contentLength
    }, [channel.port2]);

    // Upload acknowledgements and response frames share this MessagePort.
    // Install a router before reading the request body so an ack cannot race
    // the response handler setup. Non-ack messages are retained until the
    // response promise below is ready to consume them.
    const uploadAcks = new SWSPUpload.AckGate(30000);
    let bodyReader = null;
    let responseHandler = null;
    const pendingResponseMessages = [];
    channel.port1.onmessage = (msg) => {
        if (msg.data?.type === 'bodyAck') {
            if (uploadAcks.acknowledge(msg.data.seq)) return;
        }
        if (msg.data?.type === 'error') {
            const error = uploadAcks.fail(new Error(msg.data.message || 'upload failed'));
            if (bodyReader) {
                Promise.resolve(bodyReader.cancel(error)).catch(() => {});
            }
        }
        if (responseHandler) responseHandler(msg);
        else pendingResponseMessages.push(msg);
    };

    // -- Stream request body (if any) --
    if (hasBody) {
        try {
            if (event.request.body) {
                bodyReader = event.request.body.getReader();
                let seq = 0;
                try {
                    while (true) {
                        const { done, value } = await bodyReader.read();
                        uploadAcks.throwIfFailed();
                        if (done) break;

                        for (let offset = 0; offset < value.byteLength;) {
                            uploadAcks.throwIfFailed();
                            const chunk = SWSPUpload.copySlice(value, offset);
                            offset += chunk.byteLength;
                            seq++;
                            const ack = uploadAcks.wait(seq);
                            channel.port1.postMessage({
                                type: 'bodyChunk', data: chunk, seq,
                            }, [chunk.buffer]);
                            await ack;
                        }
                    }
                } finally {
                    bodyReader.releaseLock();
                    bodyReader = null;
                }
            }
            uploadAcks.throwIfFailed();
            channel.port1.postMessage({ type: 'bodyEnd' });
        } catch (e) {
            channel.port1.postMessage({
                type: 'cancel', message: e.message || 'upload failed',
            });
            return new Response(`BitBang: ${e.message || 'upload failed'}`, { status: 500 });
        }
    }

    // -- Stream response back to browser --
    return new Promise((resolve) => {
        let streamController;
        let resolved = false;
        let responseDone = false;
        let responseClosed = false;
        const responseChunks = [];
        let timeout;
        const closeResponsePort = () => {
            if (responseClosed) return;
            responseClosed = true;
            channel.port1.postMessage({ type: 'responseClosed' });
        };
        const pumpResponse = () => {
            if (!streamController) return;
            try {
                while (responseChunks.length > 0 && streamController.desiredSize > 0) {
                    const chunk = responseChunks.shift();
                    streamController.enqueue(chunk.data);
                    if (chunk.wireBytes) {
                        channel.port1.postMessage({
                            type: 'responseConsumed', bytes: chunk.wireBytes, frames: 1,
                        });
                    }
                }
                if (responseDone && responseChunks.length === 0) {
                    streamController.close();
                    closeResponsePort();
                }
            } catch (e) {
                channel.port1.postMessage({ type: 'cancel', message: String(e) });
                closeResponsePort();
            }
        };
        if (!hasBody) {
            timeout = setTimeout(() => {
                if (!resolved) {
                    channel.port1.postMessage({ type: 'cancel', message: 'request timeout' });
                    resolve(new Response('BitBang: request timeout', { status: 504 }));
                }
            }, 30000);
        }

        responseHandler = (msg) => {
            const { type, status, headers, data, message } = msg.data;

            if (type === 'uploadProgress') {
                return;
            } else if (type === 'headers') {
                if (timeout) clearTimeout(timeout);
                resolved = true;

                // Store response cookies in our jar (skipped when !nocookiejar is set)
                const setCookie = headers?.['Set-Cookie'] || headers?.['set-cookie'];
                if (setCookie && !session.noCookieJar) {
                    // keepAlive: the jar write is async and the SW can be
                    // terminated the moment this response is done streaming.
                    keepAlive(event, storeCookies(jarKey, setCookie));
                    // Surface cookies via a custom header so xhr-shim can
                    // sync them into document.cookie *synchronously* in the
                    // same Promise/event chain as the response, before app
                    // code's handler runs. JSON-encoded so multiple Set-Cookie
                    // values round-trip through a single header without
                    // ambiguity from comma joins.
                    //
                    // Strip Domain= so the browser scopes the cookie to the
                    // current document origin (bitba.ng) instead of silently
                    // refusing the write when the upstream's Domain attribute
                    // (e.g. octoprint.local, 192.168.1.10) doesn't match.
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
                    // eventually consistent.
                    // Broadcast filtered by jarKey (uid:target), not
                    // sessionId, so other tabs on the same device (same
                    // jar) receive the update. Sessions are per-tab and
                    // never match across tabs — filtering on sessionId
                    // silently dropped every cross-tab broadcast.
                    const bc = new BroadcastChannel('bitbang-cookies');
                    bc.postMessage({
                        jarKey,
                        cookies: (cookieJar.get(jarKey) || []).filter(isMirrorable),
                    });
                    bc.close();
                    delete headers['Set-Cookie'];
                    delete headers['set-cookie'];
                }

                // Re-anchor redirects onto the device proxy. The device returns
                // absolute-path Location headers (e.g. /login/ from OctoPrint's
                // forced login); the Go proxy already stripped the host. Left
                // as-is, the browser resolves /login/ against the origin
                // (bitba.ng/login/) and the redirect escapes the device. Prefix
                // it with /__device__/<sessionId> so the follow-up navigation
                // proxies back to the device.
                if (status >= 300 && status < 400 && headers) {
                    const locKey = headers['Location'] !== undefined ? 'Location'
                        : headers['location'] !== undefined ? 'location' : null;
                    const loc = locKey && headers[locKey];
                    if (typeof loc === 'string' && loc.startsWith('/') && !loc.startsWith('/__device__/')) {
                        headers[locKey] = `/__device__/${sessionId}${loc}`;
                    }
                }

                // Detect HTML navigation responses for shim injection
                const ct = headers?.['Content-Type'] || headers?.['content-type'] || '';
                const isNav = event.request?.mode === 'navigate'
                    || event.request?.destination === 'document'
                    || event._isNavigate;

                const stream = new ReadableStream({
                    start(controller) {
                        streamController = controller;

                        // Inject shims + cookie sync into HTML navigation responses
                        if (ct.includes('text/html') && isNav) {
                            let cookieSync = '';
                            if (!session?.noCookieJar) {
                                const jar = cookieJar.get(jarKey);
                                if (jar && jar.length > 0) {
                                    const now = Date.now();
                                    for (const c of jar) {
                                        if (c.expires !== null && c.expires <= now) continue;
                                        // HttpOnly stays jar-only (see invariant).
                                        if (!isMirrorable(c)) continue;
                                        cookieSync += `document.cookie=${jsonForScript(c.name + '=' + c.value + ';path=' + c.path)};`;
                                    }
                                }
                            }

                            const eruda = session?.debug
                                ? '<script src="https://cdn.jsdelivr.net/npm/eruda" onload="eruda.init();eruda.position({x:innerWidth-60,y:innerHeight-60})"></script>'
                                : '';
                            const shims = '<!DOCTYPE html>'
                                + `<script>window.__bbSessionId=${jsonForScript(sessionId)};window.__bbJarKey=${jsonForScript(jarKey)};window.__bbDebug=${!!session?.debug};${cookieSync}</script>`
                                + eruda
                                + '<script src="/__bitbang__/xhr-shim.js"></script>'
                                + '<script src="/__bitbang__/ws-shim.js"></script>';
                            controller.enqueue(new TextEncoder().encode(shims));
                        }
                        pumpResponse();
                    },
                    pull() {
                        pumpResponse();
                    },
                    cancel(reason) {
                        responseChunks.length = 0;
                        channel.port1.postMessage({
                            type: 'cancel', message: String(reason || 'response cancelled'),
                        });
                        closeResponsePort();
                    },
                });

                // CORS headers for fonts with crossorigin attributes
                if (!headers['access-control-allow-origin']) {
                    headers['access-control-allow-origin'] = '*';
                }

                // 204/304 responses must not have a body per spec
                const nullBodyStatus = (status === 204 || status === 304);
                resolve(new Response(nullBodyStatus ? null : stream, { status, headers }));
            } else if (type === 'chunk') {
                responseChunks.push({ data, wireBytes: msg.data.wireBytes || 0 });
                pumpResponse();
            } else if (type === 'done') {
                responseDone = true;
                pumpResponse();
            } else if (type === 'error') {
                if (timeout) clearTimeout(timeout);
                responseChunks.length = 0;
                if (!resolved) {
                    resolve(new Response(`BitBang: ${message}`, { status: 500 }));
                } else {
                    try { streamController?.error(new Error(message)); } catch (e) {}
                }
                closeResponsePort();
            }
        };
        for (const msg of pendingResponseMessages.splice(0)) responseHandler(msg);
    });
}
