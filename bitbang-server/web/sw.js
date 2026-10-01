/**
 * BitBang Service Worker
 *
 * Routes requests through the WebRTC data channel to the device.
 * Absolute-path requests (e.g. <script src="/app.js">) are resolved
 * to the active session and proxied directly. XHR/fetch absolute paths
 * are rewritten at the source by xhr-shim.js.
 */

// BUILD is spliced in by the server as this file is served (see
// handler.buildStamp). Every asset in a given deploy carries the same
// value, so a page whose copy differs from ours is running older code.
const BUILD = '__BB_BUILD__';

console.log('[SW] booted', BUILD);

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

// -- Persisted maps ----------------------------------------------------------
//
// A Map kept in the Cache API, so SW idle-termination (Chrome ~30s) doesn't
// lose it. Three of them -- sessions, client bindings, the cookie jar -- and
// this is the only code that reads or writes one, so what one gets right they
// all get right. They used to be written out three times, and the ordering
// fix below had reached two of the three.
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

// -- Session tracking --------------------------------------------------------

// Map of sessionId -> { clientId, uid, target, code, lastActive, ... }.
// Persisted so a session survives the SW being terminated while the
// bootstrap window is still alive.
const {
    map: sessions, ready: sessionsReady, save: saveSessions,
} = persistedMap('bitbang-sessions', '/__bitbang__/sessions');

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
const {
    map: clientSessions, ready: clientSessionsReady, save: saveClientSessions,
} = persistedMap('bitbang-sessions', '/__bitbang__/client-sessions');

sessionsReady.then(() => {
    if (sessions.size > 0) console.log(`[SW] Restored ${sessions.size} session(s) from cache`);
});

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

self.addEventListener('message', async (event) => {
    // Answered on the port the page supplied, so it works before we
    // control the page (a claim may not have landed yet).
    if (event.data?.type === 'getBuild') {
        event.ports[0]?.postMessage({ type: 'build', build: BUILD });
        return;
    }

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

// -- Session resolution ------------------------------------------------------
//
// Which session does a request belong to? findSession answers that for every
// caller: proxyAbsolutePath (a bare absolute path, proxied down the tunnel),
// redirectViaActiveSession (a popup, 302'd into a session's URL) and
// serveBareMetaPage (/*name). The callers differ in what they do with the
// answer and in how much evidence they will act on -- not in how it is found.
// There used to be a second resolver in the popup path, and the two drifted:
// each had a signal the other called decisive, so a popup and a subresource
// from one frame could resolve to different sessions.
//
// The strategies, applied in order. Each returns a sessionId or null, and
// considers only sessions in ctx.pool -- the open sessions the caller can use.
//
// `evidence`:
//
//   - 'concrete' -- the request carries an explicit handle on its session: a
//     clientId the SW bound, or a /__device__/<sid> in its referer or its
//     client's URL. Safe for pair-entry paths: an in-session iframe
//     redirected to `/` still carries one, so it is proxied correctly.
//
//   - 'fuzzy' -- inferred from weaker signals. Skipped when the caller asks
//     for concrete evidence only: a fresh tab to bitba.ng/ would otherwise
//     leak into whatever session another tab has open.
const SESSION_STRATEGIES = [
    {
        name: 'client-binding',  // clientId recorded when this frame was navigated
        evidence: 'concrete',
        // Strongest signal available and the cheapest (a Map lookup, no
        // await), so it runs first. Concrete because the binding was
        // recorded by the SW itself while proxying a navigation for a
        // known session -- it is not inferred from anything the page
        // controls, and it survives xhr-shim.js rewriting the URL.
        async match({ event, pool }) {
            if (!event.clientId) return null;
            const sid = clientSessions.get(event.clientId);
            return sid && pool.has(sid) ? sid : null;
        },
    },
    {
        name: 'referer-device',  // referer has /__device__/<sid>
        evidence: 'concrete',
        async match({ referer, pool }) {
            const m = referer.match(/\/__device__\/([^/?#]+)/);
            return m && pool.has(m[1]) ? m[1] : null;
        },
    },
    {
        name: 'client-device',  // requesting client's URL has /__device__/<sid>
        evidence: 'concrete',
        async match({ event, pool }) {
            if (!event.clientId) return null;
            const client = await self.clients.get(event.clientId);
            if (!client) return null;
            const m = client.url.match(/\/__device__\/([^/?#]+)/);
            return m && pool.has(m[1]) ? m[1] : null;
        },
    },
    {
        name: 'referer-uid',  // referer has /<uid>
        evidence: 'fuzzy',
        async match({ referer, pool }) {
            if (!referer) return null;
            try {
                const refPath = new URL(referer).pathname;
                for (const [sid, sess] of pool) {
                    if (sess.uid && refPath.startsWith('/' + sess.uid)) return sid;
                }
            } catch (e) {}
            return null;
        },
    },
    {
        name: 'focused-tab',  // the session whose tab had focus last
        evidence: 'fuzzy',
        // bootstrap.js writes its session id to this cache on iframe load,
        // window focus and visibility -> visible. Focus comes well before a
        // click, so the write has settled by the time a popup opens. For a
        // popup it is often the only signal left: Cookie and Referer are
        // stripped from it, and postMessage races its fetch.
        //
        // Fuzzy all the same. It says which tab the person was looking at,
        // not which frame sent the request, so anything concrete outranks
        // it, and a fresh tab must never be handed to it.
        async match({ pool }) {
            try {
                const cache = await caches.open('bitbang-active-session');
                const resp = await cache.match('/_/active');
                const sid = resp && await resp.text();
                return sid && pool.has(sid) ? sid : null;
            } catch (e) {
                return null;
            }
        },
    },
    {
        name: 'single-session',  // exactly one open session
        evidence: 'fuzzy',
        async match({ isUidPath, pool }) {
            // Excludes top-level UID paths (e.g. /bb29bead...) which
            // need the signaling server to load bootstrap.html, even
            // when the only open session happens to share the UID.
            if (pool.size === 1 && !isUidPath) {
                return pool.keys().next().value;
            }
            return null;
        },
    },
    {
        name: 'most-recent',  // the session that most recently proxied anything
        evidence: 'fuzzy',
        // Final fallback: covers sub-resource fetches (XHR, fetch, img,
        // ...) from contexts whose URL doesn't include /__device__/<sid>
        // -- bare-origin iframes the proxied app spawns -- form-POST
        // navigations into hidden iframes (Synology DSM uses this for
        // /webman/login.cgi), and a popup when no tab has recorded focus.
        // Top-level UID-path navigations are already excluded by the
        // isUidPath+navigate early return in findSession, so it's safe to
        // include 'navigate' mode here.
        async match({ pool }) {
            let best = null;
            for (const [sid, sess] of pool) {
                if (!best || (sess.lastActive || 0) > (pool.get(best).lastActive || 0)) best = sid;
            }
            return best;
        },
    },
];

// concreteOnly: act only on concrete evidence (see `evidence` above).
// accept: which sessions the caller can use. A strategy that names one it
// can't is a miss, and the next strategy gets its turn.
async function findSession(event, { concreteOnly = false, accept = () => true } = {}) {
    await sessionsReady;
    await clientSessionsReady;

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

    await sweepDeadSessions(event);

    const pool = new Map();
    for (const [sid, sess] of sessions) if (accept(sess)) pool.set(sid, sess);

    const ctx = {
        event,
        isUidPath,
        pool,
        referer: event.request.referrer || '',
    };
    for (const strat of SESSION_STRATEGIES) {
        if (concreteOnly && strat.evidence !== 'concrete') break;
        const sid = await strat.match(ctx);
        if (sid) {
            // On concrete evidence only, client-binding resolving is the case
            // -- a short top path, say -- that used to fall through to the
            // signaling server and load bootstrap.html into the iframe. Rare
            // by nature, so not noisy, and if it never prints on a
            // post-login navigation, the binding is not being recorded.
            if (concreteOnly && strat.name === 'client-binding') {
                console.log('[SW] client-binding resolved',
                    reqUrl.pathname, '->', sid);
            }
            return sid;
        }
    }
    return null;
}

// Drop sessions whose bootstrap page is gone, and with them the client
// bindings that pointed at them -- or a recycled clientId could resolve to a
// dead session. Without the sweep, an auto-fetch (e.g. /favicon.ico right after
// a refresh) can match a stale entry from the previous page. The pagehide
// cleanup is best-effort; this is authoritative.
//
// Run on every resolution, so it costs one clients.get per open session per
// request findSession sees -- a handful of sessions at most. It used to be
// written twice, and the popup path's copy left the bindings behind.
async function sweepDeadSessions(event) {
    let swept = false;
    for (const [sid, sess] of sessions) {
        if (!(await self.clients.get(sess.clientId))) {
            sessions.delete(sid);
            swept = true;
        }
    }
    if (!swept) return;
    saveSessions();
    pruneClientSessions();
    saveClientSessions();
    if (dropSessionCookiesForDeadDevices()) keepAlive(event, saveCookieJar());
}

// Short top-level paths -- bare `/`, 6-digit pair codes, and any
// single-segment lowercase path like `/install`, `/status`, `/health` --
// share the server-owned namespace. proxyAbsolutePath resolves them on
// concrete evidence only: an iframe inside a session that redirects to such
// a path is correctly proxied to the device, but a fresh tab to the same URL
// reaches the server.
//
// The syntactic rule means future server-side utility endpoints
// (`/install.ps1`, `/docs`, anything similar) route correctly with no SW
// change required. Convention to preserve: server routes are short,
// lowercase, single-segment; device-tunneled deep paths can be any shape
// (they're disambiguated by concrete evidence).
function isShortTopPath(pathname) {
    return pathname === '/'
        || /^\/\d{6}$/.test(pathname)
        || /^\/[a-z][a-z0-9_-]*\/?$/.test(pathname);
}

// -- Cookie jar (persisted to Cache API) -------------------------------------

// jarKey (uid:target) -> [cookie]. Loaded on SW startup; cookieJarReady is
// awaited before a request is sent, so the first one carries its cookies.
const {
    map: cookieJar, ready: cookieJarReady, save: saveCookieJar,
} = persistedMap('bitbang-cookies', '/__bitbang__/cookie-jar', {
    revive: reviveCookies,
    forSave: unexpiredCookies,
});

// Bounds on the jar. Without them it only ever grew: entries leave when a
// cookie's own expiry passes, and a session cookie (expires === null) has
// none, so proxying an app once left its cookies here permanently.
//
// Map preserves insertion order, so evicting from the front drops the
// least-recently-created partition first.
const MAX_JAR_PARTITIONS = 100;   // uid:target pairs held at once
const MAX_JAR_COOKIES = 2000;     // cookies across all partitions

function pruneCookieJar() {
    let changed = false;
    while (cookieJar.size > MAX_JAR_PARTITIONS) {
        cookieJar.delete(cookieJar.keys().next().value);
        changed = true;
    }
    let total = 0;
    for (const cookies of cookieJar.values()) total += cookies.length;
    while (total > MAX_JAR_COOKIES && cookieJar.size > 0) {
        const oldest = cookieJar.keys().next().value;
        total -= cookieJar.get(oldest).length;
        cookieJar.delete(oldest);
        changed = true;
    }
    return changed;
}

// Discard session cookies for devices that no longer have a live session.
//
// Session cookies are the ones a browser drops at the end of a browsing
// session, and this is the equivalent moment: the last tab proxying that
// device is gone. Cookies with an explicit expiry survive, exactly as they
// would in a normal browser, so "remember me" still works.
//
// Called only from the authoritative sweeps, never from the pagehide fast
// path. A refresh removes the old session and registers a new one for the
// same uid, and the ordering between those two is not guaranteed -- dropping
// on pagehide would log people out on every reload.
function dropSessionCookiesForDeadDevices() {
    const live = new Set();
    for (const sess of sessions.values()) {
        if (sess.uid) live.add(sess.uid);
    }
    let changed = false;
    for (const [key, cookies] of [...cookieJar]) {
        const sep = key.indexOf(':');
        const uid = sep < 0 ? '' : key.slice(0, sep);
        if (!uid || live.has(uid)) continue;
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

// The canonical spelling of a meta-page, and the same one the address bar
// shows after the access code: #<code>/*settings. Declared above its use in the
// fetch handler rather than beside serveBareMetaPage below -- a const in the
// temporal dead zone would still work there, since the listener runs long
// after this module is evaluated, but that is a subtlety worth not having.
const BARE_META_PATH = /^\/\*([A-Za-z0-9_-]+)$/;

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

        // A '*' first segment names a meta-page rather than a device path:
        // #<code>/*settings. The shell is ours; only the data it renders comes
        // from the device.
        //
        // It is served *inside* /__device__/<sid>/ on purpose. The routing
        // rules below match on the requesting client's URL, so a plain
        // fetch('/__bitbang/settings') from this page is proxied to the device
        // like any device page's fetch -- which means the page itself needs
        // no knowledge of sessions, prefixes, or that it is a meta-page at
        // all. Serve the same file from the bare origin and its fetches would
        // reach the signaling server instead.
        const meta = url.pathname.match(/^\/__device__\/([^/]+)\/\*([A-Za-z0-9_-]+)$/);
        if (meta) {
            event.respondWith(serveMetaPage(meta[2], meta[1]));
            return;
        }

        event.respondWith(proxyToDevice(event));
    } else if (BARE_META_PATH.test(url.pathname)) {
        // A link on a device page written the natural way -- href="/*settings"
        // -- arrives with no /__device__/<sid> prefix, because an
        // origin-absolute href discards the current path. The prefixed form
        // above never sees it, and without this the request is proxied to the
        // device, which 404s a path it has never heard of.
        event.respondWith(serveBareMetaPage(event, url));
    } else {
        event.respondWith(proxyAbsolutePath(event, url));
    }
});

// Serve a meta-page for a bare /*name, but only on concrete evidence that this
// request belongs to a device session -- a client binding, or a referer or
// client URL carrying an actual /__device__/<sid>.
//
// Concrete specifically: the fuzzy strategies (focused tab, most-recent) would
// let a stray top-level visit to bitba.ng/*settings render a settings shell
// bound to whatever session another tab happened to have open.
//
// Anything unproven falls through to proxyAbsolutePath, which is exactly what
// happened before this existed -- so the failure mode of this route is the old
// behavior rather than a new one.
async function serveBareMetaPage(event, url) {
    const name = url.pathname.match(BARE_META_PATH)[1];
    const sid = await findSession(event, { concreteOnly: true });
    if (!sid) return proxyAbsolutePath(event, url);
    return serveMetaPage(name, sid);
}

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
// We do NOT re-use proxyAbsolutePath's `isShortTopPath` short-route reservation
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

// redirectViaActiveSession: 302 the request into the URL space of the
// session it came from. Path/search from the request are preserved; the
// session provides uid, target, and code. If no session qualifies (none
// registered, or the ones we have lack a code), falls through to the
// network so the entry page still loads normally for genuinely-fresh
// visitors.
//
// Which session is findSession's answer, with fuzzy evidence allowed: a
// popup rarely carries anything better than which tab had focus.
async function redirectViaActiveSession(event, url) {
    const sid = await findSession(event, { accept: (s) => s.uid && s.code });
    if (!sid) return fetch(event.request);
    const best = sessions.get(sid);

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
// Meta-pages the server serves on a device's behalf. A page compiled into
// firmware freezes its UI at the moment it was flashed, so fixing a rendering
// bug would mean an OTA to every device in the field; a meta-page updates when
// the server does. The device supplies data and no HTML at all.
//
// The name is the filename and it arrives from the URL: /*settings serves
// /__bitbang__/settings.html. Nothing here knows which names are real.
//
// There was a META_PAGES set of exactly {settings, console, ota}. It refused
// nothing the server was not already refusing -- the only .html files that
// prefix serves are those three, so two allowlists were reaching the same
// answer independently, and this was the copy that could go stale. It did:
// config.html became settings.html while this still said 'config', so the new
// name read as unknown and the old one resolved to a file that no longer
// existed, with neither error mentioning the other half.
//
// It could not have survived plugins either. A plugin registers with the
// server, which is what knows what is deployed; a list kept by hand in a
// service worker is unreachable from there and can only be wrong in one
// direction -- refusing something real. So the refusal, and the list of what
// does exist, belong to the server.
//
// What keeps this safe is the URL pattern rather than any list. The name is
// matched as [A-Za-z0-9_-]+, so it carries no slash and no dot: it cannot climb
// out of the prefix, and it cannot name a file that is not <name>.html.
async function serveMetaPage(name, sessionId) {
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
    // bootstrap, and without it a meta-page opening /__bitbang/<type> would
    // dial bitba.ng itself and reach nothing.
    //
    // fetch() needs no shim: that does reach this handler, and the session is
    // resolved from the client URL. Which is why the settings page worked
    // before this existed and the console could not have.
    //
    // Only the two globals ws-shim reads, and no cookie replay: a meta-page is
    // ours and has no app cookies to mirror, so the jar stays out of it.
    const preamble = '<!DOCTYPE html>'
        + `<script>window.__bbSessionId=${jsonForScript(sessionId || '')};`
        + `window.__bbJarKey=null;window.__bbDebug=false;</script>`
        + '<script src="/__bitbang__/ws-shim.js"></script>';

    const body = preamble + await r.text();
    return new Response(body, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
}

async function proxyAbsolutePath(event, url) {
    const sessionId = await findSession(event, { concreteOnly: isShortTopPath(url.pathname) });
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
        // Requests with a body need the duplex option, and a browser without
        // Request.body (Firefox) has none to hand over: read the bytes here
        // instead, or the copy below carries no body at all and a form submit
        // through this path arrives empty.
        if (event.request.method !== 'GET' && event.request.method !== 'HEAD') {
            if (event.request.body) {
                reqInit.body = event.request.body;
                reqInit.duplex = 'half';
            } else {
                reqInit.body = await event.request.arrayBuffer();
            }
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

    const cleanUrl = url.origin + '/__device__' + devicePath + url.search;
    bootstrap.postMessage({
        type: 'request',
        url: cleanUrl,
        method: event.request.method,
        headers: reqHeaders,
        hasBody,
        contentLength
    }, [channel.port2]);

    // -- Stream request body (if any) --
    if (hasBody) {
        if (bufferedBody !== null) {
            if (bufferedBody.byteLength > 0) {
                // bootstrap.js splits this into MAX_CHUNK frames and applies
                // backpressure, so one message is fine however large it is.
                channel.port1.postMessage(
                    { type: 'bodyChunk', data: bufferedBody }, [bufferedBody.buffer]);
            }
        } else if (event.request.body) {
            const reader = event.request.body.getReader();
            try {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    channel.port1.postMessage({ type: 'bodyChunk', data: value }, [value.buffer]);
                }
            } finally {
                reader.releaseLock();
            }
        }
        channel.port1.postMessage({ type: 'bodyEnd' });
    }

    // -- Stream response back to browser --
    return new Promise((resolve) => {
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

        channel.port1.onmessage = (msg) => {
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
                    //
                    // It reaches the tab that made this request as well, and
                    // carries the whole jar rather than what just changed.
                    // Both are harmless only because the page writes what it
                    // receives straight to the native cookie setter, never
                    // through the one that forwards to this jar -- see the
                    // cookie section of xhr-shim.js. When it went through that
                    // one, every cookie here came back without its expiry.
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
                                        // Expiry included, as the other two
                                        // mirror sources in xhr-shim.js now
                                        // do. This one runs before that file
                                        // installs the forwarding setter, so
                                        // it never echoed -- it just made
                                        // every mirrored cookie a session one.
                                        const exp = c.expires !== null
                                            ? ';expires=' + new Date(c.expires).toUTCString() : '';
                                        cookieSync += `document.cookie=${jsonForScript(c.name + '=' + c.value + ';path=' + c.path + exp)};`;
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
                            // These two and no more, because these two are the
                            // only ones that have to precede the page's own
                            // script: they replace window.fetch and
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
                    }
                });

                // CORS headers for fonts with crossorigin attributes
                if (!headers['access-control-allow-origin']) {
                    headers['access-control-allow-origin'] = '*';
                }

                // 204/304 responses must not have a body per spec
                const nullBodyStatus = (status === 204 || status === 304);
                resolve(new Response(nullBodyStatus ? null : stream, { status, headers }));
            } else if (type === 'chunk') {
                try { streamController?.enqueue(data); } catch (e) {}
            } else if (type === 'done') {
                try { streamController?.close(); } catch (e) {}
            } else if (type === 'error') {
                if (timeout) clearTimeout(timeout);
                if (!resolved) {
                    resolve(new Response(`BitBang: ${message}`, { status: 500 }));
                } else {
                    try { streamController?.error(new Error(message)); } catch (e) {}
                }
            }
        };
    });
}
