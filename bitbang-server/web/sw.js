/**
 * BitBang Service Worker
 *
 * Routes requests through the WebRTC data channel to the device.
 * Absolute-path requests (e.g. <script src="/app.js">) are resolved
 * to the active session and proxied directly. XHR/fetch absolute paths
 * are rewritten at the source by xhr-shim.js.
 */

console.log('[SW] booted');

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

// -- Session tracking --------------------------------------------------------

// Map of sessionId -> { clientId, uid, target }.
// Persisted to Cache API so SW idle-termination (Chrome ~30s) doesn't drop
// session records while the bootstrap window is still alive.
const sessions = new Map();
const SESSIONS_CACHE_KEY = '/__bitbang__/sessions';

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
    } catch (e) {}
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
            debug: !!event.data.debug,
            noCookieJar: !!event.data.noCookieJar,
        });
        saveSessions();
        console.log('[SW] Bootstrap registered, session:', event.data.sessionId,
            event.data.noCookieJar ? '(nocookiejar)' : '');
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
        storeCookies(jarKey, event.data.value);
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
async function findSession(event) {
    await sessionsReady;

    // Top-level navigations to /<uid>/... are bootstrap-page loads — they
    // must always fall through to the signaling server (which serves
    // bootstrap.html), never get proxied to the device. Without this, a
    // page reload while the old bootstrap window is still being torn down
    // can match the stale session via Strategy 3 (uid-in-referer) and end
    // up routing the reload through the device, which then 404s.
    //
    // The UID is 22 base64url chars (alphabet [A-Za-z0-9_-]). Followed by
    // either end-of-path or "/", so we don't accidentally treat
    // /__device__/... or anything else as a UID path.
    const reqUrl = new URL(event.request.url);
    const isUidPath = /^\/[A-Za-z0-9_-]{22}(\/|$)/.test(reqUrl.pathname);
    if (isUidPath && event.request.mode === 'navigate') {
        return null;
    }

    // Drop sessions whose owning client is gone. Without this, an auto-fetch
    // (e.g. /favicon.ico right after a refresh) can match a stale uid-keyed
    // entry from a previous page and get routed into the rescue path. The
    // pagehide cleanup is best-effort; this sweep is authoritative.
    let swept = false;
    for (const [sid, sess] of sessions) {
        if (!(await self.clients.get(sess.clientId))) {
            sessions.delete(sid);
            swept = true;
        }
    }
    if (swept) saveSessions();

    const referer = event.request.referrer || '';

    // Strategy 1: referer has /__device__/<sid>
    const devMatch = referer.match(/\/__device__\/([^/]+)/);
    if (devMatch && sessions.has(devMatch[1])) return devMatch[1];

    // Strategy 2: requesting client's URL has /__device__/<sid>
    if (event.clientId) {
        const client = await self.clients.get(event.clientId);
        if (client) {
            const clientMatch = client.url.match(/\/__device__\/([^/]+)/);
            if (clientMatch && sessions.has(clientMatch[1])) return clientMatch[1];
        }
    }

    // Strategy 3: referer has /<uid>
    if (referer) {
        try {
            const refPath = new URL(referer).pathname;
            for (const [sid, sess] of sessions) {
                if (sess.uid && refPath.startsWith('/' + sess.uid)) return sid;
            }
        } catch (e) {}
    }

    // Strategy 4: single-session fallback. Safe when there's only one
    // session. Excludes top-level UID paths (e.g. /bb29bead...) which
    // need the signaling server to load bootstrap.html.
    if (sessions.size === 1 && !isUidPath) {
        return Array.from(sessions.keys())[0];
    }

    // Strategy 5 (final fallback): when no other strategy matched and
    // there's any open session, route to the most recent. Covers:
    //   - Sub-resource fetches (XHR, fetch, img, …) from contexts
    //     whose URL doesn't include /__device__/<sid> — e.g. bare-
    //     origin iframes the proxied app spawns.
    //   - Form-POST navigations into hidden iframes (Synology DSM
    //     uses this for /webman/login.cgi). These have mode ===
    //     'navigate' even though no top-level page is loading.
    //
    // Top-level UID-path navigations (i.e. real bootstrap-page loads
    // and reloads) are already excluded by the isUidPath+navigate
    // early return at the top of this function, so it's safe to
    // include 'navigate' mode here.
    if (sessions.size > 0) {
        return Array.from(sessions.keys()).pop();
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
        if (resp) {
            const data = await resp.json();
            for (const [key, cookies] of Object.entries(data)) {
                cookieJar.set(key, cookies);
            }
        }
    } catch (e) {}
}

function saveCookieJar() {
    const data = {};
    for (const [key, cookies] of cookieJar) {
        const now = Date.now();
        const valid = cookies.filter(c => c.expires === null || c.expires > now);
        if (valid.length > 0) data[key] = valid;
    }
    caches.open('bitbang-cookies').then(cache => {
        cache.put(COOKIE_CACHE_KEY,
            new Response(JSON.stringify(data), {
                headers: { 'Content-Type': 'application/json' }
            })
        );
    }).catch(() => {});
}

// Load persisted cookies on SW startup. The promise is awaited in the
// fetch handler to ensure cookies are available for the first request.
const cookieJarReady = loadCookieJar();

function parseCookie(setCookieStr) {
    const parts = setCookieStr.split(';').map(p => p.trim());
    const [nameValue, ...attrs] = parts;
    const eqIdx = nameValue.indexOf('=');
    if (eqIdx < 0) return null;

    const cookie = {
        name: nameValue.substring(0, eqIdx),
        value: nameValue.substring(eqIdx + 1),
        path: '/',
        expires: null,
    };

    for (const attr of attrs) {
        const [k, v] = attr.split('=').map(s => s.trim());
        const kl = k.toLowerCase();
        if (kl === 'path') {
            cookie.path = v || '/';
        } else if (kl === 'max-age') {
            const sec = parseInt(v, 10);
            if (!isNaN(sec)) cookie.expires = Date.now() + sec * 1000;
        } else if (kl === 'expires' && cookie.expires === null) {
            const d = new Date(v);
            if (!isNaN(d.getTime())) cookie.expires = d.getTime();
        }
    }
    return cookie;
}

function storeCookies(jarKey, setCookieHeaders) {
    if (!setCookieHeaders) return;
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

    saveCookieJar();
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

    for (let i = jar.length - 1; i >= 0; i--) {
        if (jar[i].expires !== null && jar[i].expires <= now) jar.splice(i, 1);
    }

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
    if (isServerEndpoint(url.pathname)) return;

    if (url.pathname.startsWith('/__device__/')) {
        event.respondWith(proxyToDevice(event));
    } else {
        event.respondWith(proxyAbsolutePath(event, url));
    }
});

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
        const proxyEvent = { request: new Request(deviceUrl, reqInit) };
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
    const session = sessions.get(sessionId);
    if (session) {
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

    // -- Stream request body (if any) --
    if (hasBody) {
        if (event.request.body) {
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

                // Store response cookies in our jar (skipped when ?nocookiejar is set)
                const setCookie = headers?.['Set-Cookie'] || headers?.['set-cookie'];
                if (setCookie && !session.noCookieJar) {
                    storeCookies(jarKey, setCookie);
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
                    // HttpOnly is also dropped -- it's silently ignored on JS
                    // writes anyway, just cleaner to omit.
                    const stripCookieAttrs = (s) => s.split(';')
                        .map(p => p.trim())
                        .filter(p => {
                            const lower = p.toLowerCase();
                            return !lower.startsWith('domain=') && lower !== 'httponly';
                        })
                        .join('; ');
                    const list = (Array.isArray(setCookie) ? setCookie : [setCookie])
                        .map(stripCookieAttrs);
                    headers['X-BB-Set-Cookie'] = JSON.stringify(list);
                    // Cross-tab fallback: another tab won't see X-BB-Set-Cookie
                    // (different fetch). The broadcast keeps its document.cookie
                    // eventually consistent.
                    const bc = new BroadcastChannel('bitbang-cookies');
                    bc.postMessage({ sessionId, cookies: cookieJar.get(jarKey) || [] });
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
                                        cookieSync += `document.cookie=${JSON.stringify(c.name + '=' + c.value + ';path=' + c.path)};`;
                                    }
                                }
                            }

                            const eruda = session?.debug
                                ? '<script src="https://cdn.jsdelivr.net/npm/eruda" onload="eruda.init();eruda.position({x:innerWidth-60,y:innerHeight-60})"></script>'
                                : '';
                            const shims = '<!DOCTYPE html>'
                                + `<script>window.__bbSessionId='${sessionId}';window.__bbDebug=${!!session?.debug};${cookieSync}</script>`
                                + eruda
                                + '<script src="/__bitbang__/xhr-shim.js"></script>'
                                + '<script src="/__bitbang__/ws-shim.js"></script>';
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
