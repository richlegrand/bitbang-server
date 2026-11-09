// The label worker: serves exactly one device. Its origin is the routing key,
// so there is no session to find -- only a port to the top page to get.
const BOOT = Math.random().toString(36).slice(2, 8);
const TOP = 'http://bb.localhost:__PORT__';
let port = null;
let waiters = [];
let seq = 0;
const pending = new Map();

self.addEventListener('install', (e) => {
    self.skipWaiting();
    // The start page, so later visits enter without touching the network.
    e.waitUntil(caches.open('start').then((c) => c.add('/__bb/start')));
});
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('message', (e) => {
    if (e.data && e.data.type === 'port' && e.ports[0]) {
        setPort(e.ports[0]);
        if (e.source) e.source.postMessage({ type: 'port_ok' });
    }
});

function setPort(p) {
    port = p;
    p.onmessage = (ev) => {
        const w = pending.get(ev.data.id);
        if (w) { pending.delete(ev.data.id); w(ev.data); }
    };
    const ws = waiters; waiters = [];
    for (const r of ws) r(p);
}

// A worker restarted after idling has lost its port. Ask the pages it
// controls; one of them is framed by the top page and can fetch a new one.
async function getPort(why) {
    if (port) return port;
    const got = new Promise((res, rej) => {
        waiters.push(res);
        setTimeout(() => rej(new Error('no port in 3s')), 3000);
    });
    const cs = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of cs) c.postMessage({ type: 'need_port', why });
    return got;
}

// -- cookie jar: this origin is one device, so no partitioning --
let jar = null;
async function loadJar() {
    if (jar) return;
    const c = await caches.open('jar');
    const r = await c.match('/jar');
    jar = r ? await r.json() : {};
}
async function saveJar() {
    const c = await caches.open('jar');
    await c.put('/jar', new Response(JSON.stringify(jar)));
}

const SHIM = `<script>
(function () {
    var TOP = '${TOP}';
    var sw = navigator.serviceWorker;
    sw.addEventListener('message', function (e) {
        if (e.data && e.data.type === 'swlog') console.log('[sw] ' + e.data.msg);
        if (e.data && e.data.type === 'need_port' && parent !== window) {
            parent.postMessage({ type: 'need_port', why: e.data.why }, TOP);
        }
    });
    addEventListener('message', function (e) {
        if (e.origin !== TOP || !e.data || e.data.type !== 'port' || !e.ports[0]) return;
        if (sw.controller) sw.controller.postMessage({ type: 'port' }, [e.ports[0]]);
    });
    sw.startMessages();
    window.__boot = '__BOOT__';
    addEventListener('load', function () {
        if (parent !== window) {
            parent.postMessage({ type: 'nav', path: location.pathname + location.search,
                                 title: document.title, boot: '__BOOT__' }, TOP);
        }
    });
})();
</script>`;

self.addEventListener('fetch', (e) => {
    const u = new URL(e.request.url);
    if (u.origin !== self.location.origin || u.pathname === '/sw.js') return;
    if (u.pathname === '/__bb/start') {
        e.respondWith(caches.open('start').then((c) => c.match('/__bb/start'))
            .then((r) => r || fetch(e.request)));
        return;
    }
    const what = e.request.method + ' ' + u.pathname + ' mode=' + e.request.mode
        + ' redirect=' + e.request.redirect;
    e.respondWith(proxy(e.request, u).then((r) => {
        report('ok ' + what + ' -> ' + r.status + ' type=' + r.type);
        return r;
    }, (err) => {
        report('THREW ' + what + ': ' + err);
        throw err;
    }));
});

async function report(msg) {
    const cs = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of cs) c.postMessage({ type: 'swlog', msg });
}

async function proxy(req, u) {
    await loadJar();
    const cookie = Object.entries(jar).map(([k, v]) => k + '=' + v.value).join('; ');
    const body = (req.method === 'GET' || req.method === 'HEAD') ? '' : await req.text();
    let reply = null;
    for (let attempt = 0; attempt < 2 && !reply; attempt++) {
        let p;
        try { p = await getPort(attempt ? 'retry' : 'first'); }
        catch (err) { return new Response('no connection: ' + err.message, { status: 503 }); }
        const id = ++seq;
        reply = await new Promise((res) => {
            pending.set(id, res);
            p.postMessage({ id, method: req.method, path: u.pathname + u.search,
                            headers: { cookie }, body });
            setTimeout(() => { if (pending.delete(id)) res(null); }, 2000);
        });
        if (!reply) port = null;            // a dead port: the top page went away
    }
    if (!reply) return new Response('no reply', { status: 504 });

    const h = new Headers();
    for (const [k, v] of Object.entries(reply.headers || {})) {
        if (k !== 'set-cookie') h.set(k, v);
    }
    const sets = [].concat((reply.headers || {})['set-cookie'] || []);
    for (const sc of sets) {
        const [nv, ...attrs] = sc.split(';');
        const i = nv.indexOf('=');
        jar[nv.slice(0, i).trim()] = {
            value: nv.slice(i + 1),
            httpOnly: attrs.some((a) => a.trim().toLowerCase() === 'httponly'),
        };
    }
    if (sets.length) await saveJar();
    h.set('x-sw-boot', BOOT);
    h.set('content-security-policy', 'frame-ancestors ' + TOP);
    if (reply.status >= 300 && reply.status < 400 && h.get('location')) {
        // Response.redirect, not new Response(null, {status: 302}): Firefox
        // rejects a hand-built redirect as the answer to a navigation.
        return Response.redirect(new URL(h.get('location'), u).href, reply.status);
    }
    let b = reply.body;
    if ((h.get('content-type') || '').startsWith('text/html')) {
        b = SHIM.replace(/__BOOT__/g, BOOT) + b;
    }
    return new Response(b, { status: reply.status, headers: h });
}
