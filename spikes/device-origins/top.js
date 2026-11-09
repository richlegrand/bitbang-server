// The top page: stands in for bitba.ng's bootstrap. Holds the "connection"
// (a fake device answering over a MessageChannel, standing in for the data
// channel) and hands a port to its own iframe on request.
const results = window.results = [];
const stats = window.stats = { ports: 0, requests: 0, navs: [] };
function log(...a) { results.push(a.join(' ')); console.log('[top]', ...a); }

// label = base32(HMAC-SHA256(secret, uid))[:16], secret kept in this origin.
async function labelFor(uid) {
    let s = null;
    try { s = localStorage.getItem('bb-secret'); } catch (e) {}
    if (!s) {
        s = Array.from(crypto.getRandomValues(new Uint8Array(32))).join(',');
        try { localStorage.setItem('bb-secret', s); } catch (e) {}
    }
    const key = await crypto.subtle.importKey('raw',
        new Uint8Array(s.split(',').map(Number)),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key,
        new TextEncoder().encode(uid)));
    const A = 'abcdefghijklmnopqrstuvwxyz234567';
    let bits = 0, val = 0, out = '';
    for (const b of mac.slice(0, 10)) {
        val = ((val << 8) | b) & 0xffff; bits += 8;
        while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; }
    }
    return out;
}

// A device: paths, a login that sets an HttpOnly and a plain cookie and
// redirects, and pages that show the Cookie header it received.
function device(uid) {
    function page(title) {
        return { status: 200, headers: { 'content-type': 'text/html' }, body:
`<!doctype html><title>${title}</title>
<p id="t">${uid} ${title}</p><p>cookie header: <span id="ck"></span></p>
<a id="l-b" href="/b">b</a> <a id="l-root" href="/">root</a>
<a id="l-settings" href="/*settings">settings</a> <a id="l-deep" href="/x/y/z?q=1">deep</a>
<form id="fm" method="post" action="/login"><input name="u" value="x"><button id="fb">login</button></form>
<button id="jsnav" onclick="location.href='/'">js nav to /</button>
<button id="pop" onclick="window.open('/popup')">popup</button>` };
    }
    return async function handle(req) {
        await new Promise(r => setTimeout(r, 10));   // a little link latency
        stats.requests++;
        const p = req.path.split('?')[0];
        const ck = req.headers.cookie || '';
        let r;
        if (p === '/login' && req.method === 'POST') {
            r = { status: 302, body: '', headers: { location: '/',
                'set-cookie': ['sid=S-' + uid + '; HttpOnly; Path=/',
                               'pref=P-' + uid + '; Path=/'] } };
        } else if (p === '/') r = page('ROOT');
        else if (p === '/b') r = page('B');
        else if (p === '/*settings') r = page('SETTINGS');
        else if (p === '/popup') r = page('POPUP');
        else if (p === '/x/y/z') r = page('DEEP ' + req.path);
        else r = { status: 404, headers: { 'content-type': 'text/plain' }, body: 'device 404 ' + p };
        if (r.body && r.headers['content-type'] === 'text/html') {
            r.body = r.body.replace('<span id="ck"></span>', '<span id="ck">' + ck + '</span>');
        }
        return r;
    };
}

async function open(uid) {
    const label = await labelFor(uid);
    const origin = `http://${label}.bb.localhost:__PORT__`;
    const handle = device(uid);
    window.__label = label;
    let tSrc = 0;

    window.addEventListener('message', (e) => {
        if (e.origin !== origin) return;          // only our own iframe's origin
        const m = e.data || {};
        if (m.type === 'need_port') {
            const ch = new MessageChannel();
            ch.port1.onmessage = async (ev) => {
                const req = ev.data;
                const res = await handle(req);
                ch.port1.postMessage({ id: req.id, ...res });
            };
            e.source.postMessage({ type: 'port' }, origin, [ch.port2]);
            stats.ports++;
            log('port handed', m.why || '');
        } else if (m.type === 'nav') {
            const ms = Math.round(performance.now() - tSrc);
            stats.navs.push({ path: m.path, boot: m.boot, ms });
            document.getElementById('bar').textContent = m.path;
            log('nav', m.path, 'boot', m.boot, ms + 'ms since src');
        }
    });

    const f = document.getElementById('f');
    tSrc = performance.now();
    f.src = origin + '/__bb/start#/';
    log('iframe src', f.src);
}

open(new URLSearchParams(location.search).get('uid') || 'device-one');
