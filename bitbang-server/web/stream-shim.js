/*
 * Renders the streams a device declares, inside the device's own page.
 *
 * A device page doesn't load this file by name. It includes bitbang.js, which
 * loads this when the page has a stream element:
 *
 *     <canvas data-bitbang-stream="cam"></canvas>
 *     <script src="/__bitbang__/bitbang.js"></script>
 *
 * A script tag naming stream-shim.js would work today and break the day this
 * file is renamed or split -- which bitbang.js exists so that it can be.
 *
 * It runs in the page because it needs a DOM -- a service worker could not do
 * this job at all: no canvas, no AudioContext, nothing to draw on.
 *
 * The service worker used to prepend it to every device HTML response, the way
 * it still prepends ws-shim.js and xhr-shim.js. That was wrong, and the name is
 * the clue: those two replace window.WebSocket and window.fetch and have to be
 * in place before the page's first line of script, so injection is the only way
 * to deliver them. This patches nothing and has no such requirement -- it was
 * built beside them and inherited their delivery. The bill was 15 KB on every
 * device page including ones with no stream element, and two different stories
 * for how the library reaches a page.
 *
 * The flexibility injection appeared to provide is really the attribute's: a
 * device declares where a stream goes and what renders it can change without
 * reflashing. That holds either way.
 *
 * What it replaces: until now each device's firmware carried its own renderer.
 * The camera page held a BroadcastChannel listener, createImageBitmap, a u-law
 * table and an AudioWorklet loader, in a C string. Every device author wrote
 * that again, and fixing any of it meant reflashing. Rendering is a property
 * of the codec, not of the device that happens to send it, so it belongs
 * somewhere a deploy can reach.
 *
 * The device's side of it is now two ordinary elements:
 *
 *     <canvas data-bitbang-stream="cam"></canvas>
 *     <audio  data-bitbang-stream="cam" controls></audio>
 *
 * Both name the presentation. Each takes the component whose codec has a
 * renderer registered for that element's tag -- the canvas takes cam/video
 * because (canvas, mjpeg) is registered and (canvas, ulaw) is not, and the
 * audio element takes cam/audio for the mirror reason.
 *
 * See av-streaming-api.md, which is the authority for the frame header and
 * for this boundary.
 */

(function () {
    'use strict';

    /* Loaded twice does nothing the second time.
     *
     * Not hypothetical while this moves from being injected by the service
     * worker to being a script tag in the device's own page: for one flash-and-
     * deploy either way round, a page can carry the tag and still be served the
     * prefix. Without this the second run installs a second handshake listener
     * and binds every element twice. */
    if (window.BitBang && window.BitBang.streams) {
        return;
    }


    /* codec -> { tags: Set, create }. Keyed by codec because the codec is what
       arrives on the wire; tag is the second key, since the same codec renders
       differently into an <img> than into a <canvas>. */
    const renderers = new Map();

    /* codec -> Promise, so a module is fetched once however many components
       announce it. A rejection is kept rather than retried: the failure is a
       404 or a syntax error, and neither improves on a second attempt. */
    const loading = new Map();

    /* "cam/video" -> { info, instances, active, subscribed }. A component may
       feed several elements -- two canvases showing one camera is fine --
       while an element renders at most one component.

       `active` holds a token per instance that currently wants frames, and the
       component is subscribed while that set is non-empty. Two viewers of one
       camera, one of them paused, must not stop the other. */
    const bound = new Map();

    /* One playback clock per presentation, in the device's own timebase.
     *
     * Audio plays continuously and cannot be hurried, so its position is the
     * clock everything else is drawn against -- a dropped video frame at 20
     * fps is close to invisible, 20 ms of missing audio is a click. The
     * renderer that plays audio publishes where it has reached; renderers
     * that draw read it and hold each frame until its moment arrives.
     *
     * It is keyed by presentation because that is the unit a page binds to:
     * cam/video and cam/audio are two components of one thing and share a
     * timebase. Two different cameras would each have their own.
     *
     * Empty until something publishes, which is what makes this opt-in. With
     * no audio playing there is no clock, and a video renderer draws on
     * arrival exactly as it always did. */
    const clocks = new Map();

    function clockFor(presentation) {
        let c = clocks.get(presentation);
        if (c === undefined) {
            c = { ptsMs: NaN, at: 0, movedAt: 0 };
            clocks.set(presentation, c);
        }
        return c;
    }

    /* How long a clock may stand still before it stops counting as one.
     *
     * A clock that is present but frozen is worse than no clock: every frame
     * waits for a moment that never arrives, and the picture stops dead. That
     * is exactly what a paused audio element does -- the ring keeps reporting,
     * because the context is deliberately left running, but its position no
     * longer moves.
     *
     * Pausing clears the clock outright, so this is for the cases nobody
     * announces: an underrun, a stalled stream, a renderer that went away
     * without saying. A second is long enough that a short gap still holds
     * the picture in step, and short enough that a real outage lets video run
     * free rather than freezing with it. */
    const CLOCK_STALE_MS = 1000;

    let port = null;
    let known = [];

    const ASSETS = '/__bitbang__/';

    function asset(name) {
        return ASSETS + name;
    }

    /* The convention is the whole plugin mechanism for now: a codec's renderer
       is render-<codec>.js. When plugins arrive, a plugin declares the codecs
       it supplies and this becomes a lookup, which is the only part that
       changes. See "What changes when plugins arrive". */
    function moduleFor(codec) {
        return asset('render-' + codec + '.js');
    }

    function register(def) {
        if (!def || !def.codec || typeof def.create !== 'function') {
            console.error('[streams] ignoring a malformed renderer', def);
            return;
        }
        renderers.set(def.codec, {
            tags: new Set((def.tags || []).map(t => t.toLowerCase())),
            create: def.create,
        });
    }

    window.BitBang = window.BitBang || {};
    window.BitBang.streams = { register, asset };

    function load(codec) {
        if (renderers.has(codec)) return Promise.resolve();
        let p = loading.get(codec);
        if (p) return p;
        /* The module registers itself as a side effect of being imported,
           which is why nothing is done with the resolved value. */
        p = import(moduleFor(codec)).catch(err => {
            console.error(`[streams] no renderer for ${codec}: ${err.message}`);
        });
        loading.set(codec, p);
        return p;
    }

    function subscribe(name, on) {
        /* Logged, and not only while debugging. From the device's end a
           subscription that was never sent and one that was sent into a
           closed port look exactly alike -- nothing arrives, and neither end
           reports an error, because postMessage on a closed port is silent.
           This is the only place that can tell them apart, and it happens
           once per play or pause rather than per frame. */
        console.log(`[streams] ${on ? 'subscribe' : 'unsubscribe'} ${name}` +
                    (port ? '' : ' -- NO PORT, dropped'));
        if (port) port.postMessage({ type: 'subscribe', name, on });
    }

    /* Bring the device into line with what the renderers currently want, and
       say nothing if that has not changed. Compared against the last message
       sent rather than recomputed each time, so a renderer may call setActive
       as often as it likes -- once per play and pause is the expected rate,
       but nothing here depends on that. */
    function reconcile(key) {
        const b = bound.get(key);
        if (!b) return;
        const want = b.active.size > 0;
        if (want === b.subscribed) return;
        b.subscribed = want;
        subscribe(key, want);
    }

    /* An element names either a presentation ("cam") or, for pages written
       before this shim existed, a component outright ("cam/video"). Accepting
       both costs one branch and keeps firmware already in the field working. */
    function wants(el, s) {
        const v = el.getAttribute('data-bitbang-stream');
        if (!v) return false;
        return v.indexOf('/') > 0 ? v === s.key : v === s.presentation;
    }

    async function bind() {
        const els = Array.from(document.querySelectorAll('[data-bitbang-stream]'));
        if (els.length === 0) return;

        /* Only the codecs some element might actually want, so a video-only
           page does not fetch the audio renderer to discover it has no use
           for it. */
        const needed = new Set();
        for (const s of known) {
            if (els.some(el => wants(el, s))) needed.add(s.codec);
        }
        await Promise.all([...needed].map(load));

        for (const el of els) {
            if (el.__bbStream) continue;              // an element binds once
            const tag = el.tagName.toLowerCase();
            for (const s of known) {
                if (!wants(el, s)) continue;
                const r = renderers.get(s.codec);
                if (!r || !r.tags.has(tag)) continue;

                let b = bound.get(s.key);
                if (!b) {
                    b = { info: s, instances: [], active: new Set(),
                          subscribed: false };
                    bound.set(s.key, b);
                }

                /* Wanting frames is the default, so a renderer with nothing to
                   say about it -- which is most of them -- simply gets them.
                   One that does care says so during create, and because
                   reconcile only runs once create has returned, saying "not
                   yet" costs no message at all rather than a subscribe
                   immediately undone. */
                const token = {};
                b.active.add(token);
                const info = Object.assign({}, s, {
                    /* Whether this instance currently wants frames. An <audio>
                       element that is paused does not, and a device should not
                       be sending to a page that is not listening -- which is
                       what makes the element's pause button a real pause
                       rather than a mute. */
                    setActive(on) {
                        if (on) b.active.add(token);
                        else b.active.delete(token);
                        reconcile(s.key);
                    },

                    /* The presentation's playback clock. See `clocks`.
                     *
                     * get() interpolates with wall time since the last
                     * publication, because the audio ring reports about eight
                     * times a second and drawing 20 fps of video against a
                     * value that coarse would step visibly. Between reports
                     * the clock advances in real time, which is what it is
                     * doing anyway. */
                    clock: {
                        set(ptsMs) {
                            const c = clockFor(s.presentation);
                            const now = performance.now();
                            /* Only a changed position counts as movement.
                               Republishing the same one is what a paused ring
                               does, and it must not look like progress. */
                            if (ptsMs !== c.ptsMs) {
                                c.movedAt = now;
                            }
                            c.ptsMs = ptsMs;
                            c.at = now;
                        },
                        get() {
                            const c = clockFor(s.presentation);
                            if (Number.isNaN(c.ptsMs)) {
                                return NaN;
                            }
                            if (performance.now() - c.movedAt > CLOCK_STALE_MS) {
                                return NaN;    /* stopped: draw on arrival */
                            }
                            return c.ptsMs + (performance.now() - c.at);
                        },
                    },
                });

                el.__bbStream = s.key;
                try {
                    const inst = await r.create(el, info);
                    if (inst) b.instances.push(inst);
                } catch (err) {
                    console.error(`[streams] ${s.key}: ${err.message}`);
                    b.active.delete(token);
                    el.__bbStream = null;
                }
                /* Subscribing here rather than at page load is the point of
                   the matching above: a component no element can render is
                   never asked for, so the device does not spend a radio on
                   it. */
                reconcile(s.key);
                break;
            }
        }
    }

    function unbindMissing() {
        const live = new Set(known.map(s => s.key));
        for (const [key, b] of bound) {
            if (live.has(key)) continue;
            for (const inst of b.instances) {
                try { if (inst.stop) inst.stop(); } catch (err) { /* going away anyway */ }
            }
            bound.delete(key);
            document.querySelectorAll('[data-bitbang-stream]').forEach(el => {
                if (el.__bbStream === key) el.__bbStream = null;
            });
        }
    }

    function onFrame(msg) {
        const b = bound.get(msg.key);
        if (!b) return;
        const bytes = new Uint8Array(msg.data);
        const meta = { ptsMs: msg.ptsMs, keyframe: msg.keyframe };
        for (const inst of b.instances) {
            try {
                inst.frame(bytes, meta);
            } catch (err) {
                console.error(`[streams] ${msg.key}: ${err.message}`);
            }
        }
    }

    function onPortMessage(e) {
        const msg = e.data;
        if (!msg) return;
        if (msg.type === 'frame') {
            onFrame(msg);
        } else if (msg.type === 'streams') {
            known = msg.streams || [];
            unbindMissing();
            bind();
        }
    }

    /* bootstrap hands the port over once the page has loaded. This listener is
       installed while the document is still parsing -- the shim is the first
       script in the response -- so the handshake cannot be missed.

       The whole vocabulary, with bootstrap.js's wireStreams as the other end:
         parent -> page   stream_port   (window message, carries the port)
         on the port:
           page -> parent   subscribe   { name, on }
           parent -> page   streams     the declared streams
                            frame       one decoded frame */
    window.addEventListener('message', (e) => {
        if (!e.data || e.data.type !== 'stream_port') return;
        if (!e.ports || !e.ports[0]) return;
        port = e.ports[0];
        port.onmessage = onPortMessage;
        port.start();

        /* A replacement port has no memory of what was already asked for, and
           the far side behind it may be a different connection entirely -- a
           reconnect builds a new data channel, and a subscription sent over
           the old one is gone with it.
         *
         * So a new port resets the bookkeeping rather than trusting it.
         * Without this, `subscribed` still reads true from the previous port,
         * reconcile sees no change, and the component stays silently
         * unsubscribed for the life of the page -- with nothing logged at
         * either end, because every individual step behaved correctly.
         *
         * Re-stating a subscription the device already has is harmless: it
         * sets a flag that is already set. */
        for (const key of bound.keys()) {
            bound.get(key).subscribed = false;
            reconcile(key);
        }
    });

    /* A page that builds its DOM after load can ask for another pass. The
       load-time scan cannot serve that case and watching the document would be
       more code, permanently running, for the same result. */
    window.BitBang.streams.rescan = bind;

})();
