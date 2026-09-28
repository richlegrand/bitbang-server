/*
 * The one line a device page includes.
 *
 *     <canvas data-bitbang-stream="cam"></canvas>
 *     <div data-bitbang-page="settings"></div>
 *     <script src="/__bitbang__/bitbang.js"></script>
 *
 * It loads what the page actually asked for and nothing else.
 *
 * The name is the contract. Everything behind it -- which files exist, what they
 * are called, how they split, whether a renderer is one module or three -- is
 * the server's to change, and a device flashed today keeps working through all
 * of it. That is the whole reason for the indirection, and it is worth one extra
 * request: firmware is the one part of this system that cannot be fixed by a
 * deploy, so it should contain as little as possible, and an asset filename is
 * the kind of thing that gets renamed.
 *
 * This is what the service worker used to do by prepending script tags to every
 * device HTML response. Same job, from inside the page, at the page's request,
 * and only for what the page has elements for. What injection bought was that
 * firmware needed no include line at all; what it cost was 15 KB on pages with
 * no stream element, a page that works because of something absent from its
 * source, and two different stories for how a library arrives. The two real
 * shims are still injected -- xhr-shim and ws-shim replace window.fetch and
 * window.WebSocket and have to be in place before the page's first line.
 *
 * The migration: firmware with the attributes and no script tag rendered before
 * and does not now. That is one reflash, and the last time it will be needed for
 * a change on this side.
 */
(function () {
    'use strict';

    /* Loaded twice does nothing the second time, so a page that includes it and
       is also served an old injected prefix is safe either way round. */
    if (window.__bitbangLoader) {
        return;
    }
    window.__bitbangLoader = true;

    const ASSETS = '/__bitbang__/';

    /* What the device says it answers, delivered by the service worker in the
     * same inline script that carries the session id.
     *
     * Published tidily because __bbCaps is a delivery detail and a launcher
     * should not read one. `has` is the only question anyone asks of it: is
     * there a console on this device, so should there be a way to open one.
     *
     * A cap names a reserved endpoint, never what to load. Every device has
     * settings and almost no page embeds the panel, so loading is decided by the
     * elements below; this decides what to *offer*. */
    const caps = Array.isArray(window.__bbCaps) ? window.__bbCaps.slice() : [];
    window.BitBang = window.BitBang || {};
    window.BitBang.caps = caps;
    window.BitBang.has = (cap) => caps.indexOf(cap) >= 0;

    /* A script element rather than import(), because what it loads is not all
       modules: stream-shim.js is a classic script that publishes window.BitBang,
       settings-panel.js is a module with an export. Appending an element handles
       both and is what the service worker was doing anyway. */
    function load(name, module) {
        return new Promise((resolve, reject) => {
            const s = document.createElement('script');
            if (module) s.type = 'module';
            s.src = ASSETS + name;
            s.onload = resolve;
            s.onerror = () => reject(new Error(name + ' did not load'));
            document.head.appendChild(s);
        });
    }

    /* attribute -> what renders it. The only table in here, and the only thing
       that changes when a new kind of element is added.

       `module` is the file's own business rather than the page's: a page says
       what it wants rendered and this knows how the thing that renders it is
       built. */
    const WANTS = [
        { attr: 'data-bitbang-stream', file: 'stream-shim.js',    module: false },
        { attr: 'data-bitbang-page',   file: 'settings-panel.js', module: true  },
    ];

    function boot() {
        for (const w of WANTS) {
            /* The scan has to happen regardless -- whatever loads has to find
               these elements -- so asking first costs a selector match and saves
               the whole fetch on a page that has none. A device serving plain
               pages was pulling 15 KB of stream machinery it had no element
               for. */
            if (!document.querySelector('[' + w.attr + ']')) {
                continue;
            }
            load(w.file, w.module).catch(err => {
                /* Named, because the failure is otherwise silent: elements never
                   bind and nothing appears anywhere a person is looking. That is
                   the one failure mode injection did not have. */
                console.error('[bitbang] ' + w.attr + ': ' + err.message);
            });
        }
    }

    /* A classic script in the head runs while the document is still parsing, so
       the elements it is looking for may not exist yet. */
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
