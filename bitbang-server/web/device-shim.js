/**
 * BitBang device shim
 *
 * Injected ahead of every device page in a device origin, by the label worker
 * (label-sw.js), before the page's own scripts. See
 * bitbang-docs/device-origins.md. What survives of xhr-shim.js, which existed
 * mostly to hide that device pages shared bitba.ng's origin -- prefix
 * rewriting, prefix stripping -- and none of that applies here: this origin is
 * the device's, and a page's /api/... is already the right URL.
 *
 * What is left:
 *   1. The document.cookie mirror of the worker's cookie jar.
 *   2. Sync XHR forced to async (a sync XHR bypasses the service worker, so it
 *      could never reach the device).
 *   3. Links and window.open that would leave the frame for a new tab, sent to
 *      bitba.ng's page instead (bb-open), which opens /<uid>#<code><path> -- an
 *      ordinary bitba.ng page with its own connection. A label URL opened
 *      top-level has nothing to connect with (label.go).
 *   4. The label worker kept in place: a page's own worker registration is a
 *      no-op, and unregistering ours is refused.
 *
 * None of this is a security boundary. Device script can undo any of it, and
 * nothing it gains by doing so reaches past its own device.
 */

(function() {
    // Only in a device origin's content frame. A label host serves this file
    // to nothing else, but a copy loaded anywhere else has nothing to do.
    if (window.parent === window) return;

    // -- Cookie sync ---------------------------------------------------------
    //
    // The service worker's jar is the truth about cookies: it is what goes out
    // on requests to the device, and it is persisted. document.cookie is a
    // mirror, kept so app code that reads cookies directly -- a CSRF token, a
    // preference -- sees current values. Three things write the mirror: the
    // preamble the service worker injects ahead of this file, X-BB-Set-Cookie on
    // each fetch or XHR response, and a broadcast from the service worker
    // whenever the jar changes, which is what keeps other tabs current.
    //
    // One rule makes that safe: a mirror never writes back. The setter further
    // down forwards writes to the jar, because the app writing document.cookie
    // is a real change the jar has to hear about -- but mirror writes go round
    // it, to the native setter.
    //
    // They used not to. The broadcast wrote each cookie as name=value;path=...
    // with no expiry, that went through the forwarding setter, and the service
    // worker stored it -- so after any Set-Cookie, every cookie in the jar, not
    // only the one just set, came back without an expiry and never expired
    // again. A device that logged someone out by letting a session cookie lapse
    // went on receiving it.
    //
    // The mirror is this origin's own document.cookie, which no other device
    // and not bitba.ng can read.

    var nativeCookie = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');

    // Write the mirror without forwarding. Where the forwarding setter could
    // not be installed, document.cookie is native anyway, so either path is
    // right.
    function mirrorCookie(str) {
        if (nativeCookie && nativeCookie.set) nativeCookie.set.call(document, str);
        else document.cookie = str;
    }

    // The worker renames device-set Set-Cookie headers to X-BB-Set-Cookie (a
    // worker can't put Set-Cookie on a response it builds). We mirror them
    // into document.cookie *synchronously in the same .then chain / event-loop
    // tick* as the response arrives -- guaranteeing app code that reads
    // document.cookie immediately after a fetch/XHR sees the fresh value.
    function applyCookieHeader(headerValue) {
        if (!headerValue) return;
        try {
            var list = JSON.parse(headerValue);
            for (var i = 0; i < list.length; i++) {
                mirrorCookie(list[i]);
            }
        } catch (e) {}
    }

    // The broadcast. A BroadcastChannel is per origin, so only this device's
    // pages hear it. Expiry is carried through, so the mirror is faithful as
    // well as harmless.
    try {
        var cookieChannel = new BroadcastChannel('bitbang-cookies');
        cookieChannel.onmessage = function(event) {
            var d = event.data || {};
            if (d.jarKey !== window.__bbJarKey) return;
            var cookies = d.cookies || [];
            for (var i = 0; i < cookies.length; i++) {
                var c = cookies[i];
                var s = c.name + '=' + c.value + ';path=' + c.path;
                if (typeof c.expires === 'number') {
                    s += ';expires=' + new Date(c.expires).toUTCString();
                }
                mirrorCookie(s);
            }
        };
    } catch (e) {}

    // Forward the app's own writes to the worker so the jar hears app-side
    // changes (preferences, JS-set tokens). Setter-only wrap leaves reads
    // native -- less invasive than a full getter override that some browsers
    // reject.
    try {
        if (nativeCookie && nativeCookie.configurable && nativeCookie.set && nativeCookie.get) {
            Object.defineProperty(document, 'cookie', {
                get: function() { return nativeCookie.get.call(document); },
                set: function(value) {
                    nativeCookie.set.call(document, value);
                    var sw = navigator.serviceWorker && navigator.serviceWorker.controller;
                    if (sw && window.__bbJarKey) {
                        sw.postMessage({ type: 'cookie_write', value: String(value) });
                    }
                },
                configurable: true,
            });
        }
    } catch (e) {}

    // -- Patch XMLHttpRequest ------------------------------------------------

    // Wrap the constructor so our readystatechange listener registers before
    // any app code can attach its own. Listeners fire in registration order,
    // so ours runs first -- document.cookie is fresh by the time the app's
    // handler reads it.
    var OrigXHR = window.XMLHttpRequest;
    function WrappedXHR() {
        var xhr = new OrigXHR();
        xhr.addEventListener('readystatechange', function() {
            if (xhr.readyState === 4) {
                applyCookieHeader(xhr.getResponseHeader('X-BB-Set-Cookie'));
            }
        });
        return xhr;
    }
    WrappedXHR.prototype = OrigXHR.prototype;
    WrappedXHR.UNSENT = 0;
    WrappedXHR.OPENED = 1;
    WrappedXHR.HEADERS_RECEIVED = 2;
    WrappedXHR.LOADING = 3;
    WrappedXHR.DONE = 4;
    window.XMLHttpRequest = WrappedXHR;

    var origOpen = OrigXHR.prototype.open;
    OrigXHR.prototype.open = function(method, url) {
        // Force async=true. Sync XHR bypasses the service worker entirely
        // (per spec), so it can never reach the WebRTC data channel. Most
        // apps (including jQuery with async:false) handle async responses
        // via callbacks and work fine either way.
        if (arguments.length > 2 && arguments[2] === false) {
            arguments[2] = true;
        }
        return origOpen.apply(this, arguments);
    };

    // -- Patch fetch ---------------------------------------------------------

    var origFetch = window.fetch;
    if (origFetch) {
        window.fetch = function(input, init) {
            // Our .then runs before the caller's, so document.cookie is
            // synced before any app handler sees the response.
            return origFetch.call(this, input, init).then(function(response) {
                applyCookieHeader(response.headers.get('X-BB-Set-Cookie'));
                return response;
            });
        };
    }

    // -- Keep the label worker -----------------------------------------------
    //
    // An app that registers a worker of its own would fail anyway -- a label
    // host serves no script but ours, so the browser rejects the registration
    // -- but an app may treat that failure as fatal. It is told it worked, and
    // gets the label worker's registration. Unregistering the label worker,
    // a routine "clear out stale workers" at app startup, is refused the same
    // way: without it, nothing on this origin reaches the device until the
    // connection frame registers it again.
    if (navigator.serviceWorker) {
        navigator.serviceWorker.register = function(scriptURL) {
            console.log('[BitBang] Ignored a service worker registration from the device page:', scriptURL);
            return Promise.resolve(navigator.serviceWorker.ready);
        };
    }
    var Registration = window.ServiceWorkerRegistration;
    if (Registration && Registration.prototype.unregister) {
        var origUnregister = Registration.prototype.unregister;
        Registration.prototype.unregister = function() {
            var w = this.active || this.waiting || this.installing;
            if (w && new URL(w.scriptURL).pathname === '/__bitbang__/label-sw.js') {
                console.log('[BitBang] Refused to unregister the BitBang worker');
                return Promise.resolve(true);
            }
            return origUnregister.apply(this, arguments);
        };
    }

    // -- New tabs ------------------------------------------------------------
    //
    // A page of this origin opened in a tab of its own has no connection: the
    // connection belongs to bitba.ng's page, which holds the code. So whatever
    // would open one -- a target=_blank link, a ctrl- or middle-click, a
    // window.open -- is sent to bitba.ng's page as a path, and it opens
    // /<uid>#<code><path>, a full bitba.ng page with its own connection. The
    // connection frame relays it (bb-open), adding a proxied app's target.
    //
    // Links elsewhere -- another site -- open as they always would.
    //
    // What can't be caught -- "Open link in new tab" from the context menu,
    // dragging a link to the tab bar -- lands on a label URL top-level, which
    // gets a page saying to open the device from its link.

    function samePath(href) {
        try {
            var u = new URL(href, location.href);
            if (u.origin !== location.origin) return null;
            return u.pathname + u.search + u.hash;
        } catch (e) {
            return null;
        }
    }

    function openViaBitbang(path) {
        window.parent.postMessage({ type: 'bb-open', path: path, newTab: true }, location.origin);
    }

    var origWindowOpen = window.open;
    window.open = function(url, target, features) {
        var t = (target || '_blank').toLowerCase();
        // Into this frame or a named frame of the page: an ordinary
        // navigation, which the worker serves.
        if (t === '_self' || t === '_parent' || t === '_top' ||
            (t !== '_blank' && t.charAt(0) !== '_')) {
            return origWindowOpen.apply(window, arguments);
        }
        var path = samePath(url === undefined || url === '' ? 'about:blank' : url);
        if (path === null) return origWindowOpen.apply(window, arguments);
        openViaBitbang(path);
        // There is no window to hand back: the new tab is bitba.ng's, and
        // another origin's. An app that uses the return value only to check
        // the popup wasn't blocked is told it was.
        return null;
    };

    // The link a click landed on, if it is one.
    function linkOf(event) {
        var el = event.target;
        while (el && el.nodeType === 1) {
            if ((el.tagName === 'A' || el.tagName === 'AREA') && el.hasAttribute('href')) return el;
            el = el.parentNode;
        }
        return null;
    }

    function onLinkActivate(event) {
        if (event.defaultPrevented) return;
        var a = linkOf(event);
        if (!a || a.hasAttribute('download')) return;
        var newTab = event.type === 'auxclick'
            ? event.button === 1
            : (event.button === 0 && (event.ctrlKey || event.metaKey || event.shiftKey
                || (a.target || '').toLowerCase() === '_blank'));
        if (!newTab) return;
        var path = samePath(a.href);
        if (path === null) return;
        event.preventDefault();
        openViaBitbang(path);
    }

    // Bubble phase, on window: after the app's own handlers, so an app that
    // handles the click itself (and prevents the default) is left alone, as
    // the browser would leave it. An app that stops propagation without
    // preventing the default gets the browser's new tab, and the label URL's
    // "open from your link" page.
    window.addEventListener('click', onLinkActivate);
    window.addEventListener('auxclick', onLinkActivate);
})();
