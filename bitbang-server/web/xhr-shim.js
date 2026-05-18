/**
 * BitBang XHR/Fetch/Location Shim
 *
 * Three responsibilities:
 * 1. Rewrite XHR/fetch URLs to route through /__device__/<sessionId>/
 * 2. Force sync XHR to async (sync XHR bypasses service workers)
 * 3. Strip the proxy prefix from the iframe URL so client-side routers
 *    (React Router, Vue Router, etc.) see clean paths like "/" instead
 *    of "/__device__/<sid>/<target>/"
 *
 * Injected before the app's own scripts via a <script> tag prepended
 * to HTML responses by the service worker.
 *
 * Requires window.__bbSessionId to be set before this script loads.
 */

(function() {
    var sessionId = window.__bbSessionId;
    if (!sessionId) return;

    var PREFIX = '/__device__/' + sessionId;

    // -- Strip proxy prefix from iframe URL ----------------------------------
    // SPAs with client-side routing (React Router, Vue Router) read
    // window.location.pathname to determine which route to render.
    // Without this, they see "/__device__/<sid>/<target>/path" and fail
    // to match any route. replaceState changes the iframe's URL without
    // triggering a navigation, so the app sees a clean path.
    var path = location.pathname;
    if (path.indexOf(PREFIX) === 0) {
        var cleanPath = path.slice(PREFIX.length);
        // Strip the target segment (e.g. /192.168.2.1:8000)
        // Target contains a dot or colon in the first segment
        if (cleanPath.length > 1) {
            var seg = cleanPath.slice(1).split('/')[0];
            if (seg.indexOf('.') !== -1 || seg.indexOf(':') !== -1) {
                cleanPath = cleanPath.slice(1 + seg.length) || '/';
            }
        }
        if (cleanPath !== path) {
            history.replaceState(null, '', cleanPath + location.search + location.hash);
        }
    }

    function rewriteUrl(url) {
        if (typeof url !== 'string') return url;

        // Absolute path: /foo/bar -> /__device__/<sessionId>/foo/bar
        if (url.charAt(0) === '/') {
            if (url.indexOf('/__device__/') === 0 || url.indexOf('/__bitbang__/') === 0) {
                return url;
            }
            return PREFIX + url;
        }

        // Full URL on same origin: rewrite the path portion
        try {
            var parsed = new URL(url, location.href);
            if (parsed.origin === location.origin &&
                parsed.pathname.indexOf('/__device__/') !== 0 &&
                parsed.pathname.indexOf('/__bitbang__/') !== 0) {
                parsed.pathname = PREFIX + parsed.pathname;
                return parsed.href;
            }
        } catch (e) {}

        // Relative URLs, data: URLs, external URLs: pass through unchanged
        return url;
    }

    // -- Cookie sync ---------------------------------------------------------
    //
    // The SW renames device-set Set-Cookie headers to X-BB-Set-Cookie so
    // they don't leak onto bitba.ng's own paths. We mirror them into
    // document.cookie *synchronously in the same .then chain / event-loop
    // tick* as the response arrives -- guaranteeing app code that reads
    // document.cookie immediately after a fetch/XHR sees the fresh value.

    function applyCookieHeader(headerValue) {
        if (!headerValue) return;
        try {
            var list = JSON.parse(headerValue);
            for (var i = 0; i < list.length; i++) {
                document.cookie = list[i];
            }
        } catch (e) {}
    }

    // Forward writes back to the SW so the jar mirrors app-side mutations
    // (preferences, JS-set tokens). Setter-only wrap leaves reads native --
    // less invasive than a full getter override that some browsers reject.
    try {
        var cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
        if (cookieDesc && cookieDesc.configurable && cookieDesc.set && cookieDesc.get) {
            Object.defineProperty(document, 'cookie', {
                get: function() { return cookieDesc.get.call(document); },
                set: function(value) {
                    cookieDesc.set.call(document, value);
                    var sw = navigator.serviceWorker && navigator.serviceWorker.controller;
                    if (sw && window.__bbSessionId) {
                        sw.postMessage({
                            type: 'cookieWrite',
                            sessionId: window.__bbSessionId,
                            value: value,
                        });
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
        // Rewrite URL
        arguments[1] = rewriteUrl(url);
        // Force async=true. Sync XHR bypasses the service worker entirely
        // (per spec), so it can never reach the WebRTC data channel. Most
        // apps (including jQuery with async:false) handle async responses
        // via callbacks and work fine either way.
        if (arguments.length > 2 && arguments[2] === false) {
            arguments[2] = true;
        }
        return origOpen.apply(this, arguments);
    };

    // -- Block SW registration from proxied apps ------------------------------
    // Proxied apps that register their own service worker would overwrite
    // BitBang's SW, breaking the data channel. Intercept the registration
    // and return a no-op so the app thinks it succeeded.
    if (navigator.serviceWorker) {
        var origRegister = navigator.serviceWorker.register.bind(navigator.serviceWorker);
        navigator.serviceWorker.register = function(scriptURL, options) {
            console.log('[BitBang] Blocked SW registration from proxied app:', scriptURL);
            return Promise.resolve(navigator.serviceWorker.ready);
        };
    }

    // -- Patch fetch ---------------------------------------------------------

    var origFetch = window.fetch;
    if (origFetch) {
        window.fetch = function(input, init) {
            if (typeof input === 'string') {
                input = rewriteUrl(input);
            } else if (input instanceof Request) {
                var newUrl = rewriteUrl(input.url);
                if (newUrl !== input.url) {
                    input = new Request(newUrl, input);
                }
            }
            // Our .then runs before the caller's, so document.cookie is
            // synced before any app handler sees the response.
            return origFetch.call(this, input, init).then(function(response) {
                applyCookieHeader(response.headers.get('X-BB-Set-Cookie'));
                return response;
            });
        };
    }
})();
