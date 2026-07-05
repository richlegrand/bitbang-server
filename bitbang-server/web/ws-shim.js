/**
 * BitBang WebSocket Shim
 *
 * Replaces the browser's WebSocket with an implementation that tunnels
 * over the BitBang SWSP data channel. Loaded into the device iframe
 * before the app's own scripts.
 *
 * Communication with the bootstrap parent uses postMessage:
 *   iframe -> parent: ws-open, ws-send, ws-close
 *   parent -> iframe: ws-opened, ws-message, ws-closed, ws-error
 */

(function() {
    const NativeWebSocket = window.WebSocket;
    const parent = window.parent;

    // Registry of active shim WebSockets by streamId
    const sockets = new Map();

    // Mirror SW cookie-jar updates into document.cookie so app code that
    // reads cookies directly (CSRF tokens, etc.) sees fresh values after
    // AJAX responses with Set-Cookie. The SW strips Set-Cookie from the
    // raw response, so without this mirror document.cookie goes stale.
    try {
        // Filter on jarKey (uid:target) so broadcasts from any tab on
        // the same device reach us. sessionId is per-tab and never
        // matches across tabs -- filtering on it silently dropped
        // every cross-tab cookie update.
        const cookieChannel = new BroadcastChannel('bitbang-cookies');
        cookieChannel.onmessage = (event) => {
            if (event.data?.jarKey !== window.__bbJarKey) return;
            const cookies = event.data.cookies || [];
            for (const c of cookies) {
                document.cookie = `${c.name}=${c.value};path=${c.path}`;
            }
        };
    } catch (e) {}

    // Ask the SW for the current cookie header for a given path. The SW
    // jar is the source of truth; document.cookie is a best-effort mirror.
    function getCookiesFromSW(path) {
        const sw = navigator.serviceWorker?.controller;
        if (!sw || !window.__bbSessionId) return Promise.resolve('');
        return new Promise((resolve) => {
            const channel = new MessageChannel();
            const timeout = setTimeout(() => resolve(''), 1000);
            channel.port1.onmessage = (e) => {
                clearTimeout(timeout);
                resolve(e.data?.cookies || '');
            };
            sw.postMessage({
                type: 'getCookies',
                sessionId: window.__bbSessionId,
                path,
            }, [channel.port2]);
        });
    }

    // Listen for messages from the bootstrap parent
    window.addEventListener('message', (event) => {
        if (event.source !== parent) return;
        const { type, streamId, data, code, reason, message } = event.data || {};

        const ws = sockets.get(streamId);
        if (!ws) return;

        if (type === 'ws-opened') {
            log('ws-opened, streamId=' + streamId);
            ws._readyState = NativeWebSocket.OPEN;
            ws.dispatchEvent(new Event('open'));
            if (ws.onopen) ws.onopen(new Event('open'));
        } else if (type === 'ws-message') {
            const evt = new MessageEvent('message', { data });
            ws.dispatchEvent(evt);
            if (ws.onmessage) ws.onmessage(evt);
        } else if (type === 'ws-closed') {
            log('ws-closed, streamId=' + streamId, 'code=' + code);
            ws._readyState = NativeWebSocket.CLOSED;
            sockets.delete(streamId);
            const evt = new CloseEvent('close', { code: code || 1000, reason: reason || '' });
            ws.dispatchEvent(evt);
            if (ws.onclose) ws.onclose(evt);
        } else if (type === 'ws-error') {
            log('ws-error, streamId=' + streamId);
            const evt = new Event('error');
            ws.dispatchEvent(evt);
            if (ws.onerror) ws.onerror(evt);
        }
    });

    function log(msg, ...args) {
        if (!window.__bbDebug) return;
        console.log('[ws-shim] ' + msg, ...args);
    }

    class BitBangWebSocket extends EventTarget {
        constructor(url, protocols) {
            super();
            log('constructed', url);

            this.onopen = null;
            this.onmessage = null;
            this.onclose = null;
            this.onerror = null;
            this.binaryType = 'blob';
            this._readyState = NativeWebSocket.CONNECTING;

            // Parse URL to get pathname, stripping /__device__ prefix
            let pathname;
            try {
                const parsed = new URL(url, window.location.href);
                pathname = parsed.pathname + parsed.search;
            } catch (e) {
                pathname = url;
            }
            // Strip /__device__/<sessionId> prefix from the path
            const devPrefix = '/__device__/';
            if (pathname.startsWith(devPrefix)) {
                const rest = pathname.slice(devPrefix.length);
                const slashIdx = rest.indexOf('/');
                pathname = slashIdx >= 0 ? rest.slice(slashIdx) : '/';
            }

            this.url = url;
            this._protocols = protocols;

            // Request a streamId from the bootstrap and open the WS stream.
            // Cookies come from the SW jar (canonical) instead of document.cookie,
            // which can be stale after AJAX Set-Cookie responses.
            getCookiesFromSW(pathname).then((cookies) => {
                log('ws-open posted', pathname, 'cookies.len=' + cookies.length);
                parent.postMessage({ type: 'ws-open', pathname, protocols, cookies }, '*');
            });

            // Bootstrap will respond with ws-assign containing the streamId
            const assignHandler = (event) => {
                if (event.source !== parent) return;
                if (event.data?.type === 'ws-assign' && event.data.pathname === pathname) {
                    window.removeEventListener('message', assignHandler);
                    this._streamId = event.data.streamId;
                    sockets.set(this._streamId, this);
                    log('ws-assign received, streamId=' + this._streamId);
                }
            };
            window.addEventListener('message', assignHandler);
        }

        get readyState() { return this._readyState; }

        send(data) {
            if (this._readyState !== NativeWebSocket.OPEN) {
                throw new DOMException('WebSocket is not open', 'InvalidStateError');
            }
            const isText = typeof data === 'string';
            parent.postMessage({
                type: 'ws-send',
                streamId: this._streamId,
                data,
                isText
            }, '*');
        }

        close(code, reason) {
            if (this._readyState === NativeWebSocket.CLOSED) return;
            this._readyState = NativeWebSocket.CLOSING;
            parent.postMessage({
                type: 'ws-close',
                streamId: this._streamId,
                code: code || 1000,
                reason: reason || ''
            }, '*');
        }

        // Standard WebSocket constants
        static get CONNECTING() { return 0; }
        static get OPEN() { return 1; }
        static get CLOSING() { return 2; }
        static get CLOSED() { return 3; }
    }

    // Replace the global WebSocket
    window.WebSocket = BitBangWebSocket;
    // Keep native available in case someone needs it
    window.NativeWebSocket = NativeWebSocket;
})();
