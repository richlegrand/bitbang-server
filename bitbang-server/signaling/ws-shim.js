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
        const cookieChannel = new BroadcastChannel('bitbang-cookies');
        cookieChannel.onmessage = (event) => {
            if (event.data?.sessionId !== window.__bbSessionId) return;
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
            ws._readyState = NativeWebSocket.OPEN;
            ws.dispatchEvent(new Event('open'));
            if (ws.onopen) ws.onopen(new Event('open'));
        } else if (type === 'ws-message') {
            const evt = new MessageEvent('message', { data });
            ws.dispatchEvent(evt);
            if (ws.onmessage) ws.onmessage(evt);
        } else if (type === 'ws-closed') {
            ws._readyState = NativeWebSocket.CLOSED;
            sockets.delete(streamId);
            const evt = new CloseEvent('close', { code: code || 1000, reason: reason || '' });
            ws.dispatchEvent(evt);
            if (ws.onclose) ws.onclose(evt);
        } else if (type === 'ws-error') {
            const evt = new Event('error');
            ws.dispatchEvent(evt);
            if (ws.onerror) ws.onerror(evt);
        }
    });

    class BitBangWebSocket extends EventTarget {
        constructor(url, protocols) {
            super();

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
                parent.postMessage({ type: 'ws-open', pathname, protocols, cookies }, '*');
            });

            // Bootstrap will respond with ws-assign containing the streamId
            const assignHandler = (event) => {
                if (event.source !== parent) return;
                if (event.data?.type === 'ws-assign' && event.data.pathname === pathname) {
                    window.removeEventListener('message', assignHandler);
                    this._streamId = event.data.streamId;
                    sockets.set(this._streamId, this);
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
