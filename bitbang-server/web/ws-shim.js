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
    const pendingSockets = new Map();
    let nextRequestId = 1;

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
        const {
            type, streamId, requestId, data, code, reason, message, ackToken, bytes,
        } = event.data || {};

        if (type === 'ws-rejected') {
            const pending = pendingSockets.get(requestId);
            if (!pending) return;
            pendingSockets.delete(requestId);
            window.removeEventListener('message', pending._assignHandler);
            pending._readyState = NativeWebSocket.CLOSED;
            const errorEvent = new Event('error');
            try {
                pending.dispatchEvent(errorEvent);
                if (pending.onerror) pending.onerror(errorEvent);
            } finally {
                const closeEvent = new CloseEvent('close', {
                    code: 1006, reason: message || 'Connection not ready',
                });
                pending.dispatchEvent(closeEvent);
                if (pending.onclose) pending.onclose(closeEvent);
            }
            return;
        }

        const ws = sockets.get(streamId);
        if (!ws) return;

        if (type === 'ws-opened') {
            if (ws._readyState !== NativeWebSocket.CONNECTING) return;
            log('ws-opened, streamId=' + streamId);
            ws._readyState = NativeWebSocket.OPEN;
            const evt = new Event('open');
            ws.dispatchEvent(evt);
            if (ws.onopen) ws.onopen(evt);
        } else if (type === 'ws-message') {
            const messageData = data instanceof ArrayBuffer && ws.binaryType === 'blob'
                ? new Blob([data]) : data;
            const evt = new MessageEvent('message', { data: messageData });
            try {
                ws.dispatchEvent(evt);
                if (ws.onmessage) ws.onmessage(evt);
            } finally {
                if (ackToken) {
                    parent.postMessage({
                        type: 'ws-consumed', streamId, ackToken,
                    }, '*');
                }
            }
        } else if (type === 'ws-send-ack') {
            ws._ackSend(bytes || 0);
        } else if (type === 'ws-closed') {
            log('ws-closed, streamId=' + streamId, 'code=' + code);
            ws._readyState = NativeWebSocket.CLOSED;
            ws._sendQueue.length = 0;
            ws._bufferedAmount = 0;
            ws._sendInFlight = false;
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
            this._sendQueue = [];
            this._sendInFlight = false;
            this._bufferedAmount = 0;
            this._closePending = null;
            this._requestId = nextRequestId++;
            pendingSockets.set(this._requestId, this);

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
                parent.postMessage({
                    type: 'ws-open', requestId: this._requestId,
                    pathname, protocols, cookies,
                }, '*');
            });

            // Bootstrap will respond with ws-assign containing the streamId
            const assignHandler = (event) => {
                if (event.source !== parent) return;
                if (event.data?.type === 'ws-assign'
                    && event.data.requestId === this._requestId) {
                    window.removeEventListener('message', assignHandler);
                    pendingSockets.delete(this._requestId);
                    this._streamId = event.data.streamId;
                    sockets.set(this._streamId, this);
                    log('ws-assign received, streamId=' + this._streamId);
                    this._flushSend();
                }
            };
            this._assignHandler = assignHandler;
            window.addEventListener('message', assignHandler);
        }

        get readyState() { return this._readyState; }
        get bufferedAmount() { return this._bufferedAmount; }

        send(data) {
            if (this._readyState !== NativeWebSocket.OPEN) {
                throw new DOMException('WebSocket is not open', 'InvalidStateError');
            }
            const isText = typeof data === 'string';
            let bytes;
            if (isText) bytes = new TextEncoder().encode(data).byteLength;
            else if (data instanceof Blob) bytes = data.size;
            else if (data instanceof ArrayBuffer) bytes = data.byteLength;
            else if (ArrayBuffer.isView(data)) bytes = data.byteLength;
            else throw new TypeError('WebSocket data must be a string, Blob, ArrayBuffer, or ArrayBufferView');
            this._sendQueue.push({ data, isText, bytes });
            this._bufferedAmount += bytes;
            this._flushSend();
        }

        close(code, reason) {
            if (this._readyState === NativeWebSocket.CLOSED) return;
            this._readyState = NativeWebSocket.CLOSING;
            this._closePending = { code: code || 1000, reason: reason || '' };
            this._flushSend();
        }

        _flushSend() {
            if (this._sendInFlight) return;
            if (this._streamId === undefined) return;
            const next = this._sendQueue[0];
            if (next) {
                this._sendInFlight = true;
                parent.postMessage({
                    type: 'ws-send', streamId: this._streamId,
                    data: next.data, isText: next.isText,
                    bufferedBytes: next.bytes,
                }, '*');
                return;
            }
            if (!this._closePending) return;
            const close = this._closePending;
            this._closePending = null;
            parent.postMessage({
                type: 'ws-close',
                streamId: this._streamId,
                code: close.code,
                reason: close.reason
            }, '*');
        }

        _ackSend(bytes) {
            const sent = this._sendQueue.shift();
            this._bufferedAmount = Math.max(0, this._bufferedAmount - (sent?.bytes || bytes));
            this._sendInFlight = false;
            this._flushSend();
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
