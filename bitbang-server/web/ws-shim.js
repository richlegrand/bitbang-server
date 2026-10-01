/**
 * BitBang WebSocket Shim
 *
 * Replaces the browser's WebSocket with an implementation that tunnels
 * over the BitBang SWSP data channel. Loaded into the device iframe
 * before the app's own scripts.
 *
 * Communication with the bootstrap parent uses postMessage:
 *   iframe -> parent: ws-open, ws-send, ws-close
 *   parent -> iframe: ws-assign, ws-opened, ws-message, ws-closed, ws-error
 */

(function() {
    const NativeWebSocket = window.WebSocket;
    const parent = window.parent;

    // Sockets the bootstrap has given a stream, by streamId.
    const sockets = new Map();

    // Sockets waiting for their stream, by an id this file mints. ws-open
    // carries the id and ws-assign echoes it, so each assignment finds the
    // socket that asked for it. They used to be matched on pathname, and two
    // sockets opened to one path before the first assignment both took it.
    const opening = new Map();
    let nextOpenId = 1;

    // The cookie mirror that used to be here -- a BroadcastChannel listener
    // writing jar updates into document.cookie -- is in xhr-shim.js now, with
    // the rest of the mirror. See the note there for why it had to move: from
    // here its writes went through the setter that forwards to the jar, and
    // came back without their expiry.

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
        const { type, openId, streamId, data, code, reason } = event.data || {};

        if (type === 'ws-assign') {
            const ws = opening.get(openId);
            if (!ws) return;
            opening.delete(openId);
            log('ws-assign received, streamId=' + streamId);
            // Closed while it waited: the app has already had its close
            // event, so all that's left is to give the stream back.
            if (ws._readyState === NativeWebSocket.CLOSED) {
                parent.postMessage({ type: 'ws-close', streamId, code: 1000, reason: '' }, '*');
                return;
            }
            ws._streamId = streamId;
            sockets.set(streamId, ws);
            return;
        }

        const ws = sockets.get(streamId);
        if (!ws) return;

        if (type === 'ws-opened') {
            log('ws-opened, streamId=' + streamId);
            ws._readyState = NativeWebSocket.OPEN;
            fire(ws, new Event('open'));
        } else if (type === 'ws-message') {
            // Binary comes from the bootstrap as an ArrayBuffer. A real
            // WebSocket hands it over as a Blob unless binaryType says
            // otherwise.
            const msg = data instanceof ArrayBuffer && ws.binaryType !== 'arraybuffer'
                ? new Blob([data]) : data;
            fire(ws, new MessageEvent('message', { data: msg }));
        } else if (type === 'ws-closed') {
            log('ws-closed, streamId=' + streamId, 'code=' + code);
            sockets.delete(streamId);
            ws._readyState = NativeWebSocket.CLOSED;
            fire(ws, new CloseEvent('close', { code: code || 1000, reason: reason || '', wasClean: true }));
        } else if (type === 'ws-error') {
            log('ws-error, streamId=' + streamId);
            fire(ws, new Event('error'));
        }
    });

    function fire(ws, evt) {
        ws.dispatchEvent(evt);
        const handler = ws['on' + evt.type];
        if (handler) handler.call(ws, evt);
    }

    // A socket closed before it opened fails, as a real one does: error,
    // then close with 1006. Fired a tick later, since close() never runs
    // the app's handlers from inside itself.
    function failLater(ws) {
        ws._readyState = NativeWebSocket.CLOSED;
        setTimeout(() => {
            fire(ws, new Event('error'));
            fire(ws, new CloseEvent('close', { code: 1006, reason: '', wasClean: false }));
        }, 0);
    }

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

            // Ask the bootstrap for a stream; ws-assign answers with its id.
            // Cookies come from the SW jar (canonical) instead of document.cookie,
            // which can be stale after AJAX Set-Cookie responses. A socket
            // closed during that wait never asks at all.
            const openId = nextOpenId++;
            getCookiesFromSW(pathname).then((cookies) => {
                if (this._readyState === NativeWebSocket.CLOSED) return;
                opening.set(openId, this);
                log('ws-open posted', pathname, 'cookies.len=' + cookies.length);
                parent.postMessage({ type: 'ws-open', openId, pathname, protocols, cookies }, '*');
            });
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
            if (this._readyState === NativeWebSocket.CLOSING ||
                this._readyState === NativeWebSocket.CLOSED) return;
            if (this._readyState === NativeWebSocket.CONNECTING) {
                // A stream already assigned is given back now. One not yet
                // assigned is given back by ws-assign, which finds the
                // socket CLOSED.
                if (this._streamId !== undefined) {
                    sockets.delete(this._streamId);
                    parent.postMessage({ type: 'ws-close', streamId: this._streamId,
                                         code: 1000, reason: '' }, '*');
                }
                failLater(this);
                return;
            }
            // Open: the bootstrap answers with ws-closed, and that fires close.
            this._readyState = NativeWebSocket.CLOSING;
            parent.postMessage({
                type: 'ws-close',
                streamId: this._streamId,
                code: code || 1000,
                reason: reason || ''
            }, '*');
        }

        // Sends are posted to the bootstrap, not queued here, so nothing is
        // ever buffered. No subprotocol or extension is negotiated with the
        // device, and '' is what a real WebSocket reports when none is.
        get bufferedAmount() { return 0; }
        get protocol() { return ''; }
        get extensions() { return ''; }

        // Standard WebSocket constants
        static get CONNECTING() { return 0; }
        static get OPEN() { return 1; }
        static get CLOSING() { return 2; }
        static get CLOSED() { return 3; }
    }

    // A real WebSocket has the constants on instances too, and
    // `ws.readyState === ws.OPEN` is how a lot of code checks.
    for (const name of ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED']) {
        Object.defineProperty(BitBangWebSocket.prototype, name,
            { value: BitBangWebSocket[name], enumerable: true });
    }

    // Replace the global WebSocket
    window.WebSocket = BitBangWebSocket;
    // Keep native available in case someone needs it
    window.NativeWebSocket = NativeWebSocket;
})();
