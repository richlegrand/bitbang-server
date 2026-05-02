/**
 * BitBang Bootstrap Client
 *
 * Manages WebRTC connection to device, bridges service worker to data channel,
 * and wires up media streams to the iframe.
 */

const STATUS = {
    CONNECTING: "Connecting to server...",
    WAITING_OFFER: "Waiting for device...",
    CONNECTING_WEBRTC: "Establishing peer connection...",
    CONNECTED: "Connected"
};

// SWSP (Simple WebRTC Streaming Protocol) constants
const FLAG_SYN = 0x0001;
const FLAG_FIN = 0x0004;
const FLAG_DAT = 0x0000;

class BitBangConnection {
    constructor(uid, devicePath) {
        this.uid = uid;
        this.devicePath = devicePath || '/';
        this.pc = null;
        this.dataChannel = null;
        this.ws = null;
        this.streamNameMap = {};      // from offer: { "0": "webcam", ... }
        this.resolvedStreams = {};    // name -> MediaStream
        this.pendingRequests = new Map();  // streamId -> request state
        this.connectResolve = null;   // resolved when device sends 'ready'
        this.nextStreamId = 1;        // streamId 0 is reserved for control
        this.wsStreams = new Map();    // streamId -> { iframe } for WebSocket bridging
        this.sessionId = Array.from(crypto.getRandomValues(new Uint8Array(4)), b => b.toString(16).padStart(2, '0')).join(''); // 8 hex chars
        this.localCandidateQueue = [];
        this.remoteCandidateQueue = [];
        this.remoteDescriptionSet = false;
        this.progressChannel = new BroadcastChannel('bitbang-progress');

        this.statusEl = document.getElementById('status');
        this.connectionUI = document.getElementById('connection-ui');
        this.debug = new URLSearchParams(window.location.search).has('debug');

        if (this.debug && this.connectionUI) {
            this.connectionUI.classList.add('debug');
            this.statusEl.textContent = '';
        }
    }

    // SWSP frame helpers
    createFrame(streamId, flags, payload) {
        // payload can be string or Uint8Array
        let payloadBytes;
        if (typeof payload === 'string') {
            payloadBytes = new TextEncoder().encode(payload);
        } else if (payload instanceof ArrayBuffer) {
            payloadBytes = new Uint8Array(payload);
        } else {
            payloadBytes = payload;
        }

        const buffer = new ArrayBuffer(8 + payloadBytes.byteLength);
        const view = new DataView(buffer);
        view.setUint32(0, streamId, true);  // little-endian
        view.setUint16(4, flags, true);
        view.setUint16(6, payloadBytes.byteLength, true);
        new Uint8Array(buffer).set(payloadBytes, 8);
        return buffer;
    }

    parseFrame(buffer) {
        const view = new DataView(buffer);
        const streamId = view.getUint32(0, true);
        const flags = view.getUint16(4, true);
        const length = view.getUint16(6, true);
        const payload = buffer.slice(8, 8 + length);
        return { streamId, flags, payload };
    }

    updateStatus(status) {
        if (this.debug) {
            if (this.statusEl) {
                const step = document.createElement('div');
                step.className = 'step';
                step.textContent = status;
                this.statusEl.appendChild(step);
            }
        }
        document.title = status;
    }

    async connect() {
        try {
            await this.registerServiceWorker();
            this.updateStatus(STATUS.CONNECTING);
            await this.connectWebSocket();
        } catch (error) {
            console.error('Connection failed:', error);
            const msg = this.userErrorMessage(error.message);
            if (this.debug) {
                this.updateStatus('Error: ' + msg);
            } else if (this.statusEl) {
                this.statusEl.textContent = msg;
            }
            if (this.statusEl) this.statusEl.classList.add('error');
        }
    }

    userErrorMessage(msg) {
        if (msg === 'Device not found') return 'Device not found';
        if (msg === 'WebSocket connection failed') return 'Could not reach server';
        if (msg === 'Service Worker not supported') return 'This browser is not supported';
        if (msg === 'offer_timeout') return 'Device not responding';
        return 'Connection failed';
    }

    async registerServiceWorker() {
        if (!('serviceWorker' in navigator)) {
            throw new Error('Service Worker not supported');
        }

        const reg = await navigator.serviceWorker.register('/__bitbang__/sw.js', {
            scope: '/',
            updateViaCache: 'none',
        });
        // Force check for SW update on every page load
        reg.update();

        // Handle proxy requests from SW
        navigator.serviceWorker.addEventListener('message', (event) => {
            if (event.data?.type === 'request') {
                this.handleProxyRequest(event.data, event.ports[0]);
            }
        });

        await navigator.serviceWorker.ready;
    }

    handleProxyRequest(data, responsePort) {
        const { method, url, headers, hasBody, contentLength } = data;
        console.log(`[Bootstrap] Received proxy request: ${method} ${new URL(url).pathname}, DC state: ${this.dataChannel?.readyState}`);

        if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
            console.warn('[Bootstrap] Data channel not open, rejecting request');
            responsePort.postMessage({ type: 'error', message: 'Data channel not open' });
            return;
        }

        // Strip /__device__ prefix, keep query string
        const parsed = new URL(url);
        let pathname = parsed.pathname;
        if (pathname.startsWith('/__device__')) {
            pathname = pathname.slice('/__device__'.length) || '/';
        }
        const fullPath = pathname + parsed.search;

        // Use incrementing stream ID for SWSP
        const streamId = this.nextStreamId++;

        // Timeout resets on activity (30s inactivity = timeout)
        let timeout;
        const resetTimeout = () => {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                this.pendingRequests.delete(streamId);
                responsePort.postMessage({ type: 'error', message: 'Request timeout' });
            }, 30000);
        };
        resetTimeout();

        this.pendingRequests.set(streamId, {
            responsePort,
            timeout,
            resetTimeout,
            bytesReceived: 0,
            startTime: Date.now(),
            nextLogMB: 50,
            isUpload: hasBody
        });

        // Build request metadata with all headers
        const requestMeta = { method, pathname: fullPath, headers };
        if (hasBody) {
            requestMeta.contentLength = contentLength;
            // Keep contentType for backward compatibility with older devices
            if (headers['content-type']) {
                requestMeta.contentType = headers['content-type'];
            }
        }

        if (hasBody) {
            // Send SYN frame with metadata, then stream body chunks as they arrive
            const synFrame = this.createFrame(streamId, FLAG_SYN, JSON.stringify(requestMeta));
            try {
                this.dataChannel.send(synFrame);
            } catch (e) {
                responsePort.postMessage({ type: 'error', message: 'Failed to start upload' });
                this.progressChannel.postMessage({ type: 'uploadFailed' });
                return;
            }

            const MAX_CHUNK = 16384;
            let bytesSent = 0;
            let lastProgress = 0;
            let processingChain = Promise.resolve();

            const failUpload = (msg) => {
                this.pendingRequests.delete(streamId);
                responsePort.postMessage({ type: 'error', message: msg });
                this.progressChannel.postMessage({ type: 'uploadFailed' });
            };

            const isOpen = () => this.dataChannel?.readyState === 'open';

            responsePort.onmessage = (event) => {
                processingChain = processingChain.then(async () => {
                    if (!isOpen()) return failUpload('Connection lost');

                    if (event.data.type === 'bodyChunk') {
                        const data = event.data.data;

                        for (let i = 0; i < data.byteLength; i += MAX_CHUNK) {
                            // Backpressure: wait while buffer is full
                            while (isOpen() && this.dataChannel.bufferedAmount > 1024 * 1024) {
                                await new Promise(r => setTimeout(r, 10));
                            }
                            if (!isOpen()) return failUpload('Connection lost');

                            const chunk = data.subarray(i, Math.min(i + MAX_CHUNK, data.byteLength));
                            this.dataChannel.send(this.createFrame(streamId, FLAG_DAT, chunk));
                        }

                        bytesSent += data.byteLength;
                        const now = Date.now();
                        if (now - lastProgress > 100) {
                            lastProgress = now;
                            resetTimeout();
                            this.progressChannel.postMessage({
                                type: 'uploadProgress', loaded: bytesSent, total: contentLength
                            });
                        }

                    } else if (event.data.type === 'bodyEnd') {
                        if (!isOpen()) return failUpload('Connection lost');
                        this.progressChannel.postMessage({ type: 'uploadComplete' });
                        this.dataChannel.send(this.createFrame(streamId, FLAG_FIN, new Uint8Array(0)));
                    }
                });
            };
        } else {
            // No body - send SYN|FIN together
            const frame = this.createFrame(streamId, FLAG_SYN | FLAG_FIN, JSON.stringify(requestMeta));
            this.dataChannel.send(frame);
        }
    }

    connectWebSocket() {
        return new Promise((resolve, reject) => {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            this.ws = new WebSocket(`${protocol}//${window.location.host}/ws/client/${this.uid}`);

            const offerTimeout = setTimeout(() => {
                reject(new Error('offer_timeout'));
            }, 15000);

            this.ws.onopen = () => {
                this.ws.send(JSON.stringify({ type: 'request', uid: this.uid }));
                this.updateStatus(STATUS.WAITING_OFFER);
            };

            this.ws.onmessage = async (event) => {
                const msg = JSON.parse(event.data);
                if (msg.type === 'offer') {
                    clearTimeout(offerTimeout);
                    await this.handleOffer(msg);
                    resolve();
                } else if (msg.type === 'candidate') {
                    this.handleRemoteCandidate(msg.candidate);
                } else if (msg.type === 'error') {
                    clearTimeout(offerTimeout);
                    reject(new Error(msg.message));
                }
            };

            this.ws.onerror = () => {
                clearTimeout(offerTimeout);
                reject(new Error('WebSocket connection failed'));
            };
        });
    }

    async handleOffer(msg) {
        this.updateStatus(STATUS.CONNECTING_WEBRTC);
        this.streamNameMap = msg.streams || {};
        this.deviceName = msg.device_name || null;
        this.pc = this.createPeerConnection(msg.ice_servers);

        await this.pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
        this.remoteDescriptionSet = true;

        // Flush buffered remote candidates
        for (const candidate of this.remoteCandidateQueue) {
            await this.pc.addIceCandidate(candidate).catch(() => {});
        }
        this.remoteCandidateQueue = [];

        // Create and send answer
        const answer = await this.pc.createAnswer();
        await this.pc.setLocalDescription(answer);
        this.ws.send(JSON.stringify({ type: 'answer', uid: this.uid, sdp: this.pc.localDescription.sdp }));

        // Flush buffered local candidates
        for (const msg of this.localCandidateQueue) {
            this.ws.send(JSON.stringify(msg));
        }
        this.localCandidateQueue = [];
    }

    createPeerConnection(iceServers) {
        const config = { sdpSemantics: 'unified-plan' };
        if (iceServers && iceServers.length > 0) {
            config.iceServers = iceServers;
        }
        const pc = new RTCPeerConnection(config);

        pc.onconnectionstatechange = () => {
            if (pc.connectionState === 'connected') {
                this.updateStatus(STATUS.CONNECTED);
                // Delay connection type check — ICE may initially use TURN
                // relay but switch to a direct path within seconds as better
                // candidate pairs are discovered and promoted.
                setTimeout(() => this.logConnectionType(pc), 3000);
            } else if (pc.connectionState === 'failed') {
                this.showErrorScreen('Peer connection failed');
            }
        };

        pc.onicecandidate = (event) => {
            if (event.candidate) {
                const msg = { type: 'candidate', uid: this.uid, candidate: event.candidate };
                if (this.ws?.readyState === WebSocket.OPEN && this.remoteDescriptionSet) {
                    this.ws.send(JSON.stringify(msg));
                } else {
                    this.localCandidateQueue.push(msg);
                }
            }
        };

        pc.ontrack = (event) => {
            const mid = event.transceiver.mid;
            const name = this.streamNameMap[mid] || mid || 'default';
            this.resolvedStreams[name] = event.streams[0];
        };

        pc.ondatachannel = (event) => {
            this.dataChannel = event.channel;
            this.dataChannel.binaryType = 'arraybuffer';  // SWSP uses binary frames
            this.dataChannel.onopen = () => {
                console.log('DataChannel opened');
                this.onDataChannelReady();
            };
            this.dataChannel.onclose = () => console.log('DataChannel closed');
            this.dataChannel.onerror = (e) => console.error('DataChannel error:', e);
            this.dataChannel.onmessage = (e) => this.handleDataChannelMessage(e);
        };

        return pc;
    }

    handleRemoteCandidate(candidate) {
        if (this.remoteDescriptionSet && this.pc) {
            this.pc.addIceCandidate(candidate).catch(() => {});
        } else {
            this.remoteCandidateQueue.push(candidate);
        }
    }

    async logConnectionType(pc) {
        try {
            const stats = await pc.getStats();
            // Find the nominated (active) candidate pair — not all succeeded pairs
            let nominated = null;
            for (const [, report] of stats) {
                if (report.type === 'candidate-pair' && report.nominated && report.state === 'succeeded') {
                    nominated = report;
                    break;
                }
            }
            // Fall back to any succeeded pair if no nominated flag
            if (!nominated) {
                for (const [, report] of stats) {
                    if (report.type === 'candidate-pair' && report.state === 'succeeded') {
                        nominated = report;
                        break;
                    }
                }
            }
            if (nominated) {
                const local = stats.get(nominated.localCandidateId);
                const remote = stats.get(nominated.remoteCandidateId);
                const localDesc = local ? `${local.candidateType} ${local.address}:${local.port}` : 'unknown';
                const remoteDesc = remote ? `${remote.candidateType} ${remote.address}:${remote.port}` : 'unknown';
                if (local?.candidateType === 'relay' || remote?.candidateType === 'relay') {
                    console.warn(`Using TURN relay - local: ${localDesc}, remote: ${remoteDesc}`);
                } else {
                    console.log(`Direct connection - local: ${localDesc}, remote: ${remoteDesc}`);
                }
            }
        } catch (e) {
            // Ignore stats errors
        }
    }

    handleDataChannelMessage(event) {
        // SWSP: expect binary frames
        if (!(event.data instanceof ArrayBuffer)) {
            console.error('Received non-binary message on http channel (unexpected)');
            return;
        }

        try {
            const frame = this.parseFrame(event.data);

            // StreamId 0 is reserved for control messages (connect/ready/auth)
            if (frame.streamId === 0) {
                this.handleControlMessage(frame);
                return;
            }

            // WebSocket stream -- forward to iframe
            const ws = this.wsStreams.get(frame.streamId);
            if (ws) {
                this.handleWSFrame(frame, ws);
                return;
            }

            const req = this.pendingRequests.get(frame.streamId);

            if (!req) {
                console.log('Received frame for unknown stream:', frame.streamId);
                return;
            }

            // Reset timeout on any data received
            req.resetTimeout();

            if (frame.flags & FLAG_SYN) {
                // Metadata frame - send headers to SW, it will create the stream
                const text = new TextDecoder().decode(frame.payload);
                const metadata = JSON.parse(text);
                const status = metadata.status || 200;
                console.log(`[Bootstrap] Response for stream ${frame.streamId}: ${status}`);

                // Clear timeout on first response
                clearTimeout(req.timeout);

                req.responsePort.postMessage({
                    type: 'headers',
                    status: status,
                    headers: metadata.headers || {}
                });

                // Broadcast upload result for iframe UI
                if (req.isUpload) {
                    this.progressChannel.postMessage({
                        type: status >= 200 && status < 300 ? 'uploadSuccess' : 'uploadFailed',
                        status: status
                    });
                }
            }

            if (frame.flags & FLAG_FIN) {
                // End of stream
                if (frame.payload.byteLength > 0 && !(frame.flags & FLAG_SYN)) {
                    req.bytesReceived += frame.payload.byteLength;
                    const data = new Uint8Array(frame.payload);
                    req.responsePort.postMessage({ type: 'chunk', data }, [data.buffer]);
                }

                // Log completion for large transfers
                if (req.bytesReceived > 1024 * 1024) {
                    const elapsed = (Date.now() - req.startTime) / 1000;
                    const sizeMB = req.bytesReceived / (1024 * 1024);
                    const speed = elapsed > 0 ? (sizeMB / elapsed).toFixed(1) : '0';
                    console.log(`Download complete: ${sizeMB.toFixed(0)} MB in ${elapsed.toFixed(1)}s (${speed} MB/s)`);
                }

                req.responsePort.postMessage({ type: 'done' });
                this.pendingRequests.delete(frame.streamId);
            } else if (!(frame.flags & FLAG_SYN) && frame.payload.byteLength > 0) {
                // Data chunk - use transferable to avoid copy
                req.bytesReceived += frame.payload.byteLength;
                const data = new Uint8Array(frame.payload);
                req.responsePort.postMessage({ type: 'chunk', data }, [data.buffer]);

                // Log progress at each 50MB milestone
                const currentMB = req.bytesReceived / (1024 * 1024);
                if (currentMB >= req.nextLogMB) {
                    const elapsed = (Date.now() - req.startTime) / 1000;
                    const speed = elapsed > 0 ? (currentMB / elapsed).toFixed(1) : '0';
                    console.log(`Download: ${currentMB.toFixed(0)} MB (${speed} MB/s)`);
                    req.nextLogMB += 50;
                }
            }
        } catch (e) {
            console.error('Error parsing SWSP frame:', e);
        }
    }

    handleControlMessage(frame) {
        if (!(frame.flags & FLAG_SYN)) return;

        const text = new TextDecoder().decode(frame.payload);
        const msg = JSON.parse(text);

        if (msg.type === 'ready') {
            console.log('[Bootstrap] Device ready');
            if (this.connectResolve) {
                this.connectResolve();
                this.connectResolve = null;
            }
        } else if (msg.type === 'auth_required') {
            console.log('[Bootstrap] Device requires authentication');
            // Auto-submit cached PIN from a previous successful auth
            const cachedPIN = sessionStorage.getItem('__bb_pin_' + this.uid);
            if (cachedPIN && !this._authRetry) {
                this._lastPIN = cachedPIN;
                this._authRetry = true;
                const authMsg = JSON.stringify({ type: 'auth', pin: cachedPIN });
                this.dataChannel.send(this.createFrame(0, FLAG_SYN, authMsg));
            } else {
                this._authRetry = false;
                this.showPINPrompt();
            }
        } else if (msg.type === 'auth_result') {
            const handleResult = () => {
                if (msg.success) {
                    this._authRetry = false;
                    if (this._lastPIN) {
                        sessionStorage.setItem('__bb_pin_' + this.uid, this._lastPIN);
                    }
                    if (this.connectResolve) {
                        this.connectResolve();
                        this.connectResolve = null;
                    }
                } else {
                    sessionStorage.removeItem('__bb_pin_' + this.uid);
                    this._authRetry = false;
                    this.showPINPrompt();
                }
            };

            if (this._authRetry) {
                handleResult();
            } else {
                const delay = msg.success ? 2000 : 3000;
                setTimeout(handleResult, delay);
            }
        } else if (msg.type === 'error') {
            console.error('[Bootstrap] Device error:', msg.message);
            this.showErrorScreen(msg.message || 'Connection refused');
        }
    }

    showErrorScreen(message) {
        if (this.connectionUI) {
            if (this.debug) {
                this.updateStatus('Error: ' + message);
            } else {
                this.statusEl.textContent = message;
                this.statusEl.classList.add('error');
            }
            this.connectionUI.style.display = '';
        }
    }

    showPINPrompt(errorMessage, remaining) {
        const iframe = document.getElementById('device-frame');
        if (iframe) iframe.style.display = 'none';
        if (this.connectionUI) {
            this.connectionUI.className = '';
            const error = errorMessage
                ? `<div style="color: #c00; margin-bottom: 8px;">${errorMessage}</div>`
                : '';
            this.connectionUI.innerHTML = `
                <div style="font-size: 14px; margin-bottom: 8px;">PIN Required</div>
                ${error}
                <div style="display: flex; gap: 6px; align-items: center;">
                    <input type="password" id="pin-input" placeholder="PIN"
                           style="padding: 4px 8px; font-size: 14px; border: 1px solid #ccc;
                                  border-radius: 3px; width: 120px; outline: none;"
                           onkeydown="if(event.key==='Enter')document.getElementById('pin-submit').click()"
                           autofocus>
                    <button id="pin-submit"
                            style="padding: 4px 12px; font-size: 14px; border: 1px solid #ccc;
                                   border-radius: 3px; background: #fff; cursor: pointer;"
                            >OK</button>
                </div>
            `;
            this.connectionUI.style.display = '';

            document.getElementById('pin-submit').onclick = () => {
                const pin = document.getElementById('pin-input').value;
                if (!pin) return;
                this._lastPIN = pin;
                const authMsg = JSON.stringify({ type: 'auth', pin });
                this.dataChannel.send(this.createFrame(0, FLAG_SYN, authMsg));
            };

            // Focus the input after DOM update
            setTimeout(() => document.getElementById('pin-input')?.focus(), 50);
        }
    }

    handleWSFrame(frame, ws) {
        if (frame.flags & FLAG_SYN) {
            // Device acknowledged the WebSocket open
            ws.iframe.postMessage({ type: 'ws-opened', streamId: frame.streamId }, '*');
        }

        if (frame.flags & FLAG_FIN) {
            // Device closed the WebSocket
            this.wsStreams.delete(frame.streamId);
            ws.iframe.postMessage({
                type: 'ws-closed',
                streamId: frame.streamId,
                code: 1000
            }, '*');
            return;
        }

        if (frame.payload.byteLength > 0 && !(frame.flags & FLAG_SYN)) {
            // DAT frame: type byte (0=text, 1=binary) + message
            const view = new Uint8Array(frame.payload);
            const isText = view[0] === 0;
            const messageBytes = view.slice(1);

            let data;
            if (isText) {
                data = new TextDecoder().decode(messageBytes);
            } else {
                data = messageBytes.buffer;
            }

            ws.iframe.postMessage({
                type: 'ws-message',
                streamId: frame.streamId,
                data
            }, '*');
        }
    }

    async onDataChannelReady() {
        // Register this tab's session with the SW
        const pathParts = this.devicePath.split('/').filter(Boolean);
        const target = pathParts[0] || 'device';
        const reg = await navigator.serviceWorker.ready;
        reg.active.postMessage({
            type: 'setBootstrap',
            sessionId: this.sessionId,
            uid: this.uid,
            target: target,
        });

        // Brief delay for any pending tracks to arrive
        await new Promise(resolve => setTimeout(resolve, 100));

        // Send connect handshake with path (streamId 0)
        const connectMsg = JSON.stringify({ type: 'connect', path: this.devicePath });
        this.dataChannel.send(this.createFrame(0, FLAG_SYN, connectMsg));

        // Wait for 'ready' response from device
        await new Promise(resolve => { this.connectResolve = resolve; });

        // Listen for messages from the iframe (WebSocket shim + navigation)
        window.addEventListener('message', (event) => {
            const iframe = document.getElementById('device-frame');
            if (!iframe || event.source !== iframe.contentWindow) return;
            if (event.data?.type === 'bb-navigate') {
                this.handleNavigateRequest(event.data.path);
            } else {
                this.handleWSShimMessage(event);
            }
        });

        this.createIframe();
    }

    handleNavigateRequest(path) {
        // Iframe requested navigation to a path that may need PIN auth.
        // Send a new connect message on stream 0. The device will respond
        // with 'ready' (no PIN needed) or 'auth_required'.
        console.log('[Bootstrap] Navigate request:', path);

        const iframe = document.getElementById('device-frame');
        this.devicePath = path;

        // Set up a resolve callback for the auth flow
        const navigateAfterAuth = () => {
            if (iframe) {
                iframe.src = `/__device__/${this.sessionId}${this.devicePath}`;
                iframe.style.display = '';
            }
            if (this.connectionUI) this.connectionUI.style.display = 'none';
        };
        this.connectResolve = navigateAfterAuth;

        // Send connect with the new path
        const connectMsg = JSON.stringify({ type: 'connect', path });
        this.dataChannel.send(this.createFrame(0, FLAG_SYN, connectMsg));
    }

    handleWSShimMessage(event) {
        const iframe = document.getElementById('device-frame');
        if (!iframe || event.source !== iframe.contentWindow) return;
        if (!this.dataChannel || this.dataChannel.readyState !== 'open') return;

        const msg = event.data;
        if (!msg || !msg.type?.startsWith('ws-')) return;

        if (msg.type === 'ws-open') {
            // Allocate a stream ID and send SYN with websocket type
            const streamId = this.nextStreamId++;
            this.wsStreams.set(streamId, { iframe: iframe.contentWindow });

            // Tell the shim which streamId was assigned
            iframe.contentWindow.postMessage({
                type: 'ws-assign',
                pathname: msg.pathname,
                streamId
            }, '*');

            // Send SWSP SYN to device (include cookies for session auth)
            const synPayload = JSON.stringify({
                type: 'websocket',
                pathname: msg.pathname,
                cookies: msg.cookies || '',
            });
            this.dataChannel.send(this.createFrame(streamId, FLAG_SYN, synPayload));

        } else if (msg.type === 'ws-send') {
            const ws = this.wsStreams.get(msg.streamId);
            if (!ws) return;

            // DAT frame with type byte prefix: 0=text, 1=binary
            let payload;
            if (msg.isText) {
                const textBytes = new TextEncoder().encode(msg.data);
                payload = new Uint8Array(1 + textBytes.length);
                payload[0] = 0; // text
                payload.set(textBytes, 1);
            } else {
                // Binary data (ArrayBuffer or similar)
                const binBytes = msg.data instanceof ArrayBuffer
                    ? new Uint8Array(msg.data)
                    : new Uint8Array(msg.data);
                payload = new Uint8Array(1 + binBytes.length);
                payload[0] = 1; // binary
                payload.set(binBytes, 1);
            }
            this.dataChannel.send(this.createFrame(msg.streamId, FLAG_DAT, payload));

        } else if (msg.type === 'ws-close') {
            const ws = this.wsStreams.get(msg.streamId);
            if (!ws) return;
            this.wsStreams.delete(msg.streamId);
            this.dataChannel.send(this.createFrame(msg.streamId, FLAG_FIN, new Uint8Array(0)));
        }
    }

    createIframe() {
        const iframe = document.createElement('iframe');
        iframe.id = 'device-frame';
        iframe.sandbox = 'allow-scripts allow-forms allow-same-origin allow-popups allow-modals allow-downloads';
        iframe.allow = 'fullscreen';
        iframe.scrolling = 'yes';
        iframe.style.cssText = `
            position: fixed; top: 0; left: 0;
            width: 100%; height: 100%;
            border: none; z-index: 1; background: #fff;
        `;

        iframe.onload = () => {
            // Constrain the iframe body to the viewport so modal height
            // calculations use the visible area, not the content height.
            try {
                const doc = iframe.contentDocument;
                const s = doc.createElement('style');
                s.textContent = 'html, body { height: 100% !important; overflow: auto !important; }';
                doc.head.appendChild(s);
            } catch (e) {}

            this.wireStreams(iframe);
            if (this.connectionUI) this.connectionUI.style.display = 'none';

            const iframeTitle = iframe.contentDocument?.title;
            document.title = iframeTitle || this.deviceName || "BitBang";

            // Set device favicon. Helper to update or create the link element.
            const setFavicon = (href) => {
                let link = document.querySelector('link[rel="icon"]');
                if (!link) {
                    link = document.createElement('link');
                    link.rel = 'icon';
                    document.head.appendChild(link);
                }
                link.href = href;
            };

            // Try /favicon.ico -- only set if it exists (don't clear with a 404)
            fetch(`/__device__/${this.sessionId}/favicon.ico`).then(r => {
                if (r.ok) setFavicon(`/__device__/${this.sessionId}/favicon.ico`);
            }).catch(() => {});

            // Also watch for the device setting a favicon dynamically via JS
            // (e.g. NAS sets <link rel="icon"> after page load)
            const iframeDoc = iframe.contentDocument;
            if (iframeDoc) {
                const copyIcon = () => {
                    const icon = iframeDoc.querySelector('link[rel*="icon"]');
                    if (icon) { setFavicon(icon.href); return true; }
                    return false;
                };
                if (!copyIcon()) {
                    const obs = new MutationObserver(() => { if (copyIcon()) obs.disconnect(); });
                    obs.observe(iframeDoc.head || iframeDoc.documentElement, { childList: true, subtree: true });
                    setTimeout(() => obs.disconnect(), 5000);
                }
            }
        };

        iframe.src = `/__device__/${this.sessionId}${this.devicePath}`;
        document.body.appendChild(iframe);
    }

    wireStreams(iframe) {
        const doc = iframe.contentDocument;
        if (!doc) return;

        // Wire elements with data-bitbang-stream attribute
        doc.querySelectorAll('[data-bitbang-stream]').forEach(el => {
            const name = el.getAttribute('data-bitbang-stream');
            const streamName = (name === '' || name === null)
                ? Object.keys(this.resolvedStreams)[0]
                : name;

            if (streamName && this.resolvedStreams[streamName]) {
                el.srcObject = this.resolvedStreams[streamName];
            }
        });

        // Expose __bitbang to iframe
        iframe.contentWindow.__bitbang = {
            streams: this.resolvedStreams,
            getStream: (name) => this.resolvedStreams[name],
            getDefaultStream: () => this.resolvedStreams[Object.keys(this.resolvedStreams)[0]],
            pc: this.pc
        };
    }
}

// Initialize — but only in the top-level window, not inside the device iframe.
// If bootstrap.html accidentally loads inside the iframe (e.g. due to a redirect
// that escapes the /__device__/ scope), skip initialization to avoid a second
// WebRTC connection that would fail with "Device not found".
(async function() {
    if (window !== window.top) {
        console.warn('[Bootstrap] Skipping init — running inside iframe, not top-level');
        return;
    }

    const pathParts = window.location.pathname.split('/').filter(Boolean);
    if (pathParts.length === 0) {
        const el = document.getElementById('status');
        el.textContent = 'No device ID specified';
        el.classList.add('error');
        return;
    }

    const uid = pathParts[0];
    const devicePath = '/' + pathParts.slice(1).join('/');
    const connection = new BitBangConnection(uid, devicePath);
    window.__bitbangConnection = connection;
    await connection.connect();
})();
