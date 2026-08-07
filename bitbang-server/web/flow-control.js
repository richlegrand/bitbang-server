/**
 * Per-stream SWSP v4 credit accounting.
 *
 * The transport owns when bytes are considered consumed; this helper only
 * keeps the cumulative send/receive limits and wakes ordered send waiters.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.SWSPFlowControl = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const VERSION = 4;
    const WINDOW_BYTES = 1024 * 1024;
    const UPDATE_BYTES = WINDOW_BYTES / 2;
    // The byte window caps payload memory; this separately bounds queue and
    // dispatch work for tiny or empty frames that consume little byte credit.
    const MAX_PENDING_FRAMES = 256;
    const MAX_PAYLOAD_BYTES = 32768;

    function negotiateVersion(serverVersion, selectedVersion) {
        const server = serverVersion === undefined || serverVersion === null || serverVersion === 0
            ? 2 : serverVersion;
        if (!Number.isSafeInteger(server) || server < 2) {
            throw new FlowError('protocol_error', 'unsupported SWSP server version');
        }
        const maximum = Math.min(VERSION, server);
        const selected = selectedVersion === undefined || selectedVersion === null
            ? maximum : selectedVersion;
        if (!Number.isSafeInteger(selected) || selected < 2 || selected > maximum) {
            throw new FlowError('protocol_error', 'invalid SWSP version negotiation');
        }
        return { serverVersion: server, negotiatedVersion: selected };
    }

    function asBytes(value) {
        if (value instanceof ArrayBuffer) return new Uint8Array(value);
        if (ArrayBuffer.isView(value)) {
            return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        }
        throw new TypeError('expected ArrayBuffer or ArrayBufferView');
    }

    function createFrame(streamId, flags, payload) {
        const payloadBytes = typeof payload === 'string'
            ? new TextEncoder().encode(payload) : asBytes(payload);
        if (payloadBytes.byteLength > MAX_PAYLOAD_BYTES) {
            throw new RangeError('SWSP payload exceeds frame limit');
        }
        const buffer = new ArrayBuffer(8 + payloadBytes.byteLength);
        const view = new DataView(buffer);
        view.setUint32(0, streamId, true);
        view.setUint16(4, flags, true);
        view.setUint16(6, payloadBytes.byteLength, true);
        new Uint8Array(buffer, 8).set(payloadBytes);
        return buffer;
    }

    function parseFrame(buffer) {
        const bytes = asBytes(buffer);
        if (bytes.byteLength < 8) throw new RangeError('SWSP frame is truncated');
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        const streamId = view.getUint32(0, true);
        const flags = view.getUint16(4, true);
        const length = view.getUint16(6, true);
        if (bytes.byteLength !== 8 + length) {
            throw new RangeError('SWSP frame length does not match payload');
        }
        const payload = bytes.buffer.slice(
            bytes.byteOffset + 8, bytes.byteOffset + 8 + length);
        return { streamId, flags, payload };
    }

    class FlowError extends Error {
        constructor(code, message) {
            super(message);
            this.name = 'FlowError';
            this.code = code;
        }
    }

    class Controller {
        constructor(sendControl) {
            this.sendControl = sendControl;
            this.enabled = false;
            this.closed = false;
            this.streams = new Map();
        }

        reset(enabled) {
            this.close(new FlowError('session_closed', 'session reset'));
            this.enabled = !!enabled;
            this.closed = false;
            this.streams = new Map();
        }

        open(streamId) {
            let state = this.streams.get(streamId);
            if (state) return state;
            state = {
                // A v4 SYN opens both directions with this implicit credit.
                sendLimit: this.enabled ? WINDOW_BYTES : Number.MAX_SAFE_INTEGER,
                sentBytes: 0,
                sendWaiters: [],
                recvLimit: WINDOW_BYTES,
                recvBytes: 0,
                consumedBytes: 0,
                lastUpdateBytes: 0,
                pendingFrames: 0,
                receiveEnded: false,
            };
            this.streams.set(streamId, state);
            return state;
        }

        has(streamId) {
            return this.streams.has(streamId);
        }

        updateWindow(streamId, maxBytes) {
            if (!this.enabled) return true;
            const state = this.streams.get(streamId);
            if (!state) return false;
            if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) return false;
            if (maxBytes <= state.sendLimit) return true;
            state.sendLimit = maxBytes;
            this._wake(state);
            return true;
        }

        waitToSend(streamId, byteLength) {
            if (!Number.isSafeInteger(byteLength) || byteLength < 0 || byteLength > WINDOW_BYTES) {
                return Promise.reject(new FlowError('protocol_error', 'invalid SWSP frame size'));
            }
            if (this.closed) {
                return Promise.reject(new FlowError('session_closed', 'session closed'));
            }
            const state = this.streams.get(streamId);
            if (!state) {
                return Promise.reject(new FlowError('protocol_error', 'data sent before SYN'));
            }
            if (!this.enabled || byteLength === 0) return Promise.resolve();
            return new Promise((resolve, reject) => {
                state.sendWaiters.push({ byteLength, resolve, reject });
                this._wake(state);
            });
        }

        receive(streamId, byteLength, final) {
            const state = this.streams.get(streamId);
            if (!state || state.receiveEnded) return false;
            if (final) state.receiveEnded = true;
            if (!Number.isSafeInteger(byteLength) || byteLength < 0) return false;
            if (state.pendingFrames >= MAX_PENDING_FRAMES) return false;
            if (state.recvBytes + byteLength > state.recvLimit) return false;
            state.recvBytes += byteLength;
            state.pendingFrames++;
            return true;
        }

        finishReceive(streamId) {
            const state = this.streams.get(streamId);
            if (!state || state.receiveEnded) return false;
            state.receiveEnded = true;
            return true;
        }

        consume(streamId, byteLength, frames) {
            const state = this.streams.get(streamId);
            if (!state || !Number.isSafeInteger(byteLength) || byteLength < 0) return false;
            const frameCount = frames === undefined ? 1 : frames;
            if (!Number.isSafeInteger(frameCount) || frameCount <= 0
                || frameCount > state.pendingFrames
                || byteLength > state.recvBytes - state.consumedBytes) {
                return false;
            }
            state.pendingFrames -= frameCount;
            if (byteLength === 0) return true;
            state.consumedBytes += byteLength;
            if (!this.enabled) {
                // Legacy peers do not understand window updates, but local
                // queues must remain bounded. Slide the private receive limit
                // as the application consumes data without sending a control.
                state.recvLimit = state.consumedBytes + WINDOW_BYTES;
                return true;
            }
            if (state.consumedBytes - state.lastUpdateBytes < UPDATE_BYTES) return true;
            const recvLimit = state.consumedBytes + WINDOW_BYTES;
            if (!this.sendControl({
                type: 'window_update',
                stream_id: streamId,
                max_bytes: recvLimit,
            })) return false;
            state.lastUpdateBytes = state.consumedBytes;
            state.recvLimit = recvLimit;
            return true;
        }

        resetStream(streamId, error) {
            const state = this.streams.get(streamId);
            if (!state) return;
            const err = error instanceof Error
                ? error
                : new FlowError('stream_reset', String(error || 'stream reset'));
            this.streams.delete(streamId);
            for (const waiter of state.sendWaiters) waiter.reject(err);
            state.sendWaiters.length = 0;
        }

        close(error) {
            const err = error instanceof Error
                ? error
                : new FlowError('session_closed', String(error || 'session closed'));
            this.closed = true;
            for (const streamId of Array.from(this.streams.keys())) {
                this.resetStream(streamId, err);
            }
        }

        _wake(state) {
            while (state.sendWaiters.length > 0) {
                const waiter = state.sendWaiters[0];
                if (state.sentBytes + waiter.byteLength > state.sendLimit) return;
                state.sendWaiters.shift();
                state.sentBytes += waiter.byteLength;
                waiter.resolve();
            }
        }
    }

    return {
        VERSION,
        WINDOW_BYTES,
        UPDATE_BYTES,
        MAX_PENDING_FRAMES,
        MAX_PAYLOAD_BYTES,
        negotiateVersion,
        asBytes,
        createFrame,
        parseFrame,
        FlowError,
        Controller,
    };
});
