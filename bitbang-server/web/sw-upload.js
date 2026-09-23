/**
 * Bounded request-body transfer and acknowledgement state for sw.js.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.SWSPUpload = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const MAX_SLICE_BYTES = 1024 * 1024;

    function copySlice(value, offset) {
        if (!ArrayBuffer.isView(value)) {
            throw new TypeError('request body chunk must be an ArrayBuffer view');
        }
        if (!Number.isSafeInteger(offset) || offset < 0 || offset >= value.byteLength) {
            throw new RangeError('invalid request body chunk offset');
        }
        const bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        return bytes.slice(offset, Math.min(offset + MAX_SLICE_BYTES, bytes.byteLength));
    }

    // Serializes body slices behind the peer's acknowledgements and latches
    // the first terminal error. There is deliberately no deadline: a slice is
    // acknowledged once the peer's credit lets it through, and on a slow link
    // that takes as long as it takes. A peer that is gone closes the data
    // channel, and bootstrap.js reports that here as an error.
    class AckGate {
        constructor() {
            this.pending = null;
            this.error = null;
        }

        wait(seq) {
            if (this.error) return Promise.reject(this.error);
            if (this.pending) {
                return Promise.reject(new Error('upload acknowledgement already pending'));
            }
            return new Promise((resolve, reject) => {
                this.pending = { seq, resolve, reject };
            });
        }

        acknowledge(seq) {
            if (!this.pending || seq !== this.pending.seq) return false;
            const pending = this.pending;
            this.pending = null;
            pending.resolve();
            return true;
        }

        fail(error) {
            if (!this.error) {
                this.error = error instanceof Error ? error : new Error(String(error));
            }
            if (this.pending) {
                const pending = this.pending;
                this.pending = null;
                pending.reject(this.error);
            }
            return this.error;
        }

        throwIfFailed() {
            if (this.error) throw this.error;
        }
    }

    return { MAX_SLICE_BYTES, copySlice, AckGate };
});
