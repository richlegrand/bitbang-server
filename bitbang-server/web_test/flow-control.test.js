const test = require('node:test');
const assert = require('node:assert/strict');

const {
    Controller,
    WINDOW_BYTES,
    UPDATE_BYTES,
    negotiateVersion,
    asBytes,
    createFrame,
    parseFrame,
    MAX_PAYLOAD_BYTES,
} = require('../web/flow-control.js');

test('version negotiation preserves legacy peers and selects v4 explicitly', () => {
    assert.deepEqual(negotiateVersion(), { serverVersion: 2, negotiatedVersion: 2 });
    assert.deepEqual(negotiateVersion(3), { serverVersion: 3, negotiatedVersion: 3 });
    assert.deepEqual(negotiateVersion(4, 4), { serverVersion: 4, negotiatedVersion: 4 });
    assert.deepEqual(negotiateVersion(99, 4), { serverVersion: 99, negotiatedVersion: 4 });
    assert.deepEqual(negotiateVersion(4, 3), { serverVersion: 4, negotiatedVersion: 3 });
    assert.throws(() => negotiateVersion(3, 4), /invalid SWSP version/);
    assert.throws(() => negotiateVersion(4, 0), /invalid SWSP version/);
    assert.throws(() => negotiateVersion(1), /unsupported SWSP server/);
});

test('ArrayBuffer views preserve their exact underlying bytes', () => {
    const source = new Uint8Array([9, 8, 0x34, 0x12, 7]);
    const words = new Uint16Array(source.buffer, 2, 1);
    const dataView = new DataView(source.buffer, 2, 2);

    assert.deepEqual(Array.from(asBytes(words)), [0x34, 0x12]);
    assert.deepEqual(Array.from(asBytes(dataView)), [0x34, 0x12]);
    assert.deepEqual(Array.from(asBytes(source.buffer)), [9, 8, 0x34, 0x12, 7]);
});

test('frame codec rejects oversized, truncated, and trailing payloads', () => {
    const frame = createFrame(7, 2, new Uint8Array([1, 2, 3]));
    const parsed = parseFrame(frame);
    assert.equal(parsed.streamId, 7);
    assert.equal(parsed.flags, 2);
    assert.deepEqual(Array.from(new Uint8Array(parsed.payload)), [1, 2, 3]);

    assert.throws(
        () => createFrame(1, 0, new Uint8Array(MAX_PAYLOAD_BYTES + 1)),
        /exceeds frame limit/);
    assert.throws(() => parseFrame(frame.slice(0, -1)), /does not match/);
    const trailing = new Uint8Array(frame.byteLength + 1);
    trailing.set(new Uint8Array(frame));
    assert.throws(() => parseFrame(trailing), /does not match/);
});

test('sender uses the implicit initial window and resumes on update', async () => {
    const controls = [];
    const flow = new Controller(msg => {
        controls.push(msg);
        return true;
    });
    flow.reset(true);
    flow.open(1);

    let initialReleased = false;
    const initial = flow.waitToSend(1, WINDOW_BYTES)
        .then(() => { initialReleased = true; });
    await Promise.resolve();
    assert.equal(initialReleased, true);
    await initial;
    assert.deepEqual(controls, []);

    let released = false;
    const blocked = flow.waitToSend(1, 1).then(() => { released = true; });
    await Promise.resolve();
    assert.equal(released, false);

    assert.equal(flow.updateWindow(1, WINDOW_BYTES + 1), true);
    await blocked;
    assert.equal(released, true);
});

test('receive limit is replenished only after the consumption threshold', () => {
    const controls = [];
    const flow = new Controller(msg => {
        controls.push(msg);
        return true;
    });
    flow.reset(true);
    flow.open(3);

    assert.equal(flow.receive(3, UPDATE_BYTES - 1), true);
    flow.consume(3, UPDATE_BYTES - 1);
    assert.equal(controls.length, 0);

    assert.equal(flow.receive(3, 1), true);
    flow.consume(3, 1);
    assert.deepEqual(controls[0], {
        type: 'window_update',
        stream_id: 3,
        max_bytes: WINDOW_BYTES + UPDATE_BYTES,
    });
});

test('receive and frame limits reject only the offending stream', () => {
    const flow = new Controller(() => {});
    flow.reset(true);
    flow.open(1);
    flow.open(3);

    assert.equal(flow.receive(1, WINDOW_BYTES), true);
    assert.equal(flow.receive(1, 1), false);
    assert.equal(flow.receive(3, 1), true);
});

test('empty frames are bounded and released by consumption', () => {
    const flow = new Controller(() => {});
    flow.reset(true);
    flow.open(1);

    for (let i = 0; i < 256; i++) assert.equal(flow.receive(1, 0), true);
    assert.equal(flow.receive(1, 0), false);
    assert.equal(flow.consume(1, 0, 256), true);
    assert.equal(flow.receive(1, 0), true);
});

test('receive direction rejects every frame after FIN', () => {
    const flow = new Controller(() => {});
    flow.reset(true);
    flow.open(1);

    assert.equal(flow.receive(1, 0, true), true);
    assert.equal(flow.receive(1, 1, false), false);
    assert.equal(flow.finishReceive(1), false);
});

test('consumption cannot exceed outstanding bytes or frames', () => {
    const flow = new Controller(() => {});
    flow.reset(true);
    flow.open(1);
    assert.equal(flow.receive(1, 10), true);

    assert.equal(flow.consume(1, -1), false);
    assert.equal(flow.consume(1, Number.NaN), false);
    assert.equal(flow.consume(1, 11), false);
    assert.equal(flow.consume(1, 10, 2), false);
    assert.equal(flow.consume(1, 10), true);
    assert.equal(flow.consume(1, 0), false);
});

test('window updates require a positive maximum', () => {
    const flow = new Controller(() => {});
    flow.reset(true);
    flow.open(1);

    assert.equal(flow.updateWindow(1, 0), false);
    assert.equal(flow.updateWindow(1, -1), false);
    assert.equal(flow.updateWindow(1, Number.NaN), false);
    assert.equal(flow.updateWindow(1, WINDOW_BYTES + 10), true);
    assert.equal(flow.updateWindow(1, WINDOW_BYTES + 5), true);
    assert.equal(flow.updateWindow(1, WINDOW_BYTES + 10), true);
});

test('zero-byte sends still require a live stream', async () => {
    const flow = new Controller(() => {});
    flow.reset(true);
    flow.open(1);
    flow.resetStream(1, new Error('reset'));
    await assert.rejects(flow.waitToSend(1, 0), /before SYN/);
});

test('reset rejects blocked senders without affecting another stream', async () => {
    const flow = new Controller(() => {});
    flow.reset(true);
    flow.open(1);
    flow.open(3);

    await flow.waitToSend(1, WINDOW_BYTES);
    const blocked = flow.waitToSend(1, 1);
    flow.resetStream(1, new Error('stalled'));
    await assert.rejects(blocked, /stalled/);

    flow.updateWindow(3, 1);
    await flow.waitToSend(3, 1);
});

test('legacy mode never waits for credit', async () => {
    const flow = new Controller(() => assert.fail('legacy mode sent control'));
    flow.reset(false);
    flow.open(1);
    await flow.waitToSend(1, WINDOW_BYTES);
});

test('legacy mode still bounds local receive queues without sending controls', () => {
    const flow = new Controller(() => assert.fail('legacy mode sent control'));
    flow.reset(false);
    flow.open(1);

    assert.equal(flow.receive(1, WINDOW_BYTES), true);
    assert.equal(flow.receive(1, 1), false);
    assert.equal(flow.consume(1, WINDOW_BYTES), true);
    assert.equal(flow.receive(1, WINDOW_BYTES), true);

    flow.open(3);
    for (let i = 0; i < 256; i++) assert.equal(flow.receive(3, 0), true);
    assert.equal(flow.receive(3, 0), false);
    assert.equal(flow.consume(3, 0, 256), true);
    assert.equal(flow.receive(3, 0), true);
});

test('failed replenishment control is surfaced without recording a grant', () => {
    const controls = [];
    const flow = new Controller(msg => {
        controls.push(msg);
        return false;
    });
    flow.reset(true);
    flow.open(1);

    assert.equal(flow.receive(1, UPDATE_BYTES), true);
    assert.equal(flow.consume(1, UPDATE_BYTES), false);
    assert.equal(controls.length, 1);
    assert.equal(flow.streams.get(1).lastUpdateBytes, 0);
    assert.equal(flow.streams.get(1).recvLimit, WINDOW_BYTES);
});
