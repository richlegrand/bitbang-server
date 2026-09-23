const test = require('node:test');
const assert = require('node:assert/strict');

const {
    AckGate,
    MAX_SLICE_BYTES,
    copySlice,
} = require('../web/sw-upload.js');

test('request body chunks are copied into bounded transferable slices', () => {
    const source = new Uint8Array(MAX_SLICE_BYTES + 3);
    source[0] = 1;
    source[MAX_SLICE_BYTES] = 2;

    const first = copySlice(source, 0);
    const second = copySlice(source, first.byteLength);

    assert.equal(first.byteLength, MAX_SLICE_BYTES);
    assert.equal(second.byteLength, 3);
    assert.notEqual(first.buffer, source.buffer);
    assert.notEqual(second.buffer, source.buffer);
    assert.equal(first[0], 1);
    assert.equal(second[0], 2);
});

test('terminal errors reject both current and future acknowledgements', async () => {
    const gate = new AckGate();
    const current = gate.wait(1);

    gate.fail(new Error('peer reset'));

    await assert.rejects(current, /peer reset/);
    await assert.rejects(gate.wait(2), /peer reset/);
});

test('an error latched between chunks rejects the next acknowledgement immediately', async () => {
    const gate = new AckGate();
    const first = gate.wait(1);
    assert.equal(gate.acknowledge(1), true);
    await first;

    gate.fail(new Error('stream closed'));

    await assert.rejects(gate.wait(2), /stream closed/);
});

test('an unacknowledged slice never times out on its own', async (t) => {
    const timers = t.mock.method(globalThis, 'setTimeout');
    const gate = new AckGate();
    let outcome = 'pending';
    const wait = gate.wait(1);
    wait.then(() => { outcome = 'resolved'; }, () => { outcome = 'rejected'; });

    await new Promise(resolve => setImmediate(resolve));
    assert.equal(timers.mock.callCount(), 0);
    assert.equal(outcome, 'pending');

    assert.equal(gate.acknowledge(1), true);
    await wait;
});
