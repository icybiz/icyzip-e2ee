// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
// These tests intentionally REPRODUCE vulnerabilities. Passing means the
// documented limitation exists, not that the protocol withstands the attack.
import assert from "node:assert/strict";
import test from "node:test";
import { endpoint, paired } from "./endpoint.mjs";

test("KNOWN LIMITATION: a substituting relay reads and changes text without endpoint errors", async () => {
    const primary = endpoint();
    const secondary = endpoint({ role: "secondary" });
    const relayTowardPrimary = endpoint({ role: "secondary" });
    const relayTowardSecondary = endpoint();
    await primary.receive(await relayTowardPrimary.publicKey());
    await relayTowardPrimary.receive(await primary.publicKey());
    await secondary.receive(await relayTowardSecondary.publicKey());
    await relayTowardSecondary.receive(await secondary.publicKey());
    const intercepted = await relayTowardPrimary.decrypt(await primary.encrypt("synthetic confidential message"));
    assert.equal(intercepted.text, "synthetic confidential message");
    const relayed = await relayTowardSecondary.encrypt("synthetic modified message", intercepted.updatedAt, intercepted.origin);
    assert.equal((await secondary.decrypt(relayed)).text, "synthetic modified message");
    assert.equal(primary.ready(), true);
    assert.equal(secondary.ready(), true);
    assert.equal(primary.ui.length + secondary.ui.length, 0);
});

test("KNOWN LIMITATION: revision and origin can change without invalidating the AES-GCM tag", async () => {
    const { primary, secondary } = await paired();
    const envelope = JSON.parse(await primary.encrypt("unchanged plaintext", 4503599627370497, "original-origin"));
    envelope.t = Number.MAX_SAFE_INTEGER;
    envelope.o = "relay-controlled-origin";
    const accepted = await secondary.decrypt(JSON.stringify(envelope));
    assert.equal(accepted.text, "unchanged plaintext");
    assert.equal(accepted.updatedAt, Number.MAX_SAFE_INTEGER);
    assert.equal(accepted.origin, "relay-controlled-origin");
});

test("KNOWN LIMITATION: a legacy file offer bypasses cryptographic verification entirely", async () => {
    const receiver = endpoint();
    assert.equal(receiver.ready(), false);
    const plain = new Uint8Array([0, 17, 255, 3, 128]);
    receiver.offer(["synthetic-legacy-transfer", "synthetic.bin", String(plain.length), "application/octet-stream", "65536"]);
    assert.equal(receiver.sent.at(-1).cmd, "fileAccept");
    receiver.chunk(["synthetic-legacy-transfer", "0", String(plain.length)]);
    receiver.binary(plain);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(receiver.sent.at(-1).cmd, "fileChunkAck");
    receiver.done(["synthetic-legacy-transfer", "1", String(plain.length)]);
    assert.equal(receiver.sent.at(-1).cmd, "fileReceived");
    assert.equal(receiver.received.length, 1);
    assert.deepEqual(new Uint8Array(await receiver.received[0].blob.arrayBuffer()), plain);
    assert.equal(receiver.ready(), false);
});
