// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
// Regression tests for the plaintext receive downgrade fixed in snapshot 0.2.
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { endpoint, paired } from "./endpoint.mjs";

function offer(id, plainSize = 5, wireSize = plainSize + 28)
{
    return [id, "synthetic.bin", String(plainSize), "application/octet-stream", "65536", String(wireSize), "e2ee-v1"];
}

function lastCommand(target, cmd, args)
{
    assert.equal(target.sent.at(-1)?.cmd, cmd);
    assert.deepEqual(Array.from(target.sent.at(-1).args), args);
}

async function waitFor(predicate)
{
    const until = Date.now() + 2000;
    while (!predicate())
    {
        assert.ok(Date.now() < until, "file receiver did not finish its asynchronous operation");
        await delay(1);
    }
}

async function transfer(sender, receiver, plain, id)
{
    const chunks = [];
    for (let index = 0; index < plain.length; index += 65508)
    {
        chunks.push(await sender.encryptFile(plain.slice(index, index + 65508), id, chunks.length));
    }
    const wireSize = chunks.reduce((size, chunk) => size + chunk.byteLength, 0);
    receiver.offer(offer(id, plain.length, wireSize));
    lastCommand(receiver, "fileAccept", [id]);
    for (const [seq, chunk] of chunks.entries())
    {
        const offset = receiver.sent.length;
        const cancellations = receiver.cancelled.length;
        receiver.chunk([id, String(seq), String(chunk.byteLength)]);
        receiver.binary(chunk);
        await waitFor(() => receiver.sent.length > offset || receiver.cancelled.length > cancellations);
        assert.equal(receiver.cancelled.length, cancellations);
        lastCommand(receiver, "fileChunkAck", [id, String(seq)]);
    }
    receiver.done([id, String(chunks.length), String(wireSize)]);
    lastCommand(receiver, "fileReceived", [id]);
    assert.ok(receiver.download);
    assert.deepEqual(new Uint8Array(await receiver.download.blob.arrayBuffer()), plain);
}

test("legacy and changed encryption markers reject with and without an established key", async () => {
    for (const ready of [false, true])
    {
        for (const marker of [undefined, "", "plaintext", "e2ee-v0", "E2EE-V1", "e2ee-v1 ", null, false])
        {
            const target = ready ? (await paired()).secondary : endpoint();
            const args = offer("downgraded");
            if (marker === undefined) args.length = 5;
            else args[6] = marker;
            target.offer(args);
            lastCommand(target, "fileReject", ["downgraded", "encryption-required"]);
            assert.equal(target.ui.at(-1).fileStatus, "file.encryptionRequired");
            target.chunk(["downgraded", "0", "5"]);
            target.binary(new Uint8Array([0, 17, 255, 3, 128]));
            target.done(["downgraded", "1", "5"]);
            assert.equal(target.received.length, 0);
            assert.equal(target.download, null);
            assert.equal(target.sent.some(item => ["fileAccept", "fileChunkAck", "fileReceived"].includes(item.cmd)), false);
        }
    }
});

test("the encrypted marker cannot start a transfer before ECDH key establishment", () => {
    const target = endpoint();
    target.offer(offer("no-shared-key"));
    lastCommand(target, "fileReject", ["no-shared-key", "encryption-required"]);
    assert.equal(target.ui.at(-1).fileStatus, "file.encryptionRequired");
    assert.equal(target.download, null);
});

test("encrypted offers require safe integer sizes and encrypted chunk bounds", async () => {
    const { secondary } = await paired();
    const mutations = [[5, undefined], [5, ""], [5, "5"], [5, "33.5"], [5, "Infinity"],
        [5, String(Number.MAX_SAFE_INTEGER + 1)], [4, "28"], [4, "65537"], [4, "33.5"],
        [2, "0"], [2, "5.5"], [2, String(25 * 1024 * 1024 + 1)]];
    for (const [field, value] of mutations)
    {
        const args = offer("invalid-offer");
        args[field] = value;
        secondary.offer(args);
        lastCommand(secondary, "fileReject", ["invalid-offer", "invalid"]);
        assert.equal(secondary.download, null);
    }
});

test("downgrade rejection preserves a verified download and later file/text progress", async () => {
    const { primary, secondary } = await paired();
    await transfer(primary, secondary, new Uint8Array([0, 17, 255, 3, 128]), "before-downgrade");
    const verified = secondary.download;
    secondary.offer(offer("downgraded").slice(0, 5));
    lastCommand(secondary, "fileReject", ["downgraded", "encryption-required"]);
    assert.equal(secondary.download, verified);
    assert.deepEqual(new Uint8Array(await verified.blob.arrayBuffer()), new Uint8Array([0, 17, 255, 3, 128]));
    const large = new Uint8Array(131017);
    for (let index = 0; index < large.length; index += 1) large[index] = (index * 37 + 19) % 256;
    await transfer(primary, secondary, large, "after-downgrade");
    await transfer(secondary, primary, new Uint8Array([255, 128, 0]), "reverse-direction");
    assert.equal((await secondary.decrypt(await primary.encrypt("text after rejection"))).text, "text after rejection");
});

test("plaintext under an encrypted marker cancels without acknowledgement and permits encrypted retry", async () => {
    const { primary, secondary } = await paired();
    secondary.offer(offer("fake-encrypted"));
    lastCommand(secondary, "fileAccept", ["fake-encrypted"]);
    const offset = secondary.sent.length;
    secondary.chunk(["fake-encrypted", "0", "33"]);
    secondary.binary(new Uint8Array(33).fill(97));
    await waitFor(() => secondary.cancelled.length > 0);
    assert.equal(secondary.cancelled[0].notifyPeer, true);
    assert.equal(secondary.sent.length, offset);
    assert.equal(secondary.received.length, 0);
    assert.equal(secondary.download, null);
    await transfer(primary, secondary, new Uint8Array([1, 2, 3]), "retry-after-plaintext");
});

test("ciphertext and file-context tampering cancel before completion and permit retry", async () => {
    for (const mutation of ["ciphertext", "transfer", "sequence"])
    {
        const { primary, secondary } = await paired();
        const wire = new Uint8Array(await primary.encryptFile(new Uint8Array([1, 2, 3, 4, 5]),
            mutation === "transfer" ? "wrong" : "tampered", mutation === "sequence" ? 1 : 0));
        if (mutation === "ciphertext") wire[12] ^= 1;
        secondary.offer(offer("tampered"));
        lastCommand(secondary, "fileAccept", ["tampered"]);
        const offset = secondary.sent.length;
        secondary.chunk(["tampered", "0", String(wire.byteLength)]);
        secondary.binary(wire);
        await waitFor(() => secondary.cancelled.length > 0);
        assert.equal(secondary.sent.length, offset);
        assert.equal(secondary.received.length, 0);
        assert.equal(secondary.download, null);
        await transfer(primary, secondary, new Uint8Array([255]), "retry-after-" + mutation);
    }
});

test("a busy receiver rejects another offer without interrupting authenticated progress", async () => {
    const { primary, secondary } = await paired();
    const plain = new Uint8Array([0, 1, 2, 3, 4]);
    const wire = await primary.encryptFile(plain, "active", 0);
    secondary.offer(offer("active"));
    lastCommand(secondary, "fileAccept", ["active"]);
    secondary.offer(offer("intruder").slice(0, 5));
    lastCommand(secondary, "fileReject", ["intruder", "busy"]);
    const offset = secondary.sent.length;
    secondary.chunk(["active", "0", String(wire.byteLength)]);
    secondary.binary(wire);
    await waitFor(() => secondary.sent.length > offset || secondary.cancelled.length > 0);
    assert.equal(secondary.cancelled.length, 0);
    lastCommand(secondary, "fileChunkAck", ["active", "0"]);
    secondary.done(["active", "1", String(wire.byteLength)]);
    lastCommand(secondary, "fileReceived", ["active"]);
    assert.deepEqual(new Uint8Array(await secondary.download.blob.arrayBuffer()), plain);
});
