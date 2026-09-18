// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import vm from "node:vm";
import { E2EE, client } from "./endpoint.mjs";

// Use the real current receive controller, including cancellation, UI state,
// Blob creation and the exact reviewable v3 module.
const receiverCode = await readFile(new URL("../src/snapshot.js", import.meta.url), "utf8");

function receiver()
{
    const sent = [];
    const blobs = new Map();
    let nextBlob = 0;
    const storage = new Map();
    const elements = new Map();
    for (const id of ["fileInput", "fileActionSend", "fileActionCancel", "fileProgress", "fileStatus", "fileReceivedDownload"])
    {
        elements.set(id, {
            dataset: {}, hidden: true, files: [],
            setAttribute(key, value) { this[key] = value; },
            removeAttribute(key) { delete this[key]; }
        });
    }
    class TestURL extends URL
    {
        static createObjectURL(blob) { const url = "blob:synthetic-" + (++nextBlob); blobs.set(url, blob); return url; }
        static revokeObjectURL(url) { blobs.delete(url); }
    }
    const context = vm.createContext({
        window: { crypto: webcrypto, TextEncoder, TextDecoder, IcyZipE2EE: E2EE },
        TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, Blob, URL: TestURL, atob, btoa,
        document: { getElementById: id => elements.get(id), body: { dataset: { wsState: "connected" } } },
        pairId: "synthetic-review-pair", i: "synthetic-review-pair", aid: null, requestedResumePair: null,
        publicBaseUrl: "https://icyzip.com", localTextUpdatedOrigin: "synthetic-secondary",
        pairSecret: null, pairSecretId: "", e2eeSession: null, e2eeSessionId: "", textE2eeReadyCallbacks: [],
        TEXT_REVISION_BASE: 4503599627370496, FILE_E2EE_FRAME_OVERHEAD: 28,
        normalizedTextUpdatedAt: value => Number.isSafeInteger(value) && value > 0 ? value : 0,
        fileTransferRuntimeEnabled: true, fileMaxBytes: 25 * 1024 * 1024, fileChunkBytes: 65536,
        sessionStorage: {
            getItem: key => storage.get(key) ?? null,
            setItem: (key, value) => storage.set(key, value),
            removeItem: key => storage.delete(key)
        },
        textKey: text => text.startsWith("file.") ? text : "",
        t: key => key,
        sendCommand(cmd, args) { sent.push({ cmd, args: Array.from(args) }); return true; },
        sendClientDiagnostic() {}, setStatusMessage() {}, setUiState() {}
    });
    vm.runInContext(receiverCode, context, { filename: "current-file-receiver.js" });
    const controller = context.createFileTransferController();
    controller.bind();
    return {
        sent, blobs, elements, context,
        offer: args => controller.handleCommand("fileOffer", args),
        cancel: () => controller.cancelLocal("Cancelled"),
        chunk: args => controller.handleCommand("fileChunk", args),
        binary: data => controller.handleBinary(data),
        done: args => controller.handleCommand("fileDone", args),
        get download() { return elements.get("fileReceivedDownload"); },
        get status() { return elements.get("fileStatus"); }
    };
}

async function connect(target)
{
    const sender = client({ pairId: "synthetic-review-pair" });
    target.context.usePairSecret(sender.pairId, sender.secret);
    const receiverSession = target.context.ensureTextE2eeSession(sender.pairId);
    await target.context.receiveTextE2eePublic(await sender.session.publicMessage());
    await sender.session.acceptPublicMessage(await receiverSession.publicMessage());
    return sender.session;
}

async function waitFor(target, command, offset)
{
    const until = Date.now() + 2000;
    while (Date.now() < until)
    {
        const value = target.sent.slice(offset).find(item => item.cmd === command);
        if (value) return value;
        await delay(1);
    }
    assert.fail("Missing " + command + "; observed " + target.sent.slice(offset).map(item => item.cmd).join(", "));
}

function offer(id, plainSize = 5, wireSize = plainSize + 28)
{
    return [id, "synthetic.bin", String(plainSize), "application/octet-stream", "65536", String(wireSize), "e2ee-v3"];
}

async function transfer(target, sender, plain, id)
{
    const chunks = [];
    // Exercise full-size and short terminal chunks in the same receive flow.
    for (let index = 0; index < plain.length; index += 65508)
    {
        chunks.push(await sender.encryptFile(plain.slice(index, index + 65508), id, chunks.length));
    }
    const wireSize = chunks.reduce((size, chunk) => size + chunk.byteLength, 0);
    const offerOffset = target.sent.length;
    target.offer(await sender.signFileOffer(offer(id, plain.length, wireSize)));
    await waitFor(target, "fileAccept", offerOffset);
    assert.deepEqual(target.sent.at(-1), { cmd: "fileAccept", args: [id] });
    assert.equal(target.elements.get("fileActionSend").disabled, true);
    for (const [seq, chunk] of chunks.entries())
    {
        const offset = target.sent.length;
        target.chunk([id, String(seq), String(chunk.byteLength)]);
        target.binary(chunk);
        const ack = await waitFor(target, "fileChunkAck", offset);
        assert.deepEqual(ack.args, [id, String(seq)]);
    }
    target.done([id, String(chunks.length), String(wireSize)]);
    assert.equal(target.sent.at(-1).cmd, "fileReceived");
    assert.equal(target.download.hidden, false);
    assert.deepEqual(new Uint8Array(await target.blobs.get(target.download.href).arrayBuffer()), plain);
    assert.equal(target.elements.get("fileActionSend").disabled, false);
    assert.equal(target.elements.get("fileActionCancel").disabled, true);
}

test("legacy and altered encryption markers reject without keys or download", async () => {
    for (const marker of [undefined, "", "plaintext", "e2ee-v0", "E2EE-V1", null, false])
    {
        const target = receiver();
        const args = offer("downgraded");
        if (marker === undefined) args.length = 5;
        else args[6] = marker;
        target.offer(args);
        assert.deepEqual(target.sent.at(-1), { cmd: "fileReject", args: ["downgraded", "encryption-required"] });
        assert.equal(target.status.dataset.i18nKey, "file.encryptionRequired");
        target.chunk(["downgraded", "0", "5"]);
        target.binary(new Uint8Array([0, 17, 255, 3, 128]));
        target.done(["downgraded", "1", "5"]);
        await delay(1);
        assert.equal(target.blobs.size, 0);
        assert.equal(target.download.hidden, true);
        assert.equal(target.sent.some(item => ["fileAccept", "fileChunkAck", "fileReceived"].includes(item.cmd)), false);
    }
});

test("encrypted marker alone cannot start a transfer before key establishment", () => {
    const target = receiver();
    target.offer(offer("no-shared-key"));
    assert.deepEqual(target.sent.at(-1), { cmd: "fileReject", args: ["no-shared-key", "encryption-required"] });
    assert.equal(target.status.dataset.i18nKey, "file.encryptionRequired");
    assert.equal(target.blobs.size, 0);
});

test("encrypted offers require explicit integer wire sizes and valid encrypted chunk bounds", async () => {
    const target = receiver();
    await connect(target);
    const mutations = [[5, undefined], [5, ""], [5, "5"], [5, "33.5"], [5, "Infinity"],
        [4, "28"], [4, "65537"], [4, "33.5"], [2, "0"], [2, "5.5"]];
    for (const [field, value] of mutations)
    {
        const args = offer("malformed-offer");
        args[field] = value;
        target.offer(args);
        assert.deepEqual(target.sent.at(-1), { cmd: "fileReject", args: ["malformed-offer", "invalid"] });
        assert.equal(target.blobs.size, 0);
        assert.equal(target.elements.get("fileActionSend").disabled, false);
    }
});

test("downgrade rejection preserves a verified download and later encrypted file/text progress", async () => {
    const target = receiver();
    const sender = await connect(target);
    const first = new Uint8Array([0, 17, 255, 3, 128]);
    await transfer(target, sender, first, "verified-before");
    const verifiedUrl = target.download.href;
    target.offer(offer("downgraded").slice(0, 5));
    assert.equal(target.sent.at(-1).cmd, "fileReject");
    assert.equal(target.download.href, verifiedUrl);
    assert.equal(target.download.hidden, false);
    assert.deepEqual(new Uint8Array(await target.blobs.get(verifiedUrl).arrayBuffer()), first);
    const large = new Uint8Array(131017);
    for (let index = 0; index < large.length; index += 1) large[index] = (index * 37 + 19) % 256;
    await transfer(target, sender, large, "verified-after");
    assert.equal((await target.context.decryptTextPayload(await sender.encryptText("text after rejected downgrade", 4503599627370500, "sender"))).text, "text after rejected downgrade");
});

test("a fake encrypted offer never turns plaintext bytes into a download; encrypted retry succeeds", async () => {
    const target = receiver();
    const sender = await connect(target);
    target.offer(await sender.signFileOffer(offer("fake-encrypted")));
    await waitFor(target, "fileAccept", 0);
    assert.equal(target.sent.at(-1).cmd, "fileAccept");
    const offset = target.sent.length;
    target.chunk(["fake-encrypted", "0", "33"]);
    target.binary(new Uint8Array(33).fill(97));
    await waitFor(target, "fileCancel", offset);
    assert.equal(target.sent.slice(offset).some(item => item.cmd === "fileChunkAck"), false);
    assert.equal(target.blobs.size, 0);
    assert.equal(target.download.hidden, true);
    await transfer(target, sender, new Uint8Array([1, 2, 3]), "retry-after-forgery");
});

test("tampered ciphertext and wrong transfer context cancel without a download and allow retry", async () => {
    for (const mutation of ["ciphertext", "transfer", "sequence"])
    {
        const target = receiver();
        const sender = await connect(target);
        const wire = new Uint8Array(await sender.encryptFile(new Uint8Array([1, 2, 3, 4, 5]), mutation === "transfer" ? "wrong" : "tampered", mutation === "sequence" ? 1 : 0));
        if (mutation === "ciphertext") wire[12] ^= 1;
        target.offer(await sender.signFileOffer(offer("tampered")));
        await waitFor(target, "fileAccept", 0);
        const offset = target.sent.length;
        target.chunk(["tampered", "0", String(wire.length)]);
        target.binary(wire);
        await waitFor(target, "fileCancel", offset);
        assert.equal(target.blobs.size, 0);
        assert.equal(target.sent.slice(offset).some(item => item.cmd === "fileChunkAck"), false);
        await transfer(target, sender, new Uint8Array([255]), "retry-after-" + mutation);
    }
});

test("an active encrypted transfer rejects extra offers without losing authenticated progress", async () => {
    const target = receiver();
    const sender = await connect(target);
    const plain = new Uint8Array([0, 1, 2, 3, 4]);
    const wire = await sender.encryptFile(plain, "active", 0);
    target.offer(await sender.signFileOffer(offer("active")));
    await waitFor(target, "fileAccept", 0);
    target.offer(offer("intruder").slice(0, 5));
    assert.deepEqual(target.sent.at(-1), { cmd: "fileReject", args: ["intruder", "busy"] });
    const offset = target.sent.length;
    target.chunk(["active", "0", String(wire.byteLength)]);
    target.binary(wire);
    await waitFor(target, "fileChunkAck", offset);
    target.done(["active", "1", String(wire.byteLength)]);
    assert.deepEqual(new Uint8Array(await target.blobs.get(target.download.href).arrayBuffer()), plain);
});

test("unsigned or modified offers preserve verified download; authenticated retry still works", async () => {
    const target = receiver();
    const sender = await connect(target);
    await transfer(target, sender, new Uint8Array([1, 2, 3]), "kept");
    const previous = target.download.href;
    const valid = await sender.signFileOffer(offer("tampered-metadata"));
    const unsigned = offer("unsigned");
    const changed = valid.slice(); changed[1] = "changed.bin";
    for (const args of [unsigned, changed])
    {
        const offset = target.sent.length;
        target.offer(args);
        await waitFor(target, "fileReject", offset);
        assert.equal(target.sent.slice(offset).some(item => item.cmd === "fileAccept"), false);
        assert.equal(target.download.href, previous);
        assert.equal(target.download.hidden, false);
    }
    await transfer(target, sender, new Uint8Array([4, 5]), "after-offer-rejection");
});

test("cancellation or peer reset during offer authentication cannot accept a stale transfer", async () => {
    for (const interruption of ["cancel", "reset"])
    {
        const target = receiver();
        const sender = await connect(target);
        const session = target.context.e2eeSession;
        let release;
        let finished;
        const gate = new Promise(resolve => { release = resolve; });
        const checked = new Promise(resolve => { finished = resolve; });
        target.context.e2eeSession = {
            ...session,
            async verifyFileOffer(args)
            {
                await gate;
                try { return await session.verifyFileOffer(args); }
                finally { finished(); }
            }
        };
        const offset = target.sent.length;
        target.offer(await sender.signFileOffer(offer("pending-" + interruption)));
        assert.equal(target.elements.get("fileActionSend").disabled, true);
        if (interruption === "cancel") target.cancel();
        else target.context.clearTextE2eeDerivedSecret();
        release();
        await checked;
        await delay(1);
        assert.equal(target.sent.slice(offset).some(item => item.cmd === "fileAccept"), false);
        assert.equal(target.elements.get("fileActionSend").disabled, false);
        assert.equal(target.elements.get("fileActionCancel").disabled, true);
        assert.equal(target.blobs.size, 0);
        const retrySender = await connect(target);
        await transfer(target, retrySender, new Uint8Array([9, 8, 7]), "retry-" + interruption);
    }
});
