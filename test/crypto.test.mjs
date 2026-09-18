// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { createECDH, createDecipheriv, hkdfSync, webcrypto } from "node:crypto";
import test from "node:test";
import { endpoint, paired } from "./endpoint.mjs";

test("independent endpoints exchange Unicode, empty text, and revisions in both directions", async () => {
    const { primary, secondary } = await paired();
    for (const [sender, receiver] of [[primary, secondary], [secondary, primary]])
    {
        for (const text of ["", "hello", "Grüße 👋\n日本語\u0000", "x".repeat(32000)])
        {
            const wire = await sender.encrypt(text, 4503599627370500, "fixture-origin");
            const value = await receiver.decrypt(wire);
            assert.equal(value.text, text);
            assert.equal(value.updatedAt, 4503599627370500);
            assert.equal(value.origin, "fixture-origin");
            if (text.length > 10) assert.equal(wire.includes(text), false);
        }
    }
});

test("public key command carries only routing identifier and the public point", async () => {
    const primary = endpoint();
    const publicKey = await primary.publicKey();
    await primary.sendPublic();
    assert.equal(primary.sent.length, 1);
    assert.equal(primary.sent[0].cmd, "textPub");
    assert.deepEqual(Array.from(primary.sent[0].args), ["synthetic-resume-capability", publicKey]);
    assert.equal(Buffer.from(publicKey, "base64url").length, 65);
    assert.equal(new URL(primary.pairUrl()).hash, "");
});

test("random text nonces differ across repeated encryptions", async () => {
    const { primary } = await paired();
    const nonces = new Set();
    for (let index = 0; index < 64; index += 1)
    {
        const envelope = JSON.parse(await primary.encrypt("nonce fixture"));
        assert.equal(Buffer.from(envelope.n, "base64url").length, 12);
        nonces.add(envelope.n);
    }
    assert.equal(nonces.size, 64);
});

test("invalid envelopes, ciphertext changes, wrong keys, and missing keys reject", async () => {
    const { primary, secondary } = await paired();
    const unrelated = await paired();
    const wire = await primary.encrypt("authenticated text bytes");
    const changed = JSON.parse(wire);
    const bytes = Buffer.from(changed.c, "base64url");
    bytes[0] ^= 1;
    changed.c = bytes.toString("base64url");
    for (const malformed of ["plaintext", "{}", JSON.stringify(changed), JSON.stringify({ ...JSON.parse(wire), n: "AA" })])
    {
        await assert.rejects(secondary.decrypt(malformed));
    }
    await assert.rejects(unrelated.secondary.decrypt(wire));
    await assert.rejects(endpoint().encrypt("no key"));
    assert.equal((await secondary.decrypt(wire)).text, "authenticated text bytes");
});

test("a structurally malformed or invalid-curve public point is rejected", async () => {
    const target = endpoint();
    const invalidPoint = Buffer.alloc(65);
    invalidPoint[0] = 4;
    for (const key of ["", "bad*point", "AA", invalidPoint.toString("base64url")])
    {
        await assert.rejects(target.receive(key));
        assert.equal(target.ready(), false);
    }
});

test("tab key restoration keeps public identity and rederives the shared key", async () => {
    const { primary, secondary } = await paired();
    const before = await primary.publicKey();
    assert.equal(primary.saved.size, 1);
    const restored = endpoint({ saved: primary.saved });
    assert.equal(restored.ready(), false);
    assert.equal(await restored.publicKey(), before);
    await restored.receive(await secondary.publicKey());
    assert.equal((await secondary.decrypt(await restored.encrypt("after reload"))).text, "after reload");
    restored.clear();
    assert.equal(primary.saved.size, 0);
    assert.equal(restored.ready(), false);
});

test("inconsistent saved public/private coordinates trigger fresh key generation", async () => {
    const target = endpoint();
    const before = await target.publicKey();
    const [storageKey, record] = [...target.saved][0];
    const modified = JSON.parse(record);
    modified.publicKey = await endpoint().publicKey();
    target.saved.set(storageKey, JSON.stringify(modified));
    const restored = endpoint({ saved: target.saved });
    assert.notEqual(await restored.publicKey(), before);
});

test("file chunks round-trip exact binary bytes and authenticate transfer and sequence", async () => {
    const { primary, secondary } = await paired();
    for (const length of [1, 2, 31, 255, 4096, 65508])
    {
        const plain = webcrypto.getRandomValues(new Uint8Array(length));
        const wire = await primary.encryptFile(plain, "transfer-a", 7);
        assert.equal(wire.byteLength, length + 28);
        assert.deepEqual(new Uint8Array(await secondary.decryptFile(wire, "transfer-a", 7)), plain);
        await assert.rejects(secondary.decryptFile(wire, "transfer-b", 7));
        await assert.rejects(secondary.decryptFile(wire, "transfer-a", 8));
        const changed = new Uint8Array(wire.slice(0));
        changed[12] ^= 1;
        await assert.rejects(secondary.decryptFile(changed, "transfer-a", 7));
    }
    const reply = new Uint8Array([0, 255, 1, 128]);
    assert.deepEqual(new Uint8Array(await primary.decryptFile(await secondary.encryptFile(reply))), reply);
});

test("text and file keys are distinct even when nonce and ciphertext are repackaged", async () => {
    const { primary, secondary } = await paired();
    const nonce = new Uint8Array(12).fill(1);
    const input = new Uint8Array([5, 6, 7]);
    const encrypted = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, await primary.textKey(), input);
    await assert.rejects(webcrypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, await secondary.fileKey(), encrypted));
    const wire = new Uint8Array(await primary.encryptFile(new Uint8Array([1, 2, 3])));
    const asText = JSON.stringify({ v: 1, alg: "A256GCM", n: Buffer.from(wire.slice(0, 12)).toString("base64url"), c: Buffer.from(wire.slice(12)).toString("base64url") });
    await assert.rejects(secondary.decrypt(asText));
});

test("independent Node ECDH/HKDF/AES-GCM APIs decrypt the browser text and file formats", async () => {
    const id = "independent-oracle-fixture";
    const browser = endpoint({ id });
    const oracle = createECDH("prime256v1");
    oracle.generateKeys();
    const shared = oracle.computeSecret(Buffer.from(await browser.publicKey(), "base64url"));
    await browser.receive(oracle.getPublicKey().toString("base64url"));
    function independentDecrypt(info, nonce, ciphertext, aad)
    {
        const key = Buffer.from(hkdfSync("sha256", shared, Buffer.from(id), Buffer.from(info), 32));
        const decipher = createDecipheriv("aes-256-gcm", key, nonce);
        if (aad) decipher.setAAD(aad);
        decipher.setAuthTag(ciphertext.subarray(-16));
        return Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
    }
    const envelope = JSON.parse(await browser.encrypt("independent UTF-8 🧊"));
    assert.equal(independentDecrypt("icyzip/text/ecdh/v2", Buffer.from(envelope.n, "base64url"), Buffer.from(envelope.c, "base64url")).toString(), "independent UTF-8 🧊");
    const file = new Uint8Array([0, 17, 255, 128, 3]);
    const frame = Buffer.from(await browser.encryptFile(file, "oracle-transfer", 3));
    const aad = Buffer.from(["icyzip/file/chunk/v1", id, "oracle-transfer", "3"].join("\n"));
    assert.deepEqual(independentDecrypt("icyzip/file/ecdh/v1", frame.subarray(0, 12), frame.subarray(12), aad), Buffer.from(file));
});
