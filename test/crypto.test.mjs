// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, createECDH, createHmac, createHash, hkdfSync } from "node:crypto";
import test from "node:test";
import { E2EE, webcrypto, client, connect, paired, memoryStorage } from "./endpoint.mjs";

const b64 = value => Buffer.from(value).toString("base64url");
const raw = value => Buffer.from(value, "base64url");
const json = value => Buffer.from(JSON.stringify(value));
const fields = (id = "synthetic-file") => [id, "example.txt", "5", "text/plain", "33", "33", "e2ee-v3"];

async function oracleKeys(primary, secondary)
{
    const own = JSON.parse(primary.storage.getItem(E2EE.KEYPAIR_PREFIX + primary.pairId));
    const peer = (await secondary.session.publicMessage())[1];
    const ecdh = createECDH("prime256v1");
    ecdh.setPrivateKey(raw(own.privateKey.d));
    const material = Buffer.concat([ecdh.computeSecret(raw(peer)), raw(primary.secret)]);
    const salt = createHash("sha256").update(json(["v3", primary.pairId, own.publicKey, peer])).digest();
    const derive = (context, ikm = material, selectedSalt = salt) => Buffer.from(hkdfSync("sha256", ikm, selectedSalt, context, 32));
    return { text: derive("icyzip/e2ee/text/v3"), file: derive("icyzip/e2ee/file-chunk/v3"),
        offer: derive("icyzip/e2ee/file-offer/v3"),
        auth: derive("icyzip/e2ee/pub-auth/v3", raw(primary.secret), Buffer.from(primary.pairId)) };
}

function seal(key, pairId, value)
{
    const nonce = webcrypto.getRandomValues(new Uint8Array(12));
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(json(["icyzip/text/v2", pairId]));
    const content = Buffer.concat([cipher.update(json(value)), cipher.final(), cipher.getAuthTag()]);
    return JSON.stringify({ v: 2, alg: "A256GCM", n: b64(nonce), c: b64(content) });
}

test("pairing links contain only a canonical browser-fragment v3 secret", () => {
    const seen = new Set();
    for (let index = 0; index < 64; index += 1)
    {
        const secret = E2EE.generateSecret(webcrypto);
        assert.equal(raw(secret).length, 32);
        assert.equal(secret.length, 43);
        seen.add(secret);
        const link = new URL("https://icyzip.com/?i=synthetic" + E2EE.fragmentForSecret(secret));
        assert.equal(link.search, "?i=synthetic");
        assert.equal(E2EE.parseFragment(link.hash), secret);
        for (const invalid of ["", "#", "#k=" + secret, "#k=" + secret + "&v=2",
            "#k=" + secret + "=&v=3", "#k=" + secret.slice(1) + "&v=3",
            "#k=" + secret + "&v=3&v=3", "#k=" + secret + "&v=3&extra=1"])
            assert.equal(E2EE.parseFragment(invalid), null);
    }
    assert.equal(seen.size, 64);
    assert.throws(() => client({ secret: "" }));
    assert.throws(() => E2EE.fragmentForSecret("invalid"));
});

test("a relay key without the pairing secret is rejected before ECDH import", async () => {
    let peerImports = 0;
    const crypto = { getRandomValues: value => webcrypto.getRandomValues(value),
        subtle: new Proxy(webcrypto.subtle, { get(target, key) {
            if (key === "importKey") return (...args) => {
                if (args[0] === "raw" && args[2].name === "ECDH") peerImports += 1;
                return target.importKey(...args);
            };
            const value = target[key];
            return typeof value === "function" ? value.bind(target) : value;
        } }) };
    const honest = client({ crypto });
    const attacker = client({ role: "secondary" });
    await assert.rejects(honest.session.acceptPublicMessage(await attacker.session.publicMessage()));
    assert.equal(peerImports, 0);
    assert.equal(honest.session.ready(), false);
    await assert.rejects(honest.session.encryptText("blocked", 1, "origin"));
});

test("role, pair, version, public key and tag mutations cannot authenticate", async () => {
    const primary = client();
    const secondary = client({ role: "secondary", secret: primary.secret });
    const valid = await secondary.session.publicMessage();
    const reflected = await primary.session.publicMessage();
    const otherPair = await client({ pairId: "other-pair", role: "secondary", secret: primary.secret }).session.publicMessage();
    const changedPoint = await client({ role: "secondary", secret: primary.secret }).session.publicMessage();
    for (const altered of [reflected, otherPair, ["v2", ...valid.slice(1)], valid.slice(0, 2),
        [valid[0], changedPoint[1], valid[2]], [valid[0], valid[1], valid[2].slice(1)],
        [valid[0], valid[1], b64(Buffer.alloc(32))], [valid[0], valid[1] + "=", valid[2]], valid.concat("extra")])
    {
        await assert.rejects(primary.session.acceptPublicMessage(altered));
        assert.equal(primary.session.ready(), false);
    }
    await connect(primary, secondary);
    assert.equal((await secondary.session.decryptText(await primary.session.encryptText("later valid", 1, "a"))).text, "later valid");
});

test("independent Node oracle matches public authentication and all separated keys", async () => {
    const { primary, secondary } = await paired();
    const keys = await oracleKeys(primary, secondary);
    assert.equal(new Set(Object.values(keys).map(b64)).size, 4);
    const message = await primary.session.publicMessage();
    const expected = createHmac("sha256", keys.auth).update(json(["icyzip/e2ee/pub/v3", primary.pairId, "primary", message[1]])).digest();
    assert.equal(message[2], b64(expected));
    const envelope = JSON.parse(await primary.session.encryptText("independent 🧊", 4503599627370497, "oracle"));
    const cipher = raw(envelope.c);
    const decoder = createDecipheriv("aes-256-gcm", keys.text, raw(envelope.n));
    decoder.setAAD(json(["icyzip/text/v2", primary.pairId]));
    decoder.setAuthTag(cipher.subarray(-16));
    const plain = Buffer.concat([decoder.update(cipher.subarray(0, -16)), decoder.final()]);
    assert.deepEqual(JSON.parse(plain), { text: "independent 🧊", t: 4503599627370497, o: "oracle" });
    const offer = await primary.session.signFileOffer(fields());
    assert.equal(offer[7], b64(createHmac("sha256", keys.offer)
        .update(json(["icyzip/file/offer/v3", primary.pairId, "primary", fields()])).digest()));
    const frame = Buffer.from(await primary.session.encryptFile(new Uint8Array([0, 17, 255, 3, 128]), "oracle-file", 2));
    const fileDecoder = createDecipheriv("aes-256-gcm", keys.file, frame.subarray(0, 12));
    fileDecoder.setAAD(json(["icyzip/file/chunk/v3", primary.pairId, "oracle-file", 2]));
    fileDecoder.setAuthTag(frame.subarray(-16));
    assert.deepEqual(Buffer.concat([fileDecoder.update(frame.subarray(12, -16)), fileDecoder.final()]), Buffer.from([0, 17, 255, 3, 128]));
});

test("text round trips in both directions with hidden authenticated revision and origin", async () => {
    const { primary, secondary } = await paired();
    const nonces = new Set();
    for (const [sender, receiver] of [[primary, secondary], [secondary, primary]])
    {
        for (const text of ["", "Unicode 🧊 漢字\n\u0000", "a".repeat(65536)])
        {
            const wire = await sender.session.encryptText(text, 4503599627370555, "test-origin");
            const envelope = JSON.parse(wire);
            assert.deepEqual(Object.keys(envelope), ["v", "alg", "n", "c"]);
            assert.equal(envelope.v, 2);
            assert.equal(wire.includes("test-origin"), false);
            assert.equal(wire.includes("4503599627370555"), false);
            nonces.add(envelope.n);
            assert.deepEqual(await receiver.session.decryptText(wire), { text, updatedAt: 4503599627370555, origin: "test-origin" });
        }
    }
    assert.equal(nonces.size, 6);
});

test("revision, origin, envelope and ciphertext mutations reject, then valid text progresses", async () => {
    const { primary, secondary } = await paired();
    const wire = await primary.session.encryptText("unchanged content", 4503599627370500, "honest");
    const envelope = JSON.parse(wire);
    for (const change of [item => { item.t = Number.MAX_SAFE_INTEGER; }, item => { item.o = "relay"; },
        item => { item.v = 1; }, item => { item.alg = "A128GCM"; }, item => { item.n = b64(Buffer.alloc(12)); },
        item => { const bytes = raw(item.c); bytes[0] ^= 1; item.c = b64(bytes); },
        item => { item.c = item.c.slice(0, -4); }, item => { item.c += "="; }])
    {
        const altered = { ...envelope }; change(altered);
        await assert.rejects(secondary.session.decryptText(JSON.stringify(altered)));
    }
    for (const invalid of ["not json", "null", "[]", "{}"])
        await assert.rejects(secondary.session.decryptText(invalid));
    assert.equal((await secondary.session.decryptText(wire)).text, "unchanged content");
    const other = await paired();
    await assert.rejects(other.secondary.session.decryptText(wire));
});

test("authenticated malformed metadata and cross-domain keys still fail closed", async () => {
    const { primary, secondary } = await paired();
    const keys = await oracleKeys(primary, secondary);
    const valid = { text: "value", t: 4503599627370497, o: "oracle" };
    for (const altered of [{ ...valid, text: 3 }, { ...valid, t: "5" }, { ...valid, t: -1 },
        { ...valid, t: Number.MAX_SAFE_INTEGER + 1 }, { ...valid, t: 1.5 }, { ...valid, o: "" },
        { ...valid, o: "x".repeat(129) }, { ...valid, extra: 1 }])
        await assert.rejects(secondary.session.decryptText(seal(keys.text, primary.pairId, altered)));
    for (const key of [keys.file, keys.offer, keys.auth])
        await assert.rejects(secondary.session.decryptText(seal(key, primary.pairId, valid)));
    await assert.rejects(secondary.session.decryptText(seal(keys.text, "other-pair", valid)));
    assert.equal((await secondary.session.decryptText(seal(keys.text, primary.pairId, valid))).text, "value");
});

test("every visible file-offer field, role reflection and unsigned offer reject", async () => {
    const { primary, secondary } = await paired();
    const signed = await primary.session.signFileOffer(fields());
    assert.equal(await secondary.session.verifyFileOffer(signed), true);
    assert.equal(await secondary.session.verifyFileOffer(fields()), false);
    assert.equal(await primary.session.verifyFileOffer(signed), false);
    for (const [index, replacement] of [[0, "other"], [1, "renamed.txt"], [2, "6"], [3, "image/png"],
        [4, "34"], [5, "34"], [6, "e2ee-v1"], [7, b64(Buffer.alloc(32))]])
    {
        const altered = signed.slice(); altered[index] = replacement;
        assert.equal(await secondary.session.verifyFileOffer(altered).catch(() => false), false);
    }
    assert.equal(await secondary.session.verifyFileOffer(signed), true);
});

test("file chunks bind transfer and sequence, reject mutations, and preserve exact bytes", async () => {
    const { primary, secondary } = await paired();
    for (const [sender, receiver] of [[primary, secondary], [secondary, primary]])
    {
        const plain = Uint8Array.from({ length: 65508 }, (_, index) => (index * 37 + 19) % 256);
        const encrypted = await sender.session.encryptFile(plain, "synthetic-file", 3);
        assert.equal(encrypted.byteLength, 65536);
        assert.deepEqual(new Uint8Array(await receiver.session.decryptFile(encrypted, "synthetic-file", 3)), plain);
        for (const [id, sequence] of [["wrong", 3], ["synthetic-file", 2], ["synthetic-file", -1]])
            await assert.rejects(receiver.session.decryptFile(encrypted, id, sequence));
        for (const index of [0, 12, encrypted.byteLength - 1])
        {
            const altered = new Uint8Array(encrypted.slice(0)); altered[index] ^= 1;
            await assert.rejects(receiver.session.decryptFile(altered, "synthetic-file", 3));
        }
        await assert.rejects(receiver.session.decryptFile(new Uint8Array(28), "synthetic-file", 3));
        assert.deepEqual(new Uint8Array(await receiver.session.decryptFile(encrypted, "synthetic-file", 3)), plain);
    }
});

test("tab reload reuses matching keys; damaged storage rotates consistently; reset cannot revive stale work", async () => {
    const { primary, secondary } = await paired();
    const previous = await secondary.session.publicMessage();
    const reloaded = client({ ...secondary, storage: secondary.storage });
    assert.deepEqual(await reloaded.session.publicMessage(), previous);
    await connect(primary, reloaded);
    assert.equal((await reloaded.session.decryptText(await primary.session.encryptText("reload", 2, "a"))).text, "reload");
    const saved = JSON.parse(secondary.storage.getItem(E2EE.KEYPAIR_PREFIX + secondary.pairId));
    saved.publicKey = (await client().session.publicMessage())[1];
    secondary.storage.setItem(E2EE.KEYPAIR_PREFIX + secondary.pairId, JSON.stringify(saved));
    const repaired = client({ ...secondary, storage: secondary.storage });
    assert.notEqual((await repaired.session.publicMessage())[1], previous[1]);
    await connect(primary, repaired);
    assert.equal((await repaired.session.decryptText(await primary.session.encryptText("repair", 3, "a"))).text, "repair");
    primary.session.resetPeer();
    const pending = primary.session.acceptPublicMessage(await repaired.session.publicMessage());
    primary.session.resetPeer();
    assert.equal(await pending, false);
    assert.equal(primary.session.ready(), false);
    await connect(primary, repaired);
    primary.session.close();
    assert.equal(primary.session.ready(), false);
    await assert.rejects(primary.session.publicMessage());
    await assert.rejects(primary.session.encryptText("closed", 4, "a"));
});

test("storage-denied tabs retain a working in-memory authenticated pairing", async () => {
    const storage = { getItem() { throw new Error("denied"); }, setItem() { throw new Error("denied"); }, removeItem() { throw new Error("denied"); } };
    const primary = client({ storage });
    const secondary = client({ role: "secondary", secret: primary.secret, storage });
    await connect(primary, secondary);
    assert.equal((await secondary.session.decryptText(await primary.session.encryptText("memory", 1, "a"))).text, "memory");
});
