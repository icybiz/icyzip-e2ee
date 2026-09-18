// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
// The browser and independent tests use this same protocol implementation.
(function (root, factory)
{
    const api = factory();
    if (typeof module === "object" && module.exports) module.exports = api;
    else root.IcyZipE2EE = api;
})(typeof window !== "undefined" ? window : globalThis, function ()
{
    "use strict";

    const KEYPAIR_PREFIX = "icyzip.e2ee.v3.ecdh:";
    const SECRET_PREFIX = "icyzip.e2ee.v3.secret:";
    const CURVE = { name: "ECDH", namedCurve: "P-256" };
    const encoder = new TextEncoder();

    function encode(bytes)
    {
        let raw = "";
        for (let index = 0; index < bytes.length; index += 1) raw += String.fromCharCode(bytes[index]);
        return btoa(raw).split("+").join("-").split("/").join("_").split("=").join("");
    }

    function decode(value)
    {
        if (typeof value !== "string" || !value || value.length % 4 === 1) return null;
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (const character of value) if (!alphabet.includes(character)) return null;
        try
        {
            const raw = atob(value.split("-").join("+").split("_").join("/"));
            const bytes = Uint8Array.from(raw, character => character.charCodeAt(0));
            return encode(bytes) === value ? bytes : null;
        }
        catch (error) { return null; }
    }

    function validSecret(secret)
    {
        return typeof secret === "string" && secret.length === 43 && !!decode(secret);
    }

    function generateSecret(crypto)
    {
        return encode(crypto.getRandomValues(new Uint8Array(32)));
    }

    function fragmentForSecret(secret)
    {
        if (!validSecret(secret)) throw new Error("Invalid pairing secret");
        return "#k=" + secret + "&v=3";
    }

    function parseFragment(fragment)
    {
        if (typeof fragment !== "string" || !fragment.startsWith("#")) return null;
        const params = new URLSearchParams(fragment.slice(1));
        if (Array.from(params).length !== 2 || params.getAll("k").length !== 1
            || params.getAll("v").length !== 1 || params.get("v") !== "3") return null;
        const secret = params.get("k");
        return validSecret(secret) ? secret : null;
    }

    function canonical(value) { return encoder.encode(JSON.stringify(value)); }

    function validPublic(value)
    {
        const bytes = typeof value === "string" && value.length === 87 ? decode(value) : null;
        return !!bytes && bytes.length === 65 && bytes[0] === 4;
    }

    function publicFromJwk(key)
    {
        if (!key || key.kty !== "EC" || key.crv !== "P-256") return "";
        const x = decode(key.x);
        const y = decode(key.y);
        if (!x || !y || x.length !== 32 || y.length !== 32) return "";
        const raw = new Uint8Array(65);
        raw[0] = 4;
        raw.set(x, 1);
        raw.set(y, 33);
        return encode(raw);
    }

    function storageGet(storage, key)
    {
        try { return storage && storage.getItem(key); }
        catch (error) { return null; }
    }

    function storageRemove(storage, key)
    {
        try { if (storage) storage.removeItem(key); }
        catch (error) { /* A storage-disabled tab still supports its in-memory session. */ }
    }

    function storageSet(storage, key, value)
    {
        try { if (storage) storage.setItem(key, value); }
        catch (error) { /* Reload then requires a fresh primary or the original link. */ }
    }

    function validText(value)
    {
        return value && typeof value === "object" && !Array.isArray(value)
            && Object.keys(value).length === 3 && typeof value.text === "string"
            && Number.isSafeInteger(value.t) && value.t >= 0
            && typeof value.o === "string" && value.o.length > 0 && value.o.length <= 128;
    }

    function offerFields(args)
    {
        if (!Array.isArray(args) || args.length !== 7 || args.some(value => typeof value !== "string")
            || !args[0] || args[0].length > 80 || !args[1] || args[1].length > 180
            || !args[3] || args[3].length > 120 || args[6] !== "e2ee-v3")
            throw new Error("Invalid file offer");
        for (const index of [2, 4, 5])
        {
            const number = Number(args[index]);
            if (!Number.isSafeInteger(number) || number <= 0 || String(number) !== args[index])
                throw new Error("Invalid file offer size");
        }
        return args.slice();
    }

    function fileContext(pairId, transferId, seq)
    {
        if (typeof transferId !== "string" || !transferId || transferId.length > 80
            || !Number.isSafeInteger(seq) || seq < 0) throw new Error("Invalid file context");
        return canonical(["icyzip/file/chunk/v3", pairId, transferId, seq]);
    }

    function createSession(options)
    {
        const { pairId, role, secret, crypto, storage } = options;
        if (typeof pairId !== "string" || !pairId || pairId.length > 80
            || !["primary", "secondary"].includes(role) || !validSecret(secret)
            || !crypto || !crypto.subtle || !crypto.getRandomValues)
            throw new Error("Invalid E2EE session");
        const subtle = crypto.subtle;
        const peerRole = role === "primary" ? "secondary" : "primary";
        const secretBytes = decode(secret);
        const storageKey = KEYPAIR_PREFIX + pairId;
        let keyPairPromise = null;
        let authPromise = null;
        let keys = null;
        let peerPublic = "";
        let epoch = 0;
        let closed = false;

        async function hkdf(input, salt, info, hmac)
        {
            const material = await subtle.importKey("raw", input, "HKDF", false, ["deriveKey"]);
            return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: encoder.encode(info) },
                material, hmac ? { name: "HMAC", hash: "SHA-256", length: 256 } : { name: "AES-GCM", length: 256 },
                false, hmac ? ["sign", "verify"] : ["encrypt", "decrypt"]);
        }

        async function loadKeyPair()
        {
            try
            {
                const saved = JSON.parse(storageGet(storage, storageKey) || "null");
                if (saved && validPublic(saved.publicKey) && publicFromJwk(saved.privateKey) === saved.publicKey)
                {
                    const privateKey = await subtle.importKey("jwk", saved.privateKey, CURVE, false, ["deriveBits"]);
                    return { privateKey, publicKey: saved.publicKey };
                }
            }
            catch (error) { /* Corrupted state must regenerate a matching keypair. */ }
            storageRemove(storage, storageKey);
            const generated = await subtle.generateKey(CURVE, true, ["deriveBits"]);
            const privateJwk = await subtle.exportKey("jwk", generated.privateKey);
            const publicKey = encode(new Uint8Array(await subtle.exportKey("raw", generated.publicKey)));
            if (!closed) storageSet(storage, storageKey, JSON.stringify({ privateKey: privateJwk, publicKey }));
            return { privateKey: generated.privateKey, publicKey };
        }

        function keyPair()
        {
            if (closed) return Promise.reject(new Error("Closed E2EE session"));
            if (!keyPairPromise) keyPairPromise = loadKeyPair();
            return keyPairPromise;
        }

        function authKey()
        {
            if (!authPromise) authPromise = hkdf(secretBytes, encoder.encode(pairId), "icyzip/e2ee/pub-auth/v3", true);
            return authPromise;
        }

        function publicContext(senderRole, publicKey)
        {
            return canonical(["icyzip/e2ee/pub/v3", pairId, senderRole, publicKey]);
        }

        async function publicMessage()
        {
            const own = await keyPair();
            const tag = await subtle.sign("HMAC", await authKey(), publicContext(role, own.publicKey));
            if (closed) throw new Error("Closed E2EE session");
            return ["v3", own.publicKey, encode(new Uint8Array(tag))];
        }

        async function acceptPublicMessage(message)
        {
            const started = epoch;
            if (closed || !Array.isArray(message) || message.length !== 3 || message[0] !== "v3"
                || !validPublic(message[1]) || !validSecret(message[2])) throw new Error("Invalid public-key message");
            const publicKey = message[1];
            if (!await subtle.verify("HMAC", await authKey(), decode(message[2]), publicContext(peerRole, publicKey)))
                throw new Error("Public-key authentication failed");
            if (closed || started !== epoch) return false;
            if (keys && peerPublic === publicKey) return true;
            const own = await keyPair();
            const peer = await subtle.importKey("raw", decode(publicKey), CURVE, false, []);
            const shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: peer }, own.privateKey, 256));
            const material = new Uint8Array(64);
            material.set(shared);
            material.set(secretBytes, 32);
            const primary = role === "primary" ? own.publicKey : publicKey;
            const secondary = role === "secondary" ? own.publicKey : publicKey;
            const salt = await subtle.digest("SHA-256", canonical(["v3", pairId, primary, secondary]));
            const derived = await Promise.all([
                hkdf(material, salt, "icyzip/e2ee/text/v3", false),
                hkdf(material, salt, "icyzip/e2ee/file-chunk/v3", false),
                hkdf(material, salt, "icyzip/e2ee/file-offer/v3", true)
            ]);
            shared.fill(0);
            material.fill(0);
            if (closed || started !== epoch) return false;
            keys = { text: derived[0], file: derived[1], offer: derived[2] };
            peerPublic = publicKey;
            return true;
        }

        function requireKeys()
        {
            if (closed || !keys) throw new Error("Authenticated peer key missing");
            return keys;
        }

        async function encryptText(text, revision, origin)
        {
            const content = { text, t: revision, o: origin };
            if (!validText(content)) throw new Error("Invalid text metadata");
            const key = requireKeys().text;
            const nonce = crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv: nonce,
                additionalData: canonical(["icyzip/text/v2", pairId]) }, key, canonical(content));
            return JSON.stringify({ v: 2, alg: "A256GCM", n: encode(nonce), c: encode(new Uint8Array(ciphertext)) });
        }

        async function decryptText(payload)
        {
            const key = requireKeys().text;
            const envelope = JSON.parse(payload);
            if (!envelope || Array.isArray(envelope) || Object.keys(envelope).length !== 4
                || envelope.v !== 2 || envelope.alg !== "A256GCM") throw new Error("Invalid text envelope");
            const nonce = decode(envelope.n);
            const ciphertext = decode(envelope.c);
            if (!nonce || nonce.length !== 12 || !ciphertext || ciphertext.length < 16)
                throw new Error("Invalid text ciphertext");
            const plain = await subtle.decrypt({ name: "AES-GCM", iv: nonce,
                additionalData: canonical(["icyzip/text/v2", pairId]) }, key, ciphertext);
            const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plain));
            if (!validText(value)) throw new Error("Invalid text metadata");
            return { text: value.text, updatedAt: value.t, origin: value.o };
        }

        async function encryptFile(buffer, transferId, seq)
        {
            const key = requireKeys().file;
            const nonce = crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce,
                additionalData: fileContext(pairId, transferId, seq) }, key, buffer));
            const frame = new Uint8Array(12 + ciphertext.length);
            frame.set(nonce);
            frame.set(ciphertext, 12);
            return frame.buffer;
        }

        async function decryptFile(buffer, transferId, seq)
        {
            const key = requireKeys().file;
            const frame = ArrayBuffer.isView(buffer)
                ? new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength) : new Uint8Array(buffer);
            if (frame.length <= 28) throw new Error("Invalid file frame");
            return subtle.decrypt({ name: "AES-GCM", iv: frame.slice(0, 12),
                additionalData: fileContext(pairId, transferId, seq) }, key, frame.slice(12));
        }

        async function signFileOffer(args)
        {
            const fields = offerFields(args);
            const tag = await subtle.sign("HMAC", requireKeys().offer,
                canonical(["icyzip/file/offer/v3", pairId, role, fields]));
            return fields.concat(encode(new Uint8Array(tag)));
        }

        async function verifyFileOffer(args)
        {
            if (!Array.isArray(args) || args.length !== 8 || !validSecret(args[7])) return false;
            const fields = offerFields(args.slice(0, 7));
            return subtle.verify("HMAC", requireKeys().offer, decode(args[7]),
                canonical(["icyzip/file/offer/v3", pairId, peerRole, fields]));
        }

        function resetPeer()
        {
            epoch += 1;
            keys = null;
            peerPublic = "";
        }

        function close()
        {
            resetPeer();
            closed = true;
            secretBytes.fill(0);
            authPromise = null;
            keyPairPromise = null;
        }

        return Object.freeze({ publicMessage, acceptPublicMessage, encryptText, decryptText,
            encryptFile, decryptFile, signFileOffer, verifyFileOffer, resetPeer, close,
            ready: () => !closed && !!keys });
    }

    return Object.freeze({ KEYPAIR_PREFIX, SECRET_PREFIX, generateSecret, validSecret,
        fragmentForSecret, parseFragment, createSession });
});
