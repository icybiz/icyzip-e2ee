// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { paired } from "./endpoint.mjs";

test("two local peers exchange text and reject changed ciphertext", async () => {
    const { primary, secondary } = await paired();
    const original = await primary.session.encryptText("Hello 🧊", 1, "primary");
    assert.equal((await secondary.session.decryptText(original)).text, "Hello 🧊");

    const changed = JSON.parse(original);
    const bytes = Buffer.from(changed.c, "base64url");
    bytes[0] ^= 1;
    changed.c = bytes.toString("base64url");
    await assert.rejects(secondary.session.decryptText(JSON.stringify(changed)));

    const reply = await secondary.session.encryptText("Reply after rejection", 2, "secondary");
    assert.equal((await primary.session.decryptText(reply)).text, "Reply after rejection");
    const later = await primary.session.encryptText("Still connected", 3, "primary");
    assert.equal((await secondary.session.decryptText(later)).text, "Still connected");
});
