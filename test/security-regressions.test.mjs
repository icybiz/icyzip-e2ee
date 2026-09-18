// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
// The active-relay and metadata attacks from v0.2 now must be rejected.
import assert from "node:assert/strict";
import test from "node:test";
import { client, connect, paired } from "./endpoint.mjs";

test("a substituting relay without the fragment secret cannot establish either encrypted leg", async () => {
    const primary = client();
    const secondary = client({ role: "secondary", secret: primary.secret });
    const relayTowardPrimary = client({ role: "secondary" });
    const relayTowardSecondary = client();
    await assert.rejects(primary.session.acceptPublicMessage(await relayTowardPrimary.session.publicMessage()));
    await assert.rejects(secondary.session.acceptPublicMessage(await relayTowardSecondary.session.publicMessage()));
    assert.equal(primary.session.ready(), false);
    assert.equal(secondary.session.ready(), false);
    await assert.rejects(primary.session.encryptText("synthetic confidential message", 1, "primary"));
    await connect(primary, secondary);
    const encrypted = await primary.session.encryptText("legitimate retry", 2, "primary");
    assert.equal((await secondary.session.decryptText(encrypted)).text, "legitimate retry");
});

test("adding relay-controlled revision and origin cannot alter an authenticated text update", async () => {
    const { primary, secondary } = await paired();
    const payload = await primary.session.encryptText("unchanged plaintext", 4503599627370497, "original-origin");
    const envelope = JSON.parse(payload);
    assert.deepEqual(Object.keys(envelope).sort(), ["alg", "c", "n", "v"]);
    envelope.t = Number.MAX_SAFE_INTEGER;
    envelope.o = "relay-controlled-origin";
    await assert.rejects(secondary.session.decryptText(JSON.stringify(envelope)));
    const accepted = await secondary.session.decryptText(payload);
    assert.equal(accepted.text, "unchanged plaintext");
    assert.equal(accepted.updatedAt, 4503599627370497);
    assert.equal(accepted.origin, "original-origin");
});
