// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { sha256 } from "../tools/snapshot.mjs";

test("snapshot and every verbatim section match the recorded hashes", async () => {
    const snapshot = await readFile(new URL("../src/snapshot.js", import.meta.url), "utf8");
    const provenance = JSON.parse(await readFile(new URL("../PROVENANCE.json", import.meta.url), "utf8"));
    assert.equal(sha256(snapshot), provenance.snapshotSha256);
    assert.equal(provenance.sections.length, 9);
    for (const section of provenance.sections)
    {
        const start = "// BEGIN exact source section: " + section.name + "\n";
        const end = "// END exact source section: " + section.name + "\n";
        const body = snapshot.slice(snapshot.indexOf(start) + start.length, snapshot.indexOf(end));
        assert.equal(Buffer.byteLength(body), section.bytes);
        assert.equal(sha256(body), section.sha256);
    }
});
