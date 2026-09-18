// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { extract, sha256 } from "../tools/snapshot.mjs";

test("snapshot and every verbatim section match the recorded hashes", async () => {
    const snapshot = await readFile(new URL("../src/snapshot.js", import.meta.url), "utf8");
    const provenance = JSON.parse(await readFile(new URL("../PROVENANCE.json", import.meta.url), "utf8"));
    const moduleSource = await readFile(new URL("../src/e2ee.js", import.meta.url), "utf8");
    assert.equal(provenance.format, 2);
    assert.equal(sha256(moduleSource), provenance.module.sha256);
    assert.equal(Buffer.byteLength(moduleSource), provenance.module.bytes);
    assert.equal(sha256(snapshot), provenance.snapshotSha256);
    assert.equal(provenance.sections.length, 3);
    for (const section of provenance.sections)
    {
        const start = "// BEGIN exact source section: " + section.name + "\n";
        const end = "// END exact source section: " + section.name + "\n";
        const body = snapshot.slice(snapshot.indexOf(start) + start.length, snapshot.indexOf(end));
        assert.equal(Buffer.byteLength(body), section.bytes);
        assert.equal(sha256(body), section.sha256);
    }
});

test("the exporter preserves complete module bytes and rejects missing or duplicate integration boundaries", async () => {
    const provenance = JSON.parse(await readFile(new URL("../PROVENANCE.json", import.meta.url), "utf8"));
    const moduleSource = "// synthetic module\n";
    const synthetic = provenance.sections.map(part => part.startAnchor + "\nsynthetic body\n" + part.endAnchor + "\n").join("\n");
    assert.equal(extract(synthetic, moduleSource).moduleSource, moduleSource);
    assert.throws(() => extract(synthetic.replace(provenance.sections[0].startAnchor, "absent"), moduleSource));
    assert.throws(() => extract(synthetic + provenance.sections[0].startAnchor, moduleSource));
});
