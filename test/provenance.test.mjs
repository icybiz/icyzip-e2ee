// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { extract, sha256, verifySource } from "../tools/snapshot.mjs";

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

async function reviewFixture()
{
    const snapshot = await readFile(new URL("../src/snapshot.js", import.meta.url), "utf8");
    const moduleSource = await readFile(new URL("../src/e2ee.js", import.meta.url), "utf8");
    const provenance = JSON.parse(await readFile(new URL("../PROVENANCE.json", import.meta.url), "utf8"));
    const source = provenance.sections.map(function (section)
    {
        const start = "// BEGIN exact source section: " + section.name + "\n";
        const end = "// END exact source section: " + section.name + "\n";
        const body = snapshot.slice(snapshot.indexOf(start) + start.length, snapshot.indexOf(end));
        return body + section.endAnchor + " {}\n\n";
    }).join("");
    const generated = extract(source, moduleSource);
    assert.equal(generated.snapshot, snapshot);
    return { source, moduleSource, snapshot, recorded: generated.provenance };
}

test("source checks report unrelated application edits and moved integration without rejecting identical reviewed bytes", async () => {
    const { source, moduleSource, snapshot, recorded } = await reviewFixture();
    const check = value => verifySource(extract(value, moduleSource), snapshot, moduleSource, recorded);
    assert.deepEqual(check(source), {
        fullSourceMatchesRecordedFile: true,
        integrationLocationsMatchRecordedFile: true
    });
    assert.deepEqual(check(source + "// unrelated UI update\n"), {
        fullSourceMatchesRecordedFile: false,
        integrationLocationsMatchRecordedFile: true
    });
    assert.deepEqual(check("// unrelated UI update\n" + source), {
        fullSourceMatchesRecordedFile: false,
        integrationLocationsMatchRecordedFile: false
    });
});

test("source checks still reject every changed integration section, module bytes and security provenance", async () => {
    const { source, moduleSource, snapshot, recorded } = await reviewFixture();
    const mismatch = { message: "E2EE snapshot differs from the supplied application source or provenance." };
    for (const section of recorded.sections)
    {
        const bodyChanged = source.replace(section.startAnchor, section.startAnchor + "\n/* changed body */");
        assert.throws(() => verifySource(extract(bodyChanged, moduleSource), snapshot, moduleSource, recorded), mismatch);
    }
    assert.throws(() => verifySource(extract(source, moduleSource + "\n"), snapshot, moduleSource, recorded), mismatch);
    const generated = extract(source, moduleSource);
    const wrongBytes = structuredClone(recorded);
    wrongBytes.module.bytes += 1;
    assert.throws(() => verifySource(generated, snapshot, moduleSource, wrongBytes), mismatch);
    const wrongHash = structuredClone(recorded);
    wrongHash.sections[0].sha256 = "0".repeat(64);
    assert.throws(() => verifySource(generated, snapshot, moduleSource, wrongHash), mismatch);
    const wrongAnchor = structuredClone(recorded);
    wrongAnchor.sections[1].endAnchor = "function wrongBoundary()";
    assert.throws(() => verifySource(generated, snapshot, moduleSource, wrongAnchor), mismatch);
    assert.doesNotThrow(() => verifySource(generated, snapshot, moduleSource, recorded));
});
