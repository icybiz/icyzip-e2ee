// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
// This tool reads one explicit source and emits a patch or verifies the snapshot.
// It never edits files, accesses credentials, or traverses the project tree.
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const ranges = [
    ["constants", "const TEXT_E2EE_STORAGE_PREFIX =", "const icyzipConfig ="],
    ["revision", "const TEXT_REVISION_BASE =", "const HTTP_FALLBACK_CONNECT_TIMEOUT_MS ="],
    ["state", "let textE2eeSecret =", "let sentClientDiagnostics ="],
    ["revision-validation", "function normalizedTextUpdatedAt(value)", "function nextTextRevision(value)"],
    ["cryptography-and-lifecycle", "function bytesToBase64Url(bytes)", "function readStoredPair(storage, key)"],
    ["buffer-copy", "function fileByteLength(data)", "function isBinaryMessageData(data)"],
    ["file-offer-acceptance", "    function handleFileOffer(args)", "    function handleFileAccept(args)"],
    ["file-frame-acceptance", "    function handleFileChunk(args)", "    function handleFileChunkAck(args)"],
    ["file-completion", "    function handleFileDone(args)", "    function handleFileReceived(args)"]
];
const banner = "// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0\n"
    + "// Review snapshot: exact excerpts from IcyZip's browser client.\n"
    + "// These functions require application state or the supplied test adapter.\n"
    + "// See THREAT-MODEL.md before relying on this protocol.\n\n";

export function sha256(value)
{
    return createHash("sha256").update(value).digest("hex");
}

export function extract(source)
{
    const sections = ranges.map(function ([name, startAnchor, endAnchor])
    {
        const start = source.indexOf(startAnchor);
        const end = source.indexOf(endAnchor, start + startAnchor.length);
        if (start < 0 || end < start || source.indexOf(startAnchor, start + 1) !== -1
            || source.indexOf(endAnchor, end + 1) !== -1)
        {
            throw new Error("Missing or ambiguous source boundary: " + name);
        }
        const code = source.slice(start, end);
        return {
            name,
            code,
            startAnchor,
            endAnchor,
            firstLine: source.slice(0, start).split("\n").length,
            bytes: Buffer.byteLength(code),
            sha256: sha256(code)
        };
    });
    const snapshot = banner + sections.map(function (part)
    {
        return "// BEGIN exact source section: " + part.name + "\n"
            + part.code + "// END exact source section: " + part.name + "\n\n";
    }).join("").slice(0, -1);
    return {
        snapshot,
        provenance: {
            format: 1,
            sourcePath: "client/src/js/view/client_wsscript.js",
            sourceSha256: sha256(source),
            snapshotSha256: sha256(snapshot),
            statement: "Section bodies are verbatim. The full application and relay are not included.",
            sections: sections.map(function ({ code, ...part }) { return part; })
        }
    };
}

async function main(args)
{
    let sourcePath;
    let sourceUrl;
    let mode;
    for (let index = 0; index < args.length; index += 1)
    {
        const arg = args[index];
        if (arg === "--source" && !sourcePath) sourcePath = args[++index];
        else if (arg === "--url" && !sourceUrl) sourceUrl = args[++index];
        else if ((arg === "--check" || arg === "--patch") && !mode) mode = arg;
        else throw new Error("Usage: snapshot.mjs (--source FILE | --url URL) (--check | --patch)");
    }
    if (!mode || Boolean(sourcePath) === Boolean(sourceUrl))
    {
        throw new Error("Choose exactly one source and one mode.");
    }
    let source;
    if (sourceUrl)
    {
        const url = new URL(sourceUrl);
        if (url.protocol !== "https:" || url.hostname !== "icyzip.com"
            || url.pathname !== "/js/view/client_wsscript.js" || url.username || url.password
            || url.hash || url.search)
        {
            throw new Error("Remote checks are limited to the public IcyZip browser asset.");
        }
        if (mode !== "--check") throw new Error("Remote sources can only be checked.");
        const response = await fetch(url, {
            headers: { "X-IcyZip-Test-Traffic": "e2ee-source-review" },
            redirect: "error",
            signal: AbortSignal.timeout(30000)
        });
        if (!response.ok) throw new Error("Public asset HTTP status: " + response.status);
        source = await response.text();
    }
    else source = await readFile(resolve(sourcePath), "utf8");
    if (Buffer.byteLength(source) > 1024 * 1024) throw new Error("Source exceeds 1 MiB.");
    const generated = extract(source);
    if (mode === "--patch")
    {
        const files = [
            ["src/snapshot.js", generated.snapshot],
            ["PROVENANCE.json", JSON.stringify(generated.provenance, null, 2) + "\n"]
        ];
        let patch = "*** Begin Patch\n";
        for (const [name, content] of files)
        {
            const target = resolve(root, name);
            let previous;
            try
            {
                previous = await readFile(target, "utf8");
            }
            catch (error)
            {
                if (error.code !== "ENOENT") throw error;
            }
            if (previous === content) continue;
            if (previous === undefined) patch += "*** Add File: " + target + "\n";
            else patch += "*** Update File: " + target + "\n@@\n"
                + previous.split("\n").slice(0, -1).map(line => "-" + line).join("\n") + "\n";
            patch += content.split("\n").slice(0, -1).map(line => "+" + line).join("\n") + "\n";
        }
        process.stdout.write(patch + "*** End Patch\n");
        return;
    }
    const expected = await readFile(resolve(root, "src/snapshot.js"), "utf8");
    const recorded = JSON.parse(await readFile(resolve(root, "PROVENANCE.json"), "utf8"));
    if (sha256(expected) !== recorded.snapshotSha256 || generated.snapshot !== expected)
    {
        throw new Error("E2EE snapshot differs from the supplied application source or provenance.");
    }
    console.log(JSON.stringify({
        result: "exact-e2ee-sections-match",
        source: sourceUrl ? "public-asset" : "local-file",
        sections: generated.provenance.sections.length,
        snapshotSha256: recorded.snapshotSha256,
        fullSourceMatchesRecordedFile: generated.provenance.sourceSha256 === recorded.sourceSha256
    }));
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url)
{
    main(process.argv.slice(2)).catch(function (error)
    {
        console.error(error.message);
        process.exitCode = 1;
    });
}
