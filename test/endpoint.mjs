// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
// Test-only browser state adapter. It does not implement any cryptography.
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const snapshot = await readFile(new URL("../src/snapshot.js", import.meta.url), "utf8");

export function endpoint({ id = "synthetic-review-pair", role = "primary", saved = new Map() } = {})
{
    const sent = [];
    const ui = [];
    const received = [];
    const cancelled = [];
    let download = null;
    const sandbox = {
        window: { crypto: webcrypto, TextEncoder, TextDecoder },
        TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, URL, Blob,
        atob, btoa,
        pairId: id,
        i: role === "primary" ? null : id,
        aid: role === "primary" ? "synthetic-resume-capability" : null,
        requestedResumePair: null,
        publicBaseUrl: "https://icyzip.com",
        localTextUpdatedOrigin: "synthetic-" + role,
        state: { incoming: null, outgoing: null },
        fileMaxBytes: 25 * 1024 * 1024,
        fileChunkBytes: 65536,
        controlsAvailable: () => true,
        safeDownloadName: () => "synthetic.bin",
        clearDownload() { download = null; },
        setFileProgress() {},
        setFileStatus(status) { ui.push({ fileStatus: status }); },
        // Model the application's cleanup callback; rejection decisions and
        // all decryption remain in the verbatim source sections.
        cancelActiveTransfer(notifyPeer, status) {
            cancelled.push({ notifyPeer, status });
            sandbox.state.incoming = null;
            sandbox.state.outgoing = null;
        },
        showDownload(name, blob) { download = { name, blob }; received.push(download); },
        location: { hash: "", pathname: "/", search: "", href: "https://icyzip.com/" },
        document: { title: "test" },
        history: { replaceState() {} },
        sessionStorage: {
            getItem(key) { return saved.has(key) ? saved.get(key) : null; },
            setItem(key, value) { saved.set(String(key), String(value)); },
            removeItem(key) { saved.delete(key); }
        },
        sendCommand(cmd, args) { sent.push({ cmd, args }); return true; },
        sendClientDiagnostic(code) { ui.push({ diagnostic: code }); },
        setStatusMessage(status) { ui.push({ status }); },
        setUiState(state) { ui.push({ state }); }
    };
    const context = vm.createContext(sandbox);
    vm.runInContext(snapshot, context, { filename: "src/snapshot.js" });
    return {
        saved, sent, ui, received, cancelled,
        get download() { return download; },
        async publicKey() { return (await context.ensureTextE2eeKeyPair(id)).publicKey; },
        receive: key => context.receiveTextE2eePublic(key),
        sendPublic: () => context.sendTextE2eePublic(),
        ready: () => context.textE2eeReady(),
        pairUrl: () => context.pairUrlForId(id),
        encrypt: (text, revision = 4503599627370497, origin = "synthetic-origin") => context.encryptTextPayload(text, revision, origin),
        decrypt: payload => context.decryptTextPayload(payload),
        encryptFile: (bytes, transfer = "synthetic-transfer", sequence = 0) => context.encryptFileChunk(bytes, transfer, sequence),
        decryptFile: (bytes, transfer = "synthetic-transfer", sequence = 0) => context.decryptFileChunk(bytes, transfer, sequence),
        textKey: () => context.textE2eeKeyForPair(id),
        fileKey: () => context.fileE2eeKeyForPair(id),
        offer: args => context.handleFileOffer(args),
        chunk: args => context.handleFileChunk(args),
        binary: bytes => context.handleBinary(bytes),
        done: args => context.handleFileDone(args),
        clear: () => context.clearTextE2eeSecretForId(id)
    };
}

export async function paired(id = "synthetic-review-pair")
{
    const primary = endpoint({ id });
    const secondary = endpoint({ id, role: "secondary" });
    const [a, b] = await Promise.all([primary.publicKey(), secondary.publicKey()]);
    await Promise.all([primary.receive(b), secondary.receive(a)]);
    return { primary, secondary };
}
