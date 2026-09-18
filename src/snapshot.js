// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
// Review snapshot: exact excerpts from IcyZip's browser client.
// These functions require application state or the supplied test adapter.
// See THREAT-MODEL.md before relying on this protocol.

// BEGIN exact source section: module-integration
function textE2eeSupported()
{
    return !!(window.IcyZipE2EE && window.crypto && window.crypto.subtle
        && window.crypto.getRandomValues && window.TextEncoder && window.TextDecoder);
}

function readPairSecret(id)
{
    if (pairSecretId === id && window.IcyZipE2EE.validSecret(pairSecret)) return pairSecret;
    try
    {
        const saved = sessionStorage.getItem(window.IcyZipE2EE.SECRET_PREFIX + id);
        return window.IcyZipE2EE.validSecret(saved) ? saved : null;
    }
    catch (error) { return null; }
}

function usePairSecret(id, secret)
{
    if (!id || !window.IcyZipE2EE.validSecret(secret)) return false;
    if (pairSecretId !== id || pairSecret !== secret) resetTextE2eeSecret();
    pairSecretId = id;
    pairSecret = secret;
    try { sessionStorage.setItem(window.IcyZipE2EE.SECRET_PREFIX + id, secret); }
    catch (error) {}
    return true;
}

function ensureTextE2eeSession(id)
{
    const secret = readPairSecret(id);
    if (!id || !secret || !textE2eeSupported()) throw new Error("Pair key missing");
    if (!e2eeSession || e2eeSessionId !== id)
    {
        let storage = null;
        try { storage = sessionStorage; } catch (error) {}
        e2eeSession = window.IcyZipE2EE.createSession({
            pairId: id, role: isPrimaryView() ? "primary" : "secondary",
            secret, crypto: window.crypto, storage
        });
        e2eeSessionId = id;
    }
    return e2eeSession;
}

function clearUrlFragment()
{
    if (!location.hash) return;
    try { history.replaceState(null, document.title, location.pathname + location.search); }
    catch (error) {}
}

function clearPairIdFromUrl()
{
    try
    {
        const next = new URL(location.href);
        next.searchParams.delete("i");
        history.replaceState(null, document.title, next.pathname + next.search + next.hash);
    }
    catch (error) {}
}

function clearTextE2eeDerivedSecret()
{
    if (e2eeSession) e2eeSession.resetPeer();
}

function resetTextE2eeSecret()
{
    if (e2eeSession) e2eeSession.close();
    e2eeSession = null;
    e2eeSessionId = "";
    pairSecret = null;
    pairSecretId = "";
    textE2eeReadyCallbacks = [];
}

function clearTextE2eeSecretForId(id)
{
    if (!id) return;
    try
    {
        for (const prefix of [window.IcyZipE2EE.SECRET_PREFIX, window.IcyZipE2EE.KEYPAIR_PREFIX,
            "icyzip.textE2ee.v1:", "icyzip.textE2ee.ecdh.v2:"])
            sessionStorage.removeItem(prefix + id);
    }
    catch (error) {}
    if (pairSecretId === id || e2eeSessionId === id) resetTextE2eeSecret();
}

function textE2eeReady()
{
    return !!(e2eeSession && e2eeSessionId === currentTextE2eePairId() && e2eeSession.ready());
}

function onTextE2eeReady(callback)
{
    if (typeof callback !== "function") return;
    if (textE2eeReady()) callback();
    else textE2eeReadyCallbacks.push(callback);
}

function notifyTextE2eeReady()
{
    if (!textE2eeReady()) return;
    const callbacks = textE2eeReadyCallbacks;
    textE2eeReadyCallbacks = [];
    callbacks.forEach(function (callback) { callback(); });
}

function currentTextE2eePairId()
{
    return pairId || i || (requestedResumePair && requestedResumePair.id) || "";
}

function pairUrlForId(id)
{
    const secret = id && readPairSecret(id);
    return secret ? publicBaseUrl + "/?i=" + encodeURIComponent(id)
        + window.IcyZipE2EE.fragmentForSecret(secret) : "";
}

function showTextE2eeFailure(state, diagnosticReason)
{
    const status = state === "key-mismatch" ? "Pair key mismatch" : "Pair key missing";
    sendClientDiagnostic(diagnosticReason || state);
    setStatusMessage(status);
    setUiState(state, status);
}

async function receiveTextE2eePublic(message)
{
    const session = ensureTextE2eeSession(currentTextE2eePairId());
    const accepted = await session.acceptPublicMessage(message);
    if (accepted && session === e2eeSession) notifyTextE2eeReady();
    return accepted;
}

async function sendTextE2eePublic()
{
    const id = currentTextE2eePairId();
    const targetId = isPrimaryView() ? aid : i;
    if (!id || !targetId) return false;
    try
    {
        const session = ensureTextE2eeSession(id);
        const message = await session.publicMessage();
        return session === e2eeSession && sendCommand("textPub", [targetId].concat(message));
    }
    catch (error)
    {
        showTextE2eeFailure("key-missing", "e2ee-unsupported");
        return false;
    }
}

async function encryptTextPayload(text, updatedAt, origin)
{
    const revision = normalizedTextUpdatedAt(updatedAt) || TEXT_REVISION_BASE;
    const sender = typeof origin === "string" && origin ? origin : localTextUpdatedOrigin;
    return ensureTextE2eeSession(currentTextE2eePairId()).encryptText(String(text || ""), revision, sender);
}

async function decryptTextPayload(payload)
{
    return ensureTextE2eeSession(currentTextE2eePairId()).decryptText(payload);
}

async function encryptFileChunk(buffer, transferId, seq)
{
    return ensureTextE2eeSession(currentTextE2eePairId()).encryptFile(arrayBufferCopy(buffer), transferId, seq);
}

async function decryptFileChunk(buffer, transferId, seq)
{
    return ensureTextE2eeSession(currentTextE2eePairId()).decryptFile(arrayBufferCopy(buffer), transferId, seq);
}

function isPrimaryView()
{
    return i == null;
}

// END exact source section: module-integration

// BEGIN exact source section: file-buffers
function fileByteLength(data)
{
    if (data instanceof ArrayBuffer)
    {
        return data.byteLength;
    }
    if (ArrayBuffer.isView(data))
    {
        return data.byteLength;
    }
    return 0;
}

function arrayBufferCopy(data)
{
    if (data instanceof ArrayBuffer)
    {
        return data.slice(0);
    }
    if (ArrayBuffer.isView(data))
    {
        return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    }
    return new ArrayBuffer(0);
}

function isBinaryMessageData(data)
{
    return data instanceof ArrayBuffer || ArrayBuffer.isView(data);
}

function readBlobAsArrayBuffer(blob)
{
    return new Promise(function (resolve, reject)
    {
        const reader = new FileReader();
        reader.onload = function () { resolve(reader.result); };
        reader.onerror = function () { reject(reader.error || new Error("file read failed")); };
        reader.readAsArrayBuffer(blob);
    });
}

function safeDownloadName(value)
{
    const name = String(value || "")
        .replace(/[\\\/]/g, " ")
        .replace(/[\x00-\x1f\x7f]/g, " ")
        .trim()
        .slice(0, 180);
    return name || "download";
}

// END exact source section: file-buffers

// BEGIN exact source section: file-controller
function createFileTransferController()
{
    const input = document.getElementById("fileInput");
    const sendButton = document.getElementById("fileActionSend");
    const cancelButton = document.getElementById("fileActionCancel");
    const progress = document.getElementById("fileProgress");
    const status = document.getElementById("fileStatus");
    const download = document.getElementById("fileReceivedDownload");
    const state = {
        selectedFile: null,
        outgoing: null,
        incoming: null,
        pendingOffer: null,
        receivedUrl: ""
    };

    function controlsAvailable()
    {
        return fileTransferRuntimeEnabled && input && sendButton && cancelButton && progress && status && download;
    }

    function setFileStatus(text)
    {
        if (status)
        {
            const key = textKey(text);
            if (key)
            {
                status.dataset.i18nKey = key;
                status.textContent = t(key);
            }
            else
            {
                delete status.dataset.i18nKey;
                status.textContent = text || "";
            }
        }
        updateFileActionButtons();
    }

    function updateFileActionButtons()
    {
        const available = Boolean(fileTransferRuntimeEnabled && input && sendButton && cancelButton && progress && status && download);
        const active = Boolean(state.outgoing || state.incoming || state.pendingOffer);
        if (sendButton)
        {
            sendButton.disabled = !available || active;
            sendButton.setAttribute("aria-disabled", sendButton.disabled ? "true" : "false");
        }
        if (cancelButton)
        {
            cancelButton.disabled = !available || !active;
            cancelButton.setAttribute("aria-disabled", cancelButton.disabled ? "true" : "false");
        }
    }

    function setFileProgress(value, max)
    {
        if (!progress)
        {
            return;
        }
        progress.max = Math.max(1, Number(max) || 100);
        progress.value = Math.max(0, Math.min(progress.max, Number(value) || 0));
    }

    function clearDownload()
    {
        if (state.receivedUrl)
        {
            URL.revokeObjectURL(state.receivedUrl);
        }
        state.receivedUrl = "";
        if (download)
        {
            download.hidden = true;
            download.removeAttribute("href");
            download.removeAttribute("download");
            download.textContent = t("action.download");
        }
    }

    function showDownload(name, blob)
    {
        clearDownload();
        state.receivedUrl = URL.createObjectURL(blob);
        download.href = state.receivedUrl;
        download.download = safeDownloadName(name);
        download.textContent = t("action.download");
        download.hidden = false;
    }

    function activeTransferId()
    {
        if (state.outgoing)
        {
            return state.outgoing.id;
        }
        if (state.incoming)
        {
            return state.incoming.id;
        }
        if (state.pendingOffer) return state.pendingOffer.id;
        return "";
    }

    function clearActiveTransfer(text)
    {
        state.outgoing = null;
        state.incoming = null;
        state.pendingOffer = null;
        setFileProgress(0, 100);
        setFileStatus(text || "Ready");
    }

    function cancelActiveTransfer(notifyPeer, text)
    {
        const transferId = activeTransferId();
        if (notifyPeer && transferId)
        {
            sendCommand("fileCancel", [transferId, "cancelled"]);
        }
        clearActiveTransfer(text || "Cancelled");
    }

    function selectedFileLabel(file)
    {
        if (!file)
        {
            return "file.ready";
        }
        return safeDownloadName(file.name) + " selected";
    }

    function filePlainChunkSize(file)
    {
        const maxPlainChunk = Math.max(1, fileChunkBytes - FILE_E2EE_FRAME_OVERHEAD);
        return Math.max(1, Math.min(maxPlainChunk, file.size));
    }

    function encryptedWireSize(fileSize, plainChunkSize)
    {
        const chunks = Math.ceil(fileSize / plainChunkSize);
        return fileSize + chunks * FILE_E2EE_FRAME_OVERHEAD;
    }

    function updateSelectedFile()
    {
        if (!controlsAvailable())
        {
            return;
        }
        state.selectedFile = input.files && input.files.length > 0 ? input.files[0] : null;
        if (!state.outgoing && !state.incoming && !state.pendingOffer)
        {
            setFileProgress(0, 100);
            setFileStatus(selectedFileLabel(state.selectedFile));
        }
    }

    async function sendNextChunk(transfer)
    {
        if (!state.outgoing || state.outgoing.id !== transfer.id)
        {
            return;
        }
        if (transfer.offset >= transfer.file.size)
        {
            sendCommand("fileDone", [transfer.id, String(transfer.totalChunks), String(transfer.wireSize)]);
            setFileStatus("Finishing");
            return;
        }
        const end = Math.min(transfer.offset + transfer.chunkSize, transfer.file.size);
        const buffer = await readBlobAsArrayBuffer(transfer.file.slice(transfer.offset, end));
        const encryptedBuffer = await encryptFileChunk(buffer, transfer.id, transfer.seq);
        if (!state.outgoing || state.outgoing.id !== transfer.id)
        {
            return;
        }
        transfer.pendingPlainBytes = fileByteLength(buffer);
        transfer.pendingBytes = fileByteLength(encryptedBuffer);
        transfer.awaitingAck = true;
        if (!sendCommand("fileChunk", [transfer.id, String(transfer.seq), String(transfer.pendingBytes)])
            || !sendBinaryFrame(encryptedBuffer))
        {
            clearActiveTransfer("Connection lost");
            return;
        }
        setFileStatus("Sending");
    }

    async function sendSelectedFile()
    {
        if (!controlsAvailable())
        {
            return;
        }
        clearDownload();
        updateSelectedFile();
        const file = state.selectedFile;
        if (!file)
        {
            setFileStatus("Choose a file");
            return;
        }
        if (file.size <= 0)
        {
            setFileStatus("Empty file");
            return;
        }
        if (file.size > fileMaxBytes)
        {
            setFileStatus("File too large");
            return;
        }
        if (document.body.dataset.wsState !== "connected")
        {
            setFileStatus("Peer offline");
            return;
        }
        if (!textE2eeReady())
        {
            setFileStatus("Transfer failed");
            return;
        }
        if (state.outgoing || state.incoming || state.pendingOffer)
        {
            setFileStatus("Transfer active");
            return;
        }
        const chunkSize = filePlainChunkSize(file);
        const wireSize = encryptedWireSize(file.size, chunkSize);
        if (wireSize <= file.size)
        {
            setFileStatus("Transfer failed");
            return;
        }
        const transfer = {
            id: newTransferId(),
            file,
            chunkSize,
            wireSize,
            encryptedChunkSize: chunkSize + FILE_E2EE_FRAME_OVERHEAD,
            totalChunks: Math.ceil(file.size / chunkSize),
            offset: 0,
            seq: 0,
            pendingBytes: 0,
            pendingPlainBytes: 0,
            awaitingAck: false
        };
        state.outgoing = transfer;
        setFileProgress(0, file.size);
        setFileStatus("Waiting for peer");
        const session = ensureTextE2eeSession(currentTextE2eePairId());
        const offer = await session.signFileOffer([
            transfer.id,
            safeDownloadName(file.name),
            String(file.size),
            file.type || "application/octet-stream",
            String(transfer.encryptedChunkSize),
            String(wireSize),
            "e2ee-v3"
        ]);
        if (state.outgoing === transfer && session === e2eeSession)
            sendCommand("fileOffer", offer);
    }

    async function handleFileOffer(args)
    {
        if (!controlsAvailable())
        {
            sendCommand("fileReject", [args[0] || "", "disabled"]);
            return;
        }
        const transferId = args[0] || "";
        const name = safeDownloadName(args[1]);
        const size = Number(args[2]);
        const mime = args[3] || "application/octet-stream";
        const chunkSize = Number(args[4]);
        const wireSize = Number(args[5]);
        if (state.outgoing || state.incoming || state.pendingOffer)
        {
            sendCommand("fileReject", [transferId, "busy"]);
            return;
        }
        if (args[6] !== "e2ee-v3" || !textE2eeReady())
        {
            sendCommand("fileReject", [transferId, "encryption-required"]);
            setFileStatus("file.encryptionRequired");
            return;
        }
        if (!transferId || !Number.isSafeInteger(size) || size <= 0 || size > fileMaxBytes
            || !Number.isSafeInteger(chunkSize) || chunkSize <= FILE_E2EE_FRAME_OVERHEAD || chunkSize > fileChunkBytes
            || !Number.isSafeInteger(wireSize) || wireSize <= size)
        {
            sendCommand("fileReject", [transferId, "invalid"]);
            return;
        }
        const pending = { id: transferId };
        state.pendingOffer = pending;
        updateFileActionButtons();
        const session = ensureTextE2eeSession(currentTextE2eePairId());
        let verified = false;
        try { verified = await session.verifyFileOffer(args); }
        catch (error) {}
        if (state.pendingOffer !== pending) return;
        state.pendingOffer = null;
        if (!verified || session !== e2eeSession || !textE2eeReady())
        {
            sendCommand("fileReject", [transferId, "encryption-required"]);
            setFileStatus("file.encryptionRequired");
            return;
        }
        clearDownload();
        state.incoming = {
            id: transferId,
            name,
            size,
            wireSize,
            mime,
            chunkSize,
            expectedSeq: 0,
            receivedBytes: 0,
            receivedPlainBytes: 0,
            parts: [],
            pending: null
        };
        setFileProgress(0, size);
        setFileStatus("Receiving");
        sendCommand("fileAccept", [transferId]);
    }

    function handleFileAccept(args)
    {
        const transferId = args[0] || "";
        if (!state.outgoing || state.outgoing.id !== transferId)
        {
            return;
        }
        sendNextChunk(state.outgoing).catch(function ()
        {
            cancelActiveTransfer(true, "Read failed");
        });
    }

    function handleFileChunk(args)
    {
        const transferId = args[0] || "";
        const seq = Number(args[1]);
        const byteLength = Number(args[2]);
        const transfer = state.incoming;
        if (!transfer || transfer.id !== transferId || !Number.isInteger(seq) || seq !== transfer.expectedSeq
            || !Number.isInteger(byteLength) || byteLength <= 0 || byteLength > transfer.chunkSize
            || transfer.receivedBytes + byteLength > transfer.wireSize)
        {
            cancelActiveTransfer(true, "Transfer failed");
            return;
        }
        transfer.pending = {
            seq,
            byteLength
        };
        setFileStatus("Receiving");
    }

    function handleBinary(data)
    {
        const transfer = state.incoming;
        if (!transfer || !transfer.pending)
        {
            return;
        }
        const byteLength = fileByteLength(data);
        if (byteLength !== transfer.pending.byteLength)
        {
            cancelActiveTransfer(true, "Transfer failed");
            return;
        }
        const pending = transfer.pending;
        decryptFileChunk(data, transfer.id, pending.seq).then(function (plain)
        {
            const current = state.incoming;
            if (!current || current.id !== transfer.id || current.pending !== pending)
            {
                return;
            }
            const plainBytes = fileByteLength(plain);
            if (plainBytes <= 0 || current.receivedPlainBytes + plainBytes > current.size)
            {
                cancelActiveTransfer(true, "Transfer failed");
                return;
            }
            current.parts.push(arrayBufferCopy(plain));
            current.receivedBytes += byteLength;
            current.receivedPlainBytes += plainBytes;
            current.expectedSeq += 1;
            current.pending = null;
            setFileProgress(current.receivedPlainBytes, current.size);
            sendCommand("fileChunkAck", [current.id, String(pending.seq)]);
        }).catch(function ()
        {
            cancelActiveTransfer(true, "Transfer failed");
        });
    }

    function handleFileChunkAck(args)
    {
        const transferId = args[0] || "";
        const seq = Number(args[1]);
        const transfer = state.outgoing;
        if (!transfer || transfer.id !== transferId || seq !== transfer.seq || !transfer.awaitingAck)
        {
            return;
        }
        transfer.offset += transfer.pendingPlainBytes;
        transfer.seq += 1;
        transfer.pendingBytes = 0;
        transfer.pendingPlainBytes = 0;
        transfer.awaitingAck = false;
        setFileProgress(transfer.offset, transfer.file.size);
        sendNextChunk(transfer).catch(function ()
        {
            cancelActiveTransfer(true, "Read failed");
        });
    }

    function handleFileDone(args)
    {
        const transferId = args[0] || "";
        const totalBytes = Number(args[2]);
        const transfer = state.incoming;
        if (!transfer || transfer.id !== transferId || transfer.pending || totalBytes !== transfer.wireSize
            || transfer.receivedBytes !== transfer.wireSize || transfer.receivedPlainBytes !== transfer.size)
        {
            cancelActiveTransfer(true, "Transfer failed");
            return;
        }
        const blob = new Blob(transfer.parts, { type: transfer.mime || "application/octet-stream" });
        showDownload(transfer.name, blob);
        sendCommand("fileReceived", [transfer.id]);
        state.incoming = null;
        setFileProgress(totalBytes, transfer.size);
        setFileStatus("Received");
    }

    function handleFileReceived(args)
    {
        const transferId = args[0] || "";
        if (!state.outgoing || state.outgoing.id !== transferId)
        {
            return;
        }
        state.outgoing = null;
        setFileProgress(100, 100);
        setFileStatus("Sent");
    }

    function handleFileFinishedByPeer(text)
    {
        clearActiveTransfer(text);
    }

    function handleCommand(cmd, args)
    {
        switch (cmd)
        {
            case "fileOffer":
                handleFileOffer(args);
                return true;
            case "fileAccept":
                handleFileAccept(args);
                return true;
            case "fileChunk":
                handleFileChunk(args);
                return true;
            case "fileChunkAck":
                handleFileChunkAck(args);
                return true;
            case "fileDone":
                handleFileDone(args);
                return true;
            case "fileReceived":
                handleFileReceived(args);
                return true;
            case "fileReject":
                handleFileFinishedByPeer("Rejected");
                return true;
            case "fileCancel":
                handleFileFinishedByPeer("Cancelled");
                return true;
            case "fileError":
                handleFileFinishedByPeer("Transfer failed");
                return true;
            default:
                return false;
        }
    }

    function bind()
    {
        if (!controlsAvailable())
        {
            setFileProgress(0, 100);
            setFileStatus(fileTransferRuntimeEnabled ? "Unavailable" : "Disabled");
            return;
        }
        input.onchange = updateSelectedFile;
        sendButton.onclick = function ()
        {
            sendSelectedFile().catch(function ()
            {
                cancelActiveTransfer(true, "Read failed");
            });
        };
        cancelButton.onclick = function ()
        {
            cancelActiveTransfer(true, "Cancelled");
        };
        setFileProgress(0, 100);
        setFileStatus(selectedFileLabel(state.selectedFile));
    }

    return {
        bind,
        handleCommand,
        handleBinary,
        cancelLocal: function (text)
        {
            clearActiveTransfer(text || "Ready");
        }
    };
}

// END exact source section: file-controller
