// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
// Review snapshot: exact excerpts from IcyZip's browser client.
// These functions require application state or the supplied test adapter.
// See THREAT-MODEL.md before relying on this protocol.

// BEGIN exact source section: constants
const TEXT_E2EE_STORAGE_PREFIX = "icyzip.textE2ee.v1:";
const TEXT_E2EE_KEYPAIR_STORAGE_PREFIX = "icyzip.textE2ee.ecdh.v2:";
const TEXT_E2EE_SECRET_BYTES = 32;
const TEXT_E2EE_PUBLIC_BYTES = 65;
const TEXT_E2EE_PUBLIC_COORD_BYTES = 32;
const TEXT_E2EE_NONCE_BYTES = 12;
const TEXT_E2EE_INFO = "icyzip/text/ecdh/v2";
const TEXT_E2EE_CURVE = "P-256";
const FILE_E2EE_INFO = "icyzip/file/ecdh/v1";
const FILE_E2EE_NONCE_BYTES = 12;
const FILE_E2EE_TAG_BYTES = 16;
const FILE_E2EE_FRAME_OVERHEAD = FILE_E2EE_NONCE_BYTES + FILE_E2EE_TAG_BYTES;
// END exact source section: constants

// BEGIN exact source section: revision
const TEXT_REVISION_BASE = 4503599627370496;
// END exact source section: revision

// BEGIN exact source section: state
let textE2eeSecret = null;
let textE2eeKeyPairId = "";
let textE2eeKeyPromise = null;
let textE2eeEcdhPairId = "";
let textE2eeEcdhPairPromise = null;
let textE2eePeerPublic = "";
let textE2eeReadyCallbacks = [];
let fileE2eeKeyPairId = "";
let fileE2eeKeyPromise = null;
// END exact source section: state

// BEGIN exact source section: revision-validation
function normalizedTextUpdatedAt(value)
{
    const result = Number(value);
    return Number.isSafeInteger(result) && result > 0 ? result : 0;
}

// END exact source section: revision-validation

// BEGIN exact source section: cryptography-and-lifecycle
function bytesToBase64Url(bytes)
{
    let binary = "";
    for (let index = 0; index < bytes.length; index += 1)
    {
        binary += String.fromCharCode(bytes[index]);
    }
    let encoded = btoa(binary).split("+").join("-").split("/").join("_");
    while (encoded.endsWith("="))
    {
        encoded = encoded.slice(0, -1);
    }
    return encoded;
}

function base64UrlToBytes(value)
{
    const raw = String(value || "");
    if (!raw)
    {
        return null;
    }
    for (let index = 0; index < raw.length; index += 1)
    {
        const code = raw.charCodeAt(index);
        const isDigit = code >= 48 && code <= 57;
        const isUpper = code >= 65 && code <= 90;
        const isLower = code >= 97 && code <= 122;
        if (!isDigit && !isUpper && !isLower && raw[index] !== "-" && raw[index] !== "_")
        {
            return null;
        }
    }
    let encoded = raw.split("-").join("+").split("_").join("/");
    while (encoded.length % 4 !== 0)
    {
        encoded += "=";
    }
    try
    {
        const binary = atob(encoded);
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index += 1)
        {
            bytes[index] = binary.charCodeAt(index);
        }
        return bytes;
    }
    catch (error)
    {
        return null;
    }
}

function textE2eeSupported()
{
    return !!(window.crypto && window.crypto.subtle && window.crypto.getRandomValues && window.TextEncoder && window.TextDecoder);
}

function textE2eeStorageKey(id)
{
    return TEXT_E2EE_STORAGE_PREFIX + String(id || "");
}

function textE2eeKeyPairStorageKey(id)
{
    return TEXT_E2EE_KEYPAIR_STORAGE_PREFIX + String(id || "");
}

function validTextE2eeSecret(secret)
{
    const bytes = base64UrlToBytes(secret);
    return !!(bytes && bytes.length === TEXT_E2EE_SECRET_BYTES);
}

function validTextE2eePublicKey(publicKey)
{
    const bytes = base64UrlToBytes(publicKey);
    return !!(bytes && bytes.length === TEXT_E2EE_PUBLIC_BYTES && bytes[0] === 4);
}

function textE2eePublicKeyFromPrivateJwk(privateKey)
{
    if (
        !privateKey
        || typeof privateKey !== "object"
        || privateKey.kty !== "EC"
        || privateKey.crv !== TEXT_E2EE_CURVE
        || typeof privateKey.x !== "string"
        || typeof privateKey.y !== "string"
    )
    {
        return "";
    }
    const x = base64UrlToBytes(privateKey.x);
    const y = base64UrlToBytes(privateKey.y);
    if (!x || !y || x.length !== TEXT_E2EE_PUBLIC_COORD_BYTES || y.length !== TEXT_E2EE_PUBLIC_COORD_BYTES)
    {
        return "";
    }
    const bytes = new Uint8Array(TEXT_E2EE_PUBLIC_BYTES);
    bytes[0] = 4;
    bytes.set(x, 1);
    bytes.set(y, 1 + TEXT_E2EE_PUBLIC_COORD_BYTES);
    return bytesToBase64Url(bytes);
}

function validStoredTextE2eeKeyPair(record)
{
    return !!(
        record
        && typeof record === "object"
        && record.privateKey
        && typeof record.privateKey === "object"
        && validTextE2eePublicKey(record.publicKey)
        && textE2eePublicKeyFromPrivateJwk(record.privateKey) === record.publicKey
    );
}

function removeStoredTextE2eeKeyPair(id)
{
    try
    {
        sessionStorage.removeItem(textE2eeKeyPairStorageKey(id));
    }
    catch (error)
    {
    }
}

function readStoredTextE2eeKeyPair(id)
{
    if (!id)
    {
        return null;
    }
    try
    {
        const parsed = JSON.parse(sessionStorage.getItem(textE2eeKeyPairStorageKey(id)) || "null");
        if (validStoredTextE2eeKeyPair(parsed))
        {
            return {
                privateKey: parsed.privateKey,
                publicKey: parsed.publicKey
            };
        }
    }
    catch (error)
    {
    }
    return null;
}

function storeTextE2eeKeyPair(id, record)
{
    if (!id || !record || !record.privateKey || !validTextE2eePublicKey(record.publicKey))
    {
        return;
    }
    try
    {
        sessionStorage.setItem(textE2eeKeyPairStorageKey(id), JSON.stringify(record));
    }
    catch (error)
    {
    }
}

function importTextE2eePrivateKey(privateKey)
{
    return window.crypto.subtle.importKey(
        "jwk",
        privateKey,
        { name: "ECDH", namedCurve: TEXT_E2EE_CURVE },
        true,
        ["deriveBits"]
    );
}

function loadStoredTextE2eeKeyPair(id)
{
    const stored = readStoredTextE2eeKeyPair(id);
    if (!stored)
    {
        removeStoredTextE2eeKeyPair(id);
        return Promise.resolve(null);
    }
    return importTextE2eePrivateKey(stored.privateKey).then(function (privateKey)
    {
        return {
            privateKey,
            publicKey: stored.publicKey
        };
    }).catch(function ()
    {
        removeStoredTextE2eeKeyPair(id);
        return null;
    });
}

function generateTextE2eeKeyPair(id)
{
    return window.crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: TEXT_E2EE_CURVE },
        true,
        ["deriveBits"]
    ).then(function (keyPair)
    {
        return Promise.all([
            window.crypto.subtle.exportKey("jwk", keyPair.privateKey),
            window.crypto.subtle.exportKey("raw", keyPair.publicKey)
        ]).then(function (exported)
        {
            const record = {
                privateKey: exported[0],
                publicKey: bytesToBase64Url(new Uint8Array(exported[1]))
            };
            storeTextE2eeKeyPair(id, record);
            return {
                privateKey: keyPair.privateKey,
                publicKey: record.publicKey
            };
        });
    });
}

function ensureTextE2eeKeyPair(id)
{
    if (!id || !textE2eeSupported())
    {
        return Promise.reject(new Error("text e2ee unsupported"));
    }
    if (textE2eeEcdhPairPromise && textE2eeEcdhPairId === id)
    {
        return textE2eeEcdhPairPromise;
    }
    textE2eeEcdhPairId = id;
    textE2eeEcdhPairPromise = loadStoredTextE2eeKeyPair(id).then(function (stored)
    {
        if (stored)
        {
            return stored;
        }
        return generateTextE2eeKeyPair(id);
    });
    return textE2eeEcdhPairPromise;
}

function clearUrlFragment()
{
    if (!location.hash)
    {
        return;
    }
    try
    {
        history.replaceState(null, document.title, location.pathname + location.search);
    }
    catch (error)
    {
    }
}

function clearPairIdFromUrl()
{
    try
    {
        const next = new URL(location.href);
        next.searchParams.delete("i");
        history.replaceState(null, document.title, next.pathname + next.search + next.hash);
    }
    catch (error)
    {
    }
}

function setTextE2eeSecretForPair(id, secret)
{
    if (!id || !validTextE2eeSecret(secret))
    {
        return false;
    }
    const previousSecret = textE2eeSecret;
    textE2eeSecret = secret;
    if (textE2eeKeyPairId !== id || previousSecret !== secret)
    {
        textE2eeKeyPairId = "";
        textE2eeKeyPromise = null;
        fileE2eeKeyPairId = "";
        fileE2eeKeyPromise = null;
    }
    return true;
}

function clearTextE2eeDerivedSecret()
{
    textE2eeSecret = null;
    textE2eeKeyPairId = "";
    textE2eeKeyPromise = null;
    textE2eePeerPublic = "";
    fileE2eeKeyPairId = "";
    fileE2eeKeyPromise = null;
}

function resetTextE2eeSecret()
{
    clearTextE2eeDerivedSecret();
    textE2eeEcdhPairId = "";
    textE2eeEcdhPairPromise = null;
    textE2eeReadyCallbacks = [];
}

function clearTextE2eeSecretForId(id)
{
    if (!id)
    {
        return;
    }
    try
    {
        sessionStorage.removeItem(textE2eeStorageKey(id));
        removeStoredTextE2eeKeyPair(id);
    }
    catch (error)
    {
    }
    if (currentTextE2eePairId() === id || textE2eeKeyPairId === id)
    {
        resetTextE2eeSecret();
    }
}

function textE2eeReady()
{
    return !!(currentTextE2eePairId() && validTextE2eeSecret(textE2eeSecret));
}

function onTextE2eeReady(callback)
{
    if (typeof callback !== "function")
    {
        return;
    }
    if (textE2eeReady())
    {
        callback();
        return;
    }
    textE2eeReadyCallbacks.push(callback);
}

function notifyTextE2eeReady()
{
    if (!textE2eeReady())
    {
        return;
    }
    const callbacks = textE2eeReadyCallbacks;
    textE2eeReadyCallbacks = [];
    callbacks.forEach(function (callback)
    {
        callback();
    });
}

function currentTextE2eePairId()
{
    return pairId || i || (requestedResumePair && requestedResumePair.id) || "";
}

function pairUrlForId(id)
{
    return publicBaseUrl + "/?i=" + encodeURIComponent(id);
}

function showTextE2eeFailure(state, diagnosticReason)
{
    const status = state === "key-mismatch" ? "Pair key mismatch" : "Pair key missing";
    sendClientDiagnostic(diagnosticReason || state);
    setStatusMessage(status);
    setUiState(state, status);
}

function receiveTextE2eePublic(peerPublic)
{
    const id = currentTextE2eePairId();
    if (!id || !validTextE2eePublicKey(peerPublic) || !textE2eeSupported())
    {
        return Promise.reject(new Error("invalid text public key"));
    }
    if (textE2eePeerPublic === peerPublic && textE2eeReady())
    {
        notifyTextE2eeReady();
        return Promise.resolve(true);
    }
    return ensureTextE2eeKeyPair(id).then(function (ownKeyPair)
    {
        const peerBytes = base64UrlToBytes(peerPublic);
        return window.crypto.subtle.importKey(
            "raw",
            peerBytes,
            { name: "ECDH", namedCurve: TEXT_E2EE_CURVE },
            false,
            []
        ).then(function (peerKey)
        {
            return window.crypto.subtle.deriveBits(
                { name: "ECDH", public: peerKey },
                ownKeyPair.privateKey,
                TEXT_E2EE_SECRET_BYTES * 8
            );
        });
    }).then(function (sharedBits)
    {
        if (!setTextE2eeSecretForPair(id, bytesToBase64Url(new Uint8Array(sharedBits))))
        {
            throw new Error("invalid shared text secret");
        }
        textE2eePeerPublic = peerPublic;
        notifyTextE2eeReady();
        return true;
    });
}

function sendTextE2eePublic()
{
    const id = currentTextE2eePairId();
    const targetId = isPrimaryView() ? aid : i;
    if (!id || !targetId)
    {
        return Promise.resolve(false);
    }
    return ensureTextE2eeKeyPair(id).then(function (ownKeyPair)
    {
        return sendCommand("textPub", [targetId, ownKeyPair.publicKey]);
    }).catch(function ()
    {
        showTextE2eeFailure("key-missing", "e2ee-unsupported");
        return false;
    });
}

function textE2eeKeyForPair(id)
{
    if (!id || !validTextE2eeSecret(textE2eeSecret) || !textE2eeSupported())
    {
        return Promise.reject(new Error("missing text key"));
    }
    if (textE2eeKeyPromise && textE2eeKeyPairId === id)
    {
        return textE2eeKeyPromise;
    }
    textE2eeKeyPairId = id;
    const secretBytes = base64UrlToBytes(textE2eeSecret);
    const encoder = new TextEncoder();
    textE2eeKeyPromise = window.crypto.subtle.importKey(
        "raw",
        secretBytes,
        "HKDF",
        false,
        ["deriveKey"]
    ).then(function (ikm)
    {
        return window.crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: encoder.encode(id),
                info: encoder.encode(TEXT_E2EE_INFO)
            },
            ikm,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    });
    return textE2eeKeyPromise;
}

function encryptTextPayload(text, updatedAt, origin)
{
    const id = currentTextE2eePairId();
    const textUpdatedAt = normalizedTextUpdatedAt(updatedAt) || TEXT_REVISION_BASE;
    const textOrigin = typeof origin === "string" && origin ? origin : localTextUpdatedOrigin;
    return textE2eeKeyForPair(id).then(function (key)
    {
        const nonce = new Uint8Array(TEXT_E2EE_NONCE_BYTES);
        window.crypto.getRandomValues(nonce);
        return window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: nonce },
            key,
            new TextEncoder().encode(String(text || ""))
        ).then(function (ciphertext)
        {
            return {
                nonce,
                ciphertext
            };
        });
    }).then(function (ciphertext)
    {
        return JSON.stringify({
            v: 1,
            alg: "A256GCM",
            n: bytesToBase64Url(ciphertext.nonce),
            c: bytesToBase64Url(new Uint8Array(ciphertext.ciphertext)),
            t: textUpdatedAt,
            o: textOrigin
        });
    });
}

function parseEncryptedTextPayload(payload)
{
    try
    {
        const parsed = JSON.parse(String(payload || ""));
        if (parsed && parsed.v === 1 && parsed.alg === "A256GCM")
        {
            const nonce = base64UrlToBytes(parsed.n);
            const ciphertext = base64UrlToBytes(parsed.c);
            if (nonce && nonce.length === TEXT_E2EE_NONCE_BYTES && ciphertext && ciphertext.length > 0)
            {
                return {
                    nonce,
                    ciphertext,
                    updatedAt: normalizedTextUpdatedAt(parsed.t),
                    origin: typeof parsed.o === "string" ? parsed.o : ""
                };
            }
        }
    }
    catch (error)
    {
    }
    return null;
}

function decryptTextPayload(payload)
{
    const id = currentTextE2eePairId();
    const envelope = parseEncryptedTextPayload(payload);
    if (!envelope)
    {
        return Promise.reject(new Error("invalid encrypted text"));
    }
    return textE2eeKeyForPair(id).then(function (key)
    {
        return window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: envelope.nonce },
            key,
            envelope.ciphertext
        );
    }).then(function (plaintext)
    {
        return {
            text: new TextDecoder().decode(plaintext),
            updatedAt: envelope.updatedAt || TEXT_REVISION_BASE,
            origin: envelope.origin || ""
        };
    });
}

function fileE2eeKeyForPair(id)
{
    if (!id || !validTextE2eeSecret(textE2eeSecret) || !textE2eeSupported())
    {
        return Promise.reject(new Error("missing file key"));
    }
    if (fileE2eeKeyPromise && fileE2eeKeyPairId === id)
    {
        return fileE2eeKeyPromise;
    }
    fileE2eeKeyPairId = id;
    const secretBytes = base64UrlToBytes(textE2eeSecret);
    const encoder = new TextEncoder();
    fileE2eeKeyPromise = window.crypto.subtle.importKey(
        "raw",
        secretBytes,
        "HKDF",
        false,
        ["deriveKey"]
    ).then(function (ikm)
    {
        return window.crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: encoder.encode(id),
                info: encoder.encode(FILE_E2EE_INFO)
            },
            ikm,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    });
    return fileE2eeKeyPromise;
}

function fileE2eeAdditionalData(id, transferId, seq)
{
    return new TextEncoder().encode([
        "icyzip/file/chunk/v1",
        id || "",
        transferId || "",
        String(seq)
    ].join("\n"));
}

function concatFileE2eeFrame(nonce, ciphertext)
{
    const cipherBytes = new Uint8Array(ciphertext);
    const result = new Uint8Array(nonce.length + cipherBytes.length);
    result.set(nonce, 0);
    result.set(cipherBytes, nonce.length);
    return result.buffer;
}

function splitFileE2eeFrame(data)
{
    const bytes = new Uint8Array(arrayBufferCopy(data));
    if (bytes.length <= FILE_E2EE_FRAME_OVERHEAD)
    {
        return null;
    }
    return {
        nonce: bytes.slice(0, FILE_E2EE_NONCE_BYTES),
        ciphertext: bytes.slice(FILE_E2EE_NONCE_BYTES)
    };
}

function encryptFileChunk(buffer, transferId, seq)
{
    const id = currentTextE2eePairId();
    const plain = arrayBufferCopy(buffer);
    return fileE2eeKeyForPair(id).then(function (key)
    {
        const nonce = new Uint8Array(FILE_E2EE_NONCE_BYTES);
        window.crypto.getRandomValues(nonce);
        return window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: nonce,
                additionalData: fileE2eeAdditionalData(id, transferId, seq)
            },
            key,
            plain
        ).then(function (ciphertext)
        {
            return concatFileE2eeFrame(nonce, ciphertext);
        });
    });
}

function decryptFileChunk(data, transferId, seq)
{
    const id = currentTextE2eePairId();
    const frame = splitFileE2eeFrame(data);
    if (!frame)
    {
        return Promise.reject(new Error("invalid encrypted file chunk"));
    }
    return fileE2eeKeyForPair(id).then(function (key)
    {
        return window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: frame.nonce,
                additionalData: fileE2eeAdditionalData(id, transferId, seq)
            },
            key,
            frame.ciphertext
        );
    });
}

function isPrimaryView()
{
    return i == null;
}

// END exact source section: cryptography-and-lifecycle

// BEGIN exact source section: buffer-copy
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

// END exact source section: buffer-copy

// BEGIN exact source section: file-offer-acceptance
    function handleFileOffer(args)
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
        if (state.outgoing || state.incoming)
        {
            sendCommand("fileReject", [transferId, "busy"]);
            return;
        }
        if (args[6] !== "e2ee-v1" || !textE2eeReady())
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

// END exact source section: file-offer-acceptance

// BEGIN exact source section: file-frame-acceptance
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

// END exact source section: file-frame-acceptance

// BEGIN exact source section: file-completion
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

// END exact source section: file-completion
