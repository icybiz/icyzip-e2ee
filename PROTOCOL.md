# Current IcyZip browser encryption protocol

This document describes the browser client represented by `src/snapshot.js`. It is descriptive, not a proposal for a future protocol.

## Participants and transport

One primary browser obtains a pairing id and a separate resume capability from the relay. Its QR code and copied link contain only:

```text
https://icyzip.com/?i=<pair-id>
```

The second browser sends the pair id to the relay. Once both are connected, they exchange JSON commands over WebSocket or the same-origin HTTP fallback. TLS protects both transports in production. The two transports carry the same encrypted text format. File transfer requires WebSocket binary frames.

The pair id routes messages; it is not a cryptographic key. The resume capability lets the primary browser resume server-side pairing state; it is also not input to browser encryption.

## ECDH exchange

Each browser creates an extractable P-256 ECDH keypair through WebCrypto and exports:

- the private key as a JWK stored under a pair-specific key in that tab's `sessionStorage`;
- the public key as the 65-byte uncompressed point `0x04 || X || Y`, encoded as unpadded base64url.

Each side sends:

```json
{"cmd":"textPub","args":["<relay-routing-id>","<base64url-public-point>"]}
```

The relay forwards the public point to the other browser. The recipient checks only the encoding, 65-byte length, uncompressed-point prefix, and P-256 import validity. No signature, MAC, certificate, pairing secret, fingerprint comparison, or short authentication string authenticates the point.

The recipient calculates:

```text
shared = P-256-ECDH(own-private-key, received-public-key)  // 32 bytes
```

On reconnect, the in-memory shared value is cleared and rederived after another public-key exchange. It is not persisted. The private JWK remains in `sessionStorage` until the pairing is cleared or the tab session ends.

## Key derivation

The raw 32-byte ECDH result is imported as HKDF input key material. Both application keys use SHA-256 and the UTF-8 pair id as salt:

```text
textKey = HKDF-SHA-256(shared, salt=UTF8(pairId), info=UTF8("icyzip/text/ecdh/v2"), 32)
fileKey = HKDF-SHA-256(shared, salt=UTF8(pairId), info=UTF8("icyzip/file/ecdh/v1"), 32)
```

Both outputs are non-extractable AES-GCM keys. The different `info` values provide key separation.

## Text messages

For each update the sender generates a fresh random 12-byte nonce and encrypts the UTF-8 text with AES-256-GCM. No additional authenticated data is supplied. The JSON envelope is:

```json
{
  "v": 1,
  "alg": "A256GCM",
  "n": "<12-byte nonce as base64url>",
  "c": "<ciphertext and 16-byte GCM tag as base64url>",
  "t": 4503599627370497,
  "o": "<browser-origin-id>"
}
```

`t` is a positive safe-integer Lamport-style revision. `o` is the browser's random conflict-resolution origin. These two fields are read after ciphertext verification but are not themselves encrypted or authenticated. A changed `n` or `c` fails AES-GCM verification. A changed `t` or `o` does not.

The encrypted envelope is the text argument of `tcha` from primary to secondary or `tch` from secondary to primary. The relay forwards it unchanged in ordinary operation.

## File chunks

Text and file transfer share the ECDH result but use distinct HKDF contexts. For every plaintext chunk, the sender generates a fresh 12-byte nonce and constructs UTF-8 additional authenticated data:

```text
icyzip/file/chunk/v1\n<pair-id>\n<transfer-id>\n<decimal-sequence>
```

The sender encrypts the chunk with AES-256-GCM and transmits this binary frame:

```text
12-byte nonce || ciphertext || 16-byte GCM tag
```

The recipient reconstructs the same additional data. Any change to encrypted bytes, nonce, pair id, transfer id, or sequence causes decryption to fail.

The file offer and control commands stay outside this encryption. The relay and peer see the transfer id, sanitized filename, MIME hint, plaintext size, encrypted wire size, chunk size, encryption-mode marker, timing, accept/reject/cancel state, acknowledgements, and completion counts. Those offer fields are not covered by an end-to-end MAC in this version.

The sender appends encrypted wire size and the exact marker `e2ee-v1` to every offer. Before accepting, the receiver requires that marker and an established ECDH content key. It also requires positive safe-integer plaintext size, encrypted chunk size, and wire size; enforces the configured size limits; requires the encrypted chunk size to exceed the 28-byte nonce/tag overhead; and requires wire size to exceed plaintext size. An older five-field offer, a changed marker, or an offer received before key establishment is rejected with `encryption-required`. There is no plaintext receive branch.

The marker and visible size fields are still not authenticated end to end. An active relay can change them and cause rejection or denial of service. It cannot make the current receiver accept plaintext file frames: every accepted frame is passed through AES-GCM with the pair, transfer, and sequence context before any bytes enter the file assembler.

## Failure behavior

- Invalid public-key encoding or an invalid curve point stops key establishment.
- Text cannot be sent until a shared value exists.
- Invalid JSON, algorithm/version, nonce length, ciphertext, GCM tag, or key rejects the text update; the application keeps the last valid text and shows a key-mismatch state.
- An offer without exact `e2ee-v1` or without an established ECDH key is rejected before transfer state is created.
- Invalid offer sizes are rejected. Invalid file frames, changed file context, or failed GCM verification cancel an accepted transfer instead of creating a partial download.
- Neither text nor file receive has a plaintext fallback.

## Relay role relevant to E2EE

The relay chooses pairing identifiers, connects one primary and one secondary, forwards public keys, text envelopes, file offers and file frames, enforces operational size/state limits, and serves the browser JavaScript. It does not need a content-decryption key during ordinary honest operation. Because public keys are unauthenticated, an active relay can create separate ECDH relationships with the two browsers; the executable reproduction is in `test/limitations.test.mjs`.
