# IcyZip authenticated browser E2EE v3

This repository makes the browser cryptography and security-relevant receive logic of IcyZip protocol v3 inspectable and reproducible. `src/e2ee.js` is byte-identical to the module consumed by production IcyZip. `src/snapshot.js` contains exact integration and file-receive sections. The proprietary relay is outside this repository; every relay-visible message and trust boundary relevant to E2EE is documented here.

This is review release `0.3.0` for the protocol introduced in IcyZip production/staging commit `edc7b8b80335bda8ff84589c7f4fac76c671f1f5`. It includes a minimal standalone test and focused attack regressions. The repository contains no proprietary server code.

## What v3 changes

- A new primary browser generates a random 32-byte pairing secret and places it only in the URL fragment: `#k=<base64url>&v=3`.
- The secondary stores that secret in tab-scoped `sessionStorage` and removes the fragment from its visible URL. URI fragments are not part of the HTTP request.
- The pairing secret authenticates each P-256 ECDH public key with HMAC-SHA-256 before the peer key is imported.
- The ECDH result and pairing secret jointly derive separate keys for text, file chunks, and file-offer authentication.
- Text envelope v2 encrypts the text, revision, and origin together.
- Every visible file-offer field is authenticated before the receiver accepts a transfer.
- Legacy key messages, text envelopes, file markers, malformed encodings, wrong roles, wrong pairs, altered offers, and unauthenticated ciphertext fail closed.

The complete pairing link is a secret capability. Anyone who obtains it can join that pair, so it must be kept private. The relay still sees the pair id, public keys and authentication tags, ciphertext sizes, timing, connection data, and file-offer metadata such as filename, MIME hint, sizes, and transfer identifiers. See [PROTOCOL.md](PROTOCOL.md) and [THREAT-MODEL.md](THREAT-MODEL.md) for the precise boundaries.

## Verify it

Node.js 20 or newer is required. The tests use only built-in Node modules: no package installation, server, account, or network connection is needed.

```sh
npm run test:minimal
npm test
```

Start with the 21-line [minimal test](test/minimal.test.mjs) and 33-line [endpoint adapter](test/endpoint.mjs). [TESTING.md](TESTING.md) explains how to add a small reproduction of a suspected weakness.

The full suite covers authenticated key exchange, an independent Node cryptography oracle, key separation, exact bidirectional text and file recovery, hidden and authenticated text metadata, public-key substitution and reflection rejection, ciphertext and context tampering, file-offer field authentication, downgrade rejection, cancellation and retry, storage failure, reload recovery, and deterministic source provenance.

Optionally compare the same files with the JavaScript currently served by IcyZip:

```sh
npm run check:live
```

The live check permits only the two fixed `https://icyzip.com` browser assets, follows no redirects, marks its requests as test traffic, and writes no file. See [PROVENANCE.md](PROVENANCE.md) for its exact scope.

## Source layout

- `src/e2ee.js`: complete byte-identical protocol module used by production IcyZip.
- `src/snapshot.js`: three exact integration and file-receive sections from the browser client.
- `PROVENANCE.json`: SHA-256 hashes, source anchors, original line locations, and byte counts.
- `tools/snapshot.mjs`: deterministic exporter and verifier.
- `test/endpoint.mjs`: test-only endpoint and storage adapter; it implements no cryptography.
- `test/minimal.test.mjs`: small standalone text-exchange and tampering example.
- `test/crypto.test.mjs`: protocol, tamper, recovery, and independent-oracle tests.
- `test/file-receive.test.mjs`: downgrade, offer authentication, cancellation, tamper, retry, and exact-byte tests using the real receive controller.
- `test/security-regressions.test.mjs`: expected rejection of the two active attacks disclosed by v0.2.

This code is review material for IcyZip's browser protocol, not a general-purpose cryptography library. Please report security findings privately as described in [SECURITY.md](SECURITY.md).

Licensed under Apache License 2.0. Copyright 2026 Richard Andresik.
