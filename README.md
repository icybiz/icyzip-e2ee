# IcyZip browser encryption review

This repository makes the cryptographic parts of the current IcyZip browser client inspectable and reproducible. It contains exact excerpts from the JavaScript served by [icyzip.com](https://icyzip.com), a small adapter for isolated tests, the wire format, and an explicit threat model. The relay server implementation is outside this repository because encryption and decryption happen in the two browsers; every relay behavior that affects the cryptographic claim is described here.

The current design has two confirmed limitations:

1. The relay forwards P-256 ECDH public keys without end-to-end authentication. An active or compromised relay can substitute keys, form one encrypted connection with each browser, and read or alter transferred content without a key-mismatch error.
2. Text revision and origin fields are outside AES-GCM. A relay cannot change the encrypted text without detection, but it can change those fields and influence conflict resolution.

The tests under `test/limitations.test.mjs` reproduce both behaviors with synthetic endpoints. They are disclosure tests: a passing result confirms that the documented limitation is present. Do not interpret it as resistance to those attacks.

Snapshot 0.2 closes the legacy file-offer downgrade disclosed by snapshot 0.1. The receiver now requires the exact `e2ee-v1` marker and an established ECDH content key before accepting an offer. `test/file-receive.test.mjs` keeps the old attack as a regression test and verifies encrypted recovery after rejection.

## What the current client does

- Generates one P-256 ECDH keypair per browser tab and pairing.
- Stores the private JWK in tab-scoped `sessionStorage` for reload and reconnect recovery.
- Exchanges uncompressed public points through the relay's `textPub` command.
- Derives 256 shared ECDH bits, then uses HKDF-SHA-256 with the pairing id as salt.
- Derives separate AES-256-GCM keys for text (`icyzip/text/ecdh/v2`) and file bytes (`icyzip/file/ecdh/v1`).
- Encrypts text with a fresh random 96-bit nonce.
- Encrypts each file chunk with a fresh random 96-bit nonce and authenticates pairing id, transfer id, and sequence as additional data.
- Accepts a file offer only when it carries the exact `e2ee-v1` marker and an ECDH content key is established.
- Rejects malformed offers, plaintext frames, incorrect keys, changed ciphertext, and changed file transfer or sequence context without creating a download.
- Has no plaintext file-receive branch.

The pairing URL contains a relay-visible pair id and no cryptographic secret. Filename, MIME hint, plaintext and ciphertext sizes, connection data, timing, and transfer-control messages remain visible to the service. See [PROTOCOL.md](PROTOCOL.md) and [THREAT-MODEL.md](THREAT-MODEL.md) for the exact boundaries.

## Verify it

Node.js 20 or newer is required. The tests use only Node's built-in modules and install no packages.

```sh
npm test
npm run known-limitations
```

`npm test` checks legitimate text and file exchange, independent ECDH/HKDF/AES-GCM interoperability, tamper rejection, downgrade rejection and recovery, key separation, reload recovery, random nonces, and snapshot provenance.

When this repository is checked out inside the IcyZip source tree, compare the snapshot with the local browser client:

```sh
npm run check:local
```

Compare the same sections with the JavaScript currently served by IcyZip:

```sh
npm run check:live
```

The remote check permits only `https://icyzip.com/js/view/client_wsscript.js`, follows no redirects, sends the IcyZip test-traffic marker, and never writes a file.

## Source layout

- `src/snapshot.js`: nine verbatim source sections from the browser client, with section markers and an Apache-2.0 header.
- `PROVENANCE.json`: SHA-256 hashes, source anchors, original line locations, and byte counts.
- `tools/snapshot.mjs`: deterministic extractor and verifier.
- `test/endpoint.mjs`: test-only application-state adapter; it implements no cryptography.
- `test/crypto.test.mjs`: successful operation, negative ciphertext cases, and an independent Node crypto oracle.
- `test/file-receive.test.mjs`: downgrade, malformed-offer, tamper, retry, and forward-progress regression tests.
- `test/limitations.test.mjs`: executable disclosure of the two remaining protocol limitations.

This snapshot is review material for the deployed IcyZip protocol, not a general-purpose cryptography library. Please report security findings privately as described in [SECURITY.md](SECURITY.md).

Licensed under Apache License 2.0. Copyright 2026 Richard Andresik.
