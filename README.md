# IcyZip browser encryption review

This repository makes the cryptographic parts of the current IcyZip browser client inspectable and reproducible. It contains exact excerpts from the JavaScript served by [icyzip.com](https://icyzip.com), a small adapter for isolated tests, the wire format, and an explicit threat model. The relay server implementation is outside this repository because encryption and decryption happen in the two browsers; every relay behavior that affects the cryptographic claim is described here.

The current design has three confirmed limitations:

1. The relay forwards P-256 ECDH public keys without end-to-end authentication. An active or compromised relay can substitute keys, form one encrypted connection with each browser, and read or alter transferred content without a key-mismatch error.
2. Text revision and origin fields are outside AES-GCM. A relay cannot change the encrypted text without detection, but it can change those fields and influence conflict resolution.
3. The sender marks current file offers as encrypted, but the receiver still accepts a legacy offer without that marker and then treats incoming file bytes as plaintext. An active relay can remove the encryption marker and substitute arbitrary plaintext bytes.

The tests under `test/limitations.test.mjs` reproduce all three behaviors with synthetic endpoints. They are disclosure tests: a passing result confirms that the documented limitation is present. Do not interpret it as resistance to those attacks.

## What the current client does

- Generates one P-256 ECDH keypair per browser tab and pairing.
- Stores the private JWK in tab-scoped `sessionStorage` for reload and reconnect recovery.
- Exchanges uncompressed public points through the relay's `textPub` command.
- Derives 256 shared ECDH bits, then uses HKDF-SHA-256 with the pairing id as salt.
- Derives separate AES-256-GCM keys for text (`icyzip/text/ecdh/v2`) and file bytes (`icyzip/file/ecdh/v1`).
- Encrypts text with a fresh random 96-bit nonce.
- Encrypts each file chunk with a fresh random 96-bit nonce and authenticates pairing id, transfer id, and sequence as additional data.
- Rejects malformed ciphertext, an incorrect key, or changed encrypted bytes when the received file offer retains the current `e2ee-v1` marker.
- Retains a legacy unencrypted file-receive branch, as demonstrated by the third known-limitation test.

The pairing URL contains a relay-visible pair id and no cryptographic secret. Filename, MIME hint, plaintext and ciphertext sizes, connection data, timing, and transfer-control messages remain visible to the service. See [PROTOCOL.md](PROTOCOL.md) and [THREAT-MODEL.md](THREAT-MODEL.md) for the exact boundaries.

## Verify it

Node.js 20 or newer is required. The tests use only Node's built-in modules and install no packages.

```sh
npm test
npm run known-limitations
```

`npm test` checks legitimate text and file exchange, independent ECDH/HKDF/AES-GCM interoperability, tamper rejection, key separation, reload recovery, random nonces, and snapshot provenance.

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
- `test/limitations.test.mjs`: executable disclosure of the three known protocol limitations.

This snapshot is review material for the deployed IcyZip protocol, not a general-purpose cryptography library. Please report security findings privately as described in [SECURITY.md](SECURITY.md).

Licensed under Apache License 2.0. Copyright 2026 Richard Andresik.
