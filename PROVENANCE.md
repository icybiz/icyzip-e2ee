# Source provenance

`src/e2ee.js` is a complete byte-for-byte copy of production release `edc7b8b`'s `client/src/js/e2ee.js`. `src/snapshot.js` contains three exact sections from `client/src/js/view/client_wsscript.js`: module integration and lifecycle, file buffer handling, and the complete file-transfer controller. Section markers and the Apache-2.0 banner are the only added snapshot text.

`PROVENANCE.json` records:

- the protocol module path, byte count, and SHA-256;
- the SHA-256 of the complete integration source used for extraction;
- the SHA-256 of the complete integration snapshot;
- every section's unique start/end anchors, original first line, byte count, and SHA-256.

`tools/snapshot.mjs` requires both local source files, locates every integration boundary exactly once, and rejects missing or ambiguous anchors. Check mode regenerates everything in memory and compares the full module bytes, snapshot bytes, and complete provenance object. Patch mode emits an `apply_patch` diff and does not write project files itself.

To compare two locally saved browser source files, supply their explicit paths:

```sh
node tools/snapshot.mjs --source /path/to/client_wsscript.js --module /path/to/e2ee.js --check
```

The live check fetches only `https://icyzip.com/js/view/client_wsscript.js` and `https://icyzip.com/js/e2ee.js`, rejects redirects, sends the service's test-traffic marker, writes nothing, and performs the same in-memory comparison:

```sh
npm run check:live
```

A successful live check proves that the complete protocol module and the three recorded integration sections matched this review release at the time of the requests. It does not prove that unrelated application code matched, that every visitor received the same response, that the origin cannot later change code, or that no defect exists.

The test adapter supplies endpoint role, pair id, tab storage, and WebCrypto. It implements no cryptographic primitive or key derivation. `test/crypto.test.mjs` independently verifies the protocol through Node's separate ECDH, HKDF, HMAC, and AES-GCM APIs.

The production/staging protocol release records module SHA-256 `d4572f2cbba9792274cef840ba4417aea66ca008302b8d031b90045fcfba8254`, complete integration-source SHA-256 `adbfc5177b2698550fabcfc66d89aa787149bfa3f37275f51891b3b16814a33a`, and integration snapshot SHA-256 `e488c8f43e708935ca448b623174bc838738d0b06c948523f588343cbd548dcf`. These values identify the reviewed code; run the live check to establish current correspondence.
