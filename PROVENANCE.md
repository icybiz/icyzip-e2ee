# Source provenance

`src/snapshot.js` contains nine source sections copied byte for byte from IcyZip's browser client. Comments marking section boundaries and the Apache-2.0 header are the only added text.

`PROVENANCE.json` records:

- the SHA-256 of the complete source file used for extraction;
- the SHA-256 of the complete snapshot;
- each section's start and end anchor, first source line, byte count, and SHA-256.

`tools/snapshot.mjs` locates each boundary exactly once and refuses missing or ambiguous anchors. Check mode regenerates the snapshot in memory and compares it with the tracked snapshot and provenance hashes. Patch mode emits an `apply_patch` diff for a new or updated snapshot and does not write project files itself.

The local source-tree check is:

```sh
npm run check:local
```

The live check fetches only the public browser asset over HTTPS, rejects redirects, sends the service's test-traffic marker, writes nothing, and applies the same in-memory comparison:

```sh
npm run check:live
```

A successful live check proves that the nine cryptographic and file-acceptance sections match this snapshot at the time of the request. It does not prove that unrelated JavaScript matches, that every visitor received the same response, that the server cannot later serve different code, or that the protocol withstands the known attacks in `THREAT-MODEL.md`.

The test adapter supplies application globals such as pair id, tab storage, and UI callbacks. It implements no cryptographic primitive or key derivation. An additional test independently decrypts the emitted text and file formats through Node's separate ECDH, HKDF, and AES-GCM interfaces.

Snapshot 0.2 was generated from product release `4b477092b5d0162e36bfe157794c315a0b476de2`. The full source SHA-256 in `PROVENANCE.json` also matches the browser asset served from `https://icyzip.com/js/view/client_wsscript.js` at publication verification time.
