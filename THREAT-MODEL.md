# Threat model

## Assets

The protected content is live text and file bytes transferred between the two selected browser views. Browser-local drafts and stored private JWKs are endpoint state. Pairing identifiers, file-offer metadata, traffic shape, and service diagnostics are not content secrets in the current design.

## Verified properties

Assuming both browsers run the published client code, receive the intended peer public key, and keep their private keys uncompromised:

- text and current-client file bytes leave the sender as AES-256-GCM ciphertext;
- the matching peer reconstructs exact text and file bytes;
- modified ciphertext, an incorrect key, or changed file transfer/sequence context fails authentication;
- text and file keys are separated by different HKDF contexts;
- the relay does not receive the browser's ECDH private keys or derived AES keys during ordinary operation;
- text never falls back to plaintext, and file receive requires exact `e2ee-v1`, an established ECDH content key, and successful AES-GCM verification as described in `PROTOCOL.md`.

These properties are exercised by `npm test`, including an independent implementation based on Node's ECDH, HKDF, and AES-GCM APIs.

## Confirmed limitations

### Active relay key substitution

The public-key exchange has no end-to-end authentication. A relay that changes protocol messages can replace each browser's public point with its own. It then derives one key with the primary and a different key with the secondary, decrypts content from one side, and re-encrypts content for the other. Both endpoints remain in their normal ready state.

`npm run known-limitations` reproduces this using three synthetic parties. This is the most important current protocol limitation.

### Unauthenticated text conflict metadata

Text revision `t` and origin `o` are outside AES-GCM. A relay can change them while retaining a valid encrypted text and GCM tag. The receiving application accepts the changed values and may use them to decide which offline edit wins. The same limitation test suite reproduces this behavior.

### Visible and unauthenticated file-offer metadata

Filename, MIME hint, plaintext size, encrypted size, transfer and chunk identifiers, chunk size, timing, and control state remain visible. File chunk bytes and their pair/transfer/sequence association are authenticated, but the complete visible file offer is not covered by an end-to-end authenticator.

## Resolved in snapshot 0.2

### Legacy file-offer downgrade

Snapshot 0.1 accepted an older offer without `e2ee-v1` and then treated binary frames as plaintext. Snapshot 0.2 removes that branch. The receiver rejects a missing or changed marker and rejects even an exact marker until an ECDH content key is established. The old attack is now an expected-rejection regression in `test/file-receive.test.mjs`, together with plaintext injection, ciphertext/context tampering, encrypted retry, bidirectional exact bytes, and later text progress.

This repair does not authenticate the visible offer fields and does not repair public-key substitution. An active relay can still cause denial of service by changing an offer, and can still read or replace content by first substituting ECDH public keys as described above.

## Other boundaries

### Browser and device compromise

JavaScript must hold plaintext, a private ECDH key, and derived keys to provide the service. Malicious extensions, injected scripts, browser exploits, operating-system compromise, or someone controlling an unlocked endpoint can access content. E2EE does not protect a compromised endpoint.

### Code-delivery server

The IcyZip origin serves the JavaScript that performs encryption. A server that deliberately serves modified JavaScript can obtain plaintext or keys before encryption. Publishing and hashing the source makes the implementation reviewable and lets users compare the served asset, but a normal web session does not independently enforce that correspondence.

### Pairing link

The pairing link contains only the relay-visible pair id. It does not authenticate a cryptographic key and does not repair active relay substitution. Someone with the link may try to occupy the secondary slot, which affects peer selection and availability.

### Metadata and traffic analysis

The service necessarily observes connection IP addresses while handling requests, user-agent and timing information, pair activity, ciphertext sizes, and file-offer metadata described above. Encryption does not hide traffic volume or timing.

### Availability

The relay can delay, drop, reorder, reject, disconnect, replace a peer, or refuse messages. Cryptography detects some modifications but cannot force delivery. Denial of service is outside the confidentiality and integrity claim.

## Current claim boundary

The implementation provides browser-side text and file-byte encryption against passive observation and an honest relay that forwards the intended public keys. File receipt fails closed when the encryption marker, content key, ciphertext, or file context is invalid. The protocol does not currently provide authenticated peer key agreement or end-to-end authentication of text conflict metadata and visible file-offer metadata. Security reports and proposals to close those gaps are welcome through the private route in `SECURITY.md`.
