# Threat model

## Assets and attacker model

The protected content is live text, its edit metadata, and file bytes exchanged between two selected browser views. The protocol is designed to protect confidentiality and integrity against network observers and an active relay that can inspect, replace, inject, replay, delay, or drop protocol messages while both endpoints run the authentic reviewed browser code.

The pairing id, public keys and tags, ciphertext sizes, connection addresses and timing, file-offer metadata, and traffic shape are not confidential. The complete pairing link and browser-local key state are secrets.

## Verified properties of the production v3 release

- Each peer public key is authenticated with a key derived from the 32-byte fragment secret before P-256 import or content-key derivation.
- Sender role, pair id, protocol version, and public key are covered by the public-key HMAC.
- ECDH output, the pairing secret, pair id, and ordered public-key transcript contribute to purpose-separated content keys.
- Text, revision, and origin are inside one AES-256-GCM plaintext with pair/version additional data.
- File chunks bind pair id, transfer id, and sequence through AES-GCM additional data.
- Every visible file-offer field and sender role is covered by a separate HMAC before acceptance.
- Legacy or malformed key messages, v1 text envelopes, old file markers, unsigned or altered offers, plaintext frames, and failed authentication have no receive fallback.
- Session resets and cancellation prevent stale asynchronous key or offer work from reviving a closed state.

`npm test` exercises these properties, including an independent Node ECDH/HKDF/HMAC/AES-GCM oracle and expected rejection of the active-relay and metadata attacks disclosed by v0.2. Start with the small example in [TESTING.md](TESTING.md).

## Boundaries and residual risks

### Complete pairing-link disclosure

Anyone with the full `?i=...#k=...&v=3` link has both the routing id and secret needed to authenticate a participant. The fragment is not sent in HTTP requests, and the secondary removes it after import, but it can still be exposed through copying, screenshots, QR observation, browser history, browser extensions, endpoint compromise, or deliberate sharing.

### Browser and device compromise

JavaScript must hold plaintext, the pairing secret, a private ECDH key, and derived keys to provide the service. Malicious extensions, injected scripts, browser exploits, operating-system compromise, or control of an unlocked endpoint can access them. E2EE does not protect a compromised endpoint.

### Code-delivery origin

The IcyZip origin serves the JavaScript that implements encryption. An origin that deliberately sends modified code can obtain plaintext or the fragment secret. Publishing the exact module, recording hashes, and comparing deployed assets make changes reviewable, but a normal browser session does not independently enforce that it received the published bytes.

### Metadata and traffic analysis

The service observes network addresses while handling requests, user-agent and timing information, pair activity, public keys and authentication tags, ciphertext length, and the file-offer fields listed in `PROTOCOL.md`. Encryption does not hide traffic volume, timing, filename, MIME hint, sizes, or transfer-control state.

### Availability

The relay can delay, drop, replay, disconnect, replace a connection, or refuse messages. Authentication makes unauthorized changes fail closed but cannot force delivery. A participant with the complete link can occupy or replace a peer slot. Denial of service is outside the confidentiality and integrity claim.

### Cryptographic and implementation defects

Review and tests reduce risk but do not prove the absence of design, implementation, browser, or side-channel flaws. Reports that bypass authentication, expose the secret, confuse roles or pairs, revive stale state, or create a plaintext receive path are in scope under `SECURITY.md`.

## Claim boundary

This protocol implementation passed local, staging, and production Chromium/Firefox gates at deployment. Review release `0.3.0` records the complete protocol module and three exact browser integration sections. Run `npm run check:live` to check correspondence with the currently served assets; see [PROVENANCE.md](PROVENANCE.md) for what that comparison proves.
