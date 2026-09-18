# IcyZip authenticated browser encryption protocol v3

This document describes the browser protocol represented by `src/e2ee.js` and `src/snapshot.js`, deployed to IcyZip production and staging at `edc7b8b80335bda8ff84589c7f4fac76c671f1f5`. The deterministic live correspondence check matches these review files to the production assets served at the time of verification.

## Participants, pairing link, and transport

The relay gives the primary browser a random pairing id and a separate resume capability. The primary browser independently generates 32 random bytes with WebCrypto and encodes them as unpadded base64url. The QR code and copied link have this shape:

```text
https://icyzip.com/?i=<pair-id>#k=<43-character-secret>&v=3
```

The query pair id is sent to the service and routes messages. The fragment is not part of HTTP requests. The secondary strictly validates the fragment, stores the secret under the pair id in tab-scoped `sessionStorage`, and removes the fragment with `history.replaceState` before connecting. The primary stores the same secret in its own tab session.

The complete link is a secret capability: anyone who obtains it can authenticate a browser as a participant in that pair. A secondary with a missing, malformed, or wrong secret cannot complete authenticated key establishment. A primary reload without its stored v3 secret preserves its text draft but replaces the obsolete pair with a fresh id and secret.

JSON commands use WebSocket or the same-origin text-only HTTP fallback. TLS protects both transports in production. File chunks require WebSocket binary frames.

## Authenticated P-256 ECDH

Each browser creates an extractable P-256 ECDH keypair. Its private JWK and 65-byte uncompressed public point are stored together under a pair-specific `sessionStorage` key for reload continuity. Private keys do not cross the relay.

First derive a non-extractable HMAC-SHA-256 key:

```text
pubAuthKey = HKDF-SHA-256(
  ikm=pairingSecret,
  salt=UTF8(pairId),
  info=UTF8("icyzip/e2ee/pub-auth/v3"),
  length=32
)
```

Each endpoint sends this `textPub` payload after the relay routing id:

```json
["v3", "<65-byte-public-point-as-base64url>", "<32-byte-HMAC-as-base64url>"]
```

The HMAC input is UTF-8 JSON without added whitespace:

```json
["icyzip/e2ee/pub/v3", "<pair-id>", "<sender-role>", "<public-point>"]
```

The sender role is exactly `primary` or `secondary`. The receiver verifies the version, canonical unpadded base64url, public-point length and `0x04` prefix, HMAC length, and HMAC before importing the peer point. Role reflection, pair substitution, public-key substitution, altered tags, malformed encodings, and old formats fail before content keys are derived. WebCrypto also rejects points that are not on P-256.

After authentication, each side derives 32 ECDH bytes. Key input and transcript salt are:

```text
material = ecdhSharedBits || pairingSecret
transcript = UTF8(JSON(["v3", pairId, primaryPublic, secondaryPublic]))
salt = SHA-256(transcript)
```

Four independent keys exist:

```text
textKey      = HKDF-SHA-256(material, salt, "icyzip/e2ee/text/v3", 32)
fileChunkKey = HKDF-SHA-256(material, salt, "icyzip/e2ee/file-chunk/v3", 32)
fileOfferKey = HKDF-SHA-256(material, salt, "icyzip/e2ee/file-offer/v3", 32)
pubAuthKey   = HKDF-SHA-256(pairingSecret, UTF8(pairId), "icyzip/e2ee/pub-auth/v3", 32)
```

The first two are non-extractable AES-256-GCM keys. The latter two are non-extractable HMAC-SHA-256 keys.

## Text envelope v2

The authenticated plaintext is compact UTF-8 JSON:

```json
{"text":"<text>","t":4503599627370497,"o":"<origin>"}
```

`t` must be a non-negative safe integer. `o` must be a non-empty string of at most 128 characters. A fresh random 12-byte nonce is used for each update. AES-GCM additional authenticated data is compact UTF-8 JSON:

```json
["icyzip/text/v2", "<pair-id>"]
```

The relay-visible envelope has exactly four fields:

```json
{"v":2,"alg":"A256GCM","n":"<nonce-base64url>","c":"<ciphertext-and-tag-base64url>"}
```

Text, revision, and origin are encrypted and authenticated together. An old v1 envelope, extra or missing fields, wrong pair context, malformed nonce or ciphertext, invalid decrypted field, wrong key, or failed GCM tag rejects the update while the application retains the last valid text.

## File chunks and offers

Every plaintext file chunk gets a fresh 12-byte nonce. Its AES-GCM additional authenticated data is:

```json
["icyzip/file/chunk/v3", "<pair-id>", "<transfer-id>", <sequence>]
```

The binary frame is:

```text
12-byte nonce || ciphertext || 16-byte GCM tag
```

The seven visible offer fields are strings in this order:

```json
["<transfer-id>","<filename>","<plain-size>","<MIME-hint>","<encrypted-chunk-size>","<wire-size>","e2ee-v3"]
```

The sender appends an HMAC-SHA-256 tag over compact UTF-8 JSON:

```json
["icyzip/file/offer/v3", "<pair-id>", "<sender-role>", ["<the-seven-fields>"]]
```

The receiver validates operational sizes and verifies the tag before accepting. Changing the transfer id, name, MIME hint, plaintext size, chunk size, wire size, mode, sender role, or tag causes rejection. A missing key, old marker, unsigned offer, malformed frame, changed transfer or sequence context, wrong key, or failed GCM tag cannot create a download. Cancellation or failure clears transfer state so a later valid transfer can proceed.

Filename, MIME hint, sizes, transfer id, timing, acknowledgement and completion state remain visible to the relay. Authentication prevents undetected changes; it does not conceal them.

## Relay behavior relevant to E2EE

The relay creates cryptographically random pair, resume, and fallback identifiers; connects one primary and one secondary; validates v3 message framing; forwards public-key messages and file-offer fields byte for byte; forwards opaque text ciphertext and encrypted binary frames; and enforces operational state and size limits. It does not receive the pairing secret, private ECDH keys, shared ECDH result, or derived content keys during operation with the authentic client.

The relay can still delay, drop, duplicate, reject, disconnect, or reorder allowed traffic. These actions can deny service but cannot create a valid public-key tag, text ciphertext, file chunk, or file offer without the relevant browser-held key.
