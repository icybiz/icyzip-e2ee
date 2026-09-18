# Security policy

## Reporting a vulnerability

Please send security-sensitive findings privately to `contact@icyzip.com` with `IcyZip security` in the subject. If GitHub private vulnerability reporting is enabled for this repository, that is also an appropriate private channel.

For non-sensitive bugs or general feedback, the anonymous form at [icyzip.com/feedback](https://icyzip.com/feedback) does not require a name or email address. Do not put an undisclosed vulnerability, exploit details, pairing data, keys, or private user content into the public issue tracker or general feedback form.

A useful report includes:

- the affected protocol field or source function;
- the attacker capabilities and prerequisites;
- a minimal reproduction using synthetic data;
- the confidentiality, integrity, metadata, or availability impact;
- a proposed fix or test when available.

Please do not test with another person's data, pairing, browser, or account. The repository's test adapter creates isolated synthetic endpoints for reproductions.

## Current scope

The current browser encryption snapshot and protocol documents are supported for review. The unauthenticated ECDH public-key exchange and unauthenticated text revision/origin fields are documented in `THREAT-MODEL.md` and reproduced in `test/limitations.test.mjs`. Reports that refine their impact, find additional attack paths, or propose a compatible repair remain useful.

The legacy file-offer downgrade disclosed by snapshot 0.1 is repaired in snapshot 0.2 and retained as an expected-rejection regression in `test/file-receive.test.mjs`. Reports showing a bypass of the exact-marker, established-key, or AES-GCM receive requirements are in scope.

The proprietary relay implementation and unrelated IcyZip web features are outside this repository, but a finding is in scope when relay behavior breaks or bypasses a property claimed by this E2EE snapshot.
