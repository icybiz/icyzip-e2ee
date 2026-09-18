# Security policy

## Reporting a vulnerability

Please send security-sensitive findings privately to `contact@icyzip.com` with `IcyZip security` in the subject. If GitHub private vulnerability reporting is enabled for the repository, that is also an appropriate private channel.

For non-sensitive bugs or general feedback, the anonymous form at [icyzip.com/feedback](https://icyzip.com/feedback) does not require a name or email address. Do not place an undisclosed vulnerability, exploit details, pairing links, keys, or private user content in a public issue or the general feedback form.

A useful report includes:

- the affected protocol field or source function;
- attacker capabilities and prerequisites;
- a minimal reproduction with synthetic data;
- confidentiality, integrity, metadata, or availability impact;
- a proposed fix or regression test when available.

Please do not test with another person's data, pairing, browser, or account. The repository's test adapters create isolated synthetic endpoints.

## Supported review scope

Review release `0.3.0` covers the IcyZip production/staging protocol introduced at commit `edc7b8b`. Reports about authenticated public-key exchange, fragment-secret handling, key separation, text envelope v2, file-chunk encryption, authenticated file offers, state reset, source correspondence, or a mismatch between these documents and the deployed code are in scope.

The active-relay substitution and unauthenticated text-metadata behaviors documented in public v0.2 are retained as expected-rejection tests in `test/security-regressions.test.mjs`. Reports showing a bypass remain especially useful. The v0.1 file-offer downgrade remains covered by `test/file-receive.test.mjs`.

The proprietary relay and unrelated web features are outside this source package, but a finding is in scope when relay behavior breaks or bypasses a property claimed by this E2EE release.
