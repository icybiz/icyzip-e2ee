# Test the E2EE code

Use Node.js 20 or newer. No install step, dependency, account, browser, network connection, or server is needed:

```sh
npm run test:minimal
npm test
```

Start with [`test/minimal.test.mjs`](test/minimal.test.mjs): two peers exchange text, reject a one-bit ciphertext change, and continue exchanging valid messages. The 33-line [`test/endpoint.mjs`](test/endpoint.mjs) supplies in-memory storage and passes messages directly between peers. It calls the actual [`src/e2ee.js`](src/e2ee.js) browser module and implements no cryptography or server behavior. No proprietary server code is included.

To explore a possible weakness, copy the minimal test to `test/your-case.test.mjs`, change one input or message, and run it directly:

```sh
node --test test/your-case.test.mjs
```

Keep the case small and use synthetic data. State the attacker capability and expected security property. For a rejected message, also check that legitimate messages still work afterward. Add a finished regression to the explicit `npm test` file list in `package.json`.

For examples beyond the starter, see:

- [`crypto.test.mjs`](test/crypto.test.mjs): key substitution, roles and pairs, malformed encodings, key separation, text/file tampering, storage recovery, and an independent cryptography oracle.
- [`file-receive.test.mjs`](test/file-receive.test.mjs): the actual browser receive controller with a small UI/transport adapter; altered offers, downgrade attempts, cancellation, retry, and exact file bytes.
- [`security-regressions.test.mjs`](test/security-regressions.test.mjs): previously identified relay-substitution and text-metadata attacks.

`npm test` also checks the recorded source hashes and proves that unrelated surrounding-code edits are tolerated while changes to the reviewed module, integration sections or their provenance are rejected. Separately, `npm run check:live` downloads the two public IcyZip JavaScript assets to compare the reviewed bytes with this repository; this optional check requires network access. It reports full-file and line-location drift separately because ordinary application edits can move unchanged reviewed code. See [PROVENANCE.md](PROVENANCE.md).

Read [PROTOCOL.md](PROTOCOL.md) and [THREAT-MODEL.md](THREAT-MODEL.md) when assessing an attack. Report security-sensitive findings privately through [SECURITY.md](SECURITY.md); include a minimal synthetic reproduction, not real users' content, keys, or pairing links.
