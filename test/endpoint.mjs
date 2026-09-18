// Copyright 2026 Richard Andresik. SPDX-License-Identifier: Apache-2.0
import { webcrypto } from "node:crypto";
import "../src/e2ee.js";
const E2EE = globalThis.IcyZipE2EE;

export { E2EE, webcrypto };

export function memoryStorage()
{
    const values = new Map();
    return { values, getItem: key => values.get(key) ?? null,
        setItem: (key, value) => values.set(key, String(value)), removeItem: key => values.delete(key) };
}

export function client({ pairId = "synthetic-v3-pair", role = "primary",
    secret = E2EE.generateSecret(webcrypto), storage = memoryStorage(), crypto = webcrypto } = {})
{
    return { pairId, role, secret, storage, session: E2EE.createSession({ pairId, role, secret, storage, crypto }) };
}

export async function connect(primary, secondary)
{
    const [first, second] = await Promise.all([primary.session.publicMessage(), secondary.session.publicMessage()]);
    await Promise.all([primary.session.acceptPublicMessage(second), secondary.session.acceptPublicMessage(first)]);
}

export async function paired(options = {})
{
    const primary = client(options);
    const secondary = client({ ...options, role: "secondary", secret: primary.secret, storage: memoryStorage() });
    await connect(primary, secondary);
    return { primary, secondary };
}
