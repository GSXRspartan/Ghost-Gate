import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { ReplayCoordinator } from "../src/replay-coordinator.js";

test("concurrent redemptions produce at most one usable session and preserve the reserved digest", async () => {
  const db = new DatabaseSync(":memory:");
  const sql = { exec(query, ...args) {
    if (/^\s*CREATE /i.test(query)) { db.exec(query); return []; }
    const statement = db.prepare(query);
    return /^\s*SELECT /i.test(query) ? statement.all(...args) : (statement.run(...args), []);
  } };
  const coordinator = new ReplayCoordinator({ storage: { sql } }, { GG_COORDINATOR_TOKEN: "secret" });
  const now = Math.floor(Date.now() / 1000);
  const binding = { nonce: "a".repeat(64), tenant: "t", gateId: "g", relyingSite: "https://example.com", network: 38,
    resourceAddress: "resource", thresholdRaw: "10", policyVersion: "v1", visitorSession: "visitor" };
  const call = (action, body) => coordinator.fetch(new Request(`https://coordinator/${action}`, {
    method: "POST", headers: { authorization: "Bearer secret", "content-type": "application/json" }, body: JSON.stringify(body),
  }));
  assert.equal((await call("issue", { ...binding, expiresUnix: now + 180 })).status, 201);
  const digest = "b".repeat(64);
  assert.equal((await call("reserve", { ...binding, proofJobId: "job", proofDigest: digest })).status, 200);
  const grant = { ...binding, proofJobId: "job", proofDigest: digest, verificationId: "verified", authorizationId: "auth", sessionExpiresUnix: now + 300 };
  assert.equal((await call("authorize", { ...grant, proofDigest: "c".repeat(64), sessionToken: "bad" })).status, 409);
  const responses = await Promise.all(["token-one", "token-two"].map(sessionToken => call("authorize", { ...grant, sessionToken })));
  assert.deepEqual(responses.map(r => r.status).sort(), [200, 409]);
  const accesses = await Promise.all(["token-one", "token-two"].map(sessionToken => call("access", { ...binding, sessionToken })));
  assert.deepEqual(accesses.map(r => r.status).sort(), [200, 401]);
  db.close();
});
