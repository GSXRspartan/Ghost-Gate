import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { canonical } from "../src/backend-state.js";
import { ReplayCoordinator } from "../src/replay-coordinator.js";

test("concurrent redemptions produce at most one usable session and preserve the reserved digest", async () => {
  const db = new DatabaseSync(":memory:");
  const sql = { exec(query, ...args) {
    if (/^\s*CREATE /i.test(query)) { db.exec(query); return []; }
    const statement = db.prepare(query);
    return /^\s*(SELECT |PRAGMA )/i.test(query) ? statement.all(...args) : (statement.run(...args), []);
  } };
  const env = { GG_COORDINATOR_TOKEN: "secret", GG_VERIFIER_ORIGIN:"https://backend.example", GG_VERIFIER_TOKEN:"token", GG_VERIFIER_REQUEST_KEY:"req", GG_VERIFIER_RESPONSE_KEY:"resp" };
  const previousFetch = globalThis.fetch;
  let generation = "1", revision = "", unavailable = false, stale = false, forged = false, replay = false, saved;
  globalThis.fetch = async (_url, init) => {
    if (unavailable) throw Error("tunnel unavailable");
    const body = { request: JSON.parse(init.body), state: {generation, policyHash:"a".repeat(64), haltRevision:revision, sessionTtlSecs:3600}, issuedUnix: Math.floor(Date.now()/1000) - (stale ? 60 : 0) };
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode("resp"), { name:"HMAC", hash:"SHA-256" }, false, ["sign"]);
    const sig = [...new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canonical(body))))].map(b => b.toString(16).padStart(2,"0")).join("");
    if (replay) return saved.clone();
    const response = Response.json(body, { headers:{"x-gg-verifier-signature":forged ? "0".repeat(64) : sig} });
    saved = response.clone(); return response;
  };
  const coordinator = new ReplayCoordinator({ storage: { sql } }, env);
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
  unavailable = true;
  assert.equal((await call("access", {...binding, sessionToken:"token-one"})).status, 503);
  unavailable = false; stale = true;
  assert.equal((await call("access", {...binding, sessionToken:"token-one"})).status, 503);
  stale = false; forged = true;
  assert.equal((await call("access", {...binding, sessionToken:"token-one"})).status, 503);
  forged = false; replay = true;
  assert.equal((await call("access", {...binding, sessionToken:"token-one"})).status, 503, "signed state from another request cannot be replayed");
  replay = false; generation = "2";
  assert.equal((await call("access", {...binding, sessionToken:"token-one"})).status, 409);
  generation = "1";
  assert.equal((await call("access", {...binding, sessionToken:"token-one"})).status, 401, "rollback cannot revive a retired session");
  assert.equal((await call("issue", {
    ...binding, nonce: "c".repeat(64), policyHash: "b".repeat(64), expiresUnix: now + 180,
  })).status, 503, "a catalog hash that does not match signed bridge state must fail closed");
  globalThis.fetch = previousFetch;
  db.close();
});
