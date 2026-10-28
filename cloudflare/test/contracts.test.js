import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { originMatches, parseGateCatalog } from "../src/contracts.js";

const catalog = JSON.stringify([{ tenant: "tenant-a", gateId: "esm10", relyingSite: "https://gate.example", network: 38, resourceAddress: "resource_test", thresholdRaw: "10000000", divisibility: 6, proofMode: "credential" }]);

test("edge discovery only emits public, server-configured gate metadata", () => {
  const parsed = parseGateCatalog(catalog);
  assert.deepEqual(parsed[0].network, 38);
  assert.equal(parsed[0].thresholdRaw, "10000000");
});

test("localhost HTTP is opt-in development configuration only", () => {
  const local = JSON.stringify([{ tenant: "tenant-a", gateId: "esm10", relyingSite: "http://127.0.0.1:8787", network: 38, resourceAddress: "resource_test", thresholdRaw: "10000000" }]);
  assert.throws(() => parseGateCatalog(local));
  assert.equal(parseGateCatalog(local, { allowLocalHttp: true })[0].relyingSite, "http://127.0.0.1:8787");
});

test("same-origin GET may omit Origin, but writes and foreign origins cannot", () => {
  const gate = parseGateCatalog(catalog)[0];
  assert.equal(originMatches(new Request("https://gate.example/api/session"), gate), true);
  assert.equal(originMatches(new Request("https://gate.example/api/session", { method: "POST" }), gate), false);
  assert.equal(originMatches(new Request("https://gate.example/api/session", { headers: { origin: "https://evil.example" } }), gate), false);
  assert.equal(originMatches(new Request("https://evil.example/api/session"), gate), false);
});

test("hosted Worker sends root to the hosted static entrypoint", async () => {
  const seen = [];
  const response = await worker.fetch(new Request("https://edge.example/"), {
    ASSETS: { fetch(request) { seen.push(new URL(request.url).pathname); return new Response("site"); } },
  });
  assert.equal(await response.text(), "site");
  assert.deepEqual(seen, ["/hosted.html"]);
});

test("hosted proof endpoints fail closed without an authenticated verifier", async () => {
  const request = new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/proof", { method: "POST", headers: { origin: "https://gate.example" } });
  const response = await worker.fetch(request, { GG_GATE_CATALOG: catalog });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).authorized, false);
});

test("hosted proof endpoints reject a relying-site substitution before verifier handling", async () => {
  const request = new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/proof", { method: "POST", headers: { origin: "https://attacker.example" } });
  const response = await worker.fetch(request, { GG_GATE_CATALOG: catalog });
  assert.equal(response.status, 403);
});

test("hosted proof endpoint bounds both an announced and chunked request body", async () => {
  const env = {
    GG_GATE_CATALOG: catalog, GG_VERIFIER_ORIGIN: "https://verifier.example", GG_VERIFIER_TOKEN: "verifier-secret",
    GG_VERIFIER_REQUEST_KEY: "request-secret", GG_VERIFIER_RESPONSE_KEY: "response-secret",
  };
  const oversized = JSON.stringify({ nonce: "a".repeat(64), proof: { padding: "x".repeat(20 * 1024) } });
  const request = new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/proof", {
    method: "POST", headers: { origin: "https://gate.example", "content-length": String(oversized.length) }, body: oversized,
  });
  const response = await worker.fetch(request, env);
  assert.equal(response.status, 413);
  assert.equal((await response.json()).authorized, false);
});

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

async function hmac(value, secret) {
  const text = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", text.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const bytes = new Uint8Array(await crypto.subtle.sign("HMAC", key, text.encode(canonical(value))));
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function coordinatorFixture() {
  const records = new Map();
  const binding = (record, body) => record.tenant === body.tenant && record.gateId === body.gateId
    && record.relyingSite === body.relyingSite && record.network === body.network
    && record.resourceAddress === body.resourceAddress && record.thresholdRaw === body.thresholdRaw
    && record.policyVersion === body.policyVersion && record.visitorSession === body.visitorSession;
  return {
    records,
    idFromName(name) { return name; },
    get(id) {
      return { async fetch(url, init) {
        assert.equal(init.headers.authorization, "Bearer coordinator-secret");
        const action = new URL(url).pathname.slice(1); const body = JSON.parse(init.body);
        const record = records.get(id);
        if (action === "issue") { records.set(id, { ...body, backendState: { generation:"1", policyHash:"a".repeat(64), haltRevision:"", sessionTtlSecs:3600 }, state: "issued" }); return Response.json({ state: "issued" }, { status: 201 }); }
        if (!record || !binding(record, body)) return Response.json({ error: "binding" }, { status: 409 });
        if (action === "reserve") {
          if (record.state === "issued") { record.state = "submitted"; record.proofJobId = body.proofJobId; record.proofDigest = body.proofDigest; }
          if (record.state === "submitted" && record.proofDigest !== body.proofDigest) return Response.json({ error: "different proof" }, { status: 409 });
          return Response.json({ state: "reserved", proofJobId: record.proofJobId, challenge: record });
        }
        if (action === "authorize") { record.state = "authorized"; record.authorizationId = body.authorizationId; return Response.json({ state: "authorized" }); }
        if (action === "access") return Response.json({ authorized: record.state === "authorized" });
        return Response.json({ state: record.state, proofJobId: record.proofJobId });
      } };
    },
  };
}

test("authenticated verifier result authorizes one durable hosted replay record", async () => {
  const coordinator = coordinatorFixture();
  const env = {
    GG_GATE_CATALOG: catalog, REPLAY_COORDINATOR: coordinator, GG_COORDINATOR_TOKEN: "coordinator-secret",
    GG_VERIFIER_ORIGIN: "https://verifier.example", GG_VERIFIER_TOKEN: "verifier-secret", GG_VERIFIER_REQUEST_KEY: "request-secret", GG_VERIFIER_RESPONSE_KEY: "response-secret",
  };
  const visitor = "visitor-test-session";
  const challenge = await worker.fetch(new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/challenge", {
    method: "POST", headers: { origin: "https://gate.example", cookie: `__Host_gg_visitor=${visitor}` },
  }), env);
  assert.equal(challenge.status, 201);
  const nonce = (await challenge.json()).challenge.nonce;
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    assert.equal(init.headers.authorization, "Bearer verifier-secret");
    const input = JSON.parse(init.body); const { proof, ...signed } = input;
    assert.deepEqual(Object.keys(input).sort(), ["gateId", "network", "nonce", "policyVersion", "proof", "proofDigest", "relyingSite", "resourceAddress", "tenant", "thresholdRaw"].sort());
    assert.equal(init.headers["x-gg-verifier-request-signature"], await hmac(input, "request-secret"));
    const result = { ...signed, verdict: "VERIFIED", verificationId: "verify-1234567890" };
    return new Response(JSON.stringify(result), { status: 200, headers: { "content-type": "application/json", "x-gg-verifier-signature": await hmac(result, "response-secret") } });
  };
  try {
    const proof = await worker.fetch(new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/proof", {
      method: "POST", headers: { origin: "https://gate.example", cookie: `__Host_gg_visitor=${visitor}` },
      body: JSON.stringify({ nonce, proof: { output: "fixture-only" } }),
    }), env);
    assert.equal(proof.status, 200, await proof.clone().text());
    const result = await proof.json(); assert.equal(result.authorized, true);
    assert.equal([...coordinator.records.values()][0].state, "authorized");
  } finally { globalThis.fetch = previousFetch; }
});

test("an independent visitor cannot turn a pending hosted proof into their own job", async () => {
  const coordinator = coordinatorFixture();
  const env = { GG_GATE_CATALOG: catalog, REPLAY_COORDINATOR: coordinator, GG_COORDINATOR_TOKEN: "coordinator-secret", GG_VERIFIER_ORIGIN: "https://verifier.example", GG_VERIFIER_TOKEN: "verifier-secret", GG_VERIFIER_REQUEST_KEY: "request-secret", GG_VERIFIER_RESPONSE_KEY: "response-secret" };
  const first = "first-visitor";
  const challenge = await worker.fetch(new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/challenge", { method: "POST", headers: { origin: "https://gate.example", cookie: `__Host_gg_visitor=${first}` } }), env);
  const nonce = (await challenge.json()).challenge.nonce;
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const input = JSON.parse(init.body); const { proof, ...signed } = input;
    const result = { ...signed, verdict: "UNKNOWN", verificationId: "verify-1234567890" };
    return new Response(JSON.stringify(result), { status: 200, headers: { "content-type": "application/json", "x-gg-verifier-signature": await hmac(result, "response-secret") } });
  };
  try {
    const pending = await worker.fetch(new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/proof", { method: "POST", headers: { origin: "https://gate.example", cookie: `__Host_gg_visitor=${first}` }, body: JSON.stringify({ nonce, proof: {} }) }), env);
    assert.equal(pending.status, 202);
    const stolen = await worker.fetch(new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/proof", { method: "POST", headers: { origin: "https://gate.example", cookie: "__Host_gg_visitor=other-visitor" }, body: JSON.stringify({ nonce, proof: {} }) }), env);
    assert.equal(stolen.status, 409);
  } finally { globalThis.fetch = previousFetch; }
});

test("same visitor may retry the same pending proof, but cannot replace it", async () => {
  const coordinator = coordinatorFixture();
  const env = {
    GG_GATE_CATALOG: catalog, REPLAY_COORDINATOR: coordinator, GG_COORDINATOR_TOKEN: "coordinator-secret",
    GG_VERIFIER_ORIGIN: "https://verifier.example", GG_VERIFIER_TOKEN: "verifier-secret", GG_VERIFIER_REQUEST_KEY: "request-secret", GG_VERIFIER_RESPONSE_KEY: "response-secret",
  };
  const visitor = "retrying-visitor";
  const challenge = await worker.fetch(new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/challenge", {
    method: "POST", headers: { origin: "https://gate.example", cookie: `__Host_gg_visitor=${visitor}` },
  }), env);
  const nonce = (await challenge.json()).challenge.nonce;
  const previousFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (_url, init) => {
    const input = JSON.parse(init.body); const { proof, ...signed } = input;
    const result = { ...signed, verdict: calls++ === 0 ? "UNKNOWN" : "VERIFIED", verificationId: "stable-verification-id-123" };
    return new Response(JSON.stringify(result), { status: 200, headers: { "content-type": "application/json", "x-gg-verifier-signature": await hmac(result, "response-secret") } });
  };
  const request = (proof) => worker.fetch(new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/proof", {
    method: "POST", headers: { origin: "https://gate.example", cookie: `__Host_gg_visitor=${visitor}` }, body: JSON.stringify({ nonce, proof }),
  }), env);
  try {
    assert.equal((await request({ output: "same" })).status, 202);
    const authorized = await request({ output: "same" });
    assert.equal(authorized.status, 200, await authorized.clone().text());
    assert.equal((await authorized.json()).authorized, true);
    assert.equal(calls, 2);
  } finally { globalThis.fetch = previousFetch; }

  const secondChallenge = await worker.fetch(new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/challenge", {
    method: "POST", headers: { origin: "https://gate.example", cookie: `__Host_gg_visitor=${visitor}` },
  }), env);
  const secondNonce = (await secondChallenge.json()).challenge.nonce;
  const previousFetchAgain = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const input = JSON.parse(init.body); const { proof, ...signed } = input;
    const result = { ...signed, verdict: "UNKNOWN", verificationId: "stable-verification-id-456" };
    return new Response(JSON.stringify(result), { status: 200, headers: { "content-type": "application/json", "x-gg-verifier-signature": await hmac(result, "response-secret") } });
  };
  try {
    const first = await worker.fetch(new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/proof", {
      method: "POST", headers: { origin: "https://gate.example", cookie: `__Host_gg_visitor=${visitor}` }, body: JSON.stringify({ nonce: secondNonce, proof: { output: "first" } }),
    }), env);
    assert.equal(first.status, 202);
    const replaced = await worker.fetch(new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/proof", {
      method: "POST", headers: { origin: "https://gate.example", cookie: `__Host_gg_visitor=${visitor}` }, body: JSON.stringify({ nonce: secondNonce, proof: { output: "replacement" } }),
    }), env);
    assert.equal(replaced.status, 409);
  } finally { globalThis.fetch = previousFetchAgain; }
});
