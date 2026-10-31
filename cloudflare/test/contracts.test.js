import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
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

test("hosted Worker sends root to the Privacy Lab entrypoint", async () => {
  const seen = [];
  const response = await worker.fetch(new Request("https://edge.example/"), {
    ASSETS: { fetch(request) { seen.push(new URL(request.url).pathname); return new Response("site"); } },
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("location"), null, "root must not redirect the browser to /lab/");
  assert.equal(response.headers.get("cross-origin-resource-policy"), "cross-origin", "the public dApp document must opt in to a COEP-protected wallet iframe");
  assert.equal(response.headers.get("cross-origin-embedder-policy"), "require-corp", "the nested public dApp document must carry a compatible COEP policy");
  assert.equal(await response.text(), "site");
  assert.deepEqual(seen, ["/lab/"]);
});

test("only public Privacy Lab documents opt in to Web Tari Universe cross-origin embedding", async () => {
  const env = { ASSETS: { fetch() { return new Response("site"); } } };
  for (const path of ["/lab", "/lab/"]) {
    const response = await worker.fetch(new Request(`https://ghostgate.boo${path}`), env);
    assert.equal(response.headers.get("cross-origin-resource-policy"), "cross-origin");
    assert.equal(response.headers.get("cross-origin-embedder-policy"), "require-corp");
  }
  const admin = await worker.fetch(new Request("https://ghostgate.boo/admin"), env);
  assert.equal(admin.headers.get("cross-origin-resource-policy"), null);
  assert.equal(admin.headers.get("cross-origin-embedder-policy"), null);
  const claim = await worker.fetch(new Request("https://ghostgate.boo/claim"), env);
  assert.equal(claim.headers.get("cross-origin-resource-policy"), null);
  assert.equal(claim.headers.get("cross-origin-embedder-policy"), null);
});

test("Privacy Lab footer does not advertise the blocked public administrator route", () => {
  const lab = readFileSync(new URL("../../web/lab/index.html", import.meta.url), "utf8");
  assert.match(lab, /Ghost Gate — Privacy Lab\. A minimum threshold can be proven without disclosing the amount held; the verifier learns a lower bound, never a balance\. Sessions expire and require a fresh proof\./);
  assert.match(lab, /Gate configuration is managed through the private administrator\. Published policies cannot be changed from the public Privacy Lab\./);
  assert.doesNotMatch(lab, /bridge edge-proxy/);
  assert.doesNotMatch(lab, /href=["']\/admin["']/);
});

test("Privacy Lab presents hosted browser credentials clearly and constrains the mobile status strip", () => {
  const lab = readFileSync(new URL("../../web/lab/lab.js", import.meta.url), "utf8");
  const css = readFileSync(new URL("../../web/lab/lab.css", import.meta.url), "utf8");
  assert.match(lab, /setPill\("pill-walletd", "ok", "browser credential"\)/);
  assert.match(lab, /setPill\("pill-walletd", "", "optional · not in use"\)/);
  assert.match(lab, /`healthy · \$\{bridgeVersion\}`/);
  assert.doesNotMatch(lab, /healthy v\$\{health\.body\.version/);
  assert.match(css, /grid-template-columns: repeat\(2, minmax\(0, 1fr\)\)/);
  assert.match(css, /\.pill \{ display: grid; grid-template-columns: auto auto minmax\(0, 1fr\)/);
  assert.match(css, /\.view-switch \{ flex: 1 1 auto; \}/);
  assert.match(css, /\.technical-facts \{ grid-template-columns: 1fr; gap: 0\.12rem;/);
  assert.match(css, /\.technical-facts dd \{ margin-bottom: 0\.35rem; \}/);
});

test("public aliases serve only the intended Telegram assets and never the private administrator", async () => {
  const seen = [];
  const env = { ASSETS: { fetch(request) { seen.push(new URL(request.url).pathname); return new Response("site"); } } };
  for (const path of ["/claim", "/claim/", "/telegram/join", "/telegram/join/"]) {
    const response = await worker.fetch(new Request(`https://ghostgate.boo${path}`), env);
    assert.equal(response.status, 200);
  }
  const admin = await worker.fetch(new Request("https://ghostgate.boo/admin"), env);
  assert.equal(admin.status, 404);
  assert.deepEqual(seen, ["/telegram/join/", "/telegram/join/", "/telegram/join/", "/telegram/join/"]);
});

test("bot redirect accepts only an exact Telegram bot URL", async () => {
  const valid = await worker.fetch(new Request("https://ghostgate.boo/bot"), { GG_TELEGRAM_BOT_URL: "https://t.me/GhostGateBot" });
  assert.equal(valid.status, 302);
  assert.equal(valid.headers.get("location"), "https://t.me/GhostGateBot");
  const seen = [];
  const invalid = await worker.fetch(new Request("https://ghostgate.boo/bot"), {
    GG_TELEGRAM_BOT_URL: "https://t.me/GhostGateBot?start=redirect",
    ASSETS: { fetch(request) { seen.push(new URL(request.url).pathname); return new Response("instructions"); } },
  });
  assert.equal(invalid.status, 200);
  assert.deepEqual(seen, ["/bot/"]);
});

test("bot setup page is served directly when no redirect destination is configured", async () => {
  const seen = [];
  const response = await worker.fetch(new Request("https://ghostgate.boo/bot/"), {
    ASSETS: { fetch(request) { seen.push(new URL(request.url).pathname); return new Response("bot setup"); } },
  });
  assert.equal(response.status, 200);
  assert.deepEqual(seen, ["/bot/"]);
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

test("bridge proxy rejects methods not in the allowlist", async () => {
  const env = { GG_VERIFIER_ORIGIN: "https://bridge.example", ASSETS: { fetch() { return new Response("static"); } } };
  for (const method of ["PUT", "DELETE", "PATCH", "OPTIONS"]) {
    for (const path of ["/gate/crypt/challenge", "/proof/abc/status"]) {
      const response = await worker.fetch(new Request(`https://edge.example${path}`, { method }), env);
      assert.equal(response.status, 404, `${method} ${path} must not be proxied`);
    }
  }
});

test("bridge proxy rejects paths outside the allowlist", async () => {
  const env = { GG_VERIFIER_ORIGIN: "https://bridge.example", ASSETS: { fetch() { return new Response("static"); } } };
  for (const path of ["/admin", "/admin/api", "/v1/hosted/verify", "/wallet/send", "/gate", "/gate/"]) {
    const response = await worker.fetch(new Request(`https://edge.example${path}`), env);
    const body = await response.text();
    assert.notEqual(response.status, 503, `GET ${path} must not reach bridgeProxy (got: ${body})`);
  }
});

test("bridge proxy rejects an oversized POST body", async () => {
  const env = { GG_VERIFIER_ORIGIN: "https://bridge.example" };
  const oversized = "x".repeat(128 * 1024);
  const response = await worker.fetch(new Request("https://edge.example/gate/crypt/challenge", {
    method: "POST", headers: { "content-type": "application/json", "content-length": String(oversized.length) }, body: oversized,
  }), env);
  assert.equal(response.status, 413);
});

test("bridge proxy does not forward browser cookies, Authorization, or Origin to the bridge", async () => {
  let captured = null;
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => { captured = init.headers; return new Response("{}"); };
  try {
    await worker.fetch(new Request("https://edge.example/gate/crypt/challenge", {
      method: "POST", headers: { cookie: "secret=token", authorization: "Bearer steal-me", origin: "https://evil.example", "content-type": "application/json" }, body: "{}",
    }), { GG_VERIFIER_ORIGIN: "https://bridge.example" });
    assert.ok(captured, "bridge request must have been sent");
    assert.equal(captured.cookie, undefined);
    assert.equal(captured.authorization, undefined);
    assert.equal(captured.origin, undefined);
  } finally { globalThis.fetch = previousFetch; }
});

test("bridge proxy locks content-type to application/json for POST", async () => {
  let captured = null;
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => { captured = init.headers; return new Response("{}"); };
  try {
    await worker.fetch(new Request("https://edge.example/gate/crypt/challenge", {
      method: "POST", headers: { "content-type": "text/html" }, body: "{}",
    }), { GG_VERIFIER_ORIGIN: "https://bridge.example" });
    assert.equal(captured["content-type"], "application/json");
  } finally { globalThis.fetch = previousFetch; }
});

test("bridge proxy forwards a nonempty credential body from a fresh string", async () => {
  let captured = null;
  const body = JSON.stringify({
    gate_id: "Crypt", challenge_nonce: "n", public_key: "k", public_nonce: "pn",
    session_commitment: "sc", signature: "s", substate_id: "utxo_x",
  });
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    captured = { method: init.method, contentType: init.headers["content-type"], body: await new Response(init.body).text() };
    return new Response("{}");
  };
  try {
    await worker.fetch(new Request("https://edge.example/gate/Crypt/credential", {
      method: "POST", headers: { "content-type": "application/json" }, body,
    }), { GG_VERIFIER_ORIGIN: "https://bridge.example" });
    assert.equal(captured.method, "POST");
    assert.equal(captured.contentType, "application/json");
    assert.equal(new TextEncoder().encode(captured.body).byteLength, new TextEncoder().encode(body).byteLength);
    assert.equal(createHash("sha256").update(captured.body).digest("hex"), createHash("sha256").update(body).digest("hex"));
    assert.deepEqual(Object.keys(JSON.parse(captured.body)).sort(), ["challenge_nonce", "gate_id", "public_key", "public_nonce", "session_commitment", "signature", "substate_id"]);
  } finally { globalThis.fetch = previousFetch; }
});

test("Worker-side /lab/gates serves enriched gate data from catalog", async () => {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ symbol: "tTARI", proof_kind: "ootle" }));
  try {
    const response = await worker.fetch(new Request("https://edge.example/lab/gates"), {
      GG_GATE_CATALOG: catalog, GG_VERIFIER_ORIGIN: "https://bridge.example",
      REPLAY_COORDINATOR: {}, GG_COORDINATOR_TOKEN: "token",
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.gates.length, 1);
    assert.equal(body.gates[0].gateId, "esm10");
    assert.equal(body.gates[0].symbol, "tTARI");
    assert.equal(body.gates[0].activatable, true);
    assert.equal(body.gates[0].sessionsAvailable, true);
  } finally { globalThis.fetch = previousFetch; }
});

test("Worker-side /health probes bridge via tunnel-routed path", async () => {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("{}", { status: 200 });
  try {
    const response = await worker.fetch(new Request("https://edge.example/health"), {
      GG_GATE_CATALOG: catalog, GG_VERIFIER_ORIGIN: "https://bridge.example",
      REPLAY_COORDINATOR: {},
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.service, "ghost-gate-bridge");
    assert.equal(body.credential_configured, true);
    assert.deepEqual(body.gates, ["esm10"]);
  } finally { globalThis.fetch = previousFetch; }
});

test("Worker-native /api/ routes remain unaffected by bridge proxy", async () => {
  const response = await worker.fetch(
    new Request("https://edge.example/api/tenants/tenant-a/gates/esm10/challenge", { method: "POST", headers: { origin: "https://gate.example" } }),
    { GG_GATE_CATALOG: catalog, GG_VERIFIER_ORIGIN: "https://bridge.example" },
  );
  assert.equal(response.status, 503);
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

test("Worker-side /wallet/status returns unconfigured with browser credential guidance", async () => {
  const response = await worker.fetch(new Request("https://edge.example/wallet/status"), {
    GG_GATE_CATALOG: catalog, GG_VERIFIER_ORIGIN: "https://bridge.example",
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.configured, false);
  assert.equal(body.reachable, false);
  assert.ok(body.note.includes("browser wallet"), "note should mention browser wallet for credential proofs");
});

test("ghostgate.boo relying site is a valid HTTPS origin", () => {
  const ghostgateCatalog = JSON.stringify([{
    tenant: "Crypt", gateId: "Crypt", relyingSite: "https://ghostgate.boo",
    network: 38, resourceAddress: "resource_0101010101010101010101010101010101010101010101010101010101010101",
    thresholdRaw: "100000000", divisibility: 6, proofMode: "credential", policyHash: "a".repeat(64),
  }]);
  const gates = parseGateCatalog(ghostgateCatalog);
  assert.equal(gates[0].relyingSite, "https://ghostgate.boo");
  assert.equal(gates[0].gateId, "Crypt");
  assert.equal(gates[0].policyHash, "a".repeat(64));
});

test("published catalog rejects malformed policy hashes", () => {
  const invalid = JSON.stringify([{ tenant: "Crypt", gateId: "Crypt", relyingSite: "https://ghostgate.boo", network: 38,
    resourceAddress: "resource_test", thresholdRaw: "100000000", policyHash: "not-a-policy-hash" }]);
  assert.throws(() => parseGateCatalog(invalid), /policy hash/);
});

test("relying-site origin mismatch is rejected for ghostgate.boo gate", () => {
  const ghostgateCatalog = JSON.stringify([{
    tenant: "Crypt", gateId: "Crypt", relyingSite: "https://ghostgate.boo",
    network: 38, resourceAddress: "resource_test", thresholdRaw: "100000000", proofMode: "credential",
  }]);
  const gate = parseGateCatalog(ghostgateCatalog)[0];
  assert.equal(originMatches(new Request("https://ghostgate.boo/api/session"), gate), true);
  assert.equal(originMatches(new Request("https://ghost-gate-staging.gsxrspartan.workers.dev/api/session"), gate), false);
  assert.equal(originMatches(new Request("https://evil.example/api/session"), gate), false);
});
