import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import {
  advanceTechnicalLifecycle,
  newTechnicalLifecycle,
  switchTechnicalView,
  technicalSummaryRows,
} from "../../web/lab/technical-state.js";

const policyHash = "13af3169aefb313f355368c5b9131d512d86048ab700d850024c79ddb680b74f";
const gate = {
  tenant: "Crypt", gateId: "Crypt", relyingSite: "https://ghostgate.boo", network: 38,
  resourceAddress: `resource_${"01".repeat(32)}`, thresholdRaw: "100000000", divisibility: 6,
  proofMode: "credential", policyVersion: 3, policyHash, symbol: "tTARI",
};

test("the Worker proxies the attempt-scoped technical trace and preserves its trace capability", async () => {
  const originalFetch = globalThis.fetch;
  let forwarded;
  globalThis.fetch = async (url, init) => {
    forwarded = { url: String(url), init };
    return Response.json({ events: [{ seq: 1, code: "challenge.minted" }] });
  };
  try {
    const attempt = "a".repeat(32);
    const response = await worker.fetch(new Request(`https://ghostgate.boo/lab/trace?attempt=${attempt}`, {
      headers: { "x-gg-attempt": attempt },
    }), { GG_VERIFIER_ORIGIN: "https://bridge.example" });
    assert.equal(response.status, 200);
    assert.equal(forwarded.url, `https://bridge.example/lab/trace?attempt=${attempt}`);
    assert.equal(forwarded.init.method, "GET");
    assert.equal(forwarded.init.headers["x-gg-attempt"], attempt);
    assert.deepEqual(await response.json(), { events: [{ seq: 1, code: "challenge.minted" }] });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("technical summary retains a successful proof through a view switch without credential material", () => {
  let lifecycle = newTechnicalLifecycle();
  lifecycle = advanceTechnicalLifecycle(lifecycle, {
    challenge: "issued · fresh single-use",
    credential: "submitted",
    verification: "accepted · verified against chain evidence",
    session: "issued",
    replay: "single-use challenge consumed on authorization",
  });
  const switched = switchTechnicalView(lifecycle, "technical");
  assert.equal(switched.view, "technical");
  assert.equal(switched.lifecycle, lifecycle, "a display toggle cannot reset the proof lifecycle");
  const rows = Object.fromEntries(technicalSummaryRows(gate, switched.lifecycle, "healthy · edge-proxy", "100 tTARI"));
  assert.deepEqual(rows, {
    gate: "Crypt", asset: "tTARI", threshold: "100 tTARI / 100000000 raw",
    network: "38", "proof mode": "credential", "policy version": "3", "policy hash": policyHash,
    "relying site": "https://ghostgate.boo", challenge: "issued · fresh single-use", credential: "submitted",
    verification: "accepted · verified against chain evidence", "session / access": "issued",
    "replay / freshness": "single-use challenge consumed on authorization", bridge: "healthy · edge-proxy",
  });
  assert.equal(JSON.stringify(rows).includes("signature"), false);
  assert.equal(JSON.stringify(rows).includes("nonce"), false);
});

test("technical summary renders a neutral failed-proof state instead of becoming blank", () => {
  const lifecycle = advanceTechnicalLifecycle(newTechnicalLifecycle(), {
    challenge: "issued · fresh single-use",
    credential: "submitted",
    verification: "not accepted · HTTP 409",
    replay: "challenge remains subject to normal expiry",
    failure: "proof refused",
  });
  const rows = Object.fromEntries(technicalSummaryRows(gate, lifecycle, "healthy · edge-proxy", "100 tTARI"));
  assert.equal(rows.verification, "not accepted · HTTP 409");
  assert.equal(rows["session / access"], "not issued");
  assert.equal(rows.failure, "proof refused");
});

test("public gate discovery supplies only the published policy metadata the inspector needs", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    assert.equal(String(url), "https://bridge.example/gate/Crypt");
    return Response.json({ symbol: "tTARI" });
  };
  try {
    const response = await worker.fetch(new Request("https://ghostgate.boo/lab/gates"), {
      GG_GATE_CATALOG: JSON.stringify([gate]), GG_VERIFIER_ORIGIN: "https://bridge.example",
    });
    const discovered = (await response.json()).gates[0];
    assert.deepEqual(
      { gateId: discovered.gateId, policyVersion: discovered.policyVersion, policyHash: discovered.policyHash, relyingSite: discovered.relyingSite },
      { gateId: "Crypt", policyVersion: "3", policyHash, relyingSite: "https://ghostgate.boo" },
    );
    assert.equal("signature" in discovered, false);
    assert.equal("sessionToken" in discovered, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
