import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { configuredJoinEndpoints } from "../../web/telegram/join-endpoints.js";
import { publishedGateFromCatalog, resolvePublishedGate } from "../../web/telegram/published-gate.js";

const cryptV3 = {
  tenant: "Crypt", gateId: "Crypt", symbol: "tTARI",
  resourceAddress: `resource_${"01".repeat(32)}`, thresholdRaw: "100000000",
  divisibility: 6, network: 38, proofMode: "credential", policyVersion: "v3",
  policyHash: "13af3169aefb313f355368c5b9131d512d86048ab700d850024c79ddb680b74f",
  relyingSite: "https://ghostgate.boo",
};

test("Telegram join uses only deployment-configured exact HTTPS bridge and claim endpoints", () => {
  const endpoints = configuredJoinEndpoints({
    bridgeOrigin: "https://bridge.ghostgate.boo",
    claimOrigin: "https://claim.ghostgate.boo",
    pageOrigin: "https://ghostgate.boo",
  });
  assert.deepEqual(endpoints, {
    bridgeBase: "https://bridge.ghostgate.boo",
    claimUrl: "https://claim.ghostgate.boo/claim",
  });
  assert.deepEqual(configuredJoinEndpoints({
    bridgeOrigin: "http://bridge.ghostgate.boo",
    claimOrigin: "https://claim.ghostgate.boo/other",
    pageOrigin: "https://ghostgate.boo",
  }), { bridgeBase: null, claimUrl: null });
});

test("Telegram join links cannot supply claim or bridge destinations", () => {
  const source = readFileSync(new URL("../../web/telegram/claim.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /params\.get\("claim"/);
  assert.doesNotMatch(source, /params\.get\("bridge"/);
  assert.match(source, /configuredJoinEndpoints/);
});

test("Telegram join resolves an exact-case gate from the published Privacy Lab catalog", async () => {
  let request;
  const gate = await resolvePublishedGate("Crypt", async (url, init) => {
    request = { url, init };
    return Response.json({ gates: [cryptV3] });
  });
  assert.equal(request.url, "/lab/gates");
  assert.equal(request.init.credentials, "omit");
  assert.deepEqual(gate, cryptV3);
  assert.equal(gate.thresholdRaw, "100000000");
  assert.equal(gate.network, 38);
  assert.equal(gate.policyHash, "13af3169aefb313f355368c5b9131d512d86048ab700d850024c79ddb680b74f");
  assert.equal(gate.relyingSite, "https://ghostgate.boo");
  assert.equal(publishedGateFromCatalog([cryptV3], "crypt"), null, "gate ids stay case-sensitive");
  assert.equal(publishedGateFromCatalog([cryptV3], "NoSuchGate"), null, "there is no fallback gate");
});

test("Telegram join fails closed on malformed or unavailable catalog entries", async () => {
  assert.equal(await resolvePublishedGate("Crypt", async () => new Response("unavailable", { status: 503 })), null);
  assert.equal(publishedGateFromCatalog([{ ...cryptV3, gateId: "Crypt", thresholdRaw: "0" }], "Crypt"), null);
  assert.equal(publishedGateFromCatalog([{ ...cryptV3, gateId: "Crypt", policyHash: "not-a-hash" }], "Crypt"), null);
});

test("Telegram join uses the Worker proxy for published-gate proof operations", () => {
  const source = readFileSync(new URL("../../web/telegram/claim.js", import.meta.url), "utf8");
  assert.match(source, /resolvePublishedGate\(gate\)/);
  assert.match(source, /const gatePath = `\/gate\/\$\{encodeURIComponent\(gateId\)\}`/);
  assert.doesNotMatch(source, /bridgeBase}\/gate/);
});

test("canonical and legacy Telegram join assets both expose a structured error panel", () => {
  for (const file of ["../../web/telegram/join.html", "../../web/telegram/join/index.html"]) {
    const html = readFileSync(new URL(file, import.meta.url), "utf8");
    assert.match(html, /id="tg-error-heading"/);
    assert.match(html, /id="tg-error-technical"/);
    assert.doesNotMatch(html, /<p class="error" id="tg-error"/);
  }
});
