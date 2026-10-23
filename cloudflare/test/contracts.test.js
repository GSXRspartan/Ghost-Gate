import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { parseGateCatalog } from "../src/contracts.js";

const catalog = JSON.stringify([{ tenant: "tenant-a", gateId: "esm10", relyingSite: "https://gate.example", network: 38, resourceAddress: "resource_test", thresholdRaw: "10000000", divisibility: 6, proofMode: "credential" }]);

test("edge discovery only emits public, server-configured gate metadata", () => {
  const parsed = parseGateCatalog(catalog);
  assert.deepEqual(parsed[0].network, 38);
  assert.equal(parsed[0].thresholdRaw, "10000000");
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
