import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { configuredJoinEndpoints, publishedGateFromCatalog, resolvePublishedGate } from "../../web/telegram/join-endpoints.js";

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
    assert.match(html, /id="tg-error-action" href="\/bot"/);
    assert.doesNotMatch(html, /<p class="error" id="tg-error"/);
  }
});

test("Telegram claim refusal derives human threshold wording from published gate metadata", () => {
  const source = readFileSync(new URL("../../web/telegram/claim.js", import.meta.url), "utf8");
  assert.match(source, /Reveal at least \$\{humanThreshold\} in a qualifying output and try again with \/join/);
  assert.doesNotMatch(source, /Unshield more tTARI and try again with \/join/);
  assert.match(source, /formatAmount\(meta\.thresholdRaw, div\)/);
});

test("Telegram expiry tells the user to mint a new link without weakening token checks", () => {
  const source = readFileSync(new URL("../../web/telegram/claim.js", import.meta.url), "utf8");
  assert.match(source, /Verification link expired/);
  assert.match(source, /This single-use verification link has expired\. Return to the Ghost Gate bot and send \/join again/);
  assert.match(source, /if \(!token\) return fail\("This page needs a join link from the bot/);
  assert.match(source, /includes\("join link expired"\)/);
});

test("public Telegram onboarding has a dedicated two-column layout and Privacy Lab opens it", () => {
  const bot = readFileSync(new URL("../../web/bot/index.html", import.meta.url), "utf8");
  const lab = readFileSync(new URL("../../web/lab/lab.js", import.meta.url), "utf8");
  const claim = readFileSync(new URL("../../web/telegram/claim.js", import.meta.url), "utf8");
  assert.match(bot, /class="telegram-steps"/);
  assert.match(bot, /grid-template-columns: 2rem minmax\(0, 1fr\)/);
  assert.match(bot, /\.step-copy \{ min-width: 0; \}/);
  assert.match(bot, /@media \(max-width: 480px\)/);
  assert.equal((bot.match(/class="step-num"/g) || []).length, 4);
  assert.match(bot, /<a href="https:\/\/t\.me\/GhostGateGSXRBot"[^>]*target="_blank"[^>]*rel="noopener noreferrer"[^>]*>@GhostGateGSXRBot<\/a>/);
  assert.match(bot, /@GhostGateGSXRBot<\/a> in Telegram and send <code>\/join<\/code>/);
  assert.match(lab, /window\.open\("\/bot", "_blank", "noopener,noreferrer"\)/);
  assert.doesNotMatch(lab, /window\.location\.href = "\/bot"/);
  assert.doesNotMatch(lab, /window\.location\.href = `\/telegram\/join/);
  assert.match(claim, /a\.target = "_blank"/);
  assert.match(claim, /a\.rel = "noopener noreferrer"/);
});

test("Telegram links leave an embedded dApp frame without weakening origin checks", () => {
  const bot = readFileSync(new URL("../../web/bot/index.html", import.meta.url), "utf8");
  const lab = readFileSync(new URL("../../web/lab/lab.js", import.meta.url), "utf8");
  assert.match(bot, /target="_blank" rel="noopener noreferrer"/);
  assert.match(lab, /user-initiated/);
  assert.doesNotMatch(lab, /window\.top\.location/);
  assert.doesNotMatch(lab, /location\.replace\([^)]*t\.me/);
});
