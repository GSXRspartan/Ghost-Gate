import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { configuredJoinEndpoints } from "../../web/telegram/join-endpoints.js";

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

test("canonical and legacy Telegram join assets both expose a structured error panel", () => {
  for (const file of ["../../web/telegram/join.html", "../../web/telegram/join/index.html"]) {
    const html = readFileSync(new URL(file, import.meta.url), "utf8");
    assert.match(html, /id="tg-error-heading"/);
    assert.match(html, /id="tg-error-technical"/);
    assert.doesNotMatch(html, /<p class="error" id="tg-error"/);
  }
});
