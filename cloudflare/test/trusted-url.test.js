import test from "node:test";
import assert from "node:assert/strict";
import { trustedBase } from "../../web/telegram/trusted-url.js";

test("Telegram destinations require exact configured HTTPS origins", () => {
  const page = "https://app.example.com";
  const trusted = "https://bridge.example.com:8443";
  assert.equal(trustedBase(trusted, trusted, page), trusted);
  for (const url of ["https://evil.example.com", "https://bridge.example.com", "http://bridge.example.com:8443", "https://bridge.example.com:8443.evil.com", "https://user@bridge.example.com:8443", `${trusted}/redirect`, `${trusted}/?x=1`]) {
    assert.equal(trustedBase(url, trusted, page), null, url);
  }
  assert.equal(trustedBase("http://127.0.0.1:7899", "", "http://localhost:8787"), "http://127.0.0.1:7899");
  assert.equal(trustedBase("http://127.0.0.1:7899", "", page), null);
  assert.equal(trustedBase("https://claim.example.com/claim", "https://claim.example.com", page, { allowPath: true }), "https://claim.example.com/claim");
});
