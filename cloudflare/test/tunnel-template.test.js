import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("tunnel template routes only explicitly named bridge and claim paths", () => {
  const template = readFileSync(new URL("../../deploy/cloudflared-config.yml.template", import.meta.url), "utf8");
  const entries = [...template.matchAll(/- hostname: (\S+)\s+path: '([^']+)'\s+service: (\S+)/g)]
    .map(([, host, path, service]) => ({ host, path: new RegExp(path), service }));
  assert.equal(entries.length, 3);
  const route = (host, path) => entries.find(e => e.host === host && e.path.test(path))?.service || "http_status:404";
  for (const path of ["/v1/hosted/verify", "/gate/crypt", "/gate/crypt/challenge", "/gate/crypt/credential"]) {
    assert.equal(route("bridge.DOMAIN_HERE", path), "http://127.0.0.1:7799");
  }
  for (const path of ["/admin", "/admin/api", "/health", "/walletd", "/gate/crypt/prove", "/v1/hosted/verify/extra"]) {
    assert.equal(route("bridge.DOMAIN_HERE", path), "http_status:404");
  }
  assert.equal(route("claim.DOMAIN_HERE", "/claim"), "http://127.0.0.1:7808");
  assert.equal(route("claim.DOMAIN_HERE", "/claim/extra"), "http_status:404");
  assert.match(template, /- service: http_status:404\s*$/);
});
