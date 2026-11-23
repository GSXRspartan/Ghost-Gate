import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("tunnel template routes only explicitly named bridge and claim paths", () => {
  const template = readFileSync(new URL("../../deploy/cloudflared-config.yml.template", import.meta.url), "utf8");
  const entries = [...template.matchAll(/- hostname: (\S+)\s+path: '([^']+)'\s+service: (\S+)/g)]
    .map(([, host, path, service]) => ({ host, path: new RegExp(path), service }));
  assert.equal(entries.length, 6);
  const route = (host, path) => entries.find(e => e.host === host && e.path.test(path))?.service || "http_status:404";
  for (const path of ["/v1/hosted/verify", "/gate/crypt", "/gate/crypt/challenge", "/gate/crypt/credential", "/proof/abc/status", "/lab/trace", "/v1/bot/sessions/abc123/challenge", "/v1/bot/sessions/abc123/proof"]) {
    assert.equal(route("bridge.DOMAIN_HERE", path), "http://127.0.0.1:7799");
  }
  for (const path of ["/admin", "/admin/api", "/health", "/wallet/status", "/lab/gates", "/access/check", "/walletd", "/gate/crypt/prove", "/proof/abc", "/proof/abc/status/extra", "/v1/hosted/verify/extra", "/v1/bot/sessions", "/v1/bot/sessions/abc123/redeem", "/v1/bot/sessions/abc123/extra"]) {
    assert.equal(route("bridge.DOMAIN_HERE", path), "http_status:404");
  }
  assert.equal(route("claim.DOMAIN_HERE", "/claim"), "http://127.0.0.1:7808");
  assert.equal(route("claim.DOMAIN_HERE", "/claim/extra"), "http_status:404");
  assert.match(template, /hostname: claim\.DOMAIN_HERE[\s\S]*?httpHostHeader: 127\.0\.0\.1/);
  assert.match(template, /- service: http_status:404\s*$/);
});

test("VPS backups remain root-only and publish atomically", () => {
  const backup = readFileSync(new URL("../../deploy/backup.sh", import.meta.url), "utf8");
  const setup = readFileSync(new URL("../../deploy/setup-vps.sh", import.meta.url), "utf8");
  assert.match(backup, /^umask 077$/m);
  assert.match(backup, /install -d -o root -g root -m 0700 "\$BACKUP_DIR"/);
  assert.match(backup, /chmod 0600 "\$TEMP_ARCHIVE"/);
  assert.match(backup, /mv -f -- "\$TEMP_ARCHIVE" "\$ARCHIVE"/);
  assert.match(setup, /chown root:root \/opt\/ghost-gate\/data\/backups\s+chmod 700 \/opt\/ghost-gate\/data\/backups/);
});
